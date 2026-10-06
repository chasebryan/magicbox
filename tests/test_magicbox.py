from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from magicbox import MagicBoxError, inspect_file, open_file, seal_file
from magicbox import core
from magicbox.cli import main


class MagicBoxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This temporary key is shared only to keep tests quick. Production
        # creates a fresh modulus for every seal operation.
        cls.test_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.original = self.root / "original"
        self.box = self.root / "sealed.mbox"
        self.output = self.root / "opened"
        self.original.write_bytes(b"Magic Box\x00\xff\n")

    def tearDown(self):
        self.directory.cleanup()

    def seal(self, *, work=8):
        with patch.object(core.rsa, "generate_private_key", return_value=self.test_private):
            return seal_file(self.original, self.box, work=work)

    def assert_no_output(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    def test_round_trip_binary_file_and_exact_size(self):
        sealed = self.seal()
        inspected = inspect_file(self.box)
        opened = open_file(self.box, self.output, max_work=8)
        self.assertEqual(self.output.read_bytes(), self.original.read_bytes())
        self.assertEqual(self.box.stat().st_size, self.original.stat().st_size + 854)
        self.assertFalse(inspected.authenticated)
        self.assertTrue(sealed.authenticated)
        self.assertTrue(opened.authenticated)
        self.assertEqual(inspected.work, 8)
        self.assertEqual(set(path.name for path in self.root.iterdir()),
                         {"original", "sealed.mbox", "opened"})

    def test_empty_file(self):
        self.original.write_bytes(b"")
        self.seal(work=1)
        open_file(self.box, self.output, max_work=1)
        self.assertEqual(self.output.read_bytes(), b"")
        self.assertEqual(self.box.stat().st_size, 854)

    def test_streaming_across_chunk_boundary(self):
        content = bytes(range(256)) * 129
        self.original.write_bytes(content)
        with patch.object(core, "CHUNK_BYTES", 1023):
            self.seal()
            open_file(self.box, self.output)
        self.assertEqual(self.output.read_bytes(), content)

    def test_real_key_generation_round_trip(self):
        seal_file(self.original, self.box, work=2)
        open_file(self.box, self.output, max_work=2)
        self.assertEqual(self.output.read_bytes(), self.original.read_bytes())

    def test_each_lock_parameter_ciphertext_and_tag_are_bound(self):
        self.seal()
        pristine = self.box.read_bytes()
        # work, base, nonce, wrapped key, ciphertext, tag. These mutations
        # remain structurally valid but must all fail GCM authentication.
        for offset in (17, 793, 794, 806, 838, len(pristine) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(pristine)
                changed[offset] ^= 1
                self.box.write_bytes(changed)
                with self.assertRaises(MagicBoxError):
                    open_file(self.box, self.output, max_work=32)
                self.assert_no_output()

    def test_invalid_structures_are_rejected_before_solving(self):
        self.seal()
        pristine = self.box.read_bytes()
        malformed = [b"", pristine[:837], pristine[:-1], pristine + b"extra"]
        for offset in (0, 8, 9, 25, 26):
            changed = bytearray(pristine)
            changed[offset] ^= 0xFF
            malformed.append(bytes(changed))
        for content in malformed:
            with self.subTest(length=len(content)):
                self.box.write_bytes(content)
                with patch.object(core, "_squarings") as solve:
                    with self.assertRaises(MagicBoxError):
                        open_file(self.box, self.output)
                    solve.assert_not_called()
                self.assert_no_output()

    def test_invalid_base_and_zero_work_are_rejected(self):
        self.seal()
        pristine = self.box.read_bytes()
        for base in (0, 1, self.test_private.private_numbers().public_numbers.n - 1):
            content = bytearray(pristine)
            content[410:794] = base.to_bytes(384, "big")
            self.box.write_bytes(content)
            with self.assertRaises(MagicBoxError):
                inspect_file(self.box)
        content = bytearray(pristine)
        content[10:18] = bytes(8)
        self.box.write_bytes(content)
        with self.assertRaises(MagicBoxError):
            inspect_file(self.box)

    def test_work_limit_is_checked_before_solving_or_writing(self):
        self.seal(work=9)
        with patch.object(core, "_squarings") as solve:
            with self.assertRaisesRegex(MagicBoxError, "limit is 8"):
                open_file(self.box, self.output, max_work=8)
            solve.assert_not_called()
        self.assert_no_output()

    def test_inspection_does_not_solve_the_lock(self):
        self.seal(work=core.MAX_WORK)
        with patch.object(core, "_squarings") as solve:
            info = inspect_file(self.box)
            solve.assert_not_called()
        self.assertEqual(info.work, core.MAX_WORK)
        self.assertFalse(info.authenticated)

    def test_bad_work_values_are_rejected_before_encryption(self):
        for work in (0, -1, True, 1.5, core.MAX_WORK + 1):
            with self.subTest(work=work), patch.object(core, "_create_lock") as create:
                with self.assertRaises(MagicBoxError):
                    seal_file(self.original, self.box, work=work)
                create.assert_not_called()
                self.assertFalse(self.box.exists())

    def test_oversized_plaintext_is_refused_before_key_generation(self):
        with patch.object(core, "MAX_PLAINTEXT_BYTES", 3):
            with patch.object(core, "_create_lock") as create:
                with self.assertRaises(MagicBoxError):
                    seal_file(self.original, self.box, work=1)
                create.assert_not_called()

    def test_existing_outputs_and_original_are_preserved(self):
        self.seal()
        old = self.box.read_bytes()
        with self.assertRaises(FileExistsError):
            seal_file(self.original, self.box, work=1)
        self.assertEqual(self.box.read_bytes(), old)
        self.output.write_bytes(b"keep this")
        with self.assertRaises(FileExistsError):
            open_file(self.box, self.output)
        self.assertEqual(self.output.read_bytes(), b"keep this")
        with self.assertRaises(FileExistsError):
            seal_file(self.original, self.original, work=1)
        self.assertEqual(self.original.read_bytes(), b"Magic Box\x00\xff\n")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions and symlinks")
    def test_private_permissions_and_dangling_symlink_refusal(self):
        self.seal()
        open_file(self.box, self.output)
        for path in (self.box, self.output):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "missing")
        with self.assertRaises(FileExistsError):
            open_file(self.box, dangling)
        self.assertTrue(dangling.is_symlink())

    def test_output_race_does_not_overwrite(self):
        self.seal()
        actual_link = os.link

        def raced(source, destination):
            Path(destination).write_bytes(b"another writer")
            return actual_link(source, destination)

        with patch.object(core.os, "link", side_effect=raced):
            with self.assertRaises(FileExistsError):
                open_file(self.box, self.output)
        self.assertEqual(self.output.read_bytes(), b"another writer")
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    def test_interrupted_solver_leaves_no_destination(self):
        self.seal()

        def interrupt(done, total):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            open_file(self.box, self.output, progress=interrupt)
        self.assert_no_output()

    def test_encryption_failure_cleans_staging_file(self):
        with patch.object(core.rsa, "generate_private_key", return_value=self.test_private):
            with patch.object(core, "_read_exact", side_effect=OSError("read failed")):
                with self.assertRaises(OSError):
                    seal_file(self.original, self.box, work=1)
        self.assertFalse(self.box.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    def test_cli_commands_and_clean_error(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with patch.object(core.rsa, "generate_private_key", return_value=self.test_private):
                self.assertEqual(main(["seal", str(self.original), "-o", str(self.box),
                                       "--work", "8"]), 0)
            stdout.seek(0)
            stdout.truncate()
            self.assertEqual(main(["inspect", str(self.box)]), 0)
            self.assertFalse(json.loads(stdout.getvalue())["authenticated"])
            self.assertEqual(main(["open", str(self.box), "-o", str(self.output)]), 0)
            self.assertEqual(main(["open", str(self.box), "-o", str(self.output)]), 2)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertEqual(self.output.read_bytes(), self.original.read_bytes())

    def test_module_entrypoint(self):
        result = subprocess.run([sys.executable, "-m", "magicbox", "--version"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "0.1.0")

    def test_sealing_twice_uses_fresh_lock_key_and_nonce(self):
        self.seal()
        first = self.box.read_bytes()
        other = self.root / "other.mbox"
        with patch.object(core.rsa, "generate_private_key", return_value=self.test_private):
            seal_file(self.original, other, work=8)
        second = other.read_bytes()
        self.assertNotEqual(first[410:794], second[410:794])
        self.assertNotEqual(first[794:806], second[794:806])
        self.assertNotEqual(first[806:838], second[806:838])

    def test_independent_container_vector(self):
        # Assemble the file without the production serializer or key KDF.
        # AESGCM is also independent of the streaming Cipher path under test.
        modulus = self.test_private.private_numbers().public_numbers.n
        base, work = 2, 8
        while math.gcd(base, modulus) != 1:
            base += 1
        message = b"independent format vector\x00\xff"
        nonce, key = bytes(range(12)), bytes(range(32))
        prefix = (b"MAGICBOX\x01\x01" + work.to_bytes(8, "big")
                  + len(message).to_bytes(8, "big") + modulus.to_bytes(384, "big")
                  + base.to_bytes(384, "big") + nonce)
        solution = pow(base, 1 << work, modulus).to_bytes(384, "big")
        prk = hmac.digest(hashlib.sha256(prefix).digest(), solution, "sha256")
        mask = hmac.digest(prk, b"magicbox:v1:lock-mask\x01", "sha256")
        header = prefix + bytes(a ^ b for a, b in zip(key, mask, strict=True))
        self.box.write_bytes(header + AESGCM(key).encrypt(nonce, message, header))
        open_file(self.box, self.output, max_work=8)
        self.assertEqual(self.output.read_bytes(), message)

    def test_fixed_public_vector(self):
        vector = json.loads((Path(__file__).parent / "vectors" / "v1.json").read_text())
        content = bytes.fromhex(vector["box_hex"])
        self.assertEqual(hashlib.sha256(content).hexdigest(), vector["box_sha256"])
        modulus, base = int(vector["n_hex"], 16), int(vector["a_hex"], 16)
        solution = core._squarings(base, modulus, vector["work"], None)
        self.assertEqual(solution.to_bytes(384, "big").hex(), vector["solution_hex"])
        self.assertEqual(core._mask(solution, content[:806]).hex(), vector["mask_hex"])
        self.box.write_bytes(content)
        open_file(self.box, self.output, max_work=vector["work"])
        self.assertEqual(self.output.read_bytes().hex(), vector["plaintext_hex"])

    def test_modulus_header_is_authenticated(self):
        self.seal()
        content = bytearray(self.box.read_bytes())
        content[27] ^= 1  # Preserve its odd parity and significant bit length.
        self.box.write_bytes(content)
        with self.assertRaises(MagicBoxError):
            open_file(self.box, self.output)
        self.assert_no_output()


class PrimitiveTests(unittest.TestCase):
    def test_squaring_recurrence_matches_direct_exponentiation(self):
        for work in (1, 2, 7, 16):
            with self.subTest(work=work):
                self.assertEqual(core._squarings(2, 209, work, None), pow(2, 1 << work, 209))

    def test_trapdoor_shortcut_matches_sequential_solver(self):
        n, phi, base = 11 * 19, 10 * 18, 2
        for work in (1, 8, 97):
            with self.subTest(work=work):
                self.assertEqual(pow(base, pow(2, work, phi), n),
                                 core._squarings(base, n, work, None))

    def test_nist_aes256_gcm_example_2(self):
        # NIST AES_GCM.pdf, GCM-AES256 example 2, 128-bit tag.
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" * 2)
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        )
        expected = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        )
        encryptor = Cipher(algorithms.AES256(key), modes.GCM(nonce)).encryptor()
        self.assertEqual(encryptor.update(plaintext) + encryptor.finalize(), expected)
        self.assertEqual(encryptor.tag.hex(), "b094dac5d93471bdec1a502270e3cc6c")

    def test_rfc5869_hkdf_sha256_case_1(self):
        result = HKDF(
            algorithm=hashes.SHA256(), length=42,
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        ).derive(bytes.fromhex("0b" * 22))
        self.assertEqual(result.hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


if __name__ == "__main__":
    unittest.main()
