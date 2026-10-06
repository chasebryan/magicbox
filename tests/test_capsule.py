from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from magicbox import MagicBoxError, init_file, inspect_file, open_file
from magicbox import capsule, core
from magicbox.cli import main


class CapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.vector = json.loads((Path(__file__).parent / "vectors" / "capsule.json").read_text())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.source, self.box, self.output = (self.root / name for name in ("original", "sealed.mbox", "output"))
        self.source.write_bytes(b"Magic Box\x00\xff\n")

    def tearDown(self):
        self.directory.cleanup()

    def initialize(self, *, work=8):
        with patch.object(core.rsa, "generate_private_key", return_value=self.private):
            return init_file(self.source, self.box, work=work)

    def vector_bytes(self, name):
        return bytes.fromhex(self.vector[name])

    def fixed_initialize(self):
        self.source.write_bytes(self.vector_bytes("plaintext_hex"))
        puzzle = (
            int(self.vector["n_hex"], 16), int(self.vector["a_hex"], 16),
            int(self.vector["result_hex"], 16),
        )
        entropy = [self.vector_bytes(name) for name in (
            "key_hex", "capsule_nonce_hex", "content_nonce_hex",
        )]
        with patch.object(capsule, "_create_puzzle", return_value=puzzle):
            with patch.object(capsule.secrets, "token_bytes", side_effect=entropy):
                return init_file(self.source, self.box, work=self.vector["work"])

    def assert_clean_failure(self):
        self.assertFalse(self.box.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    def test_fixed_vector_matches_independent_encryption(self):
        vector = self.vector
        plaintext = self.vector_bytes("plaintext_hex")
        prefix = (b"MAGICBOX\x01\x03" + vector["work"].to_bytes(8, "big")
                  + self.vector_bytes("n_hex") + self.vector_bytes("a_hex")
                  + self.vector_bytes("capsule_nonce_hex"))
        prk = hmac.digest(hashlib.sha256(prefix).digest(), self.vector_bytes("result_hex"), "sha256")
        key = hmac.digest(prk, b"magicbox:v1:capsule-key\x01", "sha256")
        self.assertEqual(key, self.vector_bytes("capsule_key_hex"))
        record = (b"MBKR\x01\x01" + len(plaintext).to_bytes(8, "big")
                  + self.vector_bytes("key_hex") + self.vector_bytes("content_nonce_hex"))
        self.assertEqual(record, self.vector_bytes("record_hex"))
        sealed = AESGCM(key).encrypt(self.vector_bytes("capsule_nonce_hex"), record, prefix)
        self.assertEqual(sealed, self.vector_bytes("capsule_hex"))
        header = prefix + sealed
        expected = header + AESGCM(self.vector_bytes("key_hex")).encrypt(
            self.vector_bytes("content_nonce_hex"), plaintext, header,
        )
        self.assertEqual(expected, self.vector_bytes("box_hex"))
        self.assertEqual(hashlib.sha256(expected).hexdigest(), vector["box_sha256"])
        with patch.object(capsule, "CHUNK_BYTES", 7):
            info = self.fixed_initialize()
        self.assertEqual(self.box.read_bytes(), expected)
        self.assertEqual(info.box_bytes, len(expected))
        self.assertTrue(info.authenticated)

    def test_key_nonce_and_record_are_encrypted_inside_the_file(self):
        self.fixed_initialize()
        data = self.box.read_bytes()
        for name in ("key_hex", "content_nonce_hex", "record_hex"):
            self.assertNotIn(self.vector_bytes(name), data)
        self.assertEqual(set(path.name for path in self.root.iterdir()), {"original", "sealed.mbox"})

    def test_known_key_fixture_authenticates_record_and_payload(self):
        # Only already-known, public vector keys are used here. This is not a
        # recovery implementation or an opening API for arbitrary boxes.
        data = self.vector_bytes("box_hex")
        self.assertEqual(AESGCM(self.vector_bytes("capsule_key_hex")).decrypt(
            self.vector_bytes("capsule_nonce_hex"), data[798:872], data[:798],
        ), self.vector_bytes("record_hex"))
        self.assertEqual(AESGCM(self.vector_bytes("key_hex")).decrypt(
            self.vector_bytes("content_nonce_hex"), data[872:], data[:872],
        ), self.vector_bytes("plaintext_hex"))

    def test_record_authentication_binds_all_prefix_and_capsule_fields(self):
        pristine = self.vector_bytes("box_hex")
        for offset in (0, 8, 9, 17, 18, 401, 402, 785, 786, 797, 798, 855, 856, 871):
            with self.subTest(offset=offset):
                changed = bytearray(pristine)
                changed[offset] ^= 1
                with self.assertRaises(InvalidTag):
                    AESGCM(self.vector_bytes("capsule_key_hex")).decrypt(
                        bytes(changed[786:798]), bytes(changed[798:872]), bytes(changed[:798]),
                    )

    def test_payload_authentication_binds_entire_capsule_header_and_contents(self):
        pristine = self.vector_bytes("box_hex")
        for offset in (0, 8, 9, 17, 18, 401, 402, 785, 786, 797, 798, 871, 872, len(pristine) - 1):
            with self.subTest(offset=offset):
                changed = bytearray(pristine)
                changed[offset] ^= 1
                with self.assertRaises(InvalidTag):
                    AESGCM(self.vector_bytes("key_hex")).decrypt(
                        self.vector_bytes("content_nonce_hex"), bytes(changed[872:]), bytes(changed[:872]),
                    )
        for changed in (pristine[:-1], pristine + b"extra"):
            with self.assertRaises(InvalidTag):
                AESGCM(self.vector_bytes("key_hex")).decrypt(
                    self.vector_bytes("content_nonce_hex"), changed[872:], changed[:872],
                )

    def test_empty_file_exact_size_and_input_preservation(self):
        self.source.write_bytes(b"")
        created = self.initialize(work=1)
        inspected = inspect_file(self.box)
        self.assertEqual(self.box.stat().st_size, 888)
        self.assertEqual(created.plaintext_bytes, 0)
        self.assertEqual(inspected.plaintext_bytes, 0)
        self.assertTrue(created.authenticated)
        self.assertFalse(inspected.authenticated)
        self.assertEqual(self.source.read_bytes(), b"")

    def test_streaming_initialization_matches_known_content_key(self):
        payload = bytes(range(256)) * 513
        self.source.write_bytes(payload)
        key, capsule_nonce, content_nonce = bytes(range(32)), bytes(range(12)), bytes(range(12, 24))
        with patch.object(capsule.secrets, "token_bytes", side_effect=[key, capsule_nonce, content_nonce]):
            with patch.object(capsule, "CHUNK_BYTES", 1023):
                self.initialize()
        data = self.box.read_bytes()
        self.assertEqual(AESGCM(key).decrypt(content_nonce, data[872:], data[:872]), payload)
        self.assertEqual(self.source.read_bytes(), payload)
        self.assertEqual(len(data), len(payload) + 888)

    def test_inspection_does_not_derive_keys_or_solve_a_condition(self):
        self.initialize(work=core.MAX_WORK)
        with patch.object(capsule, "HKDF") as kdf:
            with patch.object(core, "_squarings") as solver:
                inspected = inspect_file(self.box)
                kdf.assert_not_called()
                solver.assert_not_called()
        self.assertEqual(inspected.work, core.MAX_WORK)
        self.assertFalse(inspected.authenticated)

    def test_inspection_does_not_claim_payload_integrity_or_authenticated_length(self):
        self.fixed_initialize()
        pristine = self.box.read_bytes()
        for data in (pristine[:-1], pristine + b"extra", pristine[:798] + bytes(74) + pristine[872:]):
            self.box.write_bytes(data)
            info = inspect_file(self.box)
            self.assertFalse(info.authenticated)
            self.assertEqual(info.plaintext_bytes, len(data) - 888)

    def test_invalid_signatures_versions_suites_and_truncation_are_rejected(self):
        self.fixed_initialize()
        pristine = self.box.read_bytes()
        malformed = [b"", pristine[:10], pristine[:871], pristine[:887]]
        for offset in (0, 8, 9):
            changed = bytearray(pristine)
            changed[offset] ^= 0xFF
            malformed.append(bytes(changed))
        for data in malformed:
            with self.subTest(length=len(data)):
                self.box.write_bytes(data)
                with self.assertRaises(MagicBoxError):
                    inspect_file(self.box)

    def test_invalid_work_modulus_and_bases_are_rejected(self):
        self.initialize()
        pristine = self.box.read_bytes()
        n = self.private.private_numbers().public_numbers.n
        p, q = self.private.private_numbers().p, self.private.private_numbers().q
        order_two = (2 * pow(q, -1, p) * q - 1) % n
        invalid = []
        zero_work = bytearray(pristine)
        zero_work[10:18] = bytes(8)
        invalid.append(zero_work)
        for value in (n - 1, n >> 1):
            changed = bytearray(pristine)
            changed[18:402] = value.to_bytes(384, "big")
            invalid.append(changed)
        for value in (0, 1, n - 1, n, p, order_two):
            changed = bytearray(pristine)
            changed[402:786] = value.to_bytes(384, "big")
            invalid.append(changed)
        for data in invalid:
            self.box.write_bytes(data)
            with self.assertRaises(MagicBoxError):
                inspect_file(self.box)

    def test_bad_work_and_oversized_inputs_rejected_before_key_generation(self):
        for value in (0, -1, True, 1.5, core.MAX_WORK + 1):
            with patch.object(capsule, "_create_capsule") as create:
                with self.assertRaises(MagicBoxError):
                    init_file(self.source, self.box, work=value)
                create.assert_not_called()
                self.assert_clean_failure()
        with patch.object(capsule, "MAX_PLAINTEXT_BYTES", 1):
            with patch.object(capsule, "_create_capsule") as create:
                with self.assertRaises(MagicBoxError):
                    init_file(self.source, self.box, work=1)
                create.assert_not_called()
                self.assert_clean_failure()

    def test_oversized_inspection_is_refused(self):
        self.fixed_initialize()
        with patch.object(capsule, "MAX_PLAINTEXT_BYTES", 1):
            with self.assertRaises(MagicBoxError):
                inspect_file(self.box)

    def test_legacy_open_path_cannot_open_capsule_or_export_a_key(self):
        self.initialize()
        with patch.object(core, "_squarings") as solver:
            with self.assertRaises(MagicBoxError):
                open_file(self.box, self.output)
            solver.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    def test_existing_output_original_and_racing_output_are_preserved(self):
        self.initialize()
        original_box = self.box.read_bytes()
        with self.assertRaises(FileExistsError):
            init_file(self.source, self.box, work=1)
        with self.assertRaises(FileExistsError):
            init_file(self.source, self.source, work=1)
        self.assertEqual(self.box.read_bytes(), original_box)
        self.assertEqual(self.source.read_bytes(), b"Magic Box\x00\xff\n")
        raced_output = self.root / "raced.mbox"
        link = os.link

        def race(source, destination):
            Path(destination).write_bytes(b"another writer")
            return link(source, destination)

        with patch.object(core.os, "link", side_effect=race):
            with patch.object(core.rsa, "generate_private_key", return_value=self.private):
                with self.assertRaises(FileExistsError):
                    init_file(self.source, raced_output, work=1)
        self.assertEqual(raced_output.read_bytes(), b"another writer")
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX file modes and symlinks")
    def test_private_output_mode_and_dangling_symlink_refusal(self):
        self.initialize()
        self.assertEqual(self.box.stat().st_mode & 0o777, 0o600)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "missing")
        with self.assertRaises(FileExistsError):
            init_file(self.source, dangling, work=1)
        self.assertTrue(dangling.is_symlink())

    def test_read_failure_and_interruption_leave_no_box_or_staging_file(self):
        for error in (OSError("input read failed"), KeyboardInterrupt()):
            with patch.object(capsule, "_read_exact", side_effect=error):
                with self.assertRaises(type(error)):
                    self.initialize()
            self.assert_clean_failure()

    def test_changing_input_length_is_not_published(self):
        read = capsule._read_exact

        def grow(stream, size):
            result = read(stream, size)
            with self.source.open("ab") as target:
                target.write(b"extra")
            return result

        with patch.object(capsule, "_read_exact", side_effect=grow):
            with self.assertRaisesRegex(MagicBoxError, "grew"):
                self.initialize()
        self.assert_clean_failure()

    def test_fresh_initializations_change_modulus_and_capsule(self):
        init_file(self.source, self.box, work=1)
        other = self.root / "other.mbox"
        init_file(self.source, other, work=1)
        first, second = self.box.read_bytes(), other.read_bytes()
        self.assertNotEqual(first[18:402], second[18:402])
        self.assertNotEqual(first[786:798], second[786:798])
        self.assertNotEqual(first[798:872], second[798:872])

    def test_cli_initialization_inspection_and_refused_open(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with patch.object(core.rsa, "generate_private_key", return_value=self.private):
                self.assertEqual(main(["init", str(self.source), "-o", str(self.box), "--work", "8"]), 0)
            stdout.seek(0)
            stdout.truncate()
            self.assertEqual(main(["inspect", str(self.box)]), 0)
            self.assertFalse(json.loads(stdout.getvalue())["authenticated"])
            self.assertEqual(main(["open", str(self.box), "-o", str(self.output)]), 2)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
