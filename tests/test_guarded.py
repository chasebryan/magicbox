from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from magicbox import (
    BoxUnavailable, MagicBoxError, MemoryVault, TamperDetected,
    open_file, open_guarded_file, seal_guarded_file,
)
from magicbox import core, guarded


class GuardedTests(unittest.TestCase):
    def test_empty_and_binary_round_trips(self):
        for content in (b"", b"Magic Box\x00\xff", bytes(range(256)) * 257):
            with self.subTest(length=len(content)):
                vault = MemoryVault()
                box = vault.seal(content)
                self.assertEqual(len(box.data), len(content) + 94)
                self.assertEqual(vault.open(box.box_id, box.data), content)
                self.assertEqual(vault.open(box.box_id, box.data), content)
                self.assertEqual(vault.events, ())

    def test_every_field_and_length_mutation_revokes_pristine_copy(self):
        offsets = (0, 8, 9, 10, 25, 26, 33, 34, 45, 46, 77, 78, 93)
        for mutation in (*offsets, "truncate", "append", "empty"):
            with self.subTest(mutation=mutation):
                alarms = []
                vault = MemoryVault(on_alarm=alarms.append)
                box = vault.seal(b"payload")
                data = bytearray(box.data)
                if mutation == "truncate":
                    submitted = box.data[:-1]
                elif mutation == "append":
                    submitted = box.data + b"extra"
                elif mutation == "empty":
                    submitted = b""
                else:
                    data[mutation] ^= 1
                    submitted = bytes(data)
                with self.assertRaises(TamperDetected) as caught:
                    vault.open(box.box_id, submitted)
                self.assertEqual(caught.exception.event.box_id, box.box_id)
                self.assertEqual(caught.exception.event.reason, "integrity_failure")
                self.assertEqual(alarms, list(vault.events))
                self.assertEqual(len(alarms), 1)
                with self.assertRaises(BoxUnavailable):
                    vault.open(box.box_id, box.data)
                with self.assertRaises(BoxUnavailable):
                    vault.open(box.box_id, submitted)
                self.assertEqual(len(vault.events), 1)

    def test_embedded_id_cannot_select_an_unrelated_vault_record(self):
        vault = MemoryVault()
        first, second = vault.seal(b"first"), vault.seal(b"second")
        altered = first.data[:10] + bytes.fromhex(second.box_id) + first.data[26:]
        with self.assertRaises(TamperDetected) as caught:
            vault.open(first.box_id, altered)
        self.assertEqual(caught.exception.event.box_id, first.box_id)
        self.assertEqual(vault.open(second.box_id, second.data), b"second")

    def test_swapping_whole_boxes_revokes_only_the_expected_slot(self):
        vault = MemoryVault()
        first, second = vault.seal(b"first"), vault.seal(b"second")
        with self.assertRaises(TamperDetected):
            vault.open(first.box_id, second.data)
        with self.assertRaises(BoxUnavailable):
            vault.open(first.box_id, first.data)
        self.assertEqual(vault.open(second.box_id, second.data), b"second")

    def test_unknown_id_and_api_type_errors_do_not_revoke_a_box(self):
        vault = MemoryVault()
        box = vault.seal(b"keep")
        with self.assertRaises(BoxUnavailable):
            vault.open("unregistered", box.data)
        with self.assertRaises(TypeError):
            vault.open(box.box_id, bytearray(box.data))
        with self.assertRaises(TypeError):
            vault.open(1, box.data)
        with self.assertRaises(TypeError):
            vault.seal(bytearray(b"keep"))
        self.assertEqual(vault.open(box.box_id, box.data), b"keep")
        self.assertEqual(vault.events, ())

    def test_revocation_and_event_retention_precede_failing_alarm_callback(self):
        observed = []

        def alarm(event):
            observed.append(event)
            self.assertEqual(vault.events, (event,))
            with self.assertRaises(BoxUnavailable):
                vault.open(box.box_id, box.data)
            raise OSError("alarm transport unavailable")

        vault = MemoryVault(on_alarm=alarm)
        box = vault.seal(b"secret")
        with self.assertRaises(TamperDetected) as caught:
            vault.open(box.box_id, b"tampered")
        self.assertIsInstance(caught.exception.alarm_error, OSError)
        self.assertEqual(vault.events, tuple(observed))
        self.assertNotIn("secret", str(caught.exception))
        with self.assertRaises(BoxUnavailable):
            vault.open(box.box_id, box.data)

    def test_concurrent_tamper_submissions_emit_one_event(self):
        alarms = []
        vault = MemoryVault(on_alarm=alarms.append)
        box = vault.seal(b"secret")
        ready = threading.Barrier(8)

        def submit():
            ready.wait(timeout=5)
            try:
                vault.open(box.box_id, b"tampered")
            except (TamperDetected, BoxUnavailable) as error:
                return type(error)
            self.fail("tampered box opened")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: submit(), range(8)))
        self.assertEqual(results.count(TamperDetected), 1)
        self.assertEqual(results.count(BoxUnavailable), 7)
        self.assertEqual(len(alarms), 1)
        self.assertEqual(vault.events, tuple(alarms))

    def test_open_is_serialized_against_revocation(self):
        vault = MemoryVault()
        box = vault.seal(b"secret")
        entered, release, tamper_started = threading.Event(), threading.Event(), threading.Event()
        decrypt = guarded._decrypt

        def held_decrypt(*args):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test did not release the opening operation")
            return decrypt(*args)

        def submit_tamper():
            tamper_started.set()
            with self.assertRaises(TamperDetected):
                vault.open(box.box_id, b"tampered")

        with patch.object(guarded, "_decrypt", side_effect=held_decrypt):
            with ThreadPoolExecutor(max_workers=2) as pool:
                opened = pool.submit(vault.open, box.box_id, box.data)
                try:
                    self.assertTrue(entered.wait(timeout=5))
                    tampered = pool.submit(submit_tamper)
                    self.assertTrue(tamper_started.wait(timeout=5))
                    self.assertFalse(tampered.done())
                finally:
                    release.set()
                self.assertEqual(opened.result(timeout=5), b"secret")
                tampered.result(timeout=5)
        with self.assertRaises(BoxUnavailable):
            vault.open(box.box_id, box.data)

    def test_aead_failure_revokes_even_when_commitment_matches(self):
        vault = MemoryVault()
        box = vault.seal(b"secret")
        # Fault injection into protected state exercises the second integrity
        # check. Deployment must prevent an adversary changing that state.
        vault._records[box.box_id].secret = bytes(32)
        with self.assertRaises(TamperDetected):
            vault.open(box.box_id, box.data)
        with self.assertRaises(BoxUnavailable):
            vault.open(box.box_id, box.data)

    def test_structural_failure_revokes_even_when_commitment_matches(self):
        vault = MemoryVault()
        box = vault.seal(b"secret")
        altered = b"OTHERBOX" + box.data[8:]
        vault._records[box.box_id].commitment = hashlib.sha256(altered).digest()
        with self.assertRaises(TamperDetected):
            vault.open(box.box_id, altered)

    def test_oversized_submission_revokes_without_hashing_it(self):
        vault = MemoryVault()
        box = vault.seal(b"secret")
        with patch.object(guarded, "MAX_GUARDED_BOX_BYTES", 16):
            with patch.object(guarded.hashlib, "sha256") as digest:
                with self.assertRaises(TamperDetected):
                    vault.open(box.box_id, b"x" * 17)
                digest.assert_not_called()
        with self.assertRaises(BoxUnavailable):
            vault.open(box.box_id, box.data)

    def test_manual_revocation_is_idempotent_and_silent(self):
        vault = MemoryVault()
        box = vault.seal(b"secret")
        vault.revoke(box.box_id)
        vault.revoke(box.box_id)
        with self.assertRaises(BoxUnavailable):
            vault.open(box.box_id, box.data)
        with self.assertRaises(BoxUnavailable):
            vault.revoke("unknown")
        self.assertEqual(vault.events, ())

    def test_fresh_seals_have_distinct_ids_and_ciphertexts(self):
        vault = MemoryVault()
        first, second = vault.seal(b"same"), vault.seal(b"same")
        self.assertNotEqual(first.box_id, second.box_id)
        self.assertNotEqual(first.data, second.data)

    def test_fixed_vector_matches_independent_hkdf_and_aes(self):
        vector = json.loads((Path(__file__).parent / "vectors" / "guarded.json").read_text())
        identity, secret, key, nonce = (
            bytes.fromhex(vector[name]) for name in ("box_id", "secret_hex", "key_hex", "nonce_hex")
        )
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        prefix = struct.pack(">8sBB16sQ12s", b"MAGICBOX", 1, 2, identity, len(plaintext), nonce)
        prk = hmac.new(hashlib.sha256(prefix).digest(), secret, "sha256").digest()
        mask = hmac.new(prk, b"magicbox:v1:guard-mask\x01", "sha256").digest()
        header = prefix + bytes(a ^ b for a, b in zip(key, mask, strict=True))
        expected = header + AESGCM(key).encrypt(nonce, plaintext, header)
        self.assertEqual(expected.hex(), vector["box_hex"])
        self.assertEqual(hashlib.sha256(expected).hexdigest(), vector["box_sha256"])
        with patch.object(guarded.secrets, "token_bytes", side_effect=[identity, secret, key, nonce]):
            vault = MemoryVault()
            box = vault.seal(plaintext)
        self.assertEqual(box.data, expected)
        self.assertEqual(vault.open(box.box_id, expected), plaintext)


class GuardedFileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.original, self.box, self.output = (
            self.root / "original", self.root / "sealed.mbox", self.root / "opened"
        )
        self.original.write_bytes(b"Magic Box\x00\xff")
        self.vault = MemoryVault()

    def tearDown(self):
        self.directory.cleanup()

    def seal(self):
        return seal_guarded_file(self.original, self.box, vault=self.vault)

    def test_file_round_trip_preserves_original_and_private_modes(self):
        identity = self.seal()
        open_guarded_file(self.box, self.output, box_id=identity, vault=self.vault)
        self.assertEqual(self.output.read_bytes(), self.original.read_bytes())
        self.assertEqual(self.original.read_bytes(), b"Magic Box\x00\xff")
        if os.name == "posix":
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.box.stat().st_mode & 0o777, 0o600)

    def test_public_puzzle_opener_rejects_guarded_box(self):
        self.seal()
        with patch.object(core, "_squarings") as solve:
            with self.assertRaises(MagicBoxError):
                open_file(self.box, self.output)
            solve.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_tampered_file_never_publishes_plaintext(self):
        identity = self.seal()
        pristine = self.box.read_bytes()
        self.box.write_bytes(pristine[:-1] + bytes([pristine[-1] ^ 1]))
        with self.assertRaises(TamperDetected):
            open_guarded_file(self.box, self.output, box_id=identity, vault=self.vault)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])
        self.box.write_bytes(pristine)
        with self.assertRaises(BoxUnavailable):
            open_guarded_file(self.box, self.output, box_id=identity, vault=self.vault)
        self.assertFalse(self.output.exists())

    def test_existing_output_and_input_io_errors_do_not_revoke(self):
        identity = self.seal()
        self.output.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            open_guarded_file(self.box, self.output, box_id=identity, vault=self.vault)
        self.assertEqual(self.output.read_bytes(), b"keep")
        with self.assertRaises(FileNotFoundError):
            open_guarded_file(self.root / "missing", self.root / "new", box_id=identity, vault=self.vault)
        with self.assertRaises(FileExistsError):
            seal_guarded_file(self.original, self.box, vault=self.vault)
        self.assertEqual(self.vault.open(identity, self.box.read_bytes()), self.original.read_bytes())
        self.assertEqual(self.vault.events, ())

    def test_failed_box_publication_revokes_orphaned_registration(self):
        created = []
        seal = self.vault.seal

        def capture(plaintext):
            box = seal(plaintext)
            created.append(box)
            return box

        with patch.object(self.vault, "seal", side_effect=capture):
            with patch.object(core.os, "link", side_effect=OSError("publication failed")):
                with self.assertRaises(OSError):
                    self.seal()
        self.assertFalse(self.box.exists())
        self.assertEqual(list(self.root.glob(".magicbox-*")), [])
        with self.assertRaises(BoxUnavailable):
            self.vault.open(created[0].box_id, created[0].data)
        self.assertEqual(self.vault.events, ())

    def test_oversized_sealing_refused_before_registration(self):
        with patch.object(guarded, "MAX_GUARDED_PLAINTEXT_BYTES", 2):
            with patch.object(self.vault, "seal") as seal:
                with self.assertRaises(MagicBoxError):
                    self.seal()
                seal.assert_not_called()
        self.assertFalse(self.box.exists())

    def test_oversized_file_is_bounded_and_still_triggers_revocation(self):
        identity = self.seal()
        self.box.write_bytes(self.box.read_bytes() + b"x" * 10000)
        with patch.object(guarded, "MAX_GUARDED_BOX_BYTES", 128):
            with patch.object(self.vault, "open", wraps=self.vault.open) as opening:
                with self.assertRaises(TamperDetected):
                    open_guarded_file(self.box, self.output, box_id=identity, vault=self.vault)
                self.assertEqual(len(opening.call_args.args[1]), 129)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(self.vault.events), 1)


if __name__ == "__main__":
    unittest.main()
