"""Demonstrate a guarded file's revocation and alarm using temporary test data."""

import json
import tempfile
from dataclasses import asdict
from pathlib import Path

from magicbox import (
    BoxUnavailable, MemoryVault, TamperDetected, open_guarded_file, seal_guarded_file,
)


def main():
    def alarm(event):
        print("alarm:", json.dumps(asdict(event), sort_keys=True))

    vault = MemoryVault(on_alarm=alarm)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        original, boxed, output = root / "example", root / "example.mbox", root / "opened"
        original.write_bytes(b"Temporary demonstration contents.\n")
        identity = seal_guarded_file(original, boxed, vault=vault)
        pristine = boxed.read_bytes()
        print("sealed guarded .mbox; trusted registry ID:", identity)
        boxed.write_bytes(pristine[:-1] + bytes([pristine[-1] ^ 1]))
        try:
            open_guarded_file(boxed, output, box_id=identity, vault=vault)
        except TamperDetected:
            print("altered submission: secret revoked; no plaintext published")
        boxed.write_bytes(pristine)
        try:
            open_guarded_file(boxed, output, box_id=identity, vault=vault)
        except BoxUnavailable:
            print("untouched copy: refused by the same vault after revocation")
        print("Reference model only: no durable vault, secure erasure, or network alarm.")


if __name__ == "__main__":
    main()
