"""Initialize a self-contained box with an encrypted keying record.

This module supplies initialization and unauthenticated inspection. It contains
no capsule-opening API, exported secret, embedded executable, or key sidecar.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core import (
    CHUNK_BYTES, KEY_BYTES, MAGIC, MAX_PLAINTEXT_BYTES, MODULUS_BITS,
    MODULUS_BYTES, TAG_BYTES, VERSION, BoxInfo, MagicBoxError, _check_work,
    _create_puzzle, _new_output, _read_exact, _read_lock, _regular_size,
    _require_new_output,
)

CAPSULE_SUITE = 3
_PREFIX = struct.Struct(">8sBBQ384s384s12s")
_RECORD = struct.Struct(">4sBBQ32s12s")
PREFIX_BYTES = _PREFIX.size  # 798.
RECORD_BYTES = _RECORD.size  # 58, encrypted.
CAPSULE_BYTES = RECORD_BYTES + TAG_BYTES  # 74.
HEADER_BYTES = PREFIX_BYTES + CAPSULE_BYTES  # 872.
OVERHEAD_BYTES = HEADER_BYTES + TAG_BYTES  # 888.
_KDF_INFO = b"magicbox:v1:capsule-key"


def _info(work: int, length: int, *, authenticated: bool = False) -> BoxInfo:
    return BoxInfo(
        VERSION, "AES-256-GCM", "encrypted-key-capsule/HKDF-SHA256",
        MODULUS_BITS, work, length, length + OVERHEAD_BYTES, authenticated,
    )


def _create_capsule(length: int, work: int) -> tuple[bytes, bytes, bytes]:
    modulus, base, result = _create_puzzle(work)
    key = secrets.token_bytes(KEY_BYTES)
    capsule_nonce, content_nonce = secrets.token_bytes(12), secrets.token_bytes(12)
    prefix = _PREFIX.pack(
        MAGIC, VERSION, CAPSULE_SUITE, work,
        modulus.to_bytes(MODULUS_BYTES, "big"),
        base.to_bytes(MODULUS_BYTES, "big"), capsule_nonce,
    )
    capsule_key = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES,
        salt=hashlib.sha256(prefix).digest(), info=_KDF_INFO,
    ).derive(result.to_bytes(MODULUS_BYTES, "big"))
    # Fixed data fields, not instructions or dynamically loaded code.
    record = _RECORD.pack(b"MBKR", 1, 1, length, key, content_nonce)
    capsule = AESGCM(capsule_key).encrypt(capsule_nonce, record, prefix)
    return prefix + capsule, key, content_nonce


def _read_capsule(source: BinaryIO) -> BoxInfo:
    total = _regular_size(source)
    length = total - OVERHEAD_BYTES
    if not 0 <= length <= MAX_PLAINTEXT_BYTES:
        raise MagicBoxError("truncated capsule or excessive box length")
    header = _read_exact(source, HEADER_BYTES)
    magic, version, suite, work, n_bytes, a_bytes, _ = _PREFIX.unpack(header[:PREFIX_BYTES])
    if magic != MAGIC or version != VERSION or suite != CAPSULE_SUITE:
        raise MagicBoxError("unsupported Magic Box capsule signature, version, or suite")
    _check_work(work, "embedded work")
    modulus, base = int.from_bytes(n_bytes, "big"), int.from_bytes(a_bytes, "big")
    if modulus.bit_length() != MODULUS_BITS or modulus % 2 != 1:
        raise MagicBoxError("capsule modulus must be an odd 3072-bit integer")
    if not 2 <= base <= modulus - 2 or math.gcd(base, modulus) != 1:
        raise MagicBoxError("invalid capsule base")
    if base * base % modulus == 1:
        raise MagicBoxError("degenerate capsule base")
    # The encrypted length cannot be checked without authenticating the record.
    # This is only an unauthenticated size estimate derived from the file size.
    return _info(work, length)


def inspect_file(source: str | Path) -> BoxInfo:
    """Inspect either legacy or capsule metadata without solving any condition.

    Capsule plaintext_bytes is inferred from file size. Inspection cannot verify
    its encrypted record, either tag, or appended/truncated payload bytes.
    """
    with Path(source).open("rb") as stream:
        _regular_size(stream)
        signature = _read_exact(stream, 10)
        stream.seek(0)
        if signature == MAGIC + bytes((VERSION, CAPSULE_SUITE)):
            return _read_capsule(stream)
        return _read_lock(stream).info()


def init_file(source: str | Path, destination: str | Path, *, work: int) -> BoxInfo:
    """Encrypt a file and encapsulate its keying record inside the new box."""
    _check_work(work, "work")
    destination = Path(destination)
    _require_new_output(destination)
    with Path(source).open("rb") as stream:
        length = _regular_size(stream)
        if length > MAX_PLAINTEXT_BYTES:
            raise MagicBoxError("file exceeds the single-message AES-GCM limit")
        header, key, nonce = _create_capsule(length, work)
        encryptor = Cipher(algorithms.AES256(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header)
        with _new_output(destination) as target:
            target.write(header)
            remaining = length
            while remaining:
                chunk = _read_exact(stream, min(CHUNK_BYTES, remaining))
                target.write(encryptor.update(chunk))
                remaining -= len(chunk)
            if stream.read(1):
                raise MagicBoxError("input grew while being initialized")
            target.write(encryptor.finalize())
            target.write(encryptor.tag)
    return _info(work, length, authenticated=True)
