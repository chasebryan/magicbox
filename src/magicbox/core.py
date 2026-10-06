"""Fixed-format AES-256-GCM container and repeated-squaring key lock.

The lock is public data, never executable code. Solving it recovers the AES
key. This module does not implement attempt detection or secure erasure.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import stat
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"MAGICBOX"
VERSION = 1
SUITE = 1
MODULUS_BITS = 3072
MODULUS_BYTES = MODULUS_BITS // 8
KEY_BYTES = 32
TAG_BYTES = 16
MAX_WORK = (1 << 64) - 1
DEFAULT_MAX_WORK = 1_000_000
MAX_PLAINTEXT_BYTES = (1 << 36) - 32  # SP 800-38D, section 5.2.1.1.
CHUNK_BYTES = 1 << 20
_PREFIX = struct.Struct(">8sBBQQ384s384s12s")
HEADER_BYTES = _PREFIX.size + KEY_BYTES  # 838.
OVERHEAD_BYTES = HEADER_BYTES + TAG_BYTES  # 854.
_KDF_INFO = b"magicbox:v1:lock-mask"
Progress = Callable[[int, int], None]


class MagicBoxError(ValueError):
    """Invalid box, failed authentication, or refused resource use."""


@dataclass(frozen=True)
class BoxInfo:
    version: int
    cipher: str
    lock: str
    modulus_bits: int
    work: int
    plaintext_bytes: int
    box_bytes: int
    authenticated: bool


@dataclass(frozen=True)
class _Lock:
    work: int
    length: int
    modulus: int
    base: int
    nonce: bytes
    wrapped_key: bytes
    header: bytes

    def info(self, *, authenticated: bool = False) -> BoxInfo:
        return BoxInfo(
            VERSION, "AES-256-GCM", "repeated-squaring/HKDF-SHA256",
            MODULUS_BITS, self.work, self.length,
            self.length + OVERHEAD_BYTES, authenticated,
        )


def _check_work(value: int, name: str) -> None:
    if type(value) is not int or not 1 <= value <= MAX_WORK:
        raise MagicBoxError(f"{name} must be an integer from 1 to {MAX_WORK}")


def _read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise MagicBoxError("truncated box or input changed while being read")
    return data


def _regular_size(source: BinaryIO) -> int:
    metadata = os.fstat(source.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise MagicBoxError("input must be a regular file")
    return metadata.st_size


def _read_lock(source: BinaryIO) -> _Lock:
    total = _regular_size(source)
    header = _read_exact(source, HEADER_BYTES)
    magic, version, suite, work, length, n_bytes, a_bytes, nonce = (
        _PREFIX.unpack(header[:_PREFIX.size])
    )
    if magic != MAGIC or version != VERSION or suite != SUITE:
        raise MagicBoxError("unsupported Magic Box signature, version, or suite")
    _check_work(work, "embedded work")
    if length > MAX_PLAINTEXT_BYTES or total != length + OVERHEAD_BYTES:
        raise MagicBoxError("invalid box length or trailing data")
    modulus, base = int.from_bytes(n_bytes, "big"), int.from_bytes(a_bytes, "big")
    if modulus.bit_length() != MODULUS_BITS or modulus % 2 != 1:
        raise MagicBoxError("lock modulus must be an odd 3072-bit integer")
    if not 2 <= base <= modulus - 2 or math.gcd(base, modulus) != 1:
        raise MagicBoxError("invalid lock base")
    if base * base % modulus == 1:
        raise MagicBoxError("degenerate lock base")
    return _Lock(work, length, modulus, base, nonce, header[-KEY_BYTES:], header)


def _mask(solution: int, prefix: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES,
        salt=hashlib.sha256(prefix).digest(), info=_KDF_INFO,
    ).derive(solution.to_bytes(MODULUS_BYTES, "big"))


def _xor_key(left: bytes, right: bytes) -> bytes:
    if len(left) != KEY_BYTES or len(right) != KEY_BYTES:
        raise MagicBoxError("key and mask must both be exactly 32 bytes")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _create_lock(length: int, work: int) -> tuple[_Lock, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=MODULUS_BITS)
    numbers = private.private_numbers()
    modulus = numbers.public_numbers.n
    phi = (numbers.p - 1) * (numbers.q - 1)
    while True:
        base = secrets.randbelow(modulus - 3) + 2
        if math.gcd(base, modulus) == 1 and base * base % modulus != 1:
            break
    # The encryptor has the temporary factors and can take this shortcut.
    solution = pow(base, pow(2, work, phi), modulus)
    key, nonce = secrets.token_bytes(KEY_BYTES), secrets.token_bytes(12)
    prefix = _PREFIX.pack(
        MAGIC, VERSION, SUITE, work, length,
        modulus.to_bytes(MODULUS_BYTES, "big"),
        base.to_bytes(MODULUS_BYTES, "big"), nonce,
    )
    wrapped = _xor_key(key, _mask(solution, prefix))
    # Private factors, phi, solution, and the plaintext key are never serialized.
    return _Lock(work, length, modulus, base, nonce, wrapped, prefix + wrapped), key


def _squarings(base: int, modulus: int, work: int, progress: Progress | None) -> int:
    result = base
    interval = max(1, work // 100)
    for step in range(1, work + 1):
        result = result * result % modulus
        if progress is not None and (step % interval == 0 or step == work):
            progress(step, work)
    return result


def _unlock(lock: _Lock, max_work: int, progress: Progress | None) -> bytes:
    _check_work(max_work, "max_work")
    if lock.work > max_work:
        raise MagicBoxError(
            f"box requests {lock.work} squarings; limit is {max_work}; "
            "raise --max-work explicitly to allow it"
        )
    solution = _squarings(lock.base, lock.modulus, lock.work, progress)
    return _xor_key(lock.wrapped_key, _mask(solution, lock.header[:_PREFIX.size]))


def _require_new_output(destination: Path) -> None:
    if os.path.lexists(destination):
        raise FileExistsError(f"output already exists: {destination}")


@contextmanager
def _new_output(destination: Path) -> Iterator[BinaryIO]:
    """Stage privately and publish without replacing an existing path."""
    _require_new_output(destination)
    fd, name = tempfile.mkstemp(prefix=".magicbox-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as target:
            yield target
            target.flush()
            os.fsync(target.fileno())
        # A same-directory hard link gives atomic no-overwrite publication.
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def inspect_file(source: str | Path) -> BoxInfo:
    """Read structurally valid but unauthenticated public lock metadata."""
    with Path(source).open("rb") as stream:
        return _read_lock(stream).info()


def seal_file(source: str | Path, destination: str | Path, *, work: int) -> BoxInfo:
    """Encrypt a file and embed its computational key lock in the output."""
    _check_work(work, "work")
    destination = Path(destination)
    _require_new_output(destination)
    with Path(source).open("rb") as stream:
        length = _regular_size(stream)
        if length > MAX_PLAINTEXT_BYTES:
            raise MagicBoxError("file exceeds the single-message AES-GCM limit")
        lock, key = _create_lock(length, work)
        encryptor = Cipher(algorithms.AES256(key), modes.GCM(lock.nonce)).encryptor()
        encryptor.authenticate_additional_data(lock.header)
        with _new_output(destination) as target:
            target.write(lock.header)
            remaining = length
            while remaining:
                chunk = _read_exact(stream, min(CHUNK_BYTES, remaining))
                target.write(encryptor.update(chunk))
                remaining -= len(chunk)
            if stream.read(1):
                raise MagicBoxError("input grew while being encrypted")
            target.write(encryptor.finalize())
            target.write(encryptor.tag)
    return lock.info(authenticated=True)


def open_file(
    source: str | Path, destination: str | Path, *,
    max_work: int = DEFAULT_MAX_WORK, progress: Progress | None = None,
) -> BoxInfo:
    """Solve the embedded lock and publish plaintext only after authentication."""
    _check_work(max_work, "max_work")
    destination = Path(destination)
    _require_new_output(destination)
    with Path(source).open("rb") as stream:
        lock = _read_lock(stream)
        key = _unlock(lock, max_work, progress)
        decryptor = Cipher(algorithms.AES256(key), modes.GCM(lock.nonce)).decryptor()
        decryptor.authenticate_additional_data(lock.header)
        with _new_output(destination) as target:
            remaining = lock.length
            while remaining:
                chunk = _read_exact(stream, min(CHUNK_BYTES, remaining))
                target.write(decryptor.update(chunk))
                remaining -= len(chunk)
            tag = _read_exact(stream, TAG_BYTES)
            if stream.read(1):
                raise MagicBoxError("unexpected trailing data")
            try:
                target.write(decryptor.finalize_with_tag(tag))
            except InvalidTag:
                raise MagicBoxError("box authentication failed; output was not published") from None
    return lock.info(authenticated=True)
