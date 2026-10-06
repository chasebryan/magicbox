"""Guarded AES-256 boxes and a reference implementation of the trusted guard.

MemoryVault models revocation, not hardware isolation, durable storage, or
secure erasure. Its API must run inside an authenticated, trusted boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core import (
    MAGIC, KEY_BYTES, TAG_BYTES, VERSION, MagicBoxError, _new_output,
    _read_exact, _regular_size, _require_new_output, _xor_key,
)

GUARDED_SUITE = 2
MAX_GUARDED_PLAINTEXT_BYTES = 64 << 20
_PREFIX = struct.Struct(">8sBB16sQ12s")
GUARDED_HEADER_BYTES = _PREFIX.size + KEY_BYTES  # 78.
GUARDED_OVERHEAD_BYTES = GUARDED_HEADER_BYTES + TAG_BYTES  # 94.
MAX_GUARDED_BOX_BYTES = MAX_GUARDED_PLAINTEXT_BYTES + GUARDED_OVERHEAD_BYTES
_KDF_INFO = b"magicbox:v1:guard-mask"


@dataclass(frozen=True)
class GuardedBox:
    """Keep box_id in the trusted registry; data is the portable .mbox file."""

    box_id: str
    data: bytes


@dataclass(frozen=True)
class TamperEvent:
    """One event per integrity-triggered revocation; contains no key material."""

    box_id: str
    reason: str = "integrity_failure"


class BoxUnavailable(MagicBoxError):
    """The expected box is unknown or its secret has been revoked."""


class TamperDetected(MagicBoxError):
    """Revocation already happened, even when the alarm callback failed."""

    def __init__(self, event: TamperEvent, alarm_error: Exception | None = None):
        super().__init__("box revoked after integrity failure")
        self.event = event
        self.alarm_error = alarm_error


class GuardVault(Protocol):
    """An authenticated trusted service implements these operations.

    Opening and revocation must be serialized against each other. Registration,
    revocation, and alarm retention must be durable and resist rollback. This
    interface deliberately exposes neither the guard secret nor the AES key.
    """

    def seal(self, plaintext: bytes) -> GuardedBox: ...

    def open(self, box_id: str, data: bytes) -> bytes: ...

    def revoke(self, box_id: str) -> None: ...


@dataclass
class _Record:
    secret: bytes | None
    commitment: bytes


def _mask(secret: bytes, prefix: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES,
        salt=hashlib.sha256(prefix).digest(), info=_KDF_INFO,
    ).derive(secret)


def _decrypt(box_id: str, data: bytes, secret: bytes) -> bytes:
    if len(data) < GUARDED_OVERHEAD_BYTES:
        raise MagicBoxError("truncated guarded box")
    prefix = data[:_PREFIX.size]
    magic, version, suite, embedded_id, length, nonce = _PREFIX.unpack(prefix)
    if (magic != MAGIC or version != VERSION or suite != GUARDED_SUITE
            or embedded_id.hex() != box_id):
        raise MagicBoxError("guarded box identity or suite mismatch")
    if length > MAX_GUARDED_PLAINTEXT_BYTES or len(data) != length + GUARDED_OVERHEAD_BYTES:
        raise MagicBoxError("invalid guarded box length")
    header = data[:GUARDED_HEADER_BYTES]
    key = _xor_key(header[_PREFIX.size:], _mask(secret, prefix))
    return AESGCM(key).decrypt(nonce, data[GUARDED_HEADER_BYTES:], header)


class MemoryVault:
    """In-memory protocol reference for tests and integration experiments.

    A lock orders all operations. Dropping a secret reference does not securely
    erase Python memory. A hostile host, snapshot, or copied vault bypasses this
    model. No network alert is sent unless the caller supplies an alarm callback.
    """

    def __init__(self, *, on_alarm: Callable[[TamperEvent], None] | None = None):
        self._records: dict[str, _Record] = {}
        self._events: list[TamperEvent] = []
        self._lock = threading.Lock()
        self._on_alarm = on_alarm

    @property
    def events(self) -> tuple[TamperEvent, ...]:
        """Retained events, including those whose callback failed; not durable."""
        with self._lock:
            return tuple(self._events)

    def seal(self, plaintext: bytes) -> GuardedBox:
        if type(plaintext) is not bytes:
            raise TypeError("plaintext must be immutable bytes")
        if len(plaintext) > MAX_GUARDED_PLAINTEXT_BYTES:
            raise MagicBoxError("guarded prototype limits plaintext to 64 MiB")
        with self._lock:
            while True:
                box_id = secrets.token_bytes(16)
                identity = box_id.hex()
                if identity not in self._records:
                    break
            secret, key = secrets.token_bytes(KEY_BYTES), secrets.token_bytes(KEY_BYTES)
            nonce = secrets.token_bytes(12)
            prefix = _PREFIX.pack(
                MAGIC, VERSION, GUARDED_SUITE, box_id, len(plaintext), nonce,
            )
            header = prefix + _xor_key(key, _mask(secret, prefix))
            data = header + AESGCM(key).encrypt(nonce, plaintext, header)
            self._records[identity] = _Record(secret, hashlib.sha256(data).digest())
            return GuardedBox(identity, data)

    def open(self, box_id: str, data: bytes) -> bytes:
        """Verify one immutable submission against its trusted registration.

        A mismatch revokes the expected slot, not an ID selected from untrusted
        bytes. Authenticate and authorize the caller before invoking this API.
        """
        if type(box_id) is not str or type(data) is not bytes:
            raise TypeError("box_id must be a string and data must be immutable bytes")
        with self._lock:
            record = self._records.get(box_id)
            if record is None or record.secret is None:
                raise BoxUnavailable("box is unknown or revoked")
            matches = len(data) <= MAX_GUARDED_BOX_BYTES and hmac.compare_digest(
                hashlib.sha256(data).digest(), record.commitment,
            )
            if matches:
                try:
                    return _decrypt(box_id, data, record.secret)
                except (InvalidTag, MagicBoxError):
                    pass
            # Commit the model's irreversible state before calling external code.
            record.secret = None
            event = TamperEvent(box_id)
            self._events.append(event)
        alarm_error = None
        if self._on_alarm is not None:
            try:
                self._on_alarm(event)
            except Exception as error:
                alarm_error = error
        raise TamperDetected(event, alarm_error)

    def revoke(self, box_id: str) -> None:
        """Administrative revocation; idempotent for a known box, no tamper alarm."""
        with self._lock:
            record = self._records.get(box_id)
            if record is None:
                raise BoxUnavailable("box is unknown or revoked")
            record.secret = None


def seal_guarded_file(
    source: str | Path, destination: str | Path, *, vault: GuardVault,
) -> str:
    """Publish a guarded file; return the ID to keep in the trusted registry."""
    destination = Path(destination)
    _require_new_output(destination)
    with Path(source).open("rb") as stream:
        size = _regular_size(stream)
        if size > MAX_GUARDED_PLAINTEXT_BYTES:
            raise MagicBoxError("guarded prototype limits plaintext to 64 MiB")
        plaintext = _read_exact(stream, size)
        if stream.read(1):
            raise MagicBoxError("input grew while being read")
    box = None
    try:
        with _new_output(destination) as target:
            box = vault.seal(plaintext)
            target.write(box.data)
    except BaseException:
        if box is not None:
            vault.revoke(box.box_id)
        raise
    return box.box_id


def open_guarded_file(
    source: str | Path, destination: str | Path, *, box_id: str, vault: GuardVault,
) -> None:
    """Publish only authenticated plaintext returned by the trusted guard.

    Read at most the prototype's maximum box size plus one byte. An oversized
    submission triggers the same integrity response without an unbounded read.
    Local I/O and output errors do not count as integrity failures.
    """
    destination = Path(destination)
    _require_new_output(destination)
    with Path(source).open("rb") as stream:
        _regular_size(stream)
        data = stream.read(MAX_GUARDED_BOX_BYTES + 1)
    with _new_output(destination) as target:
        plaintext = vault.open(box_id, data)
        target.write(plaintext)
