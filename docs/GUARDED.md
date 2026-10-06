# Guarded Magic Box: version 1, suite 02

The `.mbox` file is a portable encrypted object. Its guard is a trusted process
with essential state. This package opens the suite through the guarded API.
It has no public puzzle for recovering its key. The package's `MemoryVault` is
a reference model; it is not a durable or hardware-protected guard.

## Layout

All integers are unsigned and big-endian. Let `L` be the plaintext byte length.

| Offset | Bytes | Field | Definition |
| --- | ---: | --- | --- |
| 0 | 8 | magic | ASCII `MAGICBOX` |
| 8 | 1 | version | `01` |
| 9 | 1 | suite | `02` |
| 10 | 16 | ID | Random box identifier |
| 26 | 8 | L | Plaintext length |
| 34 | 12 | nonce | Fresh AES-GCM nonce |
| 46 | 32 | W | Wrapped AES-256 key |
| 78 | L | C | AES-GCM ciphertext |
| 78 + L | 16 | T | Full AES-GCM authentication tag |

The prefix `B` is bytes `[0, 46)`. The header `H` is bytes `[0, 78)`.
Total size is exactly `L + 94`. The reference accepts `0 <= L <= 67,108,864`
(64 MiB). There are no extensions, trailing data, executable instructions,
public puzzles, or serialized recovery secrets.

## Sealing and protected registration

Generate independent random values: `ID` (16 bytes), guard secret `S` (32 bytes),
AES key `K` (32 bytes), and nonce (12 bytes). A vault never reuses an ID, including
one belonging to a revoked slot. Build `B` using the layout above, then compute:

```text
mask = HKDF-SHA256(
    IKM = S,
    salt = SHA256(B),
    info = ASCII("magicbox:v1:guard-mask"),
    length = 32
)
W = K XOR mask
H = B || W
(C, T) = AES-256-GCM-Encrypt(K, nonce, plaintext, AAD=H)
box = H || C || T
D = SHA256(box)
```

`XOR` is bytewise on 32-byte operands. `||` concatenates byte strings.
Register `(ID, S, D, active)` in protected state before returning the box.
Keep the expected ID and its access policy in the trusted registry.
Serialize only `box` as the `.mbox` file. Neither `S` nor `K` is a format field.
The commitment `D` is trusted vault state, not an editable field in the box.

## Opening and revocation

The caller is authenticated and authorized by the surrounding security system
before invoking `GuardVault.open(expected_id, immutable_box_bytes)`.
The expected ID is selected by that system, never by parsing the submitted file.

In one operation serialized against revocation:

1. Locate the expected slot. Refuse unknown or revoked slots without inspecting
   the submitted contents or producing a new tamper event.
2. Enforce the size limit. Compare `SHA256(submitted_bytes)` to the registered
   `D` using a constant-time digest comparison.
3. Check signature, version, suite, exact length, and embedded ID against the
   expected ID. Derive `mask` from the slot's `S` and submitted prefix.
4. Recover `K = W XOR mask`. Authenticate and decrypt with `AAD=H`.
5. Return plaintext only after all checks succeed.

An integrity failure in steps 2–4 revokes the expected slot, retains its
tombstone, and records one event before any alarm callback. A subsequent
intact copy cannot restore the slot. A production implementation must make
this transition durable and prevent rollback or recovery of the revoked secret.
The reference only removes its secret reference in Python memory.

| Previous state | Submission or operation | Next state | Result |
| --- | --- | --- | --- |
| Active | Exact registered box; all checks pass | Active | Authenticated plaintext |
| Active | Byte mismatch, invalid structure, or invalid GCM tag | Revoked | `TamperDetected`, one retained alarm event |
| Revoked | Any submission | Revoked | `BoxUnavailable`, no new event |
| Unknown | Any submission | Unknown | `BoxUnavailable`, no event |
| Active or revoked | Administrative `revoke` | Revoked | No tamper event |

An already completed opening may have released plaintext before revocation.
Revocation cannot recall that plaintext or destroy copies of exported secrets.

## Alarm contract

`TamperEvent` contains `box_id` as 32 lowercase hexadecimal characters and
`reason="integrity_failure"`. It contains no ciphertext, plaintext, or secret.
There is at most one integrity-triggered event per slot, so `box_id` also
serves as the deduplication identifier.

`MemoryVault(on_alarm=handler)` calls `handler(event)` after committing its
in-memory revocation and event. The handler runs outside the vault lock.
An ordinary callback exception is attached to `TamperDetected.alarm_error`;
it cannot restore access or remove the event from `vault.events`. Interruptions
may propagate after revocation. No callback means no automatic external delivery.

A deployed adapter must retain events durably, retry failed deliveries, and
coordinate acknowledgment with its security system. The reference has no
transport, authentication layer, durable outbox, or restart recovery.

## File helper behavior

`seal_guarded_file` returns the registered box ID and publishes the ciphertext
without replacing any existing path. Failed publication revokes the unused
registration. `open_guarded_file` takes the expected ID explicitly, reads at
most the maximum box size plus one byte, and submits that immutable snapshot.
An oversized snapshot is an integrity failure. Local I/O and destination errors
are separate failures and do not revoke an active slot.

Both helpers preserve original inputs. Private staging and no-overwrite
publication use the existing file primitives. Guarded opening writes no
plaintext to staging until the vault returns authenticated bytes. The 64 MiB
bound applies to this buffered reference; it does not promise constant memory.

## Limits and references

Offline attacks never contact the guard. Corruption and malicious modification
produce the same integrity response. An authorized malicious submitter can
cause denial of service by triggering revocation. Access control must therefore
precede the destructive rule. Copying or restoring guard state defeats the
reference model. See [SECURITY.md](../SECURITY.md) for the complete trust boundary.

- [Public interoperability vector](../tests/vectors/guarded.json).
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869).
- [NIST SP 800-88r2: cryptographic erasure and key sanitization](https://csrc.nist.gov/pubs/sp/800/88/r2/final).
