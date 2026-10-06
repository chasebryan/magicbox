# Security model

Magic Box defines two experimental version-1 suites. Both use AES-256-GCM for
content encryption and HKDF-SHA256 to wrap a random content key. Suite `01`
uses a public repeated-squaring puzzle; suite `02` requires an essential secret
held by a trusted guard. Neither has undergone independent cryptanalysis.

## Guarded suite

Suite `02` has no public recovery puzzle. The file holds the box ID, length,
nonce, wrapped AES key, ciphertext, and GCM tag. The guard holds an independent
32-byte secret and a SHA-256 commitment to the exact sealed file. The expected
box ID comes from the trusted registry, never from an untrusted submitted file.

Before releasing plaintext, the guard checks that commitment, the fixed
structure, the expected ID, and GCM authentication. Failure revokes the expected
slot's secret and records a tamper event before attempting the alarm callback.
Opening and revocation are serialized. All later submissions for that slot,
including intact copies, are refused. Unknown slots are refused without an
event. Administrative revocation is idempotent and emits no tamper event.

`MemoryVault` models these operations within one trusted Python process. It
drops the revoked secret reference and retains a tombstone, but does not securely
erase memory or persist either secrets, tombstones, or events. Restarting it
loses access to every registered box. Host administrators, process inspection,
debuggers, snapshots, backups, or another copy of the live vault can defeat the
reference model. It is not a production destructive storage mechanism.

A deployed guard must authenticate and authorize callers before inspecting
submissions, protect its secrets, commit revocation and an event durably before
acknowledgment, prevent state rollback and secret recovery, and keep opening
operations inside that boundary. A client-side parser with an exported key
cannot enforce this rule. A hardware or service adapter remains to be built
and reviewed; none is claimed by this package.

An authorized caller able to submit a changed file can deliberately revoke it.
Integrity failure also cannot distinguish an attack from accidental corruption.
Offline reading, copying, modification, and brute force do not contact the
guard, so they cause no alarm or revocation. The guard responds only when an
altered snapshot is submitted for a registered box. File contents cannot execute
an alarm handler on their own.

Revocation does not remove ciphertext, original files, plaintext already
released, retained AES keys, or leaked guard secrets. Destroying the sole
protected secret is the intended cryptographic erasure mechanism, conditional
on the cryptography and complete secret lifecycle. Python reference removal
does not establish those conditions. See NIST SP 800-88r2, sections 3.2.2 and
3.2.3, for applicability and key-sanitization requirements.

Alarm callbacks are optional and run after revocation outside the vault lock.
Ordinary callback exceptions are attached to `TamperDetected.alarm_error`; the
event stays in `vault.events`. A process crash can lose these in-memory events.
Production delivery needs a protected durable outbox, retries, and acknowledgment.
The box ID identifies the single tamper event for deduplication. No remote
security system, recipient, or network transport is configured here.

The reference API accepts immutable bytes and limits plaintext to 64 MiB.
File helpers read a bounded snapshot, preserve inputs, and publish outputs
without replacement. Plaintext is returned by AES-GCM only after authentication
succeeds. Local output conflicts, I/O failures, and API type errors do not revoke
an active box. Failure to publish a newly sealed file revokes its unused slot.
The protocol and exact format are in [docs/GUARDED.md](docs/GUARDED.md).

The remaining sections describe the computational suite `01`.

## Computational access rule

Anyone with a box can attempt its public opening computation. There is no
identity check, owner password, or exclusive recipient. Once someone solves
the lock, they can retain the result, AES key, or plaintext and share it.
Copies of the same box share the same puzzle; they do not require independent
work after a solution has been found.

The intended delay assumes that the sealing factors and content key remain
unavailable, the modulus and base are generated correctly, and no faster
applicable attack defeats the repeated-squaring construction. Work is measured
in squarings, not seconds. Faster hardware changes elapsed time. There is no
guarantee that brute force is the only possible attack.

Using a 256-bit AES key does not establish 256-bit security for the complete
box. Its effective protection also depends on the puzzle, its parameters,
key wrapping, implementation, and attack model. A small work count deliberately
makes a box quick for anyone to open.

## Integrity

The full header is AES-GCM associated data. Changes to structurally valid lock
parameters, wrapped key, ciphertext, or tag cause authentication to fail on
the normal opening path. Structural errors are rejected earlier. Inspection
does not authenticate anything.

After recovering the AES key, a person can create a valid altered box. GCM
does not establish the original creator's identity. Anyone can also create an
entirely new box. Sender authentication would require a separately trusted
signature or commitment.

The lock is declarative data. A decoder never imports, evaluates, or executes
code from the box. Structural and work-budget checks precede the expensive
solver. An authenticated work count cannot be trusted before that solver
finishes, so the local budget remains necessary for untrusted boxes.

## Storage and failure behavior

Inputs are preserved and outputs never replace an existing path. The decoder
streams tentative plaintext into a same-directory temporary file with POSIX
mode 0600, then verifies the tag before publishing the requested destination.
It removes the temporary file on handled failures and interruptions. This is
not secure deletion: a crash, filesystem snapshot, administrator, backup, or
storage recovery may expose temporary data. POSIX mode bits do not define a
Windows access-control guarantee.

Publication uses a same-directory hard link to prevent output replacement
even if another writer creates the destination during processing. A filesystem
without hard-link support fails rather than falling back to an overwrite.

The implementation does not persist sealing factors or unwrapped keys as
files. It cannot guarantee secure zeroization of Python objects, cryptographic
library buffers, swap, hibernation, crash dumps, or original-file copies.

An ordinary copyable file cannot count offline attempts, stop analysis of
copies, or destroy untouched copies. The computational suite therefore
implements no self-destruction or attempt counter. The guarded suite relies
on the separate trusted boundary described above; it cannot enforce
irreversible state inside a copyable file alone.

## Validation status

The tests establish conformance examples and reject known malformed inputs.
They include NIST AES-256-GCM and RFC 5869 HKDF vectors, a fixed container vector,
an independently assembled container, arithmetic cross-checks, and failure-path
checks. They do not prove cryptographic security. Independent review of the
format, composition, parser, and secret lifecycle is still needed.
