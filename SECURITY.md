# Security model

Magic Box's computational formats are experimental containers. They use
AES-256-GCM for content encryption, a fresh 3072-bit RSA modulus for a
repeated-squaring condition, and HKDF-SHA256 for internal keying. This branch
adds suite `03`; the original format is suite `01`. These are compositions of
existing primitives, not new AES, HKDF, or time-lock algorithms.

## Internal capsule suite 03

Initialization encrypts a 58-byte keying record containing the content key,
nonce, length, cipher identifier, and record version. The record is authenticated
under a distinct AES-256-GCM key derived from the embedded condition's result.
The capsule binds every public prefix byte. Content authentication binds the
entire header, including the encrypted record and its authentication tag.

The new construction supplies no plaintext key field, key sidecar, secret
environment variable, hard-coded recovery key, or external vault. Initialization
returns metadata only. The temporary factors, result, capsule key, content key,
and record remain transient process values; Python cannot guarantee erasure
from memory, library buffers, swap, snapshots, or crash dumps. A process observer
or retained sealing secret can bypass the condition.

Suite `03` ships initialization and unauthenticated inspection only. The legacy
opener rejects it. This API choice neither prevents independent decoders nor
turns concealed implementation details into a cryptographic boundary. Someone
who satisfies or defeats the condition can recover the record and keep its
content key or plaintext. No attempt is made to obfuscate source or prove that
brute force is the only possible route.

Inspection cannot authenticate the encrypted record or payload. Its reported
plaintext length is inferred from total file size, so added or removed payload
bytes can change the estimate while leaving inspection structurally successful.
The encrypted length and both tags must be checked by any future independent
recovery implementation before publishing plaintext. That implementation also
needs a strict local computation budget for unauthenticated work parameters.

The capsule independently authenticates keying data; it does not increase the
puzzle's computational delay or establish 256-bit security for the system.
Modulus generation, freshness, retained secrets, factoring, hardware speed,
and cryptanalytic shortcuts still affect protection. File size reveals length.
No sender identity is established by GCM alone.

Both suites are passive files. Modifying or copying an offline box invokes no
trusted component, causes no alarm, and cannot destroy an untouched copy.
Enforced destructive state needs a trusted component resistant to copying,
rollback, and secret recovery. That guarded experiment is on a separate branch
and is not represented as an internal property of this self-contained format.

The exact layout is in [docs/CAPSULE.md](docs/CAPSULE.md). Its deterministic
fixture exposes known test keys and nonces for independent checking; production
generates fresh values and must never reuse that fixture. Tests of the new
format do not include a general capsule decoder. Independent cryptographic
review of the composition and secret lifecycle is still required.

The following sections describe the original suite `01`.

## Access rule

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
copies, or destroy untouched copies. Magic Box v1 therefore implements no
self-destruction or attempt counter. Enforcing irreversible failure state
would require a separate trusted component that resists copying and rollback.

## Validation status

The tests establish conformance examples and reject known malformed inputs.
They include NIST AES-256-GCM and RFC 5869 HKDF vectors, a fixed container vector,
an independently assembled container, arithmetic cross-checks, and failure-path
checks. They do not prove cryptographic security. Independent review of the
format, composition, parser, and secret lifecycle is still needed.
