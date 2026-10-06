# Security model

Magic Box v1 is an experimental container for computationally delayed file
opening. It uses AES-256-GCM for content encryption, a fresh 3072-bit RSA modulus
for a repeated-squaring puzzle, and HKDF-SHA256 to wrap a random content key.
It makes no claim to invent AES, HKDF, or time-lock puzzles.

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
