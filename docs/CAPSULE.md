# Magic Box internal capsule: version 1, suite 03

This format places an encrypted keying record inside a portable `.mbox` file.
The initializer constructs the file and returns metadata. No capsule decoder
or key-export API is included. The format is public and the computational
condition is reproducible; withholding a decoder is not a security guarantee.

## Public layout

All integers are unsigned and big-endian. Let `L` be the plaintext byte length.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `MAGICBOX` |
| 8 | 1 | Format version `01` |
| 9 | 1 | Capsule suite `03` |
| 10 | 8 | Embedded computation count `t` |
| 18 | 384 | 3072-bit modulus `n` |
| 402 | 384 | Condition base `a`, zero-padded |
| 786 | 12 | Capsule nonce |
| 798 | 58 | Encrypted keying record |
| 856 | 16 | Capsule authentication tag |
| 872 | L | Encrypted file contents |
| 872 + L | 16 | Content authentication tag |

The public prefix `B` is bytes `[0, 798)`. The complete header `H` is bytes
`[0, 872)`. Total file size is `L + 888`. The contents' nonce and AES key
are not public header fields. File size still reveals the payload length.

## Encrypted record

These offsets refer to the authenticated plaintext record, not visible bytes
in the `.mbox` file. All 58 bytes are encrypted inside the capsule.

| Record offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 4 | Record signature `MBKR` |
| 4 | 1 | Record version `01` |
| 5 | 1 | Content cipher `01`: AES-256-GCM, full 128-bit tag |
| 6 | 8 | Original content length `L` |
| 14 | 32 | Independent random content key `K` |
| 46 | 12 | Fresh content nonce |

The record is a fixed description of content keying. It has no executable
instructions, filenames, dynamic algorithms, or extension fields.

## Initialization

Generate fresh 3072-bit RSA parameters with the same initializer as suite `01`.
Select a nondegenerate coprime base. The temporary factors permit efficient
construction of the embedded condition's result `y = a^(2^t) mod n`.
Generate an independent content key and two fresh nonces. Construct `B` and
the 58-byte record, then seal:

```text
capsule_key = HKDF-SHA256(
    IKM = encode_384(y),
    salt = SHA256(B),
    info = ASCII("magicbox:v1:capsule-key"),
    length = 32
)
capsule = AES-256-GCM-Encrypt(capsule_key, capsule_nonce, record, AAD=B)
H = B || capsule
contents = AES-256-GCM-Encrypt(K, content_nonce, plaintext, AAD=H)
box = H || contents
```

Both encryption results include their full 16-byte tag. `||` concatenates byte
strings. The capsule KDF uses a distinct domain from legacy key masking and
binds to every public prefix byte. The contents bind to the encrypted capsule
and its tag as well as the public parameters. No factor, result, unsealed
record, or plaintext key is a serialized sidecar or public return value.

The work parameter counts modular squarings, not time. The condition and
temporary-factor shortcut follow the existing time-lock construction. The new
authenticated record does not make that condition harder or secret.

## Inspection and validation

`1 <= t <= 2^64 - 1`. A modulus must be an odd integer with exactly 3072
significant bits. A base must satisfy `2 <= a <= n-2`, `gcd(a,n)=1`, and
`a*a mod n != 1`. The content bound is `2^36 - 32` bytes, the single-message
GCM limit. Files shorter than 888 bytes, unsupported versions or suites, and
invalid public parameters are rejected.

Inspection reads the header and estimates `L` from file size. It performs no
condition evaluation or authentication, and returns `authenticated=false`.
It cannot verify the encrypted length, reject appended payload bytes, prove
correct modulus generation, or distinguish intact contents from corruption.

Any independently built recovery implementation must enforce a computation
budget before processing untrusted public parameters, authenticate the capsule
before trusting the record, reject unknown record versions and ciphers, verify
the actual content length against the authenticated record, and verify the
content tag before releasing plaintext. Records must never execute code.

## Scope

The public API consists of initialization and inspection for this suite. The
legacy opening path rejects suite `03` before solving or publishing output.
The tests use known public fixture keys for authentication checks and contain
no arbitrary-box capsule recovery routine.

Anyone able to satisfy the condition can recover the record and retain the
key or plaintext. Reimplementation does not require this repository. Retaining
initialization secrets or defeating the puzzle can bypass the intended work.
The file cannot observe offline attempts, emit an alarm by itself, or destroy
copies. See [SECURITY.md](../SECURITY.md) for secret lifecycle and trust limits.

## References

- [Public encryption fixture](../tests/vectors/capsule.json), never production parameters.
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869).
- [Rivest, Shamir, Wagner: time-lock puzzles](https://people.csail.mit.edu/rivest/pubs/RSW96.pdf).
