# Magic Box format v1, legacy suite 01

This document defines the original suite `01`. The
[internal capsule suite `03`](CAPSULE.md) has a separate authenticated keying
record and no conventional opening API. Every multi-byte integer here is unsigned and
big-endian. Every field has a fixed width except the encrypted file contents.
There is no padding, compression, filename, extension field, or executable
code. Unknown versions and suites are rejected.

## Layout

Let `L` be the number of plaintext bytes.

| Offset | Bytes | Field | Definition |
| --- | ---: | --- | --- |
| 0 | 8 | magic | ASCII `MAGICBOX` |
| 8 | 1 | version | `01` |
| 9 | 1 | suite | `01` |
| 10 | 8 | t | Opening work: number of modular squarings |
| 18 | 8 | L | Plaintext byte length |
| 26 | 384 | n | 3072-bit puzzle modulus |
| 410 | 384 | a | Puzzle base, left-padded with zero bytes |
| 794 | 12 | nonce | AES-GCM nonce |
| 806 | 32 | W | Wrapped AES-256 key |
| 838 | L | C | AES-GCM ciphertext |
| 838 + L | 16 | T | Full 128-bit AES-GCM authentication tag |

The header `H` consists of bytes `[0, 838)`. Its prefix `B` consists of bytes
`[0, 806)`. Total file length is exactly `L + 854` bytes. Trailing data is an
error. Intervals use an exclusive upper endpoint.

## Sealing

1. Generate a fresh 3072-bit RSA modulus using the cryptography library's RSA
   key generator with public exponent 65537. Let the temporary primes be `p`
   and `q`, and set `n = p*q`, `phi = (p-1)*(q-1)`. RSA encryption is not used.
2. Select `a` uniformly from integers `[2, n-2]`, resampling until
   `gcd(a, n) = 1` and `a*a mod n != 1`.
3. Compute `e = 2^t mod phi` and `y = a^e mod n`. The coprimality condition
   makes this equal to `a^(2^t) mod n`.
4. Generate an independent random 32-byte key `K` and 12-byte nonce. Build `B`
   using the layout above.
5. Encode `y` as exactly 384 big-endian bytes, including leading zeros. Derive:

   ```text
   salt = SHA256(B)
   mask = HKDF-SHA256(
       IKM = encode_384(y),
       salt = salt,
       info = ASCII("magicbox:v1:lock-mask"),
       length = 32
   )
   W = K XOR mask
   H = B || W
   (C, T) = AES-256-GCM-Encrypt(K, nonce, plaintext, AAD=H)
   box = H || C || T
   ```

   `XOR` is bytewise on two 32-byte operands. `||` concatenates exact byte
   strings. HKDF is the extract-then-expand construction from RFC 5869;
   its 32-byte output takes one SHA-256 expansion block.
6. Serialize only the box. There are no sidecar secrets. The temporary factors,
   `phi`, `e`, `y`, `mask`, and plaintext `K` are not fields in the format.

This describes serialization. It is not a guarantee that discarded process
values have been securely erased from memory or operating-system storage.

## Opening

1. Validate the structure and enforce the local work budget before solving.
2. Set `x_0 = a`. For `i = 0, ..., t-1`, compute `x_(i+1) = x_i*x_i mod n`.
3. Substitute `x_t` for `y` in the same HKDF calculation. Recover `K = W XOR mask`.
4. Decrypt using AES-256-GCM with nonce and `AAD=H`. Verify all 16 tag bytes.
5. Publish the decrypted destination only after authentication succeeds.

The decoder performs exactly `t` squarings on its normal opening path. This is
an implementation count, not a proof that every possible attack requires
that many operations. Factoring the modulus, retaining sealing secrets, or a
future cryptanalytic shortcut may bypass the intended path.

## Validation and limits

- `1 <= t <= 2^64 - 1`. A caller-provided budget can impose a much smaller cap.
- `0 <= L <= 2^36 - 32`, the single-message GCM plaintext limit in SP 800-38D.
- `n` is an odd integer with exactly 3072 significant bits.
- `2 <= a <= n-2`, `gcd(a, n) = 1`, and `a*a mod n != 1`.
- Actual file size equals `L + 854`.
- Magic, version, and suite match exactly. The parser accepts no extensions.

The parser validates these public conditions. It cannot prove that an untrusted
modulus was generated correctly or that its creator discarded the factors.
Header values remain unauthenticated until opening succeeds. GCM binds every
header byte, including the work count, length, base, modulus, nonce, and wrapped
key, to the encrypted contents.

## References

- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869).
- [Rivest, Shamir, Wagner: Time-lock puzzles and timed-release Crypto](https://people.csail.mit.edu/rivest/pubs/RSW96.pdf).

Magic Box uses an HKDF mask and AES-256-GCM around the repeated-squaring
mechanism. Its particular composition is experimental and has not undergone
independent cryptanalysis or a formal security proof.
