# Magic Box

**AES-256 file encryption. The computational lock lives inside the box.**

Magic Box encrypts a file with a fresh 256-bit AES key, locks that key behind
a repeated-squaring puzzle, and puts the puzzle, wrapped key, nonce, and
authenticated encrypted contents into one `.mbox` file. Opening needs the
box and its public decoder. There is no password prompt or separate key file.

This is an experimental cryptographic container. AES-256-GCM supplies the
encryption; the embedded lock controls the intended computation needed to
recover its key. Anyone holding the box can solve that public lock and open
it. The work parameter is a computation count, not a guaranteed duration.

## Use

Python 3.11 or later:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .

magicbox seal report.pdf -o report.mbox --work 100000
magicbox inspect report.mbox
magicbox open report.mbox -o recovered.pdf --max-work 100000
```

`python -m magicbox` accepts the same commands. The number `100000` is an
example workload for experimentation, not a security recommendation.
Sealing requires an explicit `--work`. Opening refuses boxes above its
default budget of 1,000,000 squarings; raise `--max-work` explicitly for a
larger box. Inspection reads public metadata without solving or authenticating
the lock.

Inputs are preserved. Existing outputs are refused. File contents are streamed;
the format adds exactly **854 bytes**. A decrypted destination becomes visible
only after its authentication tag verifies. See the [security model](SECURITY.md)
for the temporary-file and memory guarantees.

## The internal lock

For a freshly generated 3072-bit modulus `n = p*q`, the opening computation is:

```text
x = a
repeat t times:
    x = x*x mod n
```

HKDF-SHA256 turns the final value into a 32-byte mask. The mask unwraps the
random AES key. AES-256-GCM then opens the contents and authenticates the
entire header, including the lock parameters and wrapped key.

During sealing, the temporary factors let the encryptor compute the final
value efficiently. The implementation writes neither those factors nor the
plaintext AES key to the box. It does not promise secure erasure of Python
process memory.

The format contains a fixed mathematical recipe. It contains no executable
payload, dynamic code, or plaintext decryption key. Its decoder is public.
An ordinary copyable file cannot detect offline guessing or enforce destruction
of other copies. Magic Box v1 provides a computational opening condition and
tamper detection; an irreversible attempt counter would require protected
state outside the portable box.

## Exact specification and checks

- [Format v1](docs/FORMAT.md): every field, byte offset, equation, and limit.
- [Security model](SECURITY.md): what the construction does and assumes.
- [Fixed test vector](tests/vectors/v1.json): public test values and exact bytes.

```sh
python -m unittest discover -s tests -v
```

Tests cover NIST AES-256-GCM and RFC 5869 HKDF vectors, independent container
construction, lock arithmetic, empty and binary files, streaming, malformed
input, authenticated tampering, work limits, interrupted operations, and
output preservation.

CC0-1.0. See [LICENSE](LICENSE).
