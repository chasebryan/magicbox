# Magic Box

**AES-256 file encryption. The keying record lives inside the box.**

This branch adds an internal key capsule. Initializing a file generates a fresh
AES-256 key, encrypts the contents, and seals the key, content nonce, length,
and cipher identifier together inside the same `.mbox` file. The encrypted
record is protected by an embedded computational condition. There is no
password, external key file, vault, or serialized shortcut.

The capsule and contents use separate AES-256-GCM keys and nonces. The capsule
authenticates the public prefix; the contents authenticate the prefix and
encrypted capsule together. The record is fixed data, never executable code.
File contents stream through encryption. The new format adds **888 bytes**.

This is experimental computational encryption, not permanent undecryptability.
Anyone who can satisfy the embedded condition can recover the record. A missing
opening command or concealed source cannot prevent an independent decoder.

## Use

Python 3.11 or later:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .

magicbox init report.pdf -o report.mbox --work 100000
magicbox inspect report.mbox
```

`python -m magicbox` accepts the same commands. The number `100000` is an
example workload for experimentation, not a security recommendation.
Initialization requires an explicit `--work`. It supplies initialization and
inspection only. No conventional opening command or key-export API is supplied
for the capsule suite. The legacy `open` command refuses it.

Inputs are preserved and existing outputs are refused. Inspection never solves
the condition, opens the record, or checks either authentication tag. For a
capsule, `plaintext_bytes` is only an estimate from the file size; inspection
cannot detect appended payload data or verify the encrypted length.

The Python API is `init_file(source, destination, work=...)`. Its result and the
inspector return metadata, never the AES key or unsealed record. See the exact
[capsule format](docs/CAPSULE.md) and [security model](SECURITY.md).

## The internal lock

Every box gets a freshly generated 3072-bit modulus and a nondegenerate base
for its embedded computational condition. No owner's password or supplied
key is needed to initialize it.

HKDF-SHA256 binds the condition's result to the public prefix and derives the
capsule's AES-256 key. An independent random AES-256 key protects the contents;
its keying record is encrypted inside the capsule. Neither plaintext key nor
the condition's result is serialized.

During sealing, the temporary factors let the encryptor compute the final
value efficiently. The implementation writes neither those factors nor the
plaintext AES key to the box. It does not promise secure erasure of Python
process memory.

The condition remains a repeated-squaring time-lock puzzle. The capsule changes
how keying data is packaged and authenticated; it does not prove a stronger
computational delay. A small work count is easy to satisfy. Retained factors,
leaked keys, faster factoring, or cryptanalytic shortcuts can defeat the intended
condition. The complete construction is not claimed to have 256-bit security.

A passive copyable file cannot observe offline attacks, execute an alarm, or
erase other copies. Enforced self-destruction needs protected state beyond the
file. The separate guarded experiment remains on its own branch.

## Legacy suite 01

The earlier format and commands remain compatible:

```sh
magicbox seal report.pdf -o legacy.mbox --work 100000
magicbox inspect legacy.mbox
magicbox open legacy.mbox -o recovered.pdf --max-work 100000
```

Legacy files add 854 bytes and contain a masked key rather than an encrypted
keying record. Opening defaults to a budget of 1,000,000 squarings. The inspector
recognizes both suites; no opening fallback is provided for capsules.

## Exact specification and checks

- [Capsule suite 03](docs/CAPSULE.md): fields, offsets, authenticated record, and limits.
- [Legacy suite 01](docs/FORMAT.md): original format and opening rule.
- [Security model](SECURITY.md): what the construction does and assumes.
- [Capsule encryption vector](tests/vectors/capsule.json): public fixture values and exact bytes.
- [Legacy vector](tests/vectors/v1.json): original interoperability fixture.

```sh
python -m unittest discover -s tests -v
```

Tests cover independent capsule construction, authentication of both layers,
known-key fixture checks, empty and streamed binary files, strict structural
inspection, output preservation, and legacy compatibility. The existing NIST
AES-256-GCM and RFC 5869 HKDF checks remain. There is no general capsule decoder
in the implementation or tests.

CC0-1.0. See [LICENSE](LICENSE).
