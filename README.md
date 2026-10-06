# Magic Box

**AES-256 encryption. One portable `.mbox` file. An explicit opening rule.**

Magic Box has two experimental suites. Both put a wrapped AES key, a nonce,
and authenticated encrypted contents inside the box. Neither embeds executable
code or a plaintext decryption key.

| Suite | Opening rule | Integrity failure |
| --- | --- | --- |
| Guarded (`02`) | A trusted vault must hold the essential guard secret | Revoke that secret, retain an alarm event, refuse later opens |
| Computational (`01`) | Anyone can solve the public repeated-squaring puzzle | Refuse this submission; other copies remain openable |

The guarded suite implements the stronger opening rule. Its portable file
contains the lock record; enforcement lives in a trusted security process.
An ordinary file cannot observe offline attacks or destroy untouched copies.
The included `MemoryVault` is a working protocol reference, with no durable
storage, host isolation, rollback protection, or secure memory erasure.

## Install

Python 3.11 or later:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

## Guarded files

Inside the trusted process:

```python
from magicbox import MemoryVault, open_guarded_file, seal_guarded_file

def alarm(event):
    print(event)  # Replace with your security system's event handler.

vault = MemoryVault(on_alarm=alarm)  # Reference model only.
box_id = seal_guarded_file("report.pdf", "report.mbox", vault=vault)
# Keep box_id in the trusted registry. Authorize callers before opening.
open_guarded_file("report.mbox", "recovered.pdf", box_id=box_id, vault=vault)
```

The same live vault must remain available. Guarded files have no public puzzle,
password, or ordinary CLI opening path. A registered byte mismatch or GCM
authentication failure revokes the expected box's secret before the alarm
callback runs. An untouched copy is then refused by the same vault.

Events remain available through `vault.events`. `TamperDetected.event` identifies
the revoked box; `TamperDetected.alarm_error` reports a failed callback. No
network integration is configured. A production `GuardVault` must provide
protected durable state and reliable event delivery. See the exact
[guarded protocol](docs/GUARDED.md) and [security model](SECURITY.md).

This reference buffers files and limits plaintext to **64 MiB**. The format
adds exactly **94 bytes**. Inputs are preserved, existing outputs are refused,
and failed opens publish no plaintext. Local I/O errors do not count as tamper.

Run a demonstration using temporary test files:

```sh
python examples/guarded_demo.py
```

## Computational files

The existing public-puzzle suite remains available for experimentation:

```sh
magicbox seal report.pdf -o delayed.mbox --work 100000
magicbox inspect delayed.mbox
magicbox open delayed.mbox -o recovered.pdf --max-work 100000
```

These commands operate on suite `01` only. `python -m magicbox` accepts the
same commands. Sealing requires an explicit `--work`. Opening defaults to a
budget of 1,000,000 squarings. Inspection reads unauthenticated metadata.

For a fresh 3072-bit modulus `n = p*q`, the decoder starts at `a` and repeats
`x = x*x mod n` exactly `t` times. HKDF-SHA256 derives a mask that unwraps
the random AES key. AES-256-GCM authenticates the entire header and contents.
The encryptor uses temporary factors to compute the puzzle solution efficiently;
it never serializes those factors. Python memory erasure is not guaranteed.

Anyone holding this suite's box can solve its lock. Work counts computation,
not seconds; `100000` is an example workload, not a security recommendation.
Files are streamed and the format adds exactly **854 bytes**. This suite
provides no revocation or alarm. See its [exact format](docs/FORMAT.md).

## Checks

```sh
python -m unittest discover -s tests -v
```

Tests cover primitive and container vectors, independent construction, binary
files, output preservation, malformed inputs, guarded revocation of intact
copies, trusted ID binding, concurrent operations, and alarm failures.
Both suites require independent cryptographic review.

CC0-1.0. See [LICENSE](LICENSE).
