# Fixture harness

`generate.py` runs deterministic inputs through [pyflic-ble](https://github.com/50ButtonsEach/pyflic-ble)'s
canonical implementation of the Flic 2 crypto primitives and writes NDJSON fixtures to
`crates/flic-core/tests/fixtures/`. The Rust unit tests load those NDJSON files and
byte-compare their own outputs.

## Run

```bash
cd fixtures
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python generate.py
```

On Python 3.14 pyflic-ble may need to be installed from source if PyPI doesn't yet have a
3.14-compatible wheel. In that case:

```bash
./.venv/bin/pip install 'git+https://github.com/50ButtonsEach/pyflic-ble'
```

## When to regenerate

Regenerate NDJSON only when:

1. pyflic-ble itself gains a bug fix in a crypto path (rare — check upstream commits).
2. You intentionally expand the fixture set by adding seeds to `generate.py`.

The output is committed to `crates/flic-core/tests/fixtures/` so Rust CI does not require
Python to run.

## Output files

| File                              | Exercises                                       |
| --------------------------------- | ----------------------------------------------- |
| `chaskey_subkeys.ndjson`          | `chaskey_generate_subkeys`                      |
| `chaskey_mac_dir_counter.ndjson`  | `chaskey_with_dir_and_counter` (per-packet MAC) |
| `chaskey_mac_16.ndjson`           | `chaskey_16_bytes` (QuickVerify session key)    |
| `kdf.ndjson`                      | `derive_full_verify_keys` (all KDF labels)      |
| `ed25519_variant.ndjson`          | `verify_ed25519_signature_with_variant`         |

Every row is a JSON object; one per line. Schemas are documented inline in `generate.py`.
