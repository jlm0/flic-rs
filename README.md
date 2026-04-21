# flic-rs

A Rust implementation of the [Flic 2](https://flic.io) BLE protocol. Pure-Rust, cross-platform
([btleplug](https://github.com/deviceplug/btleplug) under the hood). Two crates:

- **`flic-core`** — the library. Protocol, crypto, framing, state machine, BLE transport.
- **`flic-cli`** — a command-line validator and diagnostic tool. Pair, reconnect, listen for
  events, stress-test the reconnect loop against a real button.

The long-term goal is a published, reusable crate that ships with bindings to other runtimes
(napi for Node, pyo3 for Python, etc.). For now, `flic-core` stays thin and testable; the
CLI is the only consumer.

## Status

Pre-release. Protocol spec is understood end-to-end (see the design doc in the consuming
project). Crypto primitives are implemented with byte-exact fixtures generated from
[pyflic-ble](https://github.com/50ButtonsEach/pyflic-ble). BLE transport + state machine are
in progress.

## Build

```bash
cargo build --workspace
cargo test  --workspace
```

Requires Rust 1.85+ (see `rust-toolchain.toml`).

## Testing

Three tiers:

1. **Unit tests** (`cargo test`): deterministic crypto, framing, event decoding, state-machine
   transitions. No hardware. Byte-exact against fixtures in `crates/flic-core/tests/fixtures/`.
2. **Fixture-replay tests** (`cargo test --features replay`): replays a recorded BLE notification
   stream through the handler offline.
3. **Hardware integration tests** (`cargo test -- --ignored`): requires a real Flic 2 button
   and Bluetooth. Covers pairing, reconnect, event delivery, ACK dedup, PING timeout.

Regenerating fixtures is a one-shot step — see `fixtures/README.md`.

## Flic protocol references

- Official wiki: https://github.com/50ButtonsEach/flic2-documentation/wiki
- Python reference: https://github.com/50ButtonsEach/pyflic-ble (MIT)

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
