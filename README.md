# flic-rs

A pure-Rust implementation of the [Flic 2](https://flic.io) BLE protocol, with Node.js
bindings. Pair buttons, keep them connected through Bluetooth churn, and receive typed
press events — from Rust, from a CLI, or from Node / Electron.

```
┌─────────────────────────────────────────────────────────────────┐
│  Node.js app  ──▶  flic-napi  ──▶  flic-core  ──▶  btleplug     │
│  CLI / Rust lib  ─────────────▶  flic-core  ──▶  btleplug       │
└─────────────────────────────────────────────────────────────────┘
```

The protocol layer is byte-exact against fixtures generated from
[pyflic-ble](https://github.com/50ButtonsEach/pyflic-ble), the reference Python
implementation by the Flic team. Built from the public protocol documentation at
[50ButtonsEach/flic2-documentation](https://github.com/50ButtonsEach/flic2-documentation).

## Status

Pre-1.0. Protocol-conformant against the Flic 2 base and Duo specs — pairing,
QuickVerify reconnect, steady-state event delivery, event continuity across drops,
clean disconnect, and ACK dedup are all wired and exercised end-to-end on real
macOS hardware. The public API may still narrow before 1.0 (low-level `session` /
`protocol` / `transport` modules are exported today but are candidates for
`unstable-internals` gating). Windows and Linux should work via `btleplug` but are
not actively tested here.

## The three crates

A Cargo workspace with three members, each serving a distinct audience.

### `flic-core` — the library

Pure-Rust Flic 2 protocol. Everything the wire format requires is in here:

- Chaskey-LTS MAC, Ed25519 4-variant verify, HMAC-SHA256 KDF, X25519 ECDH
- Frame encode / decode with fragment reassembly
- Typed message parse / write for every opcode we handle
- A pure state machine (`Session`) covering FullVerify pairing, QuickVerify reconnect,
  InitEvents, steady-state ping / press / ack, and classified disconnect reasons
- A pure reconnect supervisor with exponential backoff and BLE adapter-state gating
- A `btleplug`-backed BLE transport and a single-peripheral `FlicManager` that wires
  it all together and exposes an async API + broadcast event stream

The crypto, framing, protocol, session, and reconnect modules are pure — zero I/O,
zero async, deterministic under test. The BLE transport and manager are the thin async
glue on top. Use this crate directly if you're building Rust software that talks to
Flic 2 buttons.

### `flic-cli` — validation harness

Diagnostic binary that exercises the library end-to-end against a real button:

| Command  | What it does                                                                   |
| -------- | ------------------------------------------------------------------------------ |
| `doctor` | Check that a BLE adapter is present and powered on                             |
| `scan`   | Discover Flic 2 peripherals in range (Public Mode only)                        |
| `pair`   | Run FullVerify against a button in Public Mode; write credentials JSON         |
| `listen` | Reconnect via QuickVerify, auto-reconnect on drops, print events until Ctrl-C  |
| `forget` | Delete a stored pairing on our side                                            |

Useful on its own for scripting and as a worked example of every `flic-core` surface.
Installed from source; not published.

### `flic-napi` — Node.js bindings

[napi-rs](https://napi.rs) bindings that compile `flic-core` into a native `.node`
addon, giving Node and Electron a typed async JS API with reliable cross-platform BLE
underneath.

The reason for a native binding instead of a pure-JS Flic 2 implementation:

- **No reliable pure-JS BLE across platforms.** noble / webbluetooth have gaps around
  directed advertisements (which Flic 2 uses in Private Mode), adapter-state events,
  and reconnection behavior. `btleplug` handles these uniformly.
- **Ad-hoc crypto ports are fragile.** Flic 2 uses Chaskey-LTS (bespoke MAC), Ed25519
  with a 4-variant signature search, and a specific KDF construction. Porting those
  carefully once in Rust — then letting every language bind to the same core — is the
  durable shape.
- **Heavy work off the JS event loop.** BLE notifications, reassembly, MAC verify, and
  reconnect supervision run on Tokio in a Rust background task; the binding only
  surfaces typed events to JS via `ThreadsafeFunction` — non-blocking, safe to consume
  from React or any other framework.

See [`crates/flic-napi/`](crates/flic-napi) for the JS surface and `smoke.mjs` /
`hardware-smoke.mjs` for runnable examples.

## Prerequisites

- **Rust 1.88+** (`rust-toolchain.toml` pins the toolchain; `rustup` will install it
  automatically on first build)
- **A BLE adapter.** macOS and Linux (BlueZ) are supported by `btleplug`; Windows 10+
  should also work but is untested here
- **One or more Flic 2 buttons** for anything beyond unit tests
- **macOS only:** on first run the OS will prompt for Bluetooth permission for the
  terminal / application that runs the binary
- **For `flic-napi`:** Node 18+ or Bun, plus `@napi-rs/cli` (installed by the crate's
  `package.json`)

## Build

```bash
# Rust library + CLI
cargo build --workspace
cargo test  --workspace

# napi-rs binding (from crates/flic-napi)
cd crates/flic-napi
bun install            # or: npm install
bun run build          # produces index.js, index.d.ts, flic-napi.<triple>.node
node smoke.mjs         # no-hardware sanity check
```

The CLI binary lands at `target/debug/flic-cli` (add `--release` for optimised).

## End-to-end walk-through (CLI)

```bash
# 1. Confirm the adapter is live.
flic-cli doctor

# 2. Put a fresh Flic 2 in Public Mode (hold ~7s; LED flashes rapidly, then two
#    extra flashes after release — you have ~30s). Scan to find its peripheral id.
flic-cli scan

# 3. Pair. Writes ./creds.json with the pairing key + identity + peripheral id.
flic-cli pair <peripheral_id>

# 4. Reconnect + listen. Click the button to wake it; Ctrl-C to stop. Event
#    continuity is persisted back to creds.json.
flic-cli listen <peripheral_id> --creds creds.json
```

`creds.json` contains a secret (the 16-byte pairing key). Don't commit it; the
repository's `.gitignore` already covers `creds.json`, `*.creds.json`, and
`*-creds.json` by default.

## End-to-end (Node)

```js
import { FlicManager, FlicEventKind } from 'flic-napi';

const manager = await FlicManager.create();

// Reconnect against a previously-paired button (creds from disk, keychain, HSM).
const handle = await manager.connect(peripheralId, storedCreds, resumeState);

const subscription = manager.onEvent((ev) => {
  switch (ev.kind) {
    case FlicEventKind.Connected:    console.log('battery', ev.batteryMv, 'mV'); break;
    case FlicEventKind.Press:        console.log(ev.pressKind, 'at', ev.timestamp32k); break;
    case FlicEventKind.Reconnecting: console.log('retry in', ev.afterMs, 'ms'); break;
    case FlicEventKind.Disconnected: console.log('out:', ev.reason?.kind); break;
    case FlicEventKind.Lagged:       console.log('dropped', ev.laggedCount, 'events'); break;
  }
});

// Periodically persist handle.resumeState() so the button can suppress events
// it has already delivered on a prior session. When done, call
// `await subscription.dispose()` to stop the listener.
```

## How it works

Flic 2 is a Bluetooth LE peripheral with a single custom GATT service, two
characteristics (one write-without-response, one notify), and a framed protocol
layered on top. The library maps cleanly onto four layers.

### 1. Frame layer — bytes on the wire

Every ATT packet carries a 1-byte control byte (logical connection id + fragment flag),
a 1-byte opcode, a payload, and for session-signed frames a 5-byte Chaskey-LTS MAC.
Longer payloads fragment across multiple notifications and reassemble on receive.
See `crates/flic-core/src/protocol/frame.rs` for the encode / decode + `Reassembler`.

### 2. Protocol layer — typed messages

Each opcode has a strongly-typed Rust struct with `parse()` / `write()` methods. The
opcodes and their field layouts come from the
[Flic 2 protocol documentation](https://github.com/50ButtonsEach/flic2-documentation/wiki)
with validation against pyflic-ble. See `crates/flic-core/src/protocol/messages.rs`.

### 3. Session layer — pure state machine

`Session` is a stepwise state machine that takes `SessionInput` (incoming packet, user
command, BLE drop) and returns `SessionAction` (write packet, emit event, close). It
owns the crypto counters, the reassembler, and the transitions for:

- **FullVerify** (pairing): X25519 ECDH → SHA-256 (`fullVerifySecret`) → HMAC-SHA256
  KDF (session_key, pairing_key, pairing_id, verifier) → Ed25519 verify of the
  button's attestation chain. Returns `PairingCredentials` on success.
- **QuickVerify** (reconnect): hash the stored pairing_key with fresh nonces into a
  new session_key; verify the first MAC; arm event delivery with a continuity token
  so the button only forwards events we haven't already seen.
- **Steady state**: verify inbound MAC + counter; respond to PING; decode
  `ButtonEventNotification` into typed `PressKind` events; emit ACKs for the decisive
  events (`SingleClick`, `DoubleClick`, `Hold`, `UpAfterHold`) so the button evicts
  them from its queue.

The session is pure — no I/O, no async, no clocks. That makes it easy to unit-test
and deterministic under fuzzing. See `crates/flic-core/src/session.rs`.

### 4. Transport + manager + reconnect — async glue

`BleTransport` is the `btleplug` wrapper: scan (service-UUID filtered for Public Mode
discovery), find-by-id (no filter — see the note below), GATT connect, subscribe,
write, disconnect. `FlicManager` drives the session from transport notifications,
enforces a 20s inactivity timeout (Flic 2's heartbeat is ~10s), and broadcasts typed
`FlicEvent`s to subscribers.

A second pure state machine (`Supervisor` in `crates/flic-core/src/reconnect.rs`)
decides *when* to retry a dropped connection, with inputs for attempt outcome,
backoff timer, adapter power transitions, and user disconnect. It defaults to a
half-second initial backoff doubling to a 30s cap, retries forever, and gates on BLE
adapter state so retries pause cleanly when Bluetooth goes off.
`FlicManager::listen_with_reconnect` wraps this in a background task and exposes a
`ReconnectingHandle` with a watch channel for the event-continuity state so the
caller can persist it on its own cadence.

## Private Mode caveat

Once paired, Flic 2 sits in **Private Mode**: it only advertises (`ADV_DIRECT_IND`)
briefly in response to a physical click. That has two practical consequences this
library handles internally:

1. **No service-UUID scan filter when looking for a paired button.** Directed
   advertisements don't carry a service UUID payload; macOS CoreBluetooth drops them
   before the application layer sees anything if a filter is set. `find_peripheral`
   uses an unfiltered scan.
2. **Poll `adapter.peripherals()` rather than rely on the scan event stream.**
   btleplug's macOS event stream can miss the very brief click-triggered advertisement
   due to scan coalescing, but the adapter's internal peripheral table does populate.
   Polling every ~200ms catches what the event stream misses.

The `listen_with_reconnect` supervisor keeps an indefinite find window open per
attempt, so a paired button will reconnect as soon as the user clicks it — even if
that's minutes after the previous session dropped.

## Security notes

- All session traffic is Chaskey-LTS MACed with a 40-bit tag per packet + a monotonic
  64-bit counter per direction. Counters are re-initialised per session and wrap
  safely; any mismatch fails verification immediately.
- Pairing keys (`PairingCredentials::pairing_key`) and the derived key material
  (`FullVerifyKeys::{session_key, pairing_key, verifier, full_verify_secret}`) are
  zeroised on drop via the `zeroize` crate. The public `PairingCredentials` struct is
  still `Clone` because the caller has to persist it; protect it at rest.
- Ed25519 verify delegates to `ed25519-dalek` (RustCrypto) with the 4-variant
  signature-bit search that Flic's signing scheme requires. A valid signature has
  exactly one accepting variant; zero or two-or-more → fail.

## Testing

Two tiers:

1. **Unit + integration tests** (`cargo test --workspace`): deterministic crypto,
   framing, event decoding, session-machine transitions, supervisor transitions,
   and credential I/O. No hardware. Vectors in `crates/flic-core/tests/fixtures/`
   are byte-exact against pyflic-ble's output.
2. **Hardware validation**: `flic-cli` commands and
   `crates/flic-napi/hardware-smoke.mjs` against a real button. Covers the handshake,
   reconnect, event delivery, ACK dedup, and inactivity-timeout paths.

The `fixtures/` directory has a Python harness that regenerates the NDJSON test
vectors by running deterministic seeds through pyflic-ble directly. Rerun only when
you add seeds or upstream bug-fixes a crypto path. See
[`fixtures/README.md`](fixtures/README.md).

## References

- [flic2-documentation](https://github.com/50ButtonsEach/flic2-documentation) —
  authoritative Flic 2 protocol documentation from the vendor (the spec this
  implementation was built against)
- [pyflic-ble](https://github.com/50ButtonsEach/pyflic-ble) — Python reference
  implementation the fixtures were generated against
- [btleplug](https://github.com/deviceplug/btleplug) — cross-platform Rust BLE library
- [napi-rs](https://napi.rs) — Rust → Node.js binding framework

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same dual-license by default.

`flic-rs` is not affiliated with, endorsed by, or supported by Shortcut Labs AB.
"Flic" is a trademark of its owner.
