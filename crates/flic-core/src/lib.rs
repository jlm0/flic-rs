//! `flic-core` — pure-Rust implementation of the Flic 2 BLE protocol.
//!
//! Layers:
//!
//! - [`constants`] — protocol constants (service UUIDs, MTU, opcodes, Flic's Ed25519 master key)
//! - [`crypto`] — Chaskey-LTS MAC, Ed25519 variant-verify, HMAC-SHA256 KDF, X25519 ECDH
//! - `protocol` (TODO) — frame encode/decode, fragmentation, message types
//! - `session` (TODO) — state machine: FullVerify, QuickVerify, TestIfReallyUnpaired
//! - `transport` (TODO) — btleplug wrapper (scan filter, GATT write/notify, adapter watching)
//! - `manager` (TODO) — public entry point
//!
//! The crypto and protocol layers have zero I/O, zero async, and are byte-exact against
//! fixtures generated from [pyflic-ble](https://github.com/50ButtonsEach/pyflic-ble).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    // Protocol state names (FullVerify, QuickVerify, etc.) are proper nouns in Flic's
    // documentation — we name them that way deliberately. Backticking every occurrence
    // would make the docs harder to read.
    clippy::doc_markdown,
    // Stylistic preference; `if !first` reads more naturally here than inverting.
    clippy::if_not_else,
)]

pub mod constants;
pub mod crypto;
pub mod error;

pub use error::FlicError;
