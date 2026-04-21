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
    // We document # Errors extensively; # Panics on every internal assertion is noise.
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    // Assertion wrappers often produce unnecessary Result shapes while we build; we'll
    // tighten these when each module is feature-complete.
    clippy::unnecessary_wraps,
    clippy::unused_self,
    // Our protocol data is full of byte-width constants; forcing `_` separators for
    // every u32/u64 makes the wire-format code harder to eyeball-compare against the spec.
    clippy::unreadable_literal,
    // Cast noise in protocol code: we manipulate u8/u16/u32/u64 against fixed-width
    // wire formats. Values are bounded by protocol design; surfacing try_from on every
    // conversion obscures the wire layout without catching real bugs.
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    // We frequently assign a clone where clone_from would marginally save an allocation;
    // readability wins for a once-per-pairing path.
    clippy::assigning_clones,
)]

pub mod constants;
pub mod crypto;
pub mod error;
pub mod events;
pub mod manager;
pub mod protocol;
pub mod reconnect;
pub mod session;
pub mod transport;

pub use error::FlicError;
pub use events::PressKind;
pub use manager::FlicManager;
pub use reconnect::ReconnectPolicy;
pub use session::{
    DisconnectReason, EventResumeState, PairingCredentials, Session, SessionEvent, SessionInput,
};
pub use transport::{BleTransport, Discovery};
