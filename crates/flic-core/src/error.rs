//! Error types for `flic-core`.
//!
//! The variant discriminant is the stable part of this enum — consumers
//! (including a future napi binding) should branch on the variant, not on
//! the string payloads. Payloads carry human-readable context for logs and
//! UI copy; their wording may change between releases.

use thiserror::Error;

/// Top-level error returned from every public async method.
#[derive(Debug, Error)]
pub enum FlicError {
    /// Bluetooth is powered off on this host. User-fixable — prompt to
    /// enable Bluetooth and retry.
    #[error("Bluetooth is off")]
    BluetoothOff,

    /// No BLE adapter present, or the adapter returned an error. Catches
    /// both "hardware has no Bluetooth" and mid-session transport failures.
    #[error("BLE adapter unavailable: {0}")]
    BleAdapterUnavailable(String),

    /// The requested peripheral isn't known to the adapter (scan hasn't
    /// seen it in this power cycle, or the click-triggered ad was missed).
    #[error("peripheral not found")]
    NotFound,

    #[error("pairing failed: {0}")]
    PairingFailed(String),

    #[error("invalid MAC on incoming packet")]
    InvalidMac,

    #[error("timed out waiting for opcode {opcode:#x}")]
    Timeout { opcode: u8 },

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("cryptographic error: {0}")]
    Crypto(&'static str),
}
