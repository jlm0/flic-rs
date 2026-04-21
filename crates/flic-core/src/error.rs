//! Error types for `flic-core`.

use thiserror::Error;

/// Top-level error returned from every public async method.
#[derive(Debug, Error)]
pub enum FlicError {
    #[error("BLE adapter unavailable: {0}")]
    BleAdapterUnavailable(String),

    #[error("peripheral not found")]
    NotFound,

    #[error("pairing failed: {0}")]
    PairingFailed(String),

    #[error("invalid MAC on incoming packet")]
    InvalidMac,

    #[error("timed out waiting for opcode {opcode:#x}")]
    Timeout { opcode: u8 },

    #[error("session dropped: {0}")]
    Disconnected(String),

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("cryptographic error: {0}")]
    Crypto(&'static str),
}
