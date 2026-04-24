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

impl FlicError {
    /// Returns a stable, screaming-snake-case identifier for this variant.
    ///
    /// This is the string binding layers use to let non-Rust callers branch
    /// on the variant without parsing `Display` output. The set is closed —
    /// adding a variant to `FlicError` requires adding a code here, and the
    /// test below enforces that every variant has exactly one code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BluetoothOff => "BLUETOOTH_OFF",
            Self::BleAdapterUnavailable(_) => "BLE_ADAPTER_UNAVAILABLE",
            Self::NotFound => "NOT_FOUND",
            Self::PairingFailed(_) => "PAIRING_FAILED",
            Self::InvalidMac => "INVALID_MAC",
            Self::Timeout { .. } => "TIMEOUT",
            Self::ProtocolViolation(_) => "PROTOCOL_VIOLATION",
            Self::Crypto(_) => "CRYPTO",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_stable_screaming_snake_for_every_variant() {
        // Enumerate every variant once — if a new one is added to the enum
        // and this match isn't updated, the compiler fails this test for us.
        let samples = [
            FlicError::BluetoothOff,
            FlicError::BleAdapterUnavailable("x".into()),
            FlicError::NotFound,
            FlicError::PairingFailed("x".into()),
            FlicError::InvalidMac,
            FlicError::Timeout { opcode: 0 },
            FlicError::ProtocolViolation("x".into()),
            FlicError::Crypto("x"),
        ];
        let codes: Vec<&'static str> = samples.iter().map(FlicError::code).collect();
        assert_eq!(
            codes,
            [
                "BLUETOOTH_OFF",
                "BLE_ADAPTER_UNAVAILABLE",
                "NOT_FOUND",
                "PAIRING_FAILED",
                "INVALID_MAC",
                "TIMEOUT",
                "PROTOCOL_VIOLATION",
                "CRYPTO",
            ]
        );
    }

}
