//! Ed25519 signature verification with Flic's 4-variant search.
//!
//! Flic's firmware signs `FullVerifyResponse1` with a key whose encoding can take one of
//! four equivalent forms differing only in bits 0 and 1 of byte 32 of the signature. The
//! wiki describes this as "bits 128-129"; the authoritative bit location per
//! pyflic-ble's `verify_ed25519_signature_with_variant` is `signature[32]` bits 0-1.
//!
//! [`verify_with_variant`] tries all four candidate signatures and returns the variant
//! that validates. If zero or multiple verify, we treat it as a failure — the caller
//! must see exactly one authoritative variant.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Tries all four sig[32] low-bit variants. Returns the variant (0..=3) that verifies.
///
/// Returns `None` if no variant verifies. A well-formed signature from a Flic 2 button
/// will have exactly one variant that verifies — ambiguous (multiple) or no valid
/// variants means the signature is corrupted or not from Flic firmware.
#[must_use]
pub fn verify_with_variant(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Option<u8> {
    let Ok(pk) = VerifyingKey::from_bytes(public_key) else {
        return None;
    };

    for variant in 0u8..4 {
        let mut candidate = *signature;
        candidate[32] = (candidate[32] & 0xFC) | variant;
        let sig = Signature::from_bytes(&candidate);
        if pk.verify(message, &sig).is_ok() {
            return Some(variant);
        }
    }
    None
}
