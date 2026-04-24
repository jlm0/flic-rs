//! Ed25519 signature verification with Flic's 4-variant search.
//!
//! Flic's firmware signs `FullVerifyResponse1` with a key whose encoding can take one of
//! four equivalent forms differing only in bits 0 and 1 of byte 32 of the signature. The
//! wiki describes this as "bits 128-129"; the authoritative bit location per
//! pyflic-ble's `verify_ed25519_signature_with_variant` is `signature[32]` bits 0-1.
//!
//! [`verify_with_variant`] tries all four candidate signatures and returns the variant
//! that validates. If zero or multiple verify, we treat it as a failure — the caller
//! must see exactly one authoritative variant. Security code must reject ambiguous
//! authentication states rather than pick the first match.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Tries all four sig[32] low-bit variants. Returns the variant (0..=3) that verifies.
///
/// Returns `None` if zero or more than one variants verify. A well-formed signature
/// from a Flic 2 button has exactly one accepting variant — ambiguity (multiple
/// accepting variants) must not be silently resolved by picking the first match.
#[must_use]
pub fn verify_with_variant(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Option<u8> {
    let Ok(pk) = VerifyingKey::from_bytes(public_key) else {
        return None;
    };

    let results: [bool; 4] = std::array::from_fn(|variant| {
        let mut candidate = *signature;
        candidate[32] = (candidate[32] & 0xFC) | variant as u8;
        let sig = Signature::from_bytes(&candidate);
        pk.verify(message, &sig).is_ok()
    });
    pick_unique_variant(results)
}

/// Returns `Some(i)` if exactly one entry in `results` is true, else `None`.
///
/// Exposed as a pure helper so the uniqueness rule can be tested independently
/// of the underlying Ed25519 verifier (which we can't easily coerce into
/// double-accepting a crafted signature).
#[must_use]
fn pick_unique_variant(results: [bool; 4]) -> Option<u8> {
    let mut found: Option<u8> = None;
    for (i, &ok) in results.iter().enumerate() {
        if ok {
            if found.is_some() {
                return None;
            }
            found = Some(i as u8);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_unique_variant_returns_none_when_no_variant_accepts() {
        assert_eq!(pick_unique_variant([false, false, false, false]), None);
    }

    #[test]
    fn pick_unique_variant_returns_the_sole_accepting_variant() {
        assert_eq!(pick_unique_variant([false, true, false, false]), Some(1));
        assert_eq!(pick_unique_variant([false, false, false, true]), Some(3));
        assert_eq!(pick_unique_variant([true, false, false, false]), Some(0));
    }

    #[test]
    fn pick_unique_variant_returns_none_when_multiple_variants_accept() {
        // Ambiguity must not be silently resolved by picking the first match.
        assert_eq!(pick_unique_variant([true, true, false, false]), None);
        assert_eq!(pick_unique_variant([false, true, true, false]), None);
        assert_eq!(pick_unique_variant([true, true, true, true]), None);
    }

    #[test]
    fn verify_with_variant_rejects_all_zero_signature() {
        // Sanity check: the public wrapper still returns None for nonsense input.
        let pk = [0u8; 32];
        let msg = b"hello";
        let sig = [0u8; 64];
        assert_eq!(verify_with_variant(&pk, msg, &sig), None);
    }
}
