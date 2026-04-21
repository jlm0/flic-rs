//! HMAC-SHA256 key derivation for Flic 2's FullVerify handshake.
//!
//! The handshake derives four outputs from a single 32-byte `fullVerifySecret`:
//!
//! - `verifier`    = HMAC(fvs, "AT")[0..16] — host → button authenticator
//! - `session_key` = HMAC(fvs, "SK")[0..16] — Chaskey MAC key for the session
//! - `pairing_id`  = HMAC(fvs, "PK")[0..4]  — little-endian u32
//! - `pairing_key` = HMAC(fvs, "PK")[4..20] — stored for QuickVerify reconnects
//!
//! The `fullVerifySecret` itself is SHA-256 over `shared_secret ‖ variant ‖
//! device_random ‖ client_random ‖ flags`, where `flags` is `0x80` for Flic 2/Duo
//! (`supports_duo=1` for forward compatibility) and `0x00` for Twist.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Material produced by [`derive_full_verify_keys`]. Sensitive fields are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FullVerifyKeys {
    pub verifier: [u8; 16],
    pub session_key: [u8; 16],
    pub pairing_key: [u8; 16],
    #[zeroize(skip)]
    pub pairing_id: u32,
    pub full_verify_secret: [u8; 32],
}

impl std::fmt::Debug for FullVerifyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullVerifyKeys")
            .field("pairing_id", &self.pairing_id)
            .field("verifier", &"[redacted]")
            .field("session_key", &"[redacted]")
            .field("pairing_key", &"[redacted]")
            .field("full_verify_secret", &"[redacted]")
            .finish()
    }
}

/// Derives `fullVerifySecret` and the four dependent keys from ECDH output + nonces.
///
/// `is_twist` selects the flags byte appended to the SHA-256 input: `0x00` for a Flic
/// Twist, `0x80` (supports-Duo) for everything else.
#[must_use]
pub fn derive_full_verify_keys(
    shared_secret: &[u8; 32],
    signature_variant: u8,
    device_random: &[u8; 8],
    client_random: &[u8; 8],
    is_twist: bool,
) -> FullVerifyKeys {
    let flags: u8 = if is_twist { 0x00 } else { 0x80 };

    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update([signature_variant]);
    hasher.update(device_random);
    hasher.update(client_random);
    hasher.update([flags]);
    let full_verify_secret: [u8; 32] = hasher.finalize().into();

    let verifier = hmac_prefix::<16>(&full_verify_secret, b"AT");
    let session_key = hmac_prefix::<16>(&full_verify_secret, b"SK");
    let pairing_material = hmac_full(&full_verify_secret, b"PK");

    let pairing_id = u32::from_le_bytes([
        pairing_material[0],
        pairing_material[1],
        pairing_material[2],
        pairing_material[3],
    ]);
    let mut pairing_key = [0u8; 16];
    pairing_key.copy_from_slice(&pairing_material[4..20]);

    FullVerifyKeys {
        verifier,
        session_key,
        pairing_key,
        pairing_id,
        full_verify_secret,
    }
}

/// Computes HMAC-SHA256(key, label) and returns the first `N` bytes.
fn hmac_prefix<const N: usize>(key: &[u8], label: &[u8]) -> [u8; N] {
    assert!(N <= 32, "HMAC-SHA256 produces 32 bytes");
    let mut h = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    h.update(label);
    let out = h.finalize().into_bytes();
    let mut ret = [0u8; N];
    ret.copy_from_slice(&out[..N]);
    ret
}

/// Computes HMAC-SHA256(key, label) and returns all 32 bytes.
fn hmac_full(key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    h.update(label);
    let out = h.finalize().into_bytes();
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&out);
    ret
}
