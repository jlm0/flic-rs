//! X25519 ECDH wrapper for the FullVerify handshake.
//!
//! Flic 2's pairing uses X25519 Diffie-Hellman to establish a shared secret which feeds
//! the SHA-256 input to `fullVerifySecret`. The client generates an ephemeral keypair,
//! receives the button's public key in `FullVerifyResponse1`, and derives the shared
//! secret locally.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An ephemeral X25519 keypair. The private half is wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    private: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
}

impl Keypair {
    /// Generates a fresh ephemeral keypair using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Constructs a keypair from a pre-existing private key. Used for tests and fixtures.
    #[must_use]
    pub fn from_private_bytes(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Returns the 32-byte public key (safe to share).
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Performs ECDH against `peer_public` and returns the 32-byte shared secret.
    ///
    /// # Errors
    ///
    /// X25519 has no failure modes under valid inputs — this always succeeds and returns
    /// the shared secret. The "all-zero output" edge case (low-order peer public) is not
    /// an error here; callers that care must check separately.
    #[must_use]
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(self.private);
        let peer = PublicKey::from(*peer_public);
        secret.diffie_hellman(&peer).to_bytes()
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &hex::encode(self.public))
            .field("private", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_is_symmetric() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_secret = alice.diffie_hellman(&bob.public());
        let bob_secret = bob.diffie_hellman(&alice.public());

        assert_eq!(
            alice_secret, bob_secret,
            "X25519 DH from either side must agree",
        );
    }

    #[test]
    fn deterministic_keypair_from_private_bytes() {
        let priv_bytes = [42u8; 32];
        let a = Keypair::from_private_bytes(priv_bytes);
        let b = Keypair::from_private_bytes(priv_bytes);
        assert_eq!(a.public(), b.public(), "same private → same public");
    }

    #[test]
    fn public_key_differs_from_private() {
        // X25519 private key bytes are mutated (clamped) before use; the public key
        // is never literally equal to the private input.
        let priv_bytes = [1u8; 32];
        let kp = Keypair::from_private_bytes(priv_bytes);
        assert_ne!(kp.public(), priv_bytes);
    }
}
