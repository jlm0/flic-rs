//! Cryptographic primitives for the Flic 2 protocol.
//!
//! Every primitive here is deterministic (modulo key generation) and unit-tested byte-exact
//! against fixtures produced by the Python harness in `../../fixtures/`.
//!
//! Layers:
//!
//! - [`chaskey`] — Chaskey-LTS MAC (subkey generation + 5-byte direction/counter MAC +
//!   16-byte exact-block MAC used for QuickVerify session-key derivation)
//! - `ed25519` (TODO) — Ed25519 signature verify with 4-variant bit search
//! - `kdf` (TODO) — HMAC-SHA256 key derivation using `AT` / `SK` / `PK` / `PT` / `NE` labels
//! - `x25519` (TODO) — ECDH key agreement

pub mod chaskey;
pub mod ed25519;
pub mod kdf;
pub mod x25519;
