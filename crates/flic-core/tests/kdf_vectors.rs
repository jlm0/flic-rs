//! KDF byte-exact vectors vs pyflic-ble's `derive_full_verify_keys`.

mod common;

use common::{hex_array, load_fixtures};
use flic_core::crypto::kdf;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KdfCase {
    shared_secret: String,
    signature_variant: u8,
    device_random: String,
    client_random: String,
    is_twist: bool,
    verifier: String,
    session_key: String,
    pairing_key: String,
    pairing_id: u32,
    full_verify_secret: String,
}

#[test]
fn derive_full_verify_keys_matches_pyflic() {
    let cases: Vec<KdfCase> = load_fixtures("kdf.ndjson");
    assert!(!cases.is_empty(), "no fixture cases loaded");

    for (i, case) in cases.iter().enumerate() {
        let shared = hex_array::<32>(&case.shared_secret);
        let dev = hex_array::<8>(&case.device_random);
        let cli = hex_array::<8>(&case.client_random);

        let got = kdf::derive_full_verify_keys(
            &shared,
            case.signature_variant,
            &dev,
            &cli,
            case.is_twist,
        );

        assert_eq!(
            got.full_verify_secret,
            hex_array::<32>(&case.full_verify_secret),
            "full_verify_secret mismatch, case {i}",
        );
        assert_eq!(
            got.verifier,
            hex_array::<16>(&case.verifier),
            "verifier mismatch, case {i}",
        );
        assert_eq!(
            got.session_key,
            hex_array::<16>(&case.session_key),
            "session_key mismatch, case {i}",
        );
        assert_eq!(
            got.pairing_key,
            hex_array::<16>(&case.pairing_key),
            "pairing_key mismatch, case {i}",
        );
        assert_eq!(
            got.pairing_id, case.pairing_id,
            "pairing_id mismatch, case {i}",
        );
    }
}
