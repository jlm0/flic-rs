//! Ed25519 variant-verify fixtures from pyflic-ble.

mod common;

use common::{hex_array, hex_vec, load_fixtures};
use flic_core::crypto::ed25519;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VariantCase {
    public_key: String,
    message: String,
    signature: String,
    expected_variant: Option<u8>,
}

#[test]
fn ed25519_variant_verify_matches_pyflic() {
    let cases: Vec<VariantCase> = load_fixtures("ed25519_variant.ndjson");
    assert!(!cases.is_empty(), "no fixture cases loaded");

    for (i, case) in cases.iter().enumerate() {
        let pk = hex_array::<32>(&case.public_key);
        let sig = hex_array::<64>(&case.signature);
        let msg = hex_vec(&case.message);
        let got = ed25519::verify_with_variant(&pk, &msg, &sig);
        assert_eq!(
            got, case.expected_variant,
            "variant mismatch for case {i}: expected {:?}, got {:?}",
            case.expected_variant, got,
        );
    }
}
