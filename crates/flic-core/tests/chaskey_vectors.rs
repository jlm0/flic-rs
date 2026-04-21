//! Byte-exact vectors for the Chaskey-LTS primitives.
//!
//! Fixtures in `tests/fixtures/*.ndjson` are produced by `../../fixtures/generate.py`
//! which runs pyflic-ble's canonical implementation. We must match bit-for-bit.

mod common;

use common::{hex_array, hex_vec, load_fixtures, subkeys_to_hex_triple};
use flic_core::crypto::chaskey;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SubkeysCase {
    key: String,
    subkeys: Vec<String>,
}

#[test]
fn chaskey_subkeys_match_pyflic() {
    let cases: Vec<SubkeysCase> = load_fixtures("chaskey_subkeys.ndjson");
    assert!(!cases.is_empty(), "no fixture cases loaded");

    for (i, case) in cases.iter().enumerate() {
        let key = hex_array::<16>(&case.key);
        let got = chaskey::generate_subkeys(&key);
        let got_hex = subkeys_to_hex_triple(&got);
        assert_eq!(
            got_hex.as_slice(),
            case.subkeys.as_slice(),
            "subkey mismatch for case {i}, key={}",
            case.key,
        );
    }
}

#[derive(Debug, Deserialize)]
struct MacDirCounterCase {
    key: String,
    direction: u8,
    counter: u64,
    data: String,
    mac: String,
}

#[test]
fn chaskey_mac_dir_counter_matches_pyflic() {
    let cases: Vec<MacDirCounterCase> = load_fixtures("chaskey_mac_dir_counter.ndjson");
    assert!(!cases.is_empty(), "no fixture cases loaded");

    for (i, case) in cases.iter().enumerate() {
        let key = hex_array::<16>(&case.key);
        let subkeys = chaskey::generate_subkeys(&key);
        let data = hex_vec(&case.data);
        let got = chaskey::mac_with_dir_and_counter(&subkeys, case.direction, case.counter, &data);
        let expected = hex_array::<5>(&case.mac);
        assert_eq!(
            got,
            expected,
            "MAC mismatch for case {i}: dir={} counter={} data_len={}",
            case.direction,
            case.counter,
            data.len(),
        );
    }
}

#[derive(Debug, Deserialize)]
struct Mac16Case {
    key: String,
    data: String,
    mac: String,
}

#[test]
fn chaskey_mac_16_matches_pyflic() {
    let cases: Vec<Mac16Case> = load_fixtures("chaskey_mac_16.ndjson");
    assert!(!cases.is_empty(), "no fixture cases loaded");

    for (i, case) in cases.iter().enumerate() {
        let key = hex_array::<16>(&case.key);
        let subkeys = chaskey::generate_subkeys(&key);
        let data = hex_array::<16>(&case.data);
        let got = chaskey::mac_16_bytes(&subkeys, &data);
        let expected = hex_array::<16>(&case.mac);
        assert_eq!(got, expected, "16-byte MAC mismatch for case {i}",);
    }
}
