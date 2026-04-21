//! Shared fixture-loading helpers for integration tests.
//!
//! Each integration test file in `tests/` is its own crate, so helpers that any one file
//! doesn't use would otherwise warn dead_code.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use serde::de::DeserializeOwned;

/// Loads a NDJSON fixture file from `tests/fixtures/`. Each line becomes one case.
pub fn load_fixtures<T: DeserializeOwned>(name: &str) -> Vec<T> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("parse {}: {e}\nline: {line}", path.display()))
        })
        .collect()
}

/// Decodes a hex string into a fixed-size array.
///
/// # Panics
///
/// Panics if the hex is malformed or the decoded length doesn't match `N`.
#[must_use]
pub fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).expect("valid hex");
    assert_eq!(
        v.len(),
        N,
        "expected {N} bytes, got {} for hex {s}",
        v.len()
    );
    let mut arr = [0u8; N];
    arr.copy_from_slice(&v);
    arr
}

/// Decodes a hex string into a Vec<u8>.
#[must_use]
pub fn hex_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// Converts a 12-word Chaskey subkey array into the 3-hex-string form used in fixtures.
#[must_use]
pub fn subkeys_to_hex_triple(sk: &[u32; 12]) -> [String; 3] {
    let mut out: [String; 3] = [String::new(), String::new(), String::new()];
    for (i, chunk) in sk.chunks_exact(4).enumerate() {
        let mut bytes = [0u8; 16];
        for (j, word) in chunk.iter().enumerate() {
            bytes[j * 4..j * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[i] = hex::encode(bytes);
    }
    out
}
