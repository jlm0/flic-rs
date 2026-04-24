//! Lowercase-hex string encoding/decoding for fixed-width byte arrays.
//!
//! Used by both `flic-cli` (credentials JSON) and `flic-napi` (JS-shape
//! pairing credentials) to round-trip `[u8; 16]` material — pairing keys
//! and button UUIDs — through text. Kept here so the two binding layers
//! don't drift in how they reject malformed input.

/// Encodes `bytes` as a lowercase hex string. Output length is `2 *
/// bytes.len()`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        // `write!` to a `String` is infallible per stdlib contract; the
        // `.expect()` that earlier call sites carried was dead code.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes `s` into a fixed-width byte array of length `N`. Returns `None`
/// if the length is wrong or any byte fails to parse. Accepts both upper
/// and lower case.
#[must_use]
pub fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    // Reject non-ASCII-hex up front. Without this, a length-correct input
    // that contains a multi-byte UTF-8 char passes the length guard and
    // then panics on the `&s[..]` slice when it straddles a char boundary.
    if !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_lowercase_hex() {
        assert_eq!(encode(&[0xAB, 0xCD, 0x01, 0xFF]), "abcd01ff");
    }

    #[test]
    fn encode_handles_empty_input() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decode_fixed_round_trips_through_encode() {
        let bytes: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let s = encode(&bytes);
        let back: [u8; 16] = decode_fixed(&s).expect("round-trip");
        assert_eq!(back, bytes);
    }

    #[test]
    fn decode_fixed_rejects_wrong_length() {
        // 4 hex chars is 2 bytes, not 16.
        assert_eq!(decode_fixed::<16>("00ff"), None);
        // 34 hex chars is 17 bytes, not 16.
        assert_eq!(decode_fixed::<16>(&"00".repeat(17)), None);
    }

    #[test]
    fn decode_fixed_rejects_non_hex_characters() {
        // Correct length, but 'zz' is not a hex byte.
        let mut s = "00".repeat(15);
        s.push_str("zz");
        assert_eq!(decode_fixed::<16>(&s), None);
    }

    #[test]
    fn decode_fixed_accepts_uppercase_and_mixed_case() {
        assert_eq!(decode_fixed::<2>("ABcd"), Some([0xAB, 0xCD]));
    }

    #[test]
    fn decode_fixed_rejects_non_ascii_at_correct_byte_length() {
        // "ää" is 4 UTF-8 bytes and would otherwise pass the byte-length
        // check for N=2; the slice `&s[0..2]` would panic because the
        // second byte lies mid-character. Must return None, not panic.
        assert_eq!(decode_fixed::<2>("ää"), None);
    }
}
