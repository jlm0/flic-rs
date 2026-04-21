//! Chaskey-LTS MAC. Hand-ported from pyflic-ble's `security.py`.
//!
//! Chaskey-LTS is a lightweight 128-bit MAC with a 128-bit key, 16-round permutation, and
//! CMAC-style subkey-doubling for the last (possibly partial) block. Flic 2 uses three
//! distinct entry points:
//!
//! 1. [`generate_subkeys`] — derives `(k0, k1, k2)` from a 16-byte session key.
//!    `k0` is the raw key; `k1` and `k2` are successive `times2` doublings in GF(2^128).
//! 2. [`mac_with_dir_and_counter`] — computes the 5-byte per-packet MAC. Uses a
//!    pre-state where `counter_low32 ⊕ v0`, `counter_high32 ⊕ v1`, `direction ⊕ v2`.
//! 3. [`mac_16_bytes`] — computes a full 16-byte MAC over exactly one 16-byte block,
//!    used during QuickVerify to derive the session key from the stored pairing key.

#![allow(clippy::cast_possible_truncation)]

type State = (u32, u32, u32, u32);

/// Generates the three 128-bit Chaskey subkeys from a 16-byte key.
///
/// Returns a `[u32; 12]` laid out as `[k0_0..k0_3, k1_0..k1_3, k2_0..k2_3]`, each
/// 4-word group being a 128-bit subkey in little-endian word order. This layout
/// matches pyflic-ble's `chaskey_generate_subkeys` so fixture comparisons are direct.
///
/// `k0` is the raw key. `k1 = times2(k0)` in GF(2^128) with the Chaskey reduction
/// polynomial (tap byte `0x87`). `k2 = times2(k1)`.
#[must_use]
pub fn generate_subkeys(key: &[u8; 16]) -> [u32; 12] {
    let v0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    let v1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    let v2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    let v3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

    let (k1_0, k1_1, k1_2, k1_3) = times2((v0, v1, v2, v3));
    let (k2_0, k2_1, k2_2, k2_3) = times2((k1_0, k1_1, k1_2, k1_3));

    [
        v0, v1, v2, v3, k1_0, k1_1, k1_2, k1_3, k2_0, k2_1, k2_2, k2_3,
    ]
}

/// GF(2^128) doubling with the Chaskey reduction polynomial.
///
/// If the high bit of the 128-bit value is set, the result XORs in `0x87` (the
/// polynomial-reduction constant for Chaskey's particular field representation).
#[inline]
fn times2((v0, v1, v2, v3): State) -> State {
    let carry = ((v3 >> 31) & 1) * 0x87;
    let n3 = (v3 << 1) | (v2 >> 31);
    let n2 = (v2 << 1) | (v1 >> 31);
    let n1 = (v1 << 1) | (v0 >> 31);
    let n0 = (v0 << 1) ^ carry;
    (n0, n1, n2, n3)
}

/// Computes the 5-byte Chaskey MAC over `data` with a pre-state XOR'd by `direction`
/// and `counter`. This is the per-packet MAC used for every signed Flic frame.
///
/// The pre-state is:
///
/// - `v0 = k0[0] ⊕ (counter & 0xFFFFFFFF)`
/// - `v1 = k0[1] ⊕ (counter >> 32)`
/// - `v2 = k0[2] ⊕ direction`
/// - `v3 = k0[3]`
///
/// Then the message `data` is absorbed block by block using the CMAC-style scheme
/// with k1/k2 XORed into the last block (k1 when the message ends on a 16-byte
/// boundary, k2 when it needs padding). 16 Chaskey rounds are applied.
///
/// Returns the first 5 bytes of the resulting 16-byte state (4 bytes of `v0` in
/// little-endian followed by the low byte of `v1`).
///
/// # Panics
///
/// Panics if `data` is empty. A zero-length MAC input is never valid in the Flic
/// protocol — the opcode byte is always present in the MAC input.
#[must_use]
pub fn mac_with_dir_and_counter(
    keys: &[u32; 12],
    direction: u8,
    counter: u64,
    data: &[u8],
) -> [u8; 5] {
    assert!(!data.is_empty(), "Chaskey MAC input must not be empty");

    let mut v0 = keys[0] ^ (counter as u32);
    let mut v1 = keys[1] ^ ((counter >> 32) as u32);
    let mut v2 = keys[2] ^ u32::from(direction);
    let mut v3 = keys[3];

    let mut offset = 0usize;
    let mut remaining = data.len();
    let mut first = true;

    loop {
        let mut key_offset = 0usize;

        if !first {
            if remaining >= 16 {
                v0 ^= load_u32_le(data, offset);
                v1 ^= load_u32_le(data, offset + 4);
                v2 ^= load_u32_le(data, offset + 8);
                v3 ^= load_u32_le(data, offset + 12);
                offset += 16;
                remaining -= 16;
                if remaining == 0 {
                    key_offset = 4; // last block was full → use k1
                }
            } else {
                // Partial final block: pad with 0x01 then zeros.
                let mut tmp = [0u8; 16];
                tmp[..remaining].copy_from_slice(&data[offset..offset + remaining]);
                tmp[remaining] = 0x01;
                v0 ^= u32::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
                v1 ^= u32::from_le_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]);
                v2 ^= u32::from_le_bytes([tmp[8], tmp[9], tmp[10], tmp[11]]);
                v3 ^= u32::from_le_bytes([tmp[12], tmp[13], tmp[14], tmp[15]]);
                key_offset = 8; // partial final block → use k2
            }

            if key_offset != 0 {
                v0 ^= keys[key_offset];
                v1 ^= keys[key_offset + 1];
                v2 ^= keys[key_offset + 2];
                v3 ^= keys[key_offset + 3];
            }
        } else {
            first = false;
        }

        // Pre-rotate v2.
        v2 = v2.rotate_right(16);

        // 16 rounds of Chaskey permutation.
        for _ in 0..16 {
            v0 = v0.wrapping_add(v1);
            v1 = v0 ^ v1.rotate_left(5);
            v2 = v3.wrapping_add(v2.rotate_right(16));
            v3 = v2 ^ v3.rotate_left(8);
            v2 = v2.wrapping_add(v1);
            v0 = v3.wrapping_add(v0.rotate_right(16));
            v1 = v2 ^ v1.rotate_left(7);
            v3 = v0 ^ v3.rotate_left(13);
        }

        // Post-rotate v2.
        v2 = v2.rotate_right(16);

        if key_offset != 0 {
            v0 ^= keys[key_offset];
            v1 ^= keys[key_offset + 1];

            let v0_le = v0.to_le_bytes();
            return [v0_le[0], v0_le[1], v0_le[2], v0_le[3], (v1 & 0xFF) as u8];
        }
    }
}

/// Computes a full 16-byte Chaskey MAC over exactly 16 bytes of data.
///
/// Used during QuickVerify to derive `session_key = Chaskey(pairing_key,
/// client_random ‖ 0x00 ‖ button_random)`. The initial state XORs in `k1` and
/// the input block together, applies 16 rounds, then XORs `k1` again.
///
/// # Panics
///
/// Panics if `data.len() != 16`.
#[must_use]
pub fn mac_16_bytes(keys: &[u32; 12], data: &[u8]) -> [u8; 16] {
    assert_eq!(data.len(), 16, "mac_16_bytes requires exactly 16 bytes");

    let mut v0 = keys[0] ^ keys[4] ^ load_u32_le(data, 0);
    let mut v1 = keys[1] ^ keys[5] ^ load_u32_le(data, 4);
    let mut v2 = keys[2] ^ keys[6] ^ load_u32_le(data, 8);
    let mut v3 = keys[3] ^ keys[7] ^ load_u32_le(data, 12);

    v2 = v2.rotate_right(16);

    for _ in 0..16 {
        v0 = v0.wrapping_add(v1);
        v1 = v0 ^ v1.rotate_left(5);
        v2 = v3.wrapping_add(v2.rotate_right(16));
        v3 = v2 ^ v3.rotate_left(8);
        v2 = v2.wrapping_add(v1);
        v0 = v3.wrapping_add(v0.rotate_right(16));
        v1 = v2 ^ v1.rotate_left(7);
        v3 = v0 ^ v3.rotate_left(13);
    }

    v2 = v2.rotate_right(16);

    v0 ^= keys[4];
    v1 ^= keys[5];
    v2 ^= keys[6];
    v3 ^= keys[7];

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&v0.to_le_bytes());
    out[4..8].copy_from_slice(&v1.to_le_bytes());
    out[8..12].copy_from_slice(&v2.to_le_bytes());
    out[12..16].copy_from_slice(&v3.to_le_bytes());
    out
}

#[inline]
fn load_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
