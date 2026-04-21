"""Generate byte-exact test fixtures for flic-core's crypto layer.

Imports pyflic-ble's canonical implementation, runs fixed inputs through each
primitive, and writes NDJSON to crates/flic-core/tests/fixtures/. The Rust unit
tests read these NDJSON files and byte-compare their own outputs.

Run once to regenerate. NDJSON output is committed so Rust CI never needs
Python. See fixtures/README.md for the exact invocation.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pyflic_ble.security import (
    chaskey_16_bytes,
    chaskey_generate_subkeys,
    chaskey_with_dir_and_counter,
    derive_full_verify_keys,
    verify_ed25519_signature_with_variant,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crates" / "flic-core" / "tests" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)


def hx(b: bytes) -> str:
    """Hex-encode without a 0x prefix, lowercase, no separators."""
    return b.hex()


def subkeys_to_hex(subkeys: list[int]) -> list[str]:
    """pyflic-ble returns list[int] of 12 u32s (little-endian words).

    Convert to 3 16-byte hex strings (k0, k1, k2) for compact fixture form.
    """
    out: list[str] = []
    for chunk in (subkeys[0:4], subkeys[4:8], subkeys[8:12]):
        out.append(struct.pack("<4I", *chunk).hex())
    return out


def gen_chaskey_subkeys() -> None:
    cases = []
    seeds = [
        bytes(16),                              # all zeros
        bytes(range(16)),                       # 00..0f
        bytes([0xFF] * 16),                     # all ones (forces reduction on times2)
        bytes.fromhex("0123456789abcdef0123456789abcdef"),
        bytes.fromhex("8000000000000000000000000000000000"[:32]),  # high bit of v0 set
        bytes.fromhex("00000000000000000000000000000080"),  # high bit of v3 set → forces 0x87 XOR
        bytes.fromhex("feedfacecafebeefdeadbeef0badc0de"),
        bytes.fromhex("112233445566778899aabbccddeeff00"),
    ]
    for key in seeds:
        sk = chaskey_generate_subkeys(key)
        cases.append({"key": hx(key), "subkeys": subkeys_to_hex(sk)})
    write_ndjson("chaskey_subkeys.ndjson", cases)


def gen_chaskey_mac_dir_counter() -> None:
    """Exercises chaskey_with_dir_and_counter across direction, counter, and data length."""
    key = bytes.fromhex("0123456789abcdef0123456789abcdef")
    subkeys = chaskey_generate_subkeys(key)

    inputs = [
        (0, 0, bytes([0x08])),                              # 1-byte data (opcode alone)
        (1, 0, bytes([0x08])),                              # direction flip
        (0, 1, bytes([0x08])),                              # counter=1
        (0, 0xFFFF_FFFF, bytes([0x08])),                    # counter wrapping 32→64
        (0, 0x1_0000_0000, bytes([0x08])),                  # counter high32 engaged
        (0, 42, bytes([0x17]) + bytes(12)),                 # 13 bytes — partial block
        (1, 42, bytes([0x17]) + bytes(15)),                 # 16 bytes — first full block
        (0, 42, bytes([0x17]) + bytes(16)),                 # 17 bytes — full then partial
        (0, 42, bytes([0x17]) + bytes(32)),                 # 33 bytes — 2 full blocks + partial
        (1, 42, bytes([0x17]) + bytes(47)),                 # 48 bytes — 3 full blocks (no partial)
        (0, 42, bytes.fromhex("deadbeef") * 5),             # 20 bytes
    ]
    cases = []
    for direction, counter, data in inputs:
        mac = chaskey_with_dir_and_counter(subkeys, direction, counter, data)
        cases.append({
            "key": hx(key),
            "direction": direction,
            "counter": counter,
            "data": hx(data),
            "mac": hx(mac),
        })
    write_ndjson("chaskey_mac_dir_counter.ndjson", cases)


def gen_chaskey_mac_16() -> None:
    """Exercises chaskey_16_bytes — the QuickVerify session-key derivation MAC."""
    cases = []
    key_seeds = [
        bytes(16),
        bytes(range(16)),
        bytes.fromhex("feedfacecafebeefdeadbeef0badc0de"),
    ]
    data_seeds = [
        bytes(16),
        bytes(range(16, 32)),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ]
    for key in key_seeds:
        subkeys = chaskey_generate_subkeys(key)
        for data in data_seeds:
            mac = chaskey_16_bytes(subkeys, data)
            cases.append({
                "key": hx(key),
                "data": hx(data),
                "mac": hx(mac),
            })
    write_ndjson("chaskey_mac_16.ndjson", cases)


def gen_kdf() -> None:
    """Exercises derive_full_verify_keys across flags and inputs."""
    cases = []
    fixed = [
        # (shared_secret, variant, device_random, client_random, is_twist)
        (bytes(32), 0, bytes(8), bytes(8), False),
        (bytes(range(32)), 1, bytes(range(8)), bytes(range(8, 16)), False),
        (bytes.fromhex("a0" * 32), 2, bytes.fromhex("0011223344556677"), bytes.fromhex("8899aabbccddeeff"), False),
        (bytes.fromhex("5a" * 32), 3, bytes(8), bytes(8), True),  # twist flag (flags byte = 0x00)
        (bytes.fromhex("c4" * 32), 0, bytes(range(100, 108)), bytes(range(200, 208)), False),
    ]
    for shared, variant, dev_rand, cli_rand, is_twist in fixed:
        verifier, session_key, pairing_key, pairing_id, fvs = derive_full_verify_keys(
            shared, variant, dev_rand, cli_rand, is_twist=is_twist
        )
        cases.append({
            "shared_secret": hx(shared),
            "signature_variant": variant,
            "device_random": hx(dev_rand),
            "client_random": hx(cli_rand),
            "is_twist": is_twist,
            "verifier": hx(verifier),
            "session_key": hx(session_key),
            "pairing_key": hx(pairing_key),
            "pairing_id": pairing_id,
            "full_verify_secret": hx(fvs),
        })
    write_ndjson("kdf.ndjson", cases)


def gen_ed25519_variant() -> None:
    """Generates (pubkey, message, signature, expected_variant) tuples.

    The variant-verify function tries all 4 values of signature[32] bits 0-1 and
    returns the one that validates. For a *fresh* signature the variant is
    simply whatever the original signing produced — we record that and confirm
    pyflic-ble rediscovers it.

    For the None case we corrupt the signature body (not byte 32) so no variant
    can rescue it.
    """
    cases = []
    rng_seeds = [b"seed-0", b"seed-1", b"seed-2", b"seed-3"]
    messages = [
        b"",
        b"flic test vector",
        bytes(range(32)),
        b"a" * 100,
    ]

    for i, seed in enumerate(rng_seeds):
        # Deterministic-ish keypair from a known seed (Ed25519PrivateKey.from_private_bytes
        # takes exactly 32 bytes).
        sk_bytes = (seed + b"\x00" * 32)[:32]
        sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
        pk = sk.public_key().public_bytes_raw()

        for msg in messages:
            sig = sk.sign(msg)
            variant = verify_ed25519_signature_with_variant(pk, msg, sig)
            assert variant is not None, "fresh signature must verify"
            cases.append({
                "public_key": hx(pk),
                "message": hx(msg),
                "signature": hx(sig),
                "expected_variant": variant,
            })

            # Corrupted case: flip a byte in the signature body that's NOT byte 32.
            corrupted = bytearray(sig)
            corrupted[10] ^= 0x01
            corrupted_variant = verify_ed25519_signature_with_variant(pk, msg, bytes(corrupted))
            cases.append({
                "public_key": hx(pk),
                "message": hx(msg),
                "signature": hx(bytes(corrupted)),
                "expected_variant": corrupted_variant,  # None
            })

    write_ndjson("ed25519_variant.ndjson", cases)


def write_ndjson(name: str, cases: list[dict]) -> None:
    out_path = OUT / name
    with out_path.open("w") as f:
        for case in cases:
            f.write(json.dumps(case, sort_keys=True))
            f.write("\n")
    print(f"  {name}: {len(cases)} cases")


def main() -> None:
    print(f"writing fixtures to {OUT.relative_to(ROOT)}")
    gen_chaskey_subkeys()
    gen_chaskey_mac_dir_counter()
    gen_chaskey_mac_16()
    gen_kdf()
    gen_ed25519_variant()
    print("done.")


if __name__ == "__main__":
    main()
