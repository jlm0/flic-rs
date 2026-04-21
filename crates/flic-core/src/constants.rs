//! Flic 2 protocol constants. Verified against pyflic-ble's `const.py`.

use uuid::Uuid;

/// `00420000-8F59-4420-870D-84F3B617E493` — Flic 2 primary GATT service.
pub const FLIC_SERVICE_UUID: Uuid = Uuid::from_bytes([
    0x00, 0x42, 0x00, 0x00, 0x8F, 0x59, 0x44, 0x20, 0x87, 0x0D, 0x84, 0xF3, 0xB6, 0x17, 0xE4, 0x93,
]);

/// `00420001-…` — write characteristic (Write Without Response).
pub const FLIC_WRITE_CHAR_UUID: Uuid = Uuid::from_bytes([
    0x00, 0x42, 0x00, 0x01, 0x8F, 0x59, 0x44, 0x20, 0x87, 0x0D, 0x84, 0xF3, 0xB6, 0x17, 0xE4, 0x93,
]);

/// `00420002-…` — notify characteristic.
pub const FLIC_NOTIFY_CHAR_UUID: Uuid = Uuid::from_bytes([
    0x00, 0x42, 0x00, 0x02, 0x8F, 0x59, 0x44, 0x20, 0x87, 0x0D, 0x84, 0xF3, 0xB6, 0x17, 0xE4, 0x93,
]);

/// Flic's Ed25519 master attestation public key. Every Flic 2 signs its
/// `FullVerifyResponse1` with a firmware-owned Ed25519 key whose certificate chains back
/// to this master key. Compile-time constant; there is no PKI update path in this layer.
pub const FLIC2_ED25519_PUBLIC_KEY: [u8; 32] = [
    0xd3, 0x3f, 0x24, 0x40, 0xdd, 0x54, 0xb3, 0x1b, 0x2e, 0x1d, 0xcf, 0x40, 0x13, 0x2e, 0xfa, 0x41,
    0xd8, 0xf8, 0xa7, 0x47, 0x41, 0x68, 0xdf, 0x40, 0x08, 0xf5, 0xa9, 0x5f, 0xb3, 0xb0, 0xd0, 0x22,
];

/// ATT MTU requested on connect. macOS typically negotiates 185 which covers this.
pub const FLIC_MTU: u16 = 140;

/// Max application-layer packet size = MTU − 11 bytes ATT overhead.
pub const FLIC_MAX_PACKET_SIZE: usize = 129;

/// Chaskey-LTS MAC truncated to 40 bits.
pub const FLIC_SIGNATURE_SIZE: usize = 5;

/// Frame header masks (the control byte is the first byte of every frame).
pub mod frame {
    /// Logical connection ID — bottom 5 bits of the control byte.
    pub const CONN_ID_MASK: u8 = 0x1F;
    /// Set on the response that assigns a connId.
    pub const NEWLY_ASSIGNED: u8 = 0x20;
    /// If set (with FRAGMENT_FLAG cleared), a length byte follows.
    pub const MULTI_PACKET: u8 = 0x40;
    /// 1 = more fragments follow; 0 = last fragment.
    pub const FRAGMENT_FLAG: u8 = 0x80;
}

/// Opcodes sent by the host to the button.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpcodeToFlic {
    FullVerifyRequest1 = 0,
    FullVerifyRequest2 = 2,
    FullVerifyAbortInd = 3,
    TestIfReallyUnpairedRequest = 4,
    QuickVerifyRequest = 5,
    ForceBtDisconnectInd = 6,
    BleSecurityRequestInd = 7,
    GetFirmwareVersionRequest = 8,
    DisconnectVerifiedLinkInd = 9,
    SetConnectionParametersInd = 12,
    PingResponse = 14,
    AckButtonEventsInd = 16,
    GetBatteryLevelRequest = 20,
    InitButtonEventsLightRequest = 23,
}

/// Opcodes sent by the button to the host.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpcodeFromFlic {
    FullVerifyResponse1 = 0,
    FullVerifyResponse2 = 1,
    NoLogicalConnectionSlotsInd = 2,
    FullVerifyFailResponse = 3,
    TestIfReallyUnpairedResponse = 4,
    GetFirmwareVersionResponse = 5,
    QuickVerifyNegativeResponse = 6,
    PairingFinishedInd = 7,
    QuickVerifyResponse = 8,
    DisconnectedVerifiedLinkInd = 9,
    InitButtonEventsResponseWithBootId = 10,
    InitButtonEventsResponseWithoutBootId = 11,
    ButtonEventNotification = 12,
    PingRequest = 15,
    GetBatteryLevelResponse = 20,
}

/// Direction byte used in the Chaskey MAC pre-state (XOR'd into `v2`).
#[repr(u8)]
pub enum Direction {
    /// Frames sent *from* the button to the host (notifications).
    FromButton = 0,
    /// Frames sent *to* the button from the host (writes).
    ToButton = 1,
}
