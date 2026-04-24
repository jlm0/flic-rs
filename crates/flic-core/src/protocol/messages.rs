//! Typed Flic 2 messages with parse + write.
//!
//! Each message represents a single opcode's payload (after the control byte + opcode).
//! Parse takes the `RawFrame::payload()` slice; write produces the bytes that go
//! between the opcode and the MAC. The frame codec in [`super::frame`] handles
//! control bytes and fragmentation; the MAC is appended by the handler outside
//! this module.

#![allow(clippy::cast_possible_truncation)]

use crate::error::FlicError;

// ============================================================================
// Host → Button messages (writer)
// ============================================================================

/// Opcode 0 — `FullVerifyRequest1`. Initiates pairing; unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullVerifyRequest1 {
    pub tmp_id: u32,
}

impl FullVerifyRequest1 {
    pub const OPCODE: u8 = 0;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.tmp_id.to_le_bytes());
        out
    }
}

/// Opcode 2 — `FullVerifyRequest2`. Completes pairing; unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerifyRequest2 {
    pub client_ecdh_pub: [u8; 32],
    pub client_random: [u8; 8],
    /// Per pyflic-ble: flags byte = (signature_variant bits 0-2) | (encryption_variant
    /// bits 3-5) | (must_validate bit 6) | (supports_duo bit 7). For Flic 2 we always
    /// send signature_variant=0, encryption_variant=0, must_validate=false,
    /// supports_duo=true → flags = 0x80.
    pub flags: u8,
    pub verifier: [u8; 16],
}

impl FullVerifyRequest2 {
    pub const OPCODE: u8 = 2;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 8 + 1 + 16);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.client_ecdh_pub);
        out.extend_from_slice(&self.client_random);
        out.push(self.flags);
        out.extend_from_slice(&self.verifier);
        out
    }
}

/// Opcode 3 — `FullVerifyAbortInd`. Cancel an in-flight pair; unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullVerifyAbortInd;

impl FullVerifyAbortInd {
    pub const OPCODE: u8 = 3;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        vec![Self::OPCODE]
    }
}

/// Opcode 4 (to button) — `TestIfReallyUnpairedRequest`. Unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestIfReallyUnpairedRequest {
    pub client_ecdh_pub: [u8; 32],
    pub client_random: [u8; 8],
    pub pairing_id: u32,
    pub pairing_token: [u8; 16],
}

impl TestIfReallyUnpairedRequest {
    pub const OPCODE: u8 = 4;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 8 + 4 + 16);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.client_ecdh_pub);
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.pairing_id.to_le_bytes());
        out.extend_from_slice(&self.pairing_token);
        out
    }
}

/// Opcode 5 — `QuickVerifyRequest`. Unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickVerifyRequest {
    pub client_random: [u8; 7],
    pub flags: u8, // 0x40 = supports_duo
    pub tmp_id: u32,
    pub pairing_id: u32,
}

impl QuickVerifyRequest {
    pub const OPCODE: u8 = 5;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 7 + 1 + 4 + 4);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.client_random);
        out.push(self.flags);
        out.extend_from_slice(&self.tmp_id.to_le_bytes());
        out.extend_from_slice(&self.pairing_id.to_le_bytes());
        out
    }
}

/// Opcode 9 (to button) — `DisconnectVerifiedLinkInd`. Signed; no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectVerifiedLinkInd;

impl DisconnectVerifiedLinkInd {
    pub const OPCODE: u8 = 9;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        vec![Self::OPCODE]
    }
}

/// Opcode 14 — `PingResponse`. Signed; no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingResponse;

impl PingResponse {
    pub const OPCODE: u8 = 14;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        vec![Self::OPCODE]
    }
}

/// Opcode 16 — `AckButtonEventsInd`. Signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckButtonEventsInd {
    pub event_count: u32,
}

impl AckButtonEventsInd {
    pub const OPCODE: u8 = 16;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.event_count.to_le_bytes());
        out
    }
}

/// Opcode 20 (to button) — `GetBatteryLevelRequest`. Signed; no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetBatteryLevelRequest;

impl GetBatteryLevelRequest {
    pub const OPCODE: u8 = 20;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        vec![Self::OPCODE]
    }
}

/// Opcode 23 — `InitButtonEventsLightRequest`. Signed. Arms event delivery.
///
/// The 8-byte tail packs five fields bitwise:
/// - bits  0..8   auto_disconnect_time (u9, 511 = disabled)
/// - bits  9..13  max_queued_packets (u5, max 30; 31 = unlimited)
/// - bits 14..33  max_queued_packets_age (u20, seconds, 0xFFFFF = unlimited)
/// - bits 34..39  rfu (u6, must be 0)
/// - bits 40..63  rfu2 (u24, must be 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitButtonEventsLightRequest {
    pub event_count: u32,
    pub boot_id: u32,
    pub auto_disconnect_time: u16, // u9 actually — caller responsible for bounds
    pub max_queued_packets: u8,    // u5
    pub max_queued_packets_age: u32, // u20
}

impl InitButtonEventsLightRequest {
    pub const OPCODE: u8 = 23;

    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let rfu: u64 = 0;
        let packed: u64 = (u64::from(self.auto_disconnect_time & 0x1FF))
            | (u64::from(self.max_queued_packets as u32 & 0x1F) << 9)
            | (u64::from(self.max_queued_packets_age & 0x000F_FFFF) << 14)
            | ((rfu & 0x3F) << 34);
        let mut out = Vec::with_capacity(1 + 4 + 4 + 8);
        out.push(Self::OPCODE);
        out.extend_from_slice(&self.event_count.to_le_bytes());
        out.extend_from_slice(&self.boot_id.to_le_bytes());
        out.extend_from_slice(&packed.to_le_bytes());
        out
    }
}

// ============================================================================
// Button → Host messages (parser)
// ============================================================================

/// Opcode 0 (from button) — `FullVerifyResponse1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerifyResponse1 {
    pub tmp_id: u32,
    pub signature: [u8; 64],
    pub button_address: [u8; 6],
    pub address_type: u8,
    pub button_ecdh_pub: [u8; 32],
    pub device_random: [u8; 8],
    pub flags: u8,
}

impl FullVerifyResponse1 {
    /// Parses the payload (opcode already stripped). Expects 115 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::ProtocolViolation`] if the payload is shorter than 115 bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        // payload is body[1..] = tmp_id(4) + sig(64) + addr(6) + addrtype(1) + pk(32) + rand(8) + flags(1) = 116
        if payload.len() < 116 {
            return Err(FlicError::ProtocolViolation(format!(
                "FullVerifyResponse1 payload too short: {} bytes (expected 116)",
                payload.len()
            )));
        }
        let tmp_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[4..68]);
        let mut button_address = [0u8; 6];
        button_address.copy_from_slice(&payload[68..74]);
        let address_type = payload[74];
        let mut button_ecdh_pub = [0u8; 32];
        button_ecdh_pub.copy_from_slice(&payload[75..107]);
        let mut device_random = [0u8; 8];
        device_random.copy_from_slice(&payload[107..115]);
        let flags = payload[115];
        Ok(Self {
            tmp_id,
            signature,
            button_address,
            address_type,
            button_ecdh_pub,
            device_random,
            flags,
        })
    }
}

/// Opcode 1 — `FullVerifyResponse2`. Signed (MAC already stripped by caller).
///
/// Layout per pyflic-ble:
/// - flags (1): bit 0 = `app_credentials_match`, bit 1 = `cares_about_app_credentials`,
///   bit 2 = `is_duo`
/// - button_uuid (16)
/// - name_len (1) + name (23, padded)
/// - firmware_version (4, u32 LE)
/// - battery_level (2, u16 LE) — raw ADC ×(3600/1024) = mV
/// - serial_number (11, null-terminated ASCII)
/// - optional pairing_identifier (4, u32 LE) + pairing_key_variant (1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerifyResponse2 {
    pub flags: u8,
    pub button_uuid: [u8; 16],
    pub name: String,
    pub firmware_version: u32,
    pub battery_level_raw: u16,
    pub serial_number: String,
}

impl FullVerifyResponse2 {
    /// `flags` bit 0 — the button agreed the supplied app credentials match.
    /// Only meaningful when [`Self::cares_about_app_credentials`] is true: a
    /// button that doesn't enforce credentials can legitimately report `false`
    /// here without it being a handshake failure.
    #[must_use]
    pub fn app_credentials_match(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// `flags` bit 1 — the button enforces app-credential matching. When this
    /// is set and [`Self::app_credentials_match`] is not, pairing must fail.
    #[must_use]
    pub fn cares_about_app_credentials(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// `flags` bit 2 — the button is a Flic Duo (Duo extension). Preserved for
    /// callers that want to diverge behavior for Duo-specific event encodings.
    #[must_use]
    pub fn is_duo(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// True iff the button actively rejected our app credentials — i.e. it
    /// both [`cares_about_app_credentials`](Self::cares_about_app_credentials)
    /// and signals [`app_credentials_match`](Self::app_credentials_match) is
    /// false. A button that doesn't care about credentials returns `false`
    /// here regardless of the match bit.
    #[must_use]
    pub fn credentials_rejected(&self) -> bool {
        self.cares_about_app_credentials() && !self.app_credentials_match()
    }

    /// Parses the payload (opcode already stripped).
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::ProtocolViolation`] if the payload is too short.
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        // flags(1) + uuid(16) + name_len(1) + name(23) + fw(4) + batt(2) + serial(11) = 58
        if payload.len() < 58 {
            return Err(FlicError::ProtocolViolation(format!(
                "FullVerifyResponse2 payload too short: {} bytes",
                payload.len()
            )));
        }
        let flags = payload[0];
        let mut button_uuid = [0u8; 16];
        button_uuid.copy_from_slice(&payload[1..17]);
        let name_len = payload[17] as usize;
        let name_end = 18 + name_len.min(23);
        let name = String::from_utf8_lossy(&payload[18..name_end]).into_owned();
        let firmware_version =
            u32::from_le_bytes([payload[41], payload[42], payload[43], payload[44]]);
        let battery_level_raw = u16::from_le_bytes([payload[45], payload[46]]);
        let serial_bytes = &payload[47..58];
        let serial_end = serial_bytes.iter().position(|&b| b == 0).unwrap_or(11);
        let serial_number = String::from_utf8_lossy(&serial_bytes[..serial_end]).into_owned();
        Ok(Self {
            flags,
            button_uuid,
            name,
            firmware_version,
            battery_level_raw,
            serial_number,
        })
    }
}

/// Opcode 2 (from button) — `NoLogicalConnectionSlotsInd`. Unsigned.
///
/// Payload is a variable-length list of u32 (LE) `tmp_id` values — one per
/// session the button is rejecting. A session is only affected if its
/// `expected_tmp_id` appears in this list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoLogicalConnectionSlotsInd {
    pub tmp_ids: Vec<u32>,
}

impl NoLogicalConnectionSlotsInd {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() % 4 != 0 {
            return Err(FlicError::ProtocolViolation(format!(
                "NoLogicalConnectionSlotsInd payload length {} is not a multiple of 4",
                payload.len()
            )));
        }
        let tmp_ids = payload
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(Self { tmp_ids })
    }

    /// True iff the given `expected_tmp_id` appears in the list.
    #[must_use]
    pub fn affects_tmp_id(&self, expected_tmp_id: u32) -> bool {
        self.tmp_ids.contains(&expected_tmp_id)
    }
}

/// Opcode 3 (from button) — `FullVerifyFailResponse`. Unsigned.
///
/// Reason byte: 0 = `BAD_VERIFIER`, 1 = `NOT_PUBLIC_MODE`, etc. (per firmware).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullVerifyFailResponse {
    pub reason: u8,
}

impl FullVerifyFailResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.is_empty() {
            return Err(FlicError::ProtocolViolation(
                "FullVerifyFailResponse payload missing reason".into(),
            ));
        }
        Ok(Self { reason: payload[0] })
    }
}

/// Opcode 4 (from button) — `TestIfReallyUnpairedResponse`. Unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestIfReallyUnpairedResponse {
    pub result: [u8; 16],
}

impl TestIfReallyUnpairedResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 16 {
            return Err(FlicError::ProtocolViolation(format!(
                "TestIfReallyUnpairedResponse too short: {} bytes",
                payload.len()
            )));
        }
        let mut result = [0u8; 16];
        result.copy_from_slice(&payload[..16]);
        Ok(Self { result })
    }
}

/// Opcode 6 (from button) — `QuickVerifyNegativeResponse`. Unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuickVerifyNegativeResponse {
    pub tmp_id: u32,
}

impl QuickVerifyNegativeResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 4 {
            return Err(FlicError::ProtocolViolation(format!(
                "QuickVerifyNegativeResponse too short: {} bytes",
                payload.len()
            )));
        }
        Ok(Self {
            tmp_id: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        })
    }
}

/// Opcode 8 — `QuickVerifyResponse`. Signed (MAC already stripped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuickVerifyResponse {
    pub button_random: [u8; 8],
    pub tmp_id: u32,
    pub flags: u8,
}

impl QuickVerifyResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 13 {
            return Err(FlicError::ProtocolViolation(format!(
                "QuickVerifyResponse too short: {} bytes",
                payload.len()
            )));
        }
        let mut button_random = [0u8; 8];
        button_random.copy_from_slice(&payload[0..8]);
        let tmp_id = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let flags = payload[12];
        Ok(Self {
            button_random,
            tmp_id,
            flags,
        })
    }
}

/// Opcode 9 (from button) — `DisconnectedVerifiedLinkInd`. Signed.
///
/// Typed disconnect reason:
/// - 0 = PING_TIMEOUT
/// - 1 = INVALID_SIGNATURE
/// - 2 = STARTED_NEW_WITH_SAME_PAIRING_ID
/// - 3 = BY_USER
/// - other = reserved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisconnectedVerifiedLinkInd {
    pub reason: u8,
}

impl DisconnectedVerifiedLinkInd {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.is_empty() {
            return Err(FlicError::ProtocolViolation(
                "DisconnectedVerifiedLinkInd missing reason".into(),
            ));
        }
        Ok(Self { reason: payload[0] })
    }
}

/// Opcode 10 (from button) — `InitButtonEventsResponseWithBootId`. Signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitButtonEventsResponseWithBootId {
    pub has_queued_events: bool,
    pub timestamp_32k: u64, // 47 bits
    pub event_count: u32,
    pub boot_id: u32,
}

impl InitButtonEventsResponseWithBootId {
    /// Parses the payload. Layout: 48-bit packed (1 bit has_queued + 47 bits timestamp)
    /// || event_count(4) || boot_id(4) = 14 bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 14 {
            return Err(FlicError::ProtocolViolation(format!(
                "InitButtonEventsResponse too short: {} bytes",
                payload.len()
            )));
        }
        let mut packed_bytes = [0u8; 8];
        packed_bytes[..6].copy_from_slice(&payload[0..6]);
        let packed = u64::from_le_bytes(packed_bytes);
        let has_queued_events = (packed & 0x1) != 0;
        let timestamp_32k = (packed >> 1) & 0x7FFF_FFFF_FFFF;
        let event_count = u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let boot_id = u32::from_le_bytes([payload[10], payload[11], payload[12], payload[13]]);
        Ok(Self {
            has_queued_events,
            timestamp_32k,
            event_count,
            boot_id,
        })
    }
}

/// Opcode 11 (from button) — `InitButtonEventsResponseWithoutBootId`. Signed.
///
/// The button sends this variant when the `boot_id` we supplied in
/// `InitButtonEventsLightRequest` doesn't match its current boot_id — continuity
/// is lost and the caller should treat this as a fresh start. Identical layout
/// to opcode 10 minus the `boot_id` tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitButtonEventsResponseWithoutBootId {
    pub has_queued_events: bool,
    pub timestamp_32k: u64, // 47 bits
    pub event_count: u32,
}

impl InitButtonEventsResponseWithoutBootId {
    /// Parses the payload. Layout: 48-bit packed (1 bit has_queued + 47 bits timestamp)
    /// || event_count(4) = 10 bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 10 {
            return Err(FlicError::ProtocolViolation(format!(
                "InitButtonEventsResponseWithoutBootId too short: {} bytes",
                payload.len()
            )));
        }
        let mut packed_bytes = [0u8; 8];
        packed_bytes[..6].copy_from_slice(&payload[0..6]);
        let packed = u64::from_le_bytes(packed_bytes);
        let has_queued_events = (packed & 0x1) != 0;
        let timestamp_32k = (packed >> 1) & 0x7FFF_FFFF_FFFF;
        let event_count = u32::from_le_bytes([payload[6], payload[7], payload[8], payload[9]]);
        Ok(Self {
            has_queued_events,
            timestamp_32k,
            event_count,
        })
    }
}

/// A single button event slot inside a `ButtonEventNotification` (opcode 12).
/// 7 bytes: 48-bit timestamp + 4-bit event code + 2 flag bits + 2 rfu bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonEventSlot {
    pub timestamp_32k: u64, // 48 bits
    pub event_code: u8,     // 4 bits, 0..=15
    pub was_queued: bool,
    pub was_queued_last: bool,
}

impl ButtonEventSlot {
    pub const SLOT_SIZE: usize = 7;

    pub fn parse(slot: &[u8]) -> Result<Self, FlicError> {
        if slot.len() < Self::SLOT_SIZE {
            return Err(FlicError::ProtocolViolation(format!(
                "event slot too short: {} bytes",
                slot.len()
            )));
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes[..6].copy_from_slice(&slot[0..6]);
        let timestamp_32k = u64::from_le_bytes(ts_bytes) & 0xFFFF_FFFF_FFFF;
        let flags = slot[6];
        let event_code = flags & 0x0F;
        let was_queued = (flags & 0x10) != 0;
        let was_queued_last = (flags & 0x20) != 0;
        Ok(Self {
            timestamp_32k,
            event_code,
            was_queued,
            was_queued_last,
        })
    }
}

/// Opcode 12 (from button) — `ButtonEventNotification`. Signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ButtonEventNotification {
    pub event_count: u32,
    pub events: Vec<ButtonEventSlot>,
}

impl ButtonEventNotification {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 4 {
            return Err(FlicError::ProtocolViolation(format!(
                "ButtonEventNotification too short: {} bytes",
                payload.len()
            )));
        }
        let event_count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let rest = &payload[4..];
        let slots = rest.len() / ButtonEventSlot::SLOT_SIZE;
        let mut events = Vec::with_capacity(slots);
        for i in 0..slots {
            let start = i * ButtonEventSlot::SLOT_SIZE;
            events.push(ButtonEventSlot::parse(
                &rest[start..start + ButtonEventSlot::SLOT_SIZE],
            )?);
        }
        Ok(Self {
            event_count,
            events,
        })
    }
}

/// Opcode 20 (from button) — `GetBatteryLevelResponse`. Signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetBatteryLevelResponse {
    pub raw_adc: u16, // voltage_mv = raw_adc * 3600 / 1024
}

impl GetBatteryLevelResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, FlicError> {
        if payload.len() < 2 {
            return Err(FlicError::ProtocolViolation(format!(
                "GetBatteryLevelResponse too short: {} bytes",
                payload.len()
            )));
        }
        Ok(Self {
            raw_adc: u16::from_le_bytes([payload[0], payload[1]]),
        })
    }

    /// Converts the raw ADC reading to millivolts using Flic 2's fixed scale.
    #[must_use]
    pub fn voltage_mv(&self) -> u16 {
        ((u32::from(self.raw_adc) * 3600) / 1024) as u16
    }
}

/// Opcode 15 (from button) — `PingRequest`. Signed; no payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingRequest;

impl PingRequest {
    pub fn parse(_payload: &[u8]) -> Result<Self, FlicError> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_verify_request_1_round_trip_like() {
        let msg = FullVerifyRequest1 {
            tmp_id: 0xDEAD_BEEF,
        };
        let bytes = msg.write();
        assert_eq!(bytes, vec![0x00, 0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn full_verify_request_2_layout() {
        let msg = FullVerifyRequest2 {
            client_ecdh_pub: [0x11; 32],
            client_random: [0x22; 8],
            flags: 0x80,
            verifier: [0x33; 16],
        };
        let bytes = msg.write();
        assert_eq!(bytes[0], 2, "opcode");
        assert_eq!(&bytes[1..33], &[0x11; 32]);
        assert_eq!(&bytes[33..41], &[0x22; 8]);
        assert_eq!(bytes[41], 0x80);
        assert_eq!(&bytes[42..58], &[0x33; 16]);
    }

    #[test]
    fn quick_verify_request_layout() {
        let msg = QuickVerifyRequest {
            client_random: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7],
            flags: 0x40,
            tmp_id: 0x01020304,
            pairing_id: 0xCAFEBABE,
        };
        let bytes = msg.write();
        assert_eq!(bytes.len(), 1 + 7 + 1 + 4 + 4);
        assert_eq!(bytes[0], 5);
        assert_eq!(&bytes[1..8], &[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7]);
        assert_eq!(bytes[8], 0x40);
        assert_eq!(&bytes[9..13], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&bytes[13..17], &[0xBE, 0xBA, 0xFE, 0xCA]);
    }

    #[test]
    fn ack_button_events_layout() {
        let msg = AckButtonEventsInd {
            event_count: 0x1234_5678,
        };
        assert_eq!(msg.write(), vec![0x10, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn init_button_events_packs_bits() {
        let msg = InitButtonEventsLightRequest {
            event_count: 0,
            boot_id: 0,
            auto_disconnect_time: 511,       // 9 bits all 1
            max_queued_packets: 31,          // 5 bits all 1
            max_queued_packets_age: 0xFFFFF, // 20 bits all 1
        };
        let bytes = msg.write();
        assert_eq!(bytes.len(), 1 + 4 + 4 + 8);
        // 9 bits + 5 bits + 20 bits = 34 bits all 1 → 2^34 - 1 = 0x3_FFFF_FFFF.
        let mut packed_bytes = [0u8; 8];
        packed_bytes.copy_from_slice(&bytes[9..17]);
        let packed = u64::from_le_bytes(packed_bytes);
        assert_eq!(packed, 0x3_FFFF_FFFF);
    }

    #[test]
    fn full_verify_response_1_parses() {
        let mut payload = Vec::with_capacity(116);
        payload.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // tmp_id
        payload.extend_from_slice(&[0x11; 64]); // sig
        payload.extend_from_slice(&[0x22; 6]); // addr
        payload.push(0x01); // addr type
        payload.extend_from_slice(&[0x33; 32]); // ecdh pub
        payload.extend_from_slice(&[0x44; 8]); // device random
        payload.push(0xFF); // flags

        let parsed = FullVerifyResponse1::parse(&payload).expect("parse");
        assert_eq!(parsed.tmp_id, 0xDEAD_BEEF);
        assert_eq!(parsed.signature, [0x11; 64]);
        assert_eq!(parsed.button_address, [0x22; 6]);
        assert_eq!(parsed.address_type, 0x01);
        assert_eq!(parsed.button_ecdh_pub, [0x33; 32]);
        assert_eq!(parsed.device_random, [0x44; 8]);
        assert_eq!(parsed.flags, 0xFF);
    }

    #[test]
    fn quick_verify_response_parses() {
        let mut payload = Vec::with_capacity(13);
        payload.extend_from_slice(&[0xA5; 8]); // button_random
        payload.extend_from_slice(&0x1122_3344u32.to_le_bytes()); // tmp_id
        payload.push(0x80); // flags

        let parsed = QuickVerifyResponse::parse(&payload).expect("parse");
        assert_eq!(parsed.button_random, [0xA5; 8]);
        assert_eq!(parsed.tmp_id, 0x1122_3344);
        assert_eq!(parsed.flags, 0x80);
    }

    #[test]
    fn init_button_events_response_parses() {
        let mut payload = Vec::with_capacity(14);
        // 48-bit packed: has_queued=true, timestamp=0x3FF (just a small value)
        let packed: u64 = 1 | (0x3FFu64 << 1);
        payload.extend_from_slice(&packed.to_le_bytes()[..6]);
        payload.extend_from_slice(&0x0A0B0C0Du32.to_le_bytes()); // event_count
        payload.extend_from_slice(&0x1E1F2021u32.to_le_bytes()); // boot_id

        let parsed = InitButtonEventsResponseWithBootId::parse(&payload).expect("parse");
        assert!(parsed.has_queued_events);
        assert_eq!(parsed.timestamp_32k, 0x3FF);
        assert_eq!(parsed.event_count, 0x0A0B0C0D);
        assert_eq!(parsed.boot_id, 0x1E1F2021);
    }

    #[test]
    fn init_button_events_response_without_boot_id_parses() {
        // The button emits this variant when our supplied boot_id doesn't match
        // its current one — continuity is lost. Payload is identical to the
        // WithBootId variant minus the trailing boot_id field.
        let mut payload = Vec::with_capacity(10);
        let packed: u64 = 0x1234u64 << 1; // has_queued=false
        payload.extend_from_slice(&packed.to_le_bytes()[..6]);
        payload.extend_from_slice(&42u32.to_le_bytes());

        let parsed = InitButtonEventsResponseWithoutBootId::parse(&payload).expect("parse");
        assert!(!parsed.has_queued_events);
        assert_eq!(parsed.timestamp_32k, 0x1234);
        assert_eq!(parsed.event_count, 42);
    }

    #[test]
    fn init_button_events_response_without_boot_id_rejects_short_payload() {
        let short = [0u8; 9];
        let err = InitButtonEventsResponseWithoutBootId::parse(&short)
            .expect_err("must reject < 10 bytes");
        assert!(matches!(err, FlicError::ProtocolViolation(_)));
    }

    #[test]
    fn button_event_slot_parses() {
        // timestamp = 0x010203040506 (48 bits), code = 0xA (10),
        // was_queued = true (bit 4), was_queued_last = false.
        let slot = [
            0x06,
            0x05,
            0x04,
            0x03,
            0x02,
            0x01,        // 48-bit timestamp LE
            0b0001_1010, // flags: code=0xA, was_queued=1, was_queued_last=0
        ];
        let parsed = ButtonEventSlot::parse(&slot).expect("parse");
        assert_eq!(parsed.timestamp_32k, 0x0102_0304_0506);
        assert_eq!(parsed.event_code, 0xA);
        assert!(parsed.was_queued);
        assert!(!parsed.was_queued_last);
    }

    #[test]
    fn button_event_notification_multiple_events() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3u32.to_le_bytes()); // event_count
        for i in 0..3 {
            let mut slot = [0u8; 7];
            slot[0] = i as u8; // timestamp low byte
            slot[6] = 0x01; // code = 1 (Down)
            payload.extend_from_slice(&slot);
        }
        let parsed = ButtonEventNotification::parse(&payload).expect("parse");
        assert_eq!(parsed.event_count, 3);
        assert_eq!(parsed.events.len(), 3);
        assert_eq!(parsed.events[0].event_code, 1);
        assert_eq!(parsed.events[1].timestamp_32k, 1);
    }

    #[test]
    fn battery_level_voltage_conversion() {
        // raw 1024 → 3600 mV
        let full = GetBatteryLevelResponse { raw_adc: 1024 };
        assert_eq!(full.voltage_mv(), 3600);
        // raw 512 → 1800 mV
        let half = GetBatteryLevelResponse { raw_adc: 512 };
        assert_eq!(half.voltage_mv(), 1800);
    }

    #[test]
    fn test_if_really_unpaired_response_parses() {
        let payload = [0xAB; 16];
        let parsed = TestIfReallyUnpairedResponse::parse(&payload).expect("parse");
        assert_eq!(parsed.result, [0xAB; 16]);
    }

    #[test]
    fn disconnected_verified_link_ind_reason() {
        let parsed = DisconnectedVerifiedLinkInd::parse(&[3]).expect("parse");
        assert_eq!(parsed.reason, 3);
    }

    #[test]
    fn full_verify_fail_reason() {
        let parsed = FullVerifyFailResponse::parse(&[1]).expect("parse");
        assert_eq!(parsed.reason, 1);
    }

    fn full_verify_response_2_payload(flags: u8) -> Vec<u8> {
        let mut payload = Vec::with_capacity(58);
        payload.push(flags);
        payload.extend_from_slice(&[0x22; 16]); // uuid
        payload.push(0); // name_len
        payload.extend_from_slice(&[0u8; 23]); // name
        payload.extend_from_slice(&42u32.to_le_bytes()); // fw
        payload.extend_from_slice(&512u16.to_le_bytes()); // batt raw
        payload.extend_from_slice(b"BC00-A0001\0"); // 11 bytes, null-terminated
        payload
    }

    #[test]
    fn full_verify_response_2_flag_accessors() {
        let mut parsed =
            FullVerifyResponse2::parse(&full_verify_response_2_payload(0x01)).expect("parse");
        assert!(parsed.app_credentials_match());
        assert!(!parsed.cares_about_app_credentials());
        assert!(!parsed.is_duo());

        parsed =
            FullVerifyResponse2::parse(&full_verify_response_2_payload(0x06)).expect("parse");
        assert!(!parsed.app_credentials_match());
        assert!(parsed.cares_about_app_credentials());
        assert!(parsed.is_duo());

        parsed =
            FullVerifyResponse2::parse(&full_verify_response_2_payload(0x00)).expect("parse");
        assert!(!parsed.app_credentials_match());
    }

    #[test]
    fn credentials_rejected_only_when_cares_and_mismatch() {
        let cases: &[(u8, bool, &str)] = &[
            (0x00, false, "cares=0 match=0 — button doesn't enforce, no reject"),
            (0x01, false, "cares=0 match=1 — button doesn't enforce, no reject"),
            (0x02, true, "cares=1 match=0 — enforced mismatch, REJECT"),
            (0x03, false, "cares=1 match=1 — enforced and matched, no reject"),
            (0x06, true, "cares=1 match=0 is_duo=1 — duo also rejects on mismatch"),
            (0x07, false, "cares=1 match=1 is_duo=1 — duo ok"),
        ];
        for &(flags, expected, note) in cases {
            let parsed = FullVerifyResponse2::parse(&full_verify_response_2_payload(flags))
                .expect("parse");
            assert_eq!(parsed.credentials_rejected(), expected, "{note}");
        }
    }
}
