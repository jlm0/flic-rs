//! Pure session state machine for the Flic 2 protocol.
//!
//! A [`Session`] ingests [`SessionInput`]s (commands from the user, packets from the
//! button, timer ticks, transport-level disconnects) and emits [`SessionAction`]s
//! (packets to write, high-level events to surface, terminal signals). It performs no
//! I/O and knows nothing about BLE — the transport layer drives it.
//!
//! The state machine covers:
//!
//! - FullVerify pairing (ops 0, 2, 1, 3)
//! - QuickVerify reconnect (ops 5, 8, 6)
//! - Post-session arming (op 23) and event continuity
//! - Steady state: PING/PONG (ops 15, 14), ButtonEvent + ACK (ops 12, 16)
//! - Clean disconnect (ops 9)
//!
//! `TestIfReallyUnpaired` (op 4) is surfaced as a `HandshakeFailed` error for now —
//! the client can retry pairing. A future slice may add automatic unpair-confirmation.

#![allow(clippy::too_many_lines)]

use rand::rngs::OsRng;
use rand::RngCore;

use crate::constants::{Direction, OpcodeFromFlic, OpcodeToFlic, FLIC2_ED25519_PUBLIC_KEY};
use crate::crypto::{chaskey, ed25519, kdf, x25519};
use crate::error::FlicError;
use crate::events::{decode_press_kind, requires_ack, PressKind};
use crate::protocol::frame::{self, RawFrame, Reassembler};
use crate::protocol::messages::{
    AckButtonEventsInd, ButtonEventNotification, DisconnectVerifiedLinkInd,
    DisconnectedVerifiedLinkInd, FullVerifyFailResponse, FullVerifyRequest1, FullVerifyRequest2,
    FullVerifyResponse1, FullVerifyResponse2, InitButtonEventsLightRequest,
    InitButtonEventsResponseWithBootId, NoLogicalConnectionSlotsInd, PingResponse,
    QuickVerifyNegativeResponse, QuickVerifyRequest, QuickVerifyResponse,
};

/// QuickVerify flags byte: supports_duo=1 (0x40). Sent in `QuickVerifyRequest.flags`
/// and also used as the middle byte of the session-key derivation input block —
/// the two MUST stay in lockstep or the button's MAC won't verify.
const QUICK_VERIFY_FLAGS: u8 = 0x40;

/// Persistent identity material for a paired Flic button. Caller serializes + stores.
#[derive(Debug, Clone)]
pub struct PairingCredentials {
    pub pairing_id: u32,
    pub pairing_key: [u8; 16],
    pub serial_number: String,
    pub button_uuid: [u8; 16],
    pub firmware_version: u32,
}

/// Event-delivery continuity state. Callers persist this across connects.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventResumeState {
    pub event_count: u32,
    pub boot_id: u32,
}

/// Inputs the session reacts to.
#[derive(Debug)]
pub enum SessionInput {
    /// Kick off FullVerify against a button in Public Mode.
    BeginPairing,
    /// Kick off QuickVerify using previously-saved credentials.
    BeginReconnect(PairingCredentials, EventResumeState),
    /// A notification/indication from the button (one ATT packet, including control byte).
    IncomingPacket(Vec<u8>),
    /// Caller requested a clean disconnect.
    UserDisconnect,
    /// Underlying BLE transport dropped the link.
    BleDisconnected(String),
}

/// High-level events surfaced to the caller.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// FullVerifyResponse2 processed; persistable credentials are now available.
    Paired(PairingCredentials),
    /// Session is usable — battery + firmware reported by the button.
    Connected {
        battery_voltage_mv: u16,
        firmware_version: u32,
    },
    /// `InitButtonEventsResponse` received — caller must persist continuity values.
    EventsResumed {
        event_count: u32,
        boot_id: u32,
        has_queued_events: bool,
    },
    /// A decoded button event.
    ButtonPressed {
        kind: PressKind,
        timestamp_32k: u64,
        was_queued: bool,
    },
    /// Session ended (cleanly or due to an error). No more events after this.
    Disconnected { reason: DisconnectReason },
}

/// Why the session ended.
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    PingTimeout,
    InvalidSignature,
    StartedNewWithSamePairingId,
    ByUser,
    BleTransport(String),
    HandshakeFailed(String),
    UnknownFromButton(u8),
}

/// Effectful actions the session wants the transport to perform.
#[derive(Debug, Clone)]
pub enum SessionAction {
    /// Write this packet on the Flic write characteristic.
    WritePacket(Vec<u8>),
    /// Surface this high-level event to the caller.
    Emit(SessionEvent),
    /// Session has reached a terminal state — transport should close the link and
    /// stop delivering packets.
    CloseSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Disconnected,
    WaitFullVerify1,
    WaitFullVerify2,
    WaitQuickVerify,
    InitEvents,
    SessionEstablished,
    Failed,
}

/// The pure session state machine.
pub struct Session {
    state: State,
    conn_id: u8,

    // Session key + counters after handshake completes.
    chaskey_subkeys: Option<[u32; 12]>,
    counter_to_button: u64,
    counter_from_button: u64,

    // Reassembly of incoming frames (handles fragmentation).
    reassembler: Reassembler,

    // FullVerify scratch — only valid between BeginPairing and SessionEstablished.
    client_keypair: Option<x25519::Keypair>,
    client_random_8: Option<[u8; 8]>,
    expected_tmp_id: u32,

    // QuickVerify scratch.
    reconnect_creds: Option<PairingCredentials>,
    client_random_7: Option<[u8; 7]>,

    // Event continuity supplied on reconnect.
    event_resume: EventResumeState,

    // Cached metadata from FullVerifyResponse2 (populated during pair, used when
    // emitting Paired).
    pending_paired: Option<PairingCredentials>,
}

impl Session {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Disconnected,
            conn_id: 0,
            chaskey_subkeys: None,
            counter_to_button: 0,
            counter_from_button: 0,
            reassembler: Reassembler::new(),
            client_keypair: None,
            client_random_8: None,
            expected_tmp_id: 0,
            reconnect_creds: None,
            client_random_7: None,
            event_resume: EventResumeState::default(),
            pending_paired: None,
        }
    }

    /// Apply an input and return the resulting actions.
    pub fn step(&mut self, input: SessionInput) -> Result<Vec<SessionAction>, FlicError> {
        match input {
            SessionInput::BeginPairing => self.begin_pairing(),
            SessionInput::BeginReconnect(creds, resume) => self.begin_reconnect(creds, resume),
            SessionInput::IncomingPacket(packet) => self.on_packet(&packet),
            SessionInput::UserDisconnect => self.on_user_disconnect(),
            SessionInput::BleDisconnected(reason) => {
                let mut actions = Vec::new();
                if self.state != State::Failed && self.state != State::Disconnected {
                    actions.push(SessionAction::Emit(SessionEvent::Disconnected {
                        reason: DisconnectReason::BleTransport(reason),
                    }));
                }
                self.state = State::Failed;
                actions.push(SessionAction::CloseSession);
                Ok(actions)
            }
        }
    }

    fn begin_pairing(&mut self) -> Result<Vec<SessionAction>, FlicError> {
        let tmp_id = random_u32();
        self.expected_tmp_id = tmp_id;
        self.state = State::WaitFullVerify1;
        self.conn_id = 0;

        let body = FullVerifyRequest1 { tmp_id }.write();
        Ok(vec![SessionAction::WritePacket(
            frame::encode_frame(0, false, &body).remove(0),
        )])
    }

    fn begin_reconnect(
        &mut self,
        creds: PairingCredentials,
        resume: EventResumeState,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let tmp_id = random_u32();
        self.expected_tmp_id = tmp_id;
        let mut client_random = [0u8; 7];
        OsRng.fill_bytes(&mut client_random);
        self.client_random_7 = Some(client_random);
        self.event_resume = resume;
        self.state = State::WaitQuickVerify;
        self.conn_id = 0;

        let body = QuickVerifyRequest {
            client_random,
            flags: QUICK_VERIFY_FLAGS,
            tmp_id,
            pairing_id: creds.pairing_id,
        }
        .write();

        self.reconnect_creds = Some(creds);
        Ok(vec![SessionAction::WritePacket(
            frame::encode_frame(0, false, &body).remove(0),
        )])
    }

    fn on_user_disconnect(&mut self) -> Result<Vec<SessionAction>, FlicError> {
        let mut actions = Vec::new();
        if self.state == State::SessionEstablished {
            // Send DISCONNECT_VERIFIED_LINK_IND (signed).
            let body = DisconnectVerifiedLinkInd.write();
            let signed = self.sign_outbound(&body)?;
            for pkt in frame::encode_frame(self.conn_id, false, &signed) {
                actions.push(SessionAction::WritePacket(pkt));
            }
        }
        actions.push(SessionAction::Emit(SessionEvent::Disconnected {
            reason: DisconnectReason::ByUser,
        }));
        actions.push(SessionAction::CloseSession);
        self.state = State::Failed;
        Ok(actions)
    }

    fn on_packet(&mut self, packet: &[u8]) -> Result<Vec<SessionAction>, FlicError> {
        let Some(frame) = self.reassembler.feed(packet)? else {
            return Ok(Vec::new());
        };
        match self.state {
            State::WaitFullVerify1 => self.handle_full_verify_response_1(&frame),
            State::WaitFullVerify2 => self.handle_full_verify_response_2(&frame),
            State::WaitQuickVerify => self.handle_quick_verify_response(&frame),
            State::InitEvents => self.handle_init_events_response(&frame),
            State::SessionEstablished => self.handle_established(&frame),
            _ => Err(FlicError::ProtocolViolation(format!(
                "packet received in state {:?}",
                self.state
            ))),
        }
    }

    // ----- FullVerify -----

    fn handle_full_verify_response_1(
        &mut self,
        frame: &RawFrame,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let op = frame.opcode();
        if op == OpcodeFromFlic::FullVerifyFailResponse as u8 {
            let reason = FullVerifyFailResponse::parse(frame.payload())?.reason;
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(format!(
                        "full_verify_fail(reason={reason})"
                    )),
                }),
                SessionAction::CloseSession,
            ]);
        }
        if op != OpcodeFromFlic::FullVerifyResponse1 as u8 {
            return self.unexpected_opcode(op);
        }
        let resp = FullVerifyResponse1::parse(frame.payload())?;
        if resp.tmp_id != self.expected_tmp_id {
            return Err(FlicError::ProtocolViolation(
                "FullVerifyResponse1 tmp_id mismatch".into(),
            ));
        }

        // Verify Ed25519 signature over button_address || address_type || button_ecdh_pub.
        let mut signed_data = [0u8; 39];
        signed_data[..6].copy_from_slice(&resp.button_address);
        signed_data[6] = resp.address_type;
        signed_data[7..].copy_from_slice(&resp.button_ecdh_pub);

        let Some(variant) =
            ed25519::verify_with_variant(&FLIC2_ED25519_PUBLIC_KEY, &signed_data, &resp.signature)
        else {
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(
                        "Ed25519 signature did not verify under any variant".into(),
                    ),
                }),
                SessionAction::CloseSession,
            ]);
        };

        // Record newly-assigned conn_id.
        if frame.newly_assigned {
            self.conn_id = frame.conn_id;
        }

        // Derive keys.
        let keypair = x25519::Keypair::generate();
        let shared_secret = keypair.diffie_hellman(&resp.button_ecdh_pub);
        let mut client_random = [0u8; 8];
        OsRng.fill_bytes(&mut client_random);

        let keys = kdf::derive_full_verify_keys(
            &shared_secret,
            variant,
            &resp.device_random,
            &client_random,
            false,
        );

        self.chaskey_subkeys = Some(chaskey::generate_subkeys(&keys.session_key));
        self.client_keypair = Some(keypair);
        self.client_random_8 = Some(client_random);
        self.counter_to_button = 0;
        self.counter_from_button = 0;

        // Stash partial credentials; we need FullVerifyResponse2 for serial/uuid/fw.
        self.pending_paired = Some(PairingCredentials {
            pairing_id: keys.pairing_id,
            pairing_key: keys.pairing_key,
            serial_number: String::new(),
            button_uuid: [0u8; 16],
            firmware_version: 0,
        });

        let req2 = FullVerifyRequest2 {
            client_ecdh_pub: self.client_keypair.as_ref().unwrap().public(),
            client_random,
            flags: 0x80, // supports_duo
            verifier: keys.verifier,
        };
        let body = req2.write();
        self.state = State::WaitFullVerify2;
        Ok(vec![SessionAction::WritePacket(
            frame::encode_frame(self.conn_id, false, &body).remove(0),
        )])
    }

    fn handle_full_verify_response_2(
        &mut self,
        frame: &RawFrame,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let op = frame.opcode();
        if op == OpcodeFromFlic::FullVerifyFailResponse as u8 {
            let reason = FullVerifyFailResponse::parse(frame.payload())?.reason;
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(format!(
                        "full_verify_fail_2(reason={reason})"
                    )),
                }),
                SessionAction::CloseSession,
            ]);
        }
        if op != OpcodeFromFlic::FullVerifyResponse2 as u8 {
            return self.unexpected_opcode(op);
        }

        let (payload, mac) = frame.split_signed()?;
        self.verify_inbound_mac(op, payload, mac)?;

        let resp = FullVerifyResponse2::parse(payload)?;
        let Some(mut creds) = self.pending_paired.take() else {
            return Err(FlicError::ProtocolViolation(
                "FullVerifyResponse2 without pending credentials".into(),
            ));
        };
        creds.serial_number = resp.serial_number.clone();
        creds.button_uuid = resp.button_uuid;
        creds.firmware_version = resp.firmware_version;

        self.counter_from_button = self.counter_from_button.wrapping_add(1);

        let battery_mv = (u32::from(resp.battery_level_raw) * 3600 / 1024) as u16;

        let mut actions = vec![
            SessionAction::Emit(SessionEvent::Paired(creds)),
            SessionAction::Emit(SessionEvent::Connected {
                battery_voltage_mv: battery_mv,
                firmware_version: resp.firmware_version,
            }),
        ];

        actions.extend(self.send_init_events()?);
        self.state = State::InitEvents;
        Ok(actions)
    }

    // ----- QuickVerify -----

    fn handle_quick_verify_response(
        &mut self,
        frame: &RawFrame,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let op = frame.opcode();
        if op == OpcodeFromFlic::NoLogicalConnectionSlotsInd as u8 {
            let _ = NoLogicalConnectionSlotsInd::parse(frame.payload())?;
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed("no_logical_connection_slots".into()),
                }),
                SessionAction::CloseSession,
            ]);
        }
        if op == OpcodeFromFlic::QuickVerifyNegativeResponse as u8 {
            let _ = QuickVerifyNegativeResponse::parse(frame.payload())?;
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed("quick_verify_negative".into()),
                }),
                SessionAction::CloseSession,
            ]);
        }
        if op != OpcodeFromFlic::QuickVerifyResponse as u8 {
            return self.unexpected_opcode(op);
        }

        let Some(creds) = self.reconnect_creds.as_ref() else {
            return Err(FlicError::ProtocolViolation(
                "QuickVerifyResponse without stored credentials".into(),
            ));
        };
        let Some(client_random) = self.client_random_7 else {
            return Err(FlicError::ProtocolViolation(
                "QuickVerifyResponse without client random".into(),
            ));
        };

        let (payload, mac) = frame.split_signed()?;

        // Derive session_key = Chaskey(pairing_key, client_random[7] || flags || button_random[8]).
        // The middle byte is the flags byte we sent in the QuickVerifyRequest — must match
        // bit-for-bit. We always send `supports_duo = 1` (0x40); keep the two in lockstep.
        let subkeys_from_pairing = chaskey::generate_subkeys(&creds.pairing_key);
        let resp = QuickVerifyResponse::parse(payload)?;
        let mut block = [0u8; 16];
        block[..7].copy_from_slice(&client_random);
        block[7] = QUICK_VERIFY_FLAGS;
        block[8..].copy_from_slice(&resp.button_random);
        let session_key = chaskey::mac_16_bytes(&subkeys_from_pairing, &block);

        self.chaskey_subkeys = Some(chaskey::generate_subkeys(&session_key));
        self.counter_to_button = 0;
        self.counter_from_button = 0;

        // Verify MAC.
        self.verify_inbound_mac(op, payload, mac)?;

        if frame.newly_assigned {
            self.conn_id = frame.conn_id;
        }

        self.counter_from_button = self.counter_from_button.wrapping_add(1);

        let mut actions = Vec::new();
        actions.extend(self.send_init_events()?);
        self.state = State::InitEvents;
        Ok(actions)
    }

    // ----- InitEvents -----

    fn send_init_events(&mut self) -> Result<Vec<SessionAction>, FlicError> {
        let req = InitButtonEventsLightRequest {
            event_count: self.event_resume.event_count,
            boot_id: self.event_resume.boot_id,
            auto_disconnect_time: 511,           // disabled
            max_queued_packets: 31,              // unlimited
            max_queued_packets_age: 0x000F_FFFF, // unlimited
        };
        let body = req.write();
        let signed = self.sign_outbound(&body)?;
        Ok(frame::encode_frame(self.conn_id, false, &signed)
            .into_iter()
            .map(SessionAction::WritePacket)
            .collect())
    }

    fn handle_init_events_response(
        &mut self,
        frame: &RawFrame,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let op = frame.opcode();
        if op != OpcodeFromFlic::InitButtonEventsResponseWithBootId as u8 {
            return self.unexpected_opcode(op);
        }
        let (payload, mac) = frame.split_signed()?;
        self.verify_inbound_mac(op, payload, mac)?;
        let resp = InitButtonEventsResponseWithBootId::parse(payload)?;
        self.counter_from_button = self.counter_from_button.wrapping_add(1);
        self.state = State::SessionEstablished;
        Ok(vec![SessionAction::Emit(SessionEvent::EventsResumed {
            event_count: resp.event_count,
            boot_id: resp.boot_id,
            has_queued_events: resp.has_queued_events,
        })])
    }

    // ----- Steady state -----

    fn handle_established(&mut self, frame: &RawFrame) -> Result<Vec<SessionAction>, FlicError> {
        let op = frame.opcode();
        let (payload, mac) = frame.split_signed()?;
        self.verify_inbound_mac(op, payload, mac)?;
        self.counter_from_button = self.counter_from_button.wrapping_add(1);

        if op == OpcodeFromFlic::PingRequest as u8 {
            let body = PingResponse.write();
            let signed = self.sign_outbound(&body)?;
            return Ok(frame::encode_frame(self.conn_id, false, &signed)
                .into_iter()
                .map(SessionAction::WritePacket)
                .collect());
        }
        if op == OpcodeFromFlic::ButtonEventNotification as u8 {
            let notif = ButtonEventNotification::parse(payload)?;
            let mut actions = Vec::new();
            let mut last_ack_count: Option<u32> = None;
            let base_count = notif.event_count;
            for (i, slot) in notif.events.iter().enumerate() {
                let kind = decode_press_kind(slot.event_code);
                actions.push(SessionAction::Emit(SessionEvent::ButtonPressed {
                    kind,
                    timestamp_32k: slot.timestamp_32k,
                    was_queued: slot.was_queued,
                }));
                if requires_ack(slot.event_code) {
                    // The final event_count in the notification is for the last event;
                    // we assume sequential numbering for intermediate events.
                    last_ack_count = Some(base_count.wrapping_add(i as u32));
                }
            }
            if let Some(count) = last_ack_count {
                let ack_body = AckButtonEventsInd { event_count: count }.write();
                let signed = self.sign_outbound(&ack_body)?;
                for pkt in frame::encode_frame(self.conn_id, false, &signed) {
                    actions.push(SessionAction::WritePacket(pkt));
                }
            }
            return Ok(actions);
        }
        if op == OpcodeFromFlic::DisconnectedVerifiedLinkInd as u8 {
            let resp = DisconnectedVerifiedLinkInd::parse(payload)?;
            self.state = State::Failed;
            let reason = match resp.reason {
                0 => DisconnectReason::PingTimeout,
                1 => DisconnectReason::InvalidSignature,
                2 => DisconnectReason::StartedNewWithSamePairingId,
                3 => DisconnectReason::ByUser,
                r => DisconnectReason::UnknownFromButton(r),
            };
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected { reason }),
                SessionAction::CloseSession,
            ]);
        }

        // Unknown/unhandled opcode in steady state — log and continue (don't drop
        // the session for opcodes we didn't implement).
        tracing::debug!(opcode = op, "unhandled opcode in SessionEstablished");
        Ok(Vec::new())
    }

    // ----- helpers -----

    fn sign_outbound(&mut self, body: &[u8]) -> Result<Vec<u8>, FlicError> {
        let keys = self
            .chaskey_subkeys
            .as_ref()
            .ok_or(FlicError::Crypto("no session key available"))?;
        let mac = chaskey::mac_with_dir_and_counter(
            keys,
            Direction::ToButton as u8,
            self.counter_to_button,
            body,
        );
        self.counter_to_button = self.counter_to_button.wrapping_add(1);
        let mut out = Vec::with_capacity(body.len() + mac.len());
        out.extend_from_slice(body);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    fn verify_inbound_mac(
        &self,
        opcode: u8,
        payload: &[u8],
        mac: [u8; 5],
    ) -> Result<(), FlicError> {
        let keys = self
            .chaskey_subkeys
            .as_ref()
            .ok_or(FlicError::Crypto("no session key available"))?;
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(opcode);
        mac_input.extend_from_slice(payload);
        let expected = chaskey::mac_with_dir_and_counter(
            keys,
            Direction::FromButton as u8,
            self.counter_from_button,
            &mac_input,
        );
        if expected != mac {
            return Err(FlicError::InvalidMac);
        }
        Ok(())
    }

    fn unexpected_opcode(&mut self, op: u8) -> Result<Vec<SessionAction>, FlicError> {
        self.state = State::Failed;
        Ok(vec![
            SessionAction::Emit(SessionEvent::Disconnected {
                reason: DisconnectReason::HandshakeFailed(format!(
                    "unexpected opcode 0x{op:02X} in state {:?}",
                    self.state
                )),
            }),
            SessionAction::CloseSession,
        ])
    }

    /// Test helper — peek at the current state name.
    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match self.state {
            State::Disconnected => "Disconnected",
            State::WaitFullVerify1 => "WaitFullVerify1",
            State::WaitFullVerify2 => "WaitFullVerify2",
            State::WaitQuickVerify => "WaitQuickVerify",
            State::InitEvents => "InitEvents",
            State::SessionEstablished => "SessionEstablished",
            State::Failed => "Failed",
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

// Suppress Direction dead-code warning for the OpcodeToFlic import used in
// constants but not (yet) directly here.
#[allow(dead_code)]
fn _opcode_to_flic_keep_alive() -> u8 {
    OpcodeToFlic::PingResponse as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    // The state machine's happy-path flows require multi-step orchestration against
    // fake button responses. These tests ensure the initial transitions are correct
    // and that the first packet off the wire is well-formed. Full handshake
    // integration tests require either real hardware or a simulator (planned for
    // a later slice).

    #[test]
    fn begin_pairing_emits_full_verify_request_1() {
        let mut sess = Session::new();
        let actions = sess.step(SessionInput::BeginPairing).expect("ok");
        assert_eq!(sess.state_name(), "WaitFullVerify1");
        assert_eq!(actions.len(), 1);
        let SessionAction::WritePacket(pkt) = &actions[0] else {
            panic!("expected WritePacket");
        };
        assert_eq!(pkt.len(), 1 + 1 + 4, "ctrl + opcode + tmp_id");
        assert_eq!(pkt[0] & crate::constants::frame::CONN_ID_MASK, 0);
        assert!(pkt[0] & crate::constants::frame::FRAGMENT_FLAG == 0);
        assert_eq!(pkt[1], FullVerifyRequest1::OPCODE);
    }

    #[test]
    fn begin_reconnect_emits_quick_verify_request() {
        let mut sess = Session::new();
        let creds = PairingCredentials {
            pairing_id: 0xDEAD_BEEF,
            pairing_key: [0xAA; 16],
            serial_number: "BC00-A00001".into(),
            button_uuid: [0xBB; 16],
            firmware_version: 42,
        };
        let actions = sess
            .step(SessionInput::BeginReconnect(
                creds,
                EventResumeState::default(),
            ))
            .expect("ok");
        assert_eq!(sess.state_name(), "WaitQuickVerify");
        let SessionAction::WritePacket(pkt) = &actions[0] else {
            panic!("expected WritePacket");
        };
        assert_eq!(
            pkt.len(),
            1 + 1 + 7 + 1 + 4 + 4,
            "ctrl + opcode + 7b random + flags + tmp_id + pairing_id"
        );
        assert_eq!(pkt[1], QuickVerifyRequest::OPCODE);
        // Layout: ctrl(1) + opcode(1) + random(7) + flags(1) + tmp_id(4) + pairing_id(4)
        let pid = u32::from_le_bytes([pkt[14], pkt[15], pkt[16], pkt[17]]);
        assert_eq!(pid, 0xDEAD_BEEF);
    }

    #[test]
    fn user_disconnect_before_session_just_emits() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let actions = sess.step(SessionInput::UserDisconnect).expect("ok");
        // Two actions: Emit(Disconnected), CloseSession (no signed frame without
        // a session key).
        assert!(matches!(
            actions[0],
            SessionAction::Emit(SessionEvent::Disconnected {
                reason: DisconnectReason::ByUser
            })
        ));
        assert!(matches!(actions[1], SessionAction::CloseSession));
        assert_eq!(sess.state_name(), "Failed");
    }

    #[test]
    fn ble_transport_drop_closes_session() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let actions = sess
            .step(SessionInput::BleDisconnected("adapter_off".into()))
            .expect("ok");
        assert!(matches!(
            actions[0],
            SessionAction::Emit(SessionEvent::Disconnected {
                reason: DisconnectReason::BleTransport(_)
            })
        ));
        assert!(matches!(actions[1], SessionAction::CloseSession));
    }

    #[test]
    fn unsolicited_packet_in_disconnected_state_is_protocol_error() {
        let mut sess = Session::new();
        let err = sess
            .step(SessionInput::IncomingPacket(vec![0x00, 0x00]))
            .expect_err("should error");
        assert!(matches!(err, FlicError::ProtocolViolation(_)));
    }

    #[test]
    fn is_retryable_classifies_every_disconnect_reason() {
        // Transient link-layer problems — the button is still ours, just re-handshake.
        assert!(DisconnectReason::PingTimeout.is_retryable());
        assert!(DisconnectReason::BleTransport("adapter_off".into()).is_retryable());

        // Terminal — either the pairing is gone (InvalidSignature,
        // StartedNewWithSamePairingId) or the user/firmware said no (ByUser,
        // HandshakeFailed, UnknownFromButton). Retrying would burn battery without
        // a chance of success.
        assert!(!DisconnectReason::InvalidSignature.is_retryable());
        assert!(!DisconnectReason::StartedNewWithSamePairingId.is_retryable());
        assert!(!DisconnectReason::ByUser.is_retryable());
        assert!(!DisconnectReason::HandshakeFailed("quick_verify_negative".into()).is_retryable());
        assert!(!DisconnectReason::UnknownFromButton(99).is_retryable());
    }
}
