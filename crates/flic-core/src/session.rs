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

use crate::constants::{Direction, OpcodeFromFlic, FLIC2_ED25519_PUBLIC_KEY};
use crate::crypto::{chaskey, ed25519, kdf, x25519};
use crate::error::FlicError;
use crate::events::{decode_press_kind, requires_ack, PressKind};
use crate::protocol::frame::{self, RawFrame, Reassembler};
use crate::protocol::messages::{
    AckButtonEventsInd, ButtonEventNotification, DisconnectVerifiedLinkInd,
    DisconnectedVerifiedLinkInd, FullVerifyFailResponse, FullVerifyRequest1, FullVerifyRequest2,
    FullVerifyResponse1, FullVerifyResponse2, InitButtonEventsLightRequest,
    InitButtonEventsResponseWithBootId, InitButtonEventsResponseWithoutBootId,
    NoLogicalConnectionSlotsInd, PingResponse, QuickVerifyNegativeResponse, QuickVerifyRequest,
    QuickVerifyResponse,
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
    /// Underlying BLE transport dropped the link. The caller supplies the
    /// `DisconnectReason` so subscribers see a single, correctly-classified
    /// `Disconnected` event (e.g. `PingTimeout` vs generic `BleTransport`).
    BleDisconnected { reason: DisconnectReason },
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

impl DisconnectReason {
    /// Whether a reconnect attempt could plausibly succeed after this kind of
    /// disconnect. `true` means "the pairing is still valid, just re-run
    /// QuickVerify"; `false` means either the user asked to stop, the pairing was
    /// invalidated, or the button told us something unrecoverable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            DisconnectReason::PingTimeout | DisconnectReason::BleTransport(_)
        )
    }
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

    /// Records the button's reported continuity from
    /// `InitButtonEventsResponseWithBootId`. Called once per QuickVerify.
    fn record_events_resumed(&mut self, event_count: u32, boot_id: u32) {
        self.event_resume = EventResumeState {
            event_count,
            boot_id,
        };
    }

    /// Advances the persisted event_count after we ACK a `ButtonEventNotification`.
    /// `boot_id` is invariant across a single session and is left untouched.
    fn record_acked_events(&mut self, last_ack_count: u32) {
        self.event_resume.event_count = last_ack_count;
    }

    /// Returns the event-continuity values the session currently knows about.
    /// Callers persist this across reconnects so the button can suppress events
    /// already delivered on a previous session.
    ///
    /// Returns `EventResumeState::default()` before any reconnect is started.
    /// Updated when `BeginReconnect` supplies resume values, when
    /// `InitButtonEventsResponseWithBootId` lands, and after each ACK we emit for
    /// a `ButtonEventNotification`.
    #[must_use]
    pub fn resume_state(&self) -> EventResumeState {
        self.event_resume
    }

    /// Apply an input and return the resulting actions.
    pub fn step(&mut self, input: SessionInput) -> Result<Vec<SessionAction>, FlicError> {
        match input {
            SessionInput::BeginPairing => self.begin_pairing(),
            SessionInput::BeginReconnect(creds, resume) => self.begin_reconnect(creds, resume),
            SessionInput::IncomingPacket(packet) => self.on_packet(&packet),
            SessionInput::UserDisconnect => self.on_user_disconnect(),
            SessionInput::BleDisconnected { reason } => {
                let mut actions = Vec::new();
                if self.state != State::Failed && self.state != State::Disconnected {
                    actions.push(SessionAction::Emit(SessionEvent::Disconnected { reason }));
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
        if op == OpcodeFromFlic::NoLogicalConnectionSlotsInd as u8 {
            // Valid in this state per the base spec. The indication only
            // terminates pairing if the listed tmp_ids include our session's.
            let ind = NoLogicalConnectionSlotsInd::parse(frame.payload())?;
            if !ind.affects_tmp_id(self.expected_tmp_id) {
                return Ok(Vec::new());
            }
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed("no_logical_connection_slots".into()),
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

        // FullVerifyResponse1 is the frame that assigns our logical connection
        // id. The base spec requires `newly_assigned` to be set here and the
        // assigned conn_id to be nonzero.
        if !frame.newly_assigned || frame.conn_id == 0 {
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(
                        "FullVerifyResponse1 missing newly_assigned or assigned conn_id=0".into(),
                    ),
                }),
                SessionAction::CloseSession,
            ]);
        }

        // Signed message shape: button_address || address_type || button_ecdh_pub.
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

        self.conn_id = frame.conn_id;

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
        if resp.credentials_rejected() {
            // The button both enforces app-credentials and told us our
            // credentials don't match. Per spec the session MUST terminate —
            // pairing credentials are the root of future reconnect identity,
            // and silently accepting a mismatch would break the handshake
            // contract. Buttons that don't enforce credentials (bit 1 = 0)
            // fall through unchanged; bit 0's value is not authoritative
            // then.
            self.state = State::Failed;
            self.pending_paired = None;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(
                        "app_credentials_match=0 with cares_about_app_credentials=1".into(),
                    ),
                }),
                SessionAction::CloseSession,
            ]);
        }
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
            let ind = NoLogicalConnectionSlotsInd::parse(frame.payload())?;
            if !ind.affects_tmp_id(self.expected_tmp_id) {
                return Ok(Vec::new());
            }
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed("no_logical_connection_slots".into()),
                }),
                SessionAction::CloseSession,
            ]);
        }
        if op == OpcodeFromFlic::QuickVerifyNegativeResponse as u8 {
            let neg = QuickVerifyNegativeResponse::parse(frame.payload())?;
            // Per spec, the negative response is only authoritative when its
            // tmp_id matches our session's tmp_id. Otherwise it is stale or
            // spoofed — drop it and keep waiting.
            if neg.tmp_id != self.expected_tmp_id {
                return Ok(Vec::new());
            }
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
        let resp = QuickVerifyResponse::parse(payload)?;

        // Drop packets that don't match our session's tmp_id before doing any
        // crypto: tmp-id matching is what binds this unauthenticated early
        // packet to this session.
        if resp.tmp_id != self.expected_tmp_id {
            return Ok(Vec::new());
        }

        // The positive response carries the logical connection assignment; if
        // it isn't marked `newly_assigned` the handshake is malformed.
        if !frame.newly_assigned {
            self.state = State::Failed;
            return Ok(vec![
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(
                        "QuickVerifyResponse without newly_assigned".into(),
                    ),
                }),
                SessionAction::CloseSession,
            ]);
        }

        // Derive session_key = Chaskey(pairing_key, client_random[7] || flags || button_random[8]).
        // The middle byte is the flags byte we sent in the QuickVerifyRequest — must match
        // bit-for-bit. We always send `supports_duo = 1` (0x40); keep the two in lockstep.
        let subkeys_from_pairing = chaskey::generate_subkeys(&creds.pairing_key);
        let mut block = [0u8; 16];
        block[..7].copy_from_slice(&client_random);
        block[7] = QUICK_VERIFY_FLAGS;
        block[8..].copy_from_slice(&resp.button_random);
        let session_key = chaskey::mac_16_bytes(&subkeys_from_pairing, &block);

        self.chaskey_subkeys = Some(chaskey::generate_subkeys(&session_key));
        self.counter_to_button = 0;
        self.counter_from_button = 0;

        self.verify_inbound_mac(op, payload, mac)?;

        self.conn_id = frame.conn_id;
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
        let (payload, mac) = frame.split_signed()?;
        self.verify_inbound_mac(op, payload, mac)?;

        let (event_count, boot_id, has_queued_events) =
            if op == OpcodeFromFlic::InitButtonEventsResponseWithBootId as u8 {
                let resp = InitButtonEventsResponseWithBootId::parse(payload)?;
                (resp.event_count, resp.boot_id, resp.has_queued_events)
            } else if op == OpcodeFromFlic::InitButtonEventsResponseWithoutBootId as u8 {
                // Continuity lost — our stored boot_id didn't match the device's.
                // Persist boot_id=0 so the next reconnect sends the "no prior
                // context" sentinel, letting the device re-establish continuity
                // cleanly via the WithBootId reply.
                let resp = InitButtonEventsResponseWithoutBootId::parse(payload)?;
                (resp.event_count, 0, resp.has_queued_events)
            } else {
                return self.unexpected_opcode(op);
            };

        self.counter_from_button = self.counter_from_button.wrapping_add(1);
        self.record_events_resumed(event_count, boot_id);
        self.state = State::SessionEstablished;
        Ok(vec![SessionAction::Emit(SessionEvent::EventsResumed {
            event_count,
            boot_id,
            has_queued_events,
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
            return self.handle_button_event_notification(&notif);
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

    /// Processes a parsed `ButtonEventNotification`, updating persistent resume
    /// state and (when required) emitting a signed `AckButtonEventsInd`.
    fn handle_button_event_notification(
        &mut self,
        notif: &ButtonEventNotification,
    ) -> Result<Vec<SessionAction>, FlicError> {
        let plan = plan_button_event_actions(notif);
        let mut actions: Vec<SessionAction> = plan
            .press_events
            .into_iter()
            .map(SessionAction::Emit)
            .collect();
        // Persist resume state on every notification — the base spec requires
        // storage to be updated with the packet's event_count after button
        // events are processed, regardless of whether we ACK.
        self.record_acked_events(notif.event_count);
        if plan.should_ack {
            // One ACK per notification. Per spec, the ACK's event_count is the
            // same value as the ButtonEventNotification's event_count (which
            // corresponds to the LAST event in the slot array — intermediate
            // counts are not sequential because hold/timeout events can be
            // skipped).
            let ack_body = AckButtonEventsInd {
                event_count: notif.event_count,
            }
            .write();
            let signed = self.sign_outbound(&ack_body)?;
            for pkt in frame::encode_frame(self.conn_id, false, &signed) {
                actions.push(SessionAction::WritePacket(pkt));
            }
        }
        Ok(actions)
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

    /// Test helper — force the session into `SessionEstablished` with a fixed
    /// chaskey subkey so handlers that sign outbound frames can run without
    /// completing the real handshake.
    #[cfg(test)]
    fn test_force_established(&mut self, pairing_key: [u8; 16]) {
        self.state = State::SessionEstablished;
        self.chaskey_subkeys = Some(crate::crypto::chaskey::generate_subkeys(&pairing_key));
        self.counter_to_button = 0;
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

/// Pure decision over a `ButtonEventNotification`.
///
/// Returns the `ButtonPressed` emissions the session should surface and whether
/// the notification needs an ACK. Per the Flic 2 base spec:
///
/// - Only one ACK per notification, regardless of how many slots are carried.
/// - The ACK's `event_count` is the notification's `event_count` — which per
///   the spec corresponds to the **last** event in the array. Hold and
///   single-click-timeout events may be skipped, so intermediate event counts
///   cannot be derived from slot index.
/// - The ACK fires only if at least one slot carries an event code listed in
///   [`requires_ack`] (2, 10, 11, 14).
struct ButtonEventPlan {
    press_events: Vec<SessionEvent>,
    should_ack: bool,
}

fn plan_button_event_actions(notif: &ButtonEventNotification) -> ButtonEventPlan {
    let press_events = notif
        .events
        .iter()
        .map(|slot| SessionEvent::ButtonPressed {
            kind: decode_press_kind(slot.event_code),
            timestamp_32k: slot.timestamp_32k,
            was_queued: slot.was_queued,
        })
        .collect();
    let should_ack = notif.events.iter().any(|s| requires_ack(s.event_code));
    ButtonEventPlan {
        press_events,
        should_ack,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let pid = u32::from_le_bytes([pkt[14], pkt[15], pkt[16], pkt[17]]);
        assert_eq!(pid, 0xDEAD_BEEF);
    }

    #[test]
    fn user_disconnect_before_session_just_emits() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let actions = sess.step(SessionInput::UserDisconnect).expect("ok");
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
            .step(SessionInput::BleDisconnected {
                reason: DisconnectReason::BleTransport("adapter_off".into()),
            })
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
    fn ble_disconnected_carries_ping_timeout_reason_through_to_emit() {
        // When drive_loop decides the link is dead due to inactivity, it passes
        // DisconnectReason::PingTimeout into the session. The session must emit
        // that exact reason — NOT downgrade it to BleTransport — so subscribers
        // see a single Disconnected event with the correct classification.
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let actions = sess
            .step(SessionInput::BleDisconnected {
                reason: DisconnectReason::PingTimeout,
            })
            .expect("ok");
        assert!(matches!(
            actions[0],
            SessionAction::Emit(SessionEvent::Disconnected {
                reason: DisconnectReason::PingTimeout
            })
        ));
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
    fn resume_state_defaults_to_zero_before_reconnect() {
        let sess = Session::new();
        let state = sess.resume_state();
        assert_eq!(state.event_count, 0);
        assert_eq!(state.boot_id, 0);
    }

    #[test]
    fn resume_state_reflects_values_supplied_on_begin_reconnect() {
        let mut sess = Session::new();
        let creds = PairingCredentials {
            pairing_id: 0x1234_5678,
            pairing_key: [0x11; 16],
            serial_number: "BC00-A00001".into(),
            button_uuid: [0x22; 16],
            firmware_version: 7,
        };
        let resume = EventResumeState {
            event_count: 147,
            boot_id: 3,
        };
        sess.step(SessionInput::BeginReconnect(creds, resume))
            .expect("ok");
        let state = sess.resume_state();
        assert_eq!(state.event_count, 147);
        assert_eq!(state.boot_id, 3);
    }

    #[test]
    fn record_events_resumed_updates_resume_state() {
        let mut sess = Session::new();
        sess.record_events_resumed(1024, 7);
        let state = sess.resume_state();
        assert_eq!(state.event_count, 1024);
        assert_eq!(state.boot_id, 7);
    }

    #[test]
    fn record_acked_events_advances_count_keeps_boot_id() {
        let mut sess = Session::new();
        sess.record_events_resumed(500, 2);
        sess.record_acked_events(503);
        let state = sess.resume_state();
        assert_eq!(state.event_count, 503);
        assert_eq!(state.boot_id, 2, "boot_id is fixed for the session");
    }

    #[test]
    fn record_acked_events_before_resume_still_works() {
        let mut sess = Session::new();
        sess.record_acked_events(42);
        let state = sess.resume_state();
        assert_eq!(state.event_count, 42);
        assert_eq!(state.boot_id, 0);
    }

    fn slot(event_code: u8) -> crate::protocol::messages::ButtonEventSlot {
        crate::protocol::messages::ButtonEventSlot {
            timestamp_32k: 0,
            event_code,
            was_queued: false,
            was_queued_last: false,
        }
    }

    #[test]
    fn plan_button_events_multi_slot_two_ack_worthy_sends_one_ack() {
        // Two ACK-worthy events (code 2 = SingleClick) plus one raw Down (code 1).
        // Spec: one ACK per notification, value is the packet's event_count,
        // NOT slot-index-derived.
        let notif = ButtonEventNotification {
            event_count: 987,
            events: vec![slot(1), slot(2), slot(2)],
        };
        let plan = plan_button_event_actions(&notif);
        assert_eq!(plan.press_events.len(), 3);
        assert!(
            plan.should_ack,
            "any slot with an ACK-worthy code requires ACK"
        );
    }

    #[test]
    fn plan_button_events_only_down_does_not_require_ack() {
        let notif = ButtonEventNotification {
            event_count: 42,
            events: vec![slot(1), slot(1)],
        };
        let plan = plan_button_event_actions(&notif);
        assert_eq!(plan.press_events.len(), 2);
        assert!(
            !plan.should_ack,
            "plain Down events are intermediate and never ACKed"
        );
    }

    #[test]
    fn plan_button_events_hold_code_3_does_not_require_ack() {
        // Regression against the prior implementation that included code 3.
        let notif = ButtonEventNotification {
            event_count: 10,
            events: vec![slot(3)],
        };
        let plan = plan_button_event_actions(&notif);
        assert!(!plan.should_ack, "plain Hold (code 3) is not ACKed");
    }

    #[test]
    fn plan_button_events_up_after_hold_code_14_requires_ack() {
        // UpAfterHold (code 14) has type=0 (up) and single-click bit set,
        // matching the base-spec ACK condition.
        let notif = ButtonEventNotification {
            event_count: 1,
            events: vec![slot(14)],
        };
        let plan = plan_button_event_actions(&notif);
        assert!(plan.should_ack);
    }

    #[test]
    fn button_event_ack_uses_packet_event_count_not_slot_index() {
        let mut sess = Session::new();
        sess.test_force_established([0xAA; 16]);
        let notif = ButtonEventNotification {
            event_count: 987,
            events: vec![slot(2), slot(2), slot(2)],
        };
        let actions = sess.handle_button_event_notification(&notif).expect("ok");

        // Three ButtonPressed emits + exactly one AckButtonEventsInd write.
        let writes: Vec<&Vec<u8>> = actions
            .iter()
            .filter_map(|a| match a {
                SessionAction::WritePacket(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(writes.len(), 1, "exactly one ACK packet per notification");
        let ack = writes[0];
        // ack layout: [ctrl(1), opcode(1), event_count(4 LE), mac(5)] = 11 bytes
        assert_eq!(ack.len(), 11);
        assert_eq!(ack[1], AckButtonEventsInd::OPCODE);
        let ack_count = u32::from_le_bytes([ack[2], ack[3], ack[4], ack[5]]);
        assert_eq!(
            ack_count, 987,
            "ACK carries the packet's event_count, not a slot-derived value"
        );
    }

    #[test]
    fn button_event_resume_state_advances_even_without_ack() {
        // Notification full of Down events — no ACK, but storage must advance
        // so a reconnect does not replay events the host already saw.
        let mut sess = Session::new();
        sess.test_force_established([0xBB; 16]);
        sess.record_events_resumed(100, 7); // prior state

        let notif = ButtonEventNotification {
            event_count: 150,
            events: vec![slot(1), slot(1), slot(1)],
        };
        let actions = sess.handle_button_event_notification(&notif).expect("ok");

        let writes = actions
            .iter()
            .filter(|a| matches!(a, SessionAction::WritePacket(_)))
            .count();
        assert_eq!(writes, 0, "Down-only notifications do not ACK");

        let resume = sess.resume_state();
        assert_eq!(resume.event_count, 150, "resume state advances without ACK");
        assert_eq!(resume.boot_id, 7, "boot_id is invariant across notifications");
    }

    /// Build a FullVerifyResponse1 incoming packet with the given `tmp_id` and
    /// control flags. Signature/crypto payloads are arbitrary bytes; tests
    /// using this helper rely on the session failing the newly_assigned /
    /// conn_id check before Ed25519 verification runs.
    fn full_verify_response_1_packet(
        tmp_id: u32,
        conn_id: u8,
        newly_assigned: bool,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(1 + 1 + 116);
        let ctrl = (conn_id & 0x1F) | if newly_assigned { 0x20 } else { 0x00 };
        pkt.push(ctrl);
        pkt.push(OpcodeFromFlic::FullVerifyResponse1 as u8);
        pkt.extend_from_slice(&tmp_id.to_le_bytes()); // 4
        pkt.extend_from_slice(&[0u8; 64]); // signature
        pkt.extend_from_slice(&[0u8; 6]); // addr
        pkt.push(0); // addr type
        pkt.extend_from_slice(&[0u8; 32]); // ecdh
        pkt.extend_from_slice(&[0u8; 8]); // device_random
        pkt.push(0); // flags
        pkt
    }

    fn no_logical_connection_slots_packet(tmp_ids: &[u32]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(1 + 1 + tmp_ids.len() * 4);
        pkt.push(0x00);
        pkt.push(OpcodeFromFlic::NoLogicalConnectionSlotsInd as u8);
        for id in tmp_ids {
            pkt.extend_from_slice(&id.to_le_bytes());
        }
        pkt
    }

    #[test]
    fn full_verify_1_without_newly_assigned_fails_handshake() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let tmp = sess.expected_tmp_id;
        // conn_id=1 but newly_assigned=false → must fail.
        let pkt = full_verify_response_1_packet(tmp, 1, false);
        let actions = sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert_eq!(sess.state_name(), "Failed");
        let ok = actions.iter().any(|a| {
            matches!(
                a,
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(_),
                })
            )
        });
        assert!(ok);
    }

    #[test]
    fn full_verify_1_with_zero_conn_id_fails_handshake() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let tmp = sess.expected_tmp_id;
        // conn_id=0 with newly_assigned set → still invalid per spec.
        let pkt = full_verify_response_1_packet(tmp, 0, true);
        sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert_eq!(sess.state_name(), "Failed");
    }

    #[test]
    fn full_verify_1_no_logical_connection_slots_with_matching_tmp_id_fails() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let tmp = sess.expected_tmp_id;
        let pkt = no_logical_connection_slots_packet(&[0xDEAD_BEEF, tmp, 0x1234]);
        sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert_eq!(sess.state_name(), "Failed");
    }

    #[test]
    fn full_verify_1_no_logical_connection_slots_without_matching_tmp_id_is_ignored() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginPairing).expect("ok");
        let tmp = sess.expected_tmp_id;
        // A list not containing our tmp_id → ignore.
        let other = tmp.wrapping_add(1);
        let pkt = no_logical_connection_slots_packet(&[other, other.wrapping_add(7)]);
        let actions = sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert!(actions.is_empty());
        assert_eq!(sess.state_name(), "WaitFullVerify1");
    }

    fn test_creds() -> PairingCredentials {
        PairingCredentials {
            pairing_id: 0xCAFE_BABE,
            pairing_key: [0x11; 16],
            serial_number: "BC00-A00001".into(),
            button_uuid: [0x22; 16],
            firmware_version: 7,
        }
    }

    /// Build an incoming QuickVerifyResponse packet with the given tmp_id and
    /// newly_assigned flag. MAC bytes are arbitrary — tests that rely on this
    /// helper are expected to fail the tmp_id or newly_assigned check BEFORE
    /// any MAC verification runs.
    fn quick_verify_positive_packet(tmp_id: u32, newly_assigned: bool) -> Vec<u8> {
        let mut pkt = Vec::new();
        let ctrl = if newly_assigned { 0x20 } else { 0x00 };
        pkt.push(ctrl);
        pkt.push(OpcodeFromFlic::QuickVerifyResponse as u8);
        pkt.extend_from_slice(&[0xAA; 8]); // button_random
        pkt.extend_from_slice(&tmp_id.to_le_bytes());
        pkt.push(0x40); // flags
        pkt.extend_from_slice(&[0u8; 5]); // mac placeholder
        pkt
    }

    fn quick_verify_negative_packet(tmp_id: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push(0x00);
        pkt.push(OpcodeFromFlic::QuickVerifyNegativeResponse as u8);
        pkt.extend_from_slice(&tmp_id.to_le_bytes());
        pkt
    }

    #[test]
    fn quick_verify_positive_with_mismatched_tmp_id_is_ignored() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginReconnect(
            test_creds(),
            EventResumeState::default(),
        ))
        .expect("ok");
        assert_eq!(sess.state_name(), "WaitQuickVerify");
        let expected = sess.expected_tmp_id;

        // Use a tmp_id that cannot equal the session's (flip all bits).
        let spoof = quick_verify_positive_packet(!expected, true);
        let actions = sess.step(SessionInput::IncomingPacket(spoof)).expect("ok");
        assert!(
            actions.is_empty(),
            "mismatched tmp_id must not produce any actions"
        );
        assert_eq!(
            sess.state_name(),
            "WaitQuickVerify",
            "state must not transition on spoofed positive"
        );
    }

    #[test]
    fn quick_verify_negative_with_mismatched_tmp_id_is_ignored() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginReconnect(
            test_creds(),
            EventResumeState::default(),
        ))
        .expect("ok");
        let expected = sess.expected_tmp_id;
        let spoof = quick_verify_negative_packet(!expected);
        let actions = sess.step(SessionInput::IncomingPacket(spoof)).expect("ok");
        assert!(actions.is_empty());
        assert_eq!(sess.state_name(), "WaitQuickVerify");
    }

    #[test]
    fn quick_verify_negative_with_matching_tmp_id_terminates_session() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginReconnect(
            test_creds(),
            EventResumeState::default(),
        ))
        .expect("ok");
        let expected = sess.expected_tmp_id;
        let pkt = quick_verify_negative_packet(expected);
        let actions = sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, SessionAction::CloseSession)),
            "matching negative must close"
        );
        assert_eq!(sess.state_name(), "Failed");
    }

    #[test]
    fn quick_verify_positive_without_newly_assigned_fails_handshake() {
        let mut sess = Session::new();
        sess.step(SessionInput::BeginReconnect(
            test_creds(),
            EventResumeState::default(),
        ))
        .expect("ok");
        let expected = sess.expected_tmp_id;
        let pkt = quick_verify_positive_packet(expected, false);
        let actions = sess.step(SessionInput::IncomingPacket(pkt)).expect("ok");
        assert_eq!(sess.state_name(), "Failed");
        let has_handshake_fail = actions.iter().any(|a| {
            matches!(
                a,
                SessionAction::Emit(SessionEvent::Disconnected {
                    reason: DisconnectReason::HandshakeFailed(_),
                })
            )
        });
        assert!(has_handshake_fail, "missing newly_assigned must fail");
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
