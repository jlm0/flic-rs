//! Frame encode/decode + fragment reassembly.
//!
//! Every Flic 2 packet on the wire is a single ATT payload framed as:
//!
//! ```text
//!  ┌──────────────┬────────┬─────────────┬─────────────────────┐
//!  │ Control byte │ Opcode │ Payload     │ 5-byte Chaskey MAC  │
//!  │ (1 byte)     │ (1 B)  │ (N bytes)   │ (optional)          │
//!  └──────────────┴────────┴─────────────┴─────────────────────┘
//! ```
//!
//! Control byte bit layout:
//!
//! | Bit | Field          | Meaning                                              |
//! | :-: | -------------- | ---------------------------------------------------- |
//! | 0-4 | conn_id        | Logical connection ID (server-assigned after step 1) |
//! |  5  | newly_assigned | 1 = this response assigns conn_id                    |
//! |  6  | multi_packet   | (unused in practice — reserved per spec)             |
//! |  7  | fragment_flag  | 1 = more fragments follow; 0 = last/only fragment    |
//!
//! pyflic-ble doesn't use bit 6 (multi_packet) and neither do we. Fragmentation is
//! signaled purely by bit 7.

use crate::constants::{frame as flags, FLIC_MAX_PACKET_SIZE, FLIC_SIGNATURE_SIZE};
use crate::error::FlicError;

/// A reassembled Flic frame, ready for the protocol handler to interpret.
///
/// `body` is `opcode || payload || optional_mac`. The caller decides whether to strip
/// a 5-byte MAC based on the opcode's signed/unsigned category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub conn_id: u8,
    pub newly_assigned: bool,
    pub body: Vec<u8>,
}

impl RawFrame {
    /// Returns the opcode (first byte of `body`).
    ///
    /// # Panics
    ///
    /// Panics if `body` is empty — a frame with zero bytes after the control byte is
    /// invalid and would have been rejected during parse/reassembly.
    #[must_use]
    pub fn opcode(&self) -> u8 {
        self.body[0]
    }

    /// Returns the payload (body with opcode stripped, MAC still attached if present).
    #[must_use]
    pub fn payload_with_mac(&self) -> &[u8] {
        &self.body[1..]
    }

    /// Splits the body into `(payload, mac)`. Assumes the frame is signed.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::ProtocolViolation`] if the body is shorter than
    /// `1 (opcode) + 5 (MAC)` = 6 bytes.
    pub fn split_signed(&self) -> Result<(&[u8], [u8; 5]), FlicError> {
        if self.body.len() < 1 + FLIC_SIGNATURE_SIZE {
            return Err(FlicError::ProtocolViolation(format!(
                "signed frame body too short: {} bytes",
                self.body.len()
            )));
        }
        let split = self.body.len() - FLIC_SIGNATURE_SIZE;
        let payload = &self.body[1..split];
        let mac_slice = &self.body[split..];
        let mut mac = [0u8; 5];
        mac.copy_from_slice(mac_slice);
        Ok((payload, mac))
    }

    /// Returns the payload (body with opcode stripped, no MAC assumed).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.body[1..]
    }
}

/// Encodes a logical frame into one or more ATT packets, fragmenting if necessary.
///
/// `body` is `opcode || payload || optional_mac` — already assembled and signed.
/// Returns a `Vec<Vec<u8>>` where each inner `Vec` is one packet to write onto the
/// write characteristic.
///
/// Fragmentation: if the body doesn't fit alongside the control byte within
/// [`FLIC_MAX_PACKET_SIZE`] (default 129 bytes per ATT packet), split into chunks.
/// The first N-1 fragments set [`FRAGMENT_FLAG`]; the last clears it. Each fragment
/// repeats the conn_id + newly_assigned bits in its control byte so the receiver
/// knows which logical connection they belong to.
///
/// Body size contract: per the Flic 2 base spec, a non-multipacket reassembled
/// frame (opcode + data + signature) must not exceed [`FLIC_MAX_PACKET_SIZE`]
/// bytes. Callers MUST NOT pass a `body` longer than that — larger frames
/// require the multipacket framing (control bit 6) which this crate does not
/// implement. The [`Reassembler`] enforces the same cap on the receive path.
///
/// [`FRAGMENT_FLAG`]: crate::constants::frame::FRAGMENT_FLAG
#[must_use]
pub fn encode_frame(conn_id: u8, newly_assigned: bool, body: &[u8]) -> Vec<Vec<u8>> {
    encode_frame_with_mtu(conn_id, newly_assigned, body, FLIC_MAX_PACKET_SIZE)
}

/// Same as [`encode_frame`] but with caller-chosen max packet size (for tests).
#[must_use]
pub fn encode_frame_with_mtu(
    conn_id: u8,
    newly_assigned: bool,
    body: &[u8],
    max_packet: usize,
) -> Vec<Vec<u8>> {
    assert!(
        max_packet >= 2,
        "max_packet must hold control byte + 1 body byte"
    );
    let base_control = (conn_id & flags::CONN_ID_MASK)
        | if newly_assigned {
            flags::NEWLY_ASSIGNED
        } else {
            0
        };

    if body.len() < max_packet {
        let mut packet = Vec::with_capacity(1 + body.len());
        packet.push(base_control);
        packet.extend_from_slice(body);
        return vec![packet];
    }

    let chunk_size = max_packet - 1;
    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let remaining = body.len() - offset;
        let take = remaining.min(chunk_size);
        let is_last = offset + take == body.len();
        let control = base_control | if is_last { 0 } else { flags::FRAGMENT_FLAG };
        let mut packet = Vec::with_capacity(1 + take);
        packet.push(control);
        packet.extend_from_slice(&body[offset..offset + take]);
        fragments.push(packet);
        offset += take;
    }
    fragments
}

/// Accumulates fragmented ATT packets into a complete [`RawFrame`].
///
/// Call [`Self::feed`] with each incoming packet. When the final fragment arrives
/// (FRAGMENT_FLAG cleared), it returns `Ok(Some(frame))`. Until then it returns
/// `Ok(None)`. Any protocol-level inconsistency (zero-length packet, stray "last"
/// fragment with no buffered predecessors but fragment_flag is *set*) produces an
/// error — the caller is expected to drop the session in that case.
#[derive(Debug, Default)]
pub struct Reassembler {
    buffer: Vec<u8>,
    expecting_more: bool,
    /// When receiving fragments, the control byte is taken from the *first* fragment.
    /// Subsequent fragments carry a control byte whose `fragment_flag` tells us whether
    /// to keep going or finalize.
    held_conn_id: u8,
    held_newly_assigned: bool,
}

impl Reassembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets any in-progress reassembly. Call on session teardown.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expecting_more = false;
        self.held_conn_id = 0;
        self.held_newly_assigned = false;
    }

    /// Feeds one incoming ATT packet.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::ProtocolViolation`] if the packet is empty, if its
    /// control byte sets the MULTI_PACKET bit (bit 6 — not implemented in this
    /// layer), or if fragment reassembly would exceed
    /// [`FLIC_MAX_PACKET_SIZE`] bytes of body (opcode + data + signature). An
    /// oversize reassembly resets the internal buffer to a clean state so the
    /// next frame can start fresh.
    pub fn feed(&mut self, packet: &[u8]) -> Result<Option<RawFrame>, FlicError> {
        if packet.is_empty() {
            return Err(FlicError::ProtocolViolation("empty packet".into()));
        }
        let control = packet[0];
        if (control & flags::MULTI_PACKET) != 0 {
            // Multipacket framing (bit 6) is optional per spec; we do not
            // implement it. Rejecting is required to avoid misinterpreting an
            // unsupported frame form as an ordinary fragment.
            self.reset();
            return Err(FlicError::ProtocolViolation(
                "multipacket framing (control bit 6) is not supported".into(),
            ));
        }
        let is_fragment = (control & flags::FRAGMENT_FLAG) != 0;
        let conn_id = control & flags::CONN_ID_MASK;
        let newly_assigned = (control & flags::NEWLY_ASSIGNED) != 0;
        let body = &packet[1..];

        if self.expecting_more {
            // Continuation fragment — append body regardless of control byte's conn_id
            // (the button echoes it but we use the first fragment's identity).
            if self.buffer.len() + body.len() > FLIC_MAX_PACKET_SIZE {
                self.reset();
                return Err(FlicError::ProtocolViolation(format!(
                    "reassembled frame body exceeds FLIC_MAX_PACKET_SIZE ({FLIC_MAX_PACKET_SIZE})"
                )));
            }
            self.buffer.extend_from_slice(body);
            if !is_fragment {
                let mut out_body = Vec::new();
                std::mem::swap(&mut out_body, &mut self.buffer);
                let frame = RawFrame {
                    conn_id: self.held_conn_id,
                    newly_assigned: self.held_newly_assigned,
                    body: out_body,
                };
                self.expecting_more = false;
                self.held_conn_id = 0;
                self.held_newly_assigned = false;
                return self.validate(frame).map(Some);
            }
            Ok(None)
        } else if is_fragment {
            if body.len() > FLIC_MAX_PACKET_SIZE {
                return Err(FlicError::ProtocolViolation(format!(
                    "first fragment body exceeds FLIC_MAX_PACKET_SIZE ({FLIC_MAX_PACKET_SIZE})"
                )));
            }
            self.held_conn_id = conn_id;
            self.held_newly_assigned = newly_assigned;
            self.buffer.clear();
            self.buffer.extend_from_slice(body);
            self.expecting_more = true;
            Ok(None)
        } else {
            if body.len() > FLIC_MAX_PACKET_SIZE {
                return Err(FlicError::ProtocolViolation(format!(
                    "single frame body exceeds FLIC_MAX_PACKET_SIZE ({FLIC_MAX_PACKET_SIZE})"
                )));
            }
            let frame = RawFrame {
                conn_id,
                newly_assigned,
                body: body.to_vec(),
            };
            self.validate(frame).map(Some)
        }
    }

    fn validate(&self, frame: RawFrame) -> Result<RawFrame, FlicError> {
        if frame.body.is_empty() {
            return Err(FlicError::ProtocolViolation(
                "frame with no body bytes (missing opcode)".into(),
            ));
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_packet_no_fragment() {
        let body = [0x08, 0xAA, 0xBB, 0xCC];
        let packets = encode_frame(0x03, false, &body);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], vec![0x03, 0x08, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn encode_sets_newly_assigned_bit() {
        let body = [0x00];
        let packets = encode_frame(0x07, true, &body);
        assert_eq!(packets[0][0], 0x27, "conn_id=7 + newly_assigned bit");
    }

    #[test]
    fn encode_conn_id_is_masked() {
        // Caller passes an out-of-range conn_id; we mask to bottom 5 bits.
        let body = [0x00];
        let packets = encode_frame(0xFF, false, &body);
        assert_eq!(packets[0][0], 0x1F, "conn_id mask to 5 bits");
    }

    #[test]
    fn encode_fragments_across_mtu() {
        // body is 6 bytes, max_packet is 3 → 1 ctrl byte + 2 data bytes per packet
        // 3 fragments expected, last one has fragment_flag cleared.
        let body = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let packets = encode_frame_with_mtu(0x02, false, &body, 3);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0], vec![0x82, 0x01, 0x02]); // fragment_flag set
        assert_eq!(packets[1], vec![0x82, 0x03, 0x04]); // fragment_flag set
        assert_eq!(packets[2], vec![0x02, 0x05, 0x06]); // fragment_flag cleared
    }

    #[test]
    fn reassemble_single_packet() {
        let mut r = Reassembler::new();
        let frame = r
            .feed(&[0x05, 0x17, 0xAA, 0xBB])
            .expect("ok")
            .expect("complete");
        assert_eq!(frame.conn_id, 5);
        assert!(!frame.newly_assigned);
        assert_eq!(frame.opcode(), 0x17);
        assert_eq!(frame.payload(), &[0xAA, 0xBB]);
    }

    #[test]
    fn reassemble_newly_assigned_bit() {
        let mut r = Reassembler::new();
        let frame = r.feed(&[0x25, 0x00]).expect("ok").expect("complete");
        assert_eq!(frame.conn_id, 5);
        assert!(frame.newly_assigned);
    }

    #[test]
    fn reassemble_multi_fragment_round_trip() {
        // Encode an 8-byte body across an mtu-4 channel, then reassemble.
        let body = [0x17, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00];
        let packets = encode_frame_with_mtu(0x09, true, &body, 4);
        assert!(packets.len() >= 2, "expected multi-fragment");

        let mut r = Reassembler::new();
        let mut got: Option<RawFrame> = None;
        for (i, pkt) in packets.iter().enumerate() {
            match r.feed(pkt).expect("ok") {
                None => assert!(i < packets.len() - 1, "None before the final fragment"),
                Some(f) => got = Some(f),
            }
        }
        let frame = got.expect("final fragment produces a frame");
        assert_eq!(frame.conn_id, 9);
        assert!(frame.newly_assigned);
        assert_eq!(frame.body, body);
    }

    #[test]
    fn reassemble_rejects_empty_packet() {
        let mut r = Reassembler::new();
        assert!(r.feed(&[]).is_err());
    }

    #[test]
    fn reassemble_rejects_body_with_only_control_byte() {
        let mut r = Reassembler::new();
        assert!(r.feed(&[0x00]).is_err());
    }

    #[test]
    fn split_signed_extracts_mac() {
        let frame = RawFrame {
            conn_id: 1,
            newly_assigned: false,
            body: vec![
                0x0C, // opcode
                0xDE, 0xAD, 0xBE, // payload
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // mac
            ],
        };
        let (payload, mac) = frame.split_signed().expect("ok");
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE]);
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn split_signed_too_short() {
        let frame = RawFrame {
            conn_id: 1,
            newly_assigned: false,
            body: vec![0x0C, 0xDE, 0xAD, 0xBE], // no room for 5-byte MAC
        };
        assert!(frame.split_signed().is_err());
    }

    #[test]
    fn reassemble_handles_max_legal_fragmented_body() {
        // A 125-byte body fragmented across a tiny per-packet MTU reassembles
        // back to the original. Proves the 129-byte cap does not reject
        // legitimate fragmented frames under the spec's non-multipacket limit.
        let body: Vec<u8> = (0..125u8).collect();
        let packets = encode_frame_with_mtu(0x03, false, &body, 50);
        assert!(
            packets.len() >= 2,
            "body=125 with mtu=50 should produce multiple fragments"
        );

        let mut r = Reassembler::new();
        let mut got: Option<RawFrame> = None;
        for pkt in &packets {
            if let Some(f) = r.feed(pkt).expect("ok") {
                got = Some(f);
            }
        }
        let frame = got.expect("reassembly must complete");
        assert_eq!(frame.body, body);
    }

    #[test]
    fn reassemble_rejects_multipacket_bit() {
        let mut r = Reassembler::new();
        // Control byte 0x40 = MULTI_PACKET set, no fragment, conn_id 0.
        let err = r
            .feed(&[0x40, 0x08, 0xAA])
            .expect_err("multipacket must be rejected");
        assert!(matches!(err, FlicError::ProtocolViolation(_)));
    }

    #[test]
    fn reassemble_rejects_oversized_continuation() {
        let mut r = Reassembler::new();
        // First fragment: 100 body bytes, fragment flag set, conn_id 1.
        let mut first = Vec::with_capacity(101);
        first.push(0x80 | 0x01); // fragment + conn_id=1
        first.extend(std::iter::repeat_n(0xAB, 100));
        assert!(r.feed(&first).expect("ok").is_none());

        // Second fragment: 50 body bytes — 100 + 50 = 150 > 129 cap.
        let mut second = Vec::with_capacity(51);
        second.push(0x01); // last fragment, conn_id=1
        second.extend(std::iter::repeat_n(0xCD, 50));
        let err = r
            .feed(&second)
            .expect_err("reassembly past cap must error");
        assert!(matches!(err, FlicError::ProtocolViolation(_)));
        // After overflow, the buffer should be reset so the next frame starts clean.
        assert!(!r.expecting_more);
        assert!(r.buffer.is_empty());
    }

    #[test]
    fn reassemble_rejects_oversized_single_frame() {
        let mut r = Reassembler::new();
        let mut pkt = Vec::with_capacity(1 + FLIC_MAX_PACKET_SIZE + 1);
        pkt.push(0x00); // not a fragment
        pkt.extend(std::iter::repeat_n(0xAA, FLIC_MAX_PACKET_SIZE + 1));
        let err = r.feed(&pkt).expect_err("oversize body must error");
        assert!(matches!(err, FlicError::ProtocolViolation(_)));
    }

    #[test]
    fn reset_clears_inflight_reassembly() {
        let mut r = Reassembler::new();
        let packets = encode_frame_with_mtu(1, false, &[0x01, 0x02, 0x03, 0x04], 3);
        r.feed(&packets[0]).expect("ok");
        assert!(r.expecting_more);
        r.reset();
        assert!(!r.expecting_more);
        assert!(r.buffer.is_empty());
    }
}
