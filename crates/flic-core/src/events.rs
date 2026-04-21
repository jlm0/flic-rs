//! Button event decoding. The 4-bit `event_encoded` field from each
//! `ButtonEventNotification` slot maps to a protocol-level [`PressKind`] here.
//!
//! The Flic 2 firmware emits eight distinct event codes (0, 1, 2, 3, 8, 10, 11, 14).
//! Codes 4–7, 9, 12, 13, 15 are reserved — observing one is a protocol violation from
//! the button. We report those as [`PressKind::Unknown`] rather than silently dropping
//! them so the higher layers can log and investigate.

use crate::protocol::messages::ButtonEventSlot;

/// Every distinct button event the Flic 2 protocol can emit.
///
/// The mapping from the 4-bit `event_encoded` field is fixed and documented in the
/// Flic 2 protocol wiki plus pyflic-ble's `handlers/flic2.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressKind {
    /// Raw release with no click context (code 0).
    Up,
    /// Raw press (code 1).
    Down,
    /// Single-click confirmed, usually by timeout waiting for a second press (code 2).
    /// Code 10 also maps here — it's the release that confirmed a single-click.
    SingleClick,
    /// Double-click confirmed on release (code 11).
    DoubleClick,
    /// Button held ≥ ~1s — emitted on the hold threshold crossing (code 3).
    Hold,
    /// The release after a hold (code 14).
    UpAfterHold,
    /// Release while the button is still deciding between single and double click
    /// (codes 8 and 15). Intermediate; usually followed by a confirming 10/11/2.
    ClickPending,
    /// Reserved / unknown wire code — surfaced for diagnostics.
    Unknown,
}

/// Decodes the raw 4-bit event code into a typed [`PressKind`].
///
/// # Panics
///
/// Panics if `code > 0x0F`. Callers are expected to mask the encoded field.
#[must_use]
pub fn decode_press_kind(code: u8) -> PressKind {
    assert!(code < 16, "event code is 4-bit; {code} is out of range");
    match code {
        0 => PressKind::Up,
        1 => PressKind::Down,
        2 | 10 => PressKind::SingleClick,
        3 => PressKind::Hold,
        8 | 15 => PressKind::ClickPending,
        11 => PressKind::DoubleClick,
        14 => PressKind::UpAfterHold,
        _ => PressKind::Unknown,
    }
}

/// Whether an event code requires a subsequent `AckButtonEventsInd` to prevent replay.
///
/// Per the Flic 2 spec: events that indicate a *decision* (SingleClick, DoubleClick,
/// UpAfterHold, Hold) are stored in the button's queue and must be acknowledged. Raw
/// down/up events aren't queued. `ClickPending` is intermediate — no ack.
#[must_use]
pub fn requires_ack(code: u8) -> bool {
    matches!(code, 2 | 3 | 10 | 11 | 14)
}

/// Convenience: decode a whole slot into a `(PressKind, u64)` tuple.
#[must_use]
pub fn decode_slot(slot: &ButtonEventSlot) -> (PressKind, u64) {
    (decode_press_kind(slot.event_code), slot.timestamp_32k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_16_codes_decode() {
        assert_eq!(decode_press_kind(0), PressKind::Up);
        assert_eq!(decode_press_kind(1), PressKind::Down);
        assert_eq!(decode_press_kind(2), PressKind::SingleClick);
        assert_eq!(decode_press_kind(3), PressKind::Hold);
        assert_eq!(decode_press_kind(8), PressKind::ClickPending);
        assert_eq!(decode_press_kind(10), PressKind::SingleClick);
        assert_eq!(decode_press_kind(11), PressKind::DoubleClick);
        assert_eq!(decode_press_kind(14), PressKind::UpAfterHold);
        assert_eq!(decode_press_kind(15), PressKind::ClickPending);

        for code in [4, 5, 6, 7, 9, 12, 13] {
            assert_eq!(
                decode_press_kind(code),
                PressKind::Unknown,
                "reserved code {code} must map to Unknown",
            );
        }
    }

    #[test]
    fn ack_rules() {
        for code in [2, 3, 10, 11, 14] {
            assert!(requires_ack(code), "code {code} must require ack");
        }
        for code in [0, 1, 4, 5, 6, 7, 8, 9, 12, 13, 15] {
            assert!(!requires_ack(code), "code {code} must not require ack");
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn decode_panics_on_out_of_range() {
        let _ = decode_press_kind(16);
    }
}
