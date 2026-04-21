//! Flic 2 byte-level protocol: framing, fragmentation, typed messages.
//!
//! Two layers:
//!
//! - [`frame`] — control-byte header, fragment encoding, reassembly
//! - [`messages`] — typed structs for each opcode with parse + write
//!
//! Both layers are pure — no I/O, no async, no timing. The session state machine in
//! `crate::session` (TODO) orchestrates them.

pub mod frame;
pub mod messages;
