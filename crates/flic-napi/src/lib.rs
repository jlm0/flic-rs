//! `flic-napi` — Node.js bindings for `flic-core`.
//!
//! The binding stays deliberately thin. Rust exposes primitives (commands +
//! a typed event stream); the Node/Electron host owns all product policy
//! (press → action mapping, arming, persistence location).

#![deny(clippy::all)]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use flic_core::manager::{FlicEvent as CoreFlicEvent, ReconnectingHandle};
use flic_core::{
    AdapterState as CoreAdapterState, DisconnectReason as CoreDisconnectReason,
    EventResumeState as CoreEventResumeState, FlicError, FlicManager as CoreFlicManager,
    PairingCredentials as CorePairingCredentials, PressKind as CorePressKind, ReconnectPolicy,
};
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{
    ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use napi::JsFunction;
use napi_derive::napi;

/// Current binding version. Smoke-test probe; harmless to keep in the release surface.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Power state of the BLE adapter, as reported by the OS.
///
/// `Unknown` is a transient state macOS emits during power transitions —
/// callers should treat it as "try anyway" rather than a hard error.
#[napi(string_enum)]
pub enum AdapterState {
    PoweredOn,
    PoweredOff,
    Unknown,
}

impl From<CoreAdapterState> for AdapterState {
    fn from(s: CoreAdapterState) -> Self {
        match s {
            CoreAdapterState::PoweredOn => Self::PoweredOn,
            CoreAdapterState::PoweredOff => Self::PoweredOff,
            CoreAdapterState::Unknown => Self::Unknown,
        }
    }
}

/// A Flic peripheral discovered by a scan. `id` is the opaque platform identifier;
/// pass it back into `pair()` / `connect()` as-is.
#[napi(object)]
pub struct Discovery {
    pub id: String,
    pub local_name: Option<String>,
    pub rssi: Option<i32>,
}

/// Persistent identity material for a paired Flic. Hand this back to `connect()`
/// on subsequent sessions. Persistence location is the host's responsibility —
/// the binding never touches disk.
///
/// `pairingKeyHex` and `buttonUuidHex` are 32-char (16-byte) lowercase hex.
#[napi(object)]
pub struct PairingCredentials {
    pub pairing_id: u32,
    pub pairing_key_hex: String,
    pub serial_number: String,
    pub button_uuid_hex: String,
    pub firmware_version: u32,
}

impl PairingCredentials {
    fn from_core(c: CorePairingCredentials) -> Self {
        Self {
            pairing_id: c.pairing_id,
            pairing_key_hex: hex_encode(&c.pairing_key),
            serial_number: c.serial_number,
            button_uuid_hex: hex_encode(&c.button_uuid),
            firmware_version: c.firmware_version,
        }
    }

    fn to_core(&self) -> Result<CorePairingCredentials> {
        let pairing_key = hex_decode_fixed::<16>(&self.pairing_key_hex)
            .ok_or_else(|| Error::new(Status::InvalidArg, "pairingKeyHex must be 32 hex chars"))?;
        let button_uuid = hex_decode_fixed::<16>(&self.button_uuid_hex)
            .ok_or_else(|| Error::new(Status::InvalidArg, "buttonUuidHex must be 32 hex chars"))?;
        Ok(CorePairingCredentials {
            pairing_id: self.pairing_id,
            pairing_key,
            serial_number: self.serial_number.clone(),
            button_uuid,
            firmware_version: self.firmware_version,
        })
    }
}

/// Event-delivery continuity state. The host persists this alongside the
/// `PairingCredentials` and passes it back on every `connect()`. Use `{
/// eventCount: 0, bootId: 0 }` for a fresh paired button.
#[napi(object)]
pub struct EventResumeState {
    pub event_count: u32,
    pub boot_id: u32,
}

impl EventResumeState {
    fn from_core(s: CoreEventResumeState) -> Self {
        Self {
            event_count: s.event_count,
            boot_id: s.boot_id,
        }
    }
    fn to_core(&self) -> CoreEventResumeState {
        CoreEventResumeState {
            event_count: self.event_count,
            boot_id: self.boot_id,
        }
    }
}

/// How a button press was classified by the Flic firmware.
#[napi(string_enum)]
pub enum PressKind {
    Up,
    Down,
    SingleClick,
    DoubleClick,
    Hold,
    UpAfterHold,
    ClickPending,
    Unknown,
}

impl From<CorePressKind> for PressKind {
    fn from(k: CorePressKind) -> Self {
        match k {
            CorePressKind::Up => Self::Up,
            CorePressKind::Down => Self::Down,
            CorePressKind::SingleClick => Self::SingleClick,
            CorePressKind::DoubleClick => Self::DoubleClick,
            CorePressKind::Hold => Self::Hold,
            CorePressKind::UpAfterHold => Self::UpAfterHold,
            CorePressKind::ClickPending => Self::ClickPending,
            CorePressKind::Unknown => Self::Unknown,
        }
    }
}

/// Why a session ended. `kind` is the stable discriminant; `message` and
/// `opcode` carry context for specific variants (see comments below).
#[napi(object)]
pub struct DisconnectReason {
    /// One of: `"pingTimeout"`, `"invalidSignature"`,
    /// `"startedNewWithSamePairingId"`, `"byUser"`, `"bleTransport"`,
    /// `"handshakeFailed"`, `"unknownFromButton"`.
    pub kind: String,
    /// Present on `bleTransport` + `handshakeFailed` — diagnostic text only.
    pub message: Option<String>,
    /// Present on `unknownFromButton` — the wire-level opcode the button sent.
    pub opcode: Option<u32>,
}

impl From<CoreDisconnectReason> for DisconnectReason {
    fn from(r: CoreDisconnectReason) -> Self {
        match r {
            CoreDisconnectReason::PingTimeout => Self {
                kind: "pingTimeout".into(),
                message: None,
                opcode: None,
            },
            CoreDisconnectReason::InvalidSignature => Self {
                kind: "invalidSignature".into(),
                message: None,
                opcode: None,
            },
            CoreDisconnectReason::StartedNewWithSamePairingId => Self {
                kind: "startedNewWithSamePairingId".into(),
                message: None,
                opcode: None,
            },
            CoreDisconnectReason::ByUser => Self {
                kind: "byUser".into(),
                message: None,
                opcode: None,
            },
            CoreDisconnectReason::BleTransport(m) => Self {
                kind: "bleTransport".into(),
                message: Some(m),
                opcode: None,
            },
            CoreDisconnectReason::HandshakeFailed(m) => Self {
                kind: "handshakeFailed".into(),
                message: Some(m),
                opcode: None,
            },
            CoreDisconnectReason::UnknownFromButton(op) => Self {
                kind: "unknownFromButton".into(),
                message: None,
                opcode: Some(u32::from(op)),
            },
        }
    }
}

/// An event from the flic subsystem. `kind` discriminates; the remaining
/// fields are payload-bearing per variant (see below).
///
/// - `"connected"`: `peripheralId`, `batteryMv`, `firmware`
/// - `"press"`: `peripheralId`, `pressKind`, `timestamp32k`, `wasQueued`
/// - `"eventsResumed"`: `peripheralId`, `eventCount`, `bootId`, `hasQueued`
/// - `"disconnected"`: `peripheralId`, `reason`
/// - `"reconnecting"`: `peripheralId`, `attempt`, `afterMs`, `lastReason`
/// - `"adapterUnavailable"`: `peripheralId`
#[napi(object)]
pub struct FlicEvent {
    pub kind: String,
    pub peripheral_id: String,
    pub battery_mv: Option<u32>,
    pub firmware: Option<u32>,
    pub press_kind: Option<PressKind>,
    /// 32.768 kHz timer on the button. Value is a JS number (f64) — precision
    /// is safe for all practical session durations.
    pub timestamp32k: Option<f64>,
    pub was_queued: Option<bool>,
    pub event_count: Option<u32>,
    pub boot_id: Option<u32>,
    pub has_queued: Option<bool>,
    pub reason: Option<DisconnectReason>,
    pub attempt: Option<u32>,
    pub after_ms: Option<u32>,
    pub last_reason: Option<DisconnectReason>,
}

impl FlicEvent {
    fn from_core(ev: CoreFlicEvent) -> Self {
        match ev {
            CoreFlicEvent::Connected {
                id,
                battery_voltage_mv,
                firmware_version,
            } => Self {
                kind: "connected".into(),
                peripheral_id: id,
                battery_mv: Some(u32::from(battery_voltage_mv)),
                firmware: Some(firmware_version),
                ..empty()
            },
            CoreFlicEvent::ButtonPressed {
                id,
                kind,
                timestamp_32k,
                was_queued,
            } => Self {
                kind: "press".into(),
                peripheral_id: id,
                press_kind: Some(kind.into()),
                timestamp32k: Some(timestamp_32k as f64),
                was_queued: Some(was_queued),
                ..empty()
            },
            CoreFlicEvent::EventsResumed {
                id,
                event_count,
                boot_id,
                has_queued_events,
            } => Self {
                kind: "eventsResumed".into(),
                peripheral_id: id,
                event_count: Some(event_count),
                boot_id: Some(boot_id),
                has_queued: Some(has_queued_events),
                ..empty()
            },
            CoreFlicEvent::Disconnected { id, reason } => Self {
                kind: "disconnected".into(),
                peripheral_id: id,
                reason: Some(reason.into()),
                ..empty()
            },
            CoreFlicEvent::Reconnecting {
                id,
                attempt,
                after_millis,
                last_reason,
            } => Self {
                kind: "reconnecting".into(),
                peripheral_id: id,
                attempt: Some(attempt),
                after_ms: Some(u32::try_from(after_millis).unwrap_or(u32::MAX)),
                last_reason: Some(last_reason.into()),
                ..empty()
            },
            CoreFlicEvent::AdapterUnavailable { id } => Self {
                kind: "adapterUnavailable".into(),
                peripheral_id: id,
                ..empty()
            },
        }
    }
}

fn empty() -> FlicEvent {
    FlicEvent {
        kind: String::new(),
        peripheral_id: String::new(),
        battery_mv: None,
        firmware: None,
        press_kind: None,
        timestamp32k: None,
        was_queued: None,
        event_count: None,
        boot_id: None,
        has_queued: None,
        reason: None,
        attempt: None,
        after_ms: None,
        last_reason: None,
    }
}

/// An active reconnect supervisor for one paired Flic. Drop or call
/// `disconnect()` to end the session cleanly. The handle's `resumeState()`
/// reflects the latest event-continuity values; persist it periodically
/// (the host owns the schedule — the binding has no opinion).
#[napi]
pub struct ConnectionHandle {
    handle: Mutex<Option<ReconnectingHandle>>,
}

#[napi]
impl ConnectionHandle {
    /// Requests a clean disconnect and waits for the supervisor to exit.
    /// Idempotent — calling twice is a no-op on the second call.
    #[napi]
    pub async fn disconnect(&self) {
        let taken = self.handle.lock().expect("lock poisoned").take();
        if let Some(h) = taken {
            h.disconnect().await;
        }
    }

    /// Returns the latest persisted event-continuity state, or null if the
    /// handle has already been disconnected.
    #[napi]
    pub fn resume_state(&self) -> Option<EventResumeState> {
        self.handle
            .lock()
            .expect("lock poisoned")
            .as_ref()
            .map(|h| EventResumeState::from_core(h.resume_state()))
    }
}

/// The FlicManager handle. Owns a BLE adapter and a shared event broadcast.
///
/// Construct with `FlicManager.create()` (async). There is intentionally no
/// synchronous constructor — opening the BLE adapter is async on every OS.
#[napi]
pub struct FlicManager {
    inner: Arc<CoreFlicManager>,
}

#[napi]
impl FlicManager {
    /// Opens the first available BLE adapter. Throws `BluetoothOff` or
    /// `BleAdapterUnavailable` if the adapter can't be acquired.
    #[napi(factory)]
    pub async fn create() -> Result<Self> {
        let inner = CoreFlicManager::new().await.map_err(to_napi_err)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Returns the current BLE adapter power state.
    #[napi]
    pub async fn adapter_state(&self) -> AdapterState {
        self.inner.adapter_state().await.into()
    }

    /// Scans for Flic 2 peripherals for `timeout_ms` milliseconds. Returns
    /// every Flic that advertised during the window.
    ///
    /// This uses a service-UUID filter, so it only sees Flic 2s in Public Mode
    /// (7-second hold on an unpaired button). For paired buttons in Private
    /// Mode, use `connect()` directly — the supervisor waits for a click-
    /// triggered advertisement internally.
    #[napi]
    pub async fn scan(&self, timeout_ms: u32) -> Result<Vec<Discovery>> {
        let found = self
            .inner
            .scan(Duration::from_millis(u64::from(timeout_ms)))
            .await
            .map_err(to_napi_err)?;
        Ok(found
            .into_iter()
            .map(|d| Discovery {
                id: d.id,
                local_name: d.local_name,
                rssi: d.rssi.map(i32::from),
            })
            .collect())
    }

    /// Waits for the peripheral to advertise (up to `findTimeoutMs`) and then
    /// runs FullVerify pairing against a button in Public Mode. The returned
    /// `PairingCredentials` is the identity used for every subsequent
    /// `connect()` — the host must persist it.
    ///
    /// The button enters Public Mode after a ~7-second hold (LED flashes
    /// rapidly, then two extra flashes after release). You have ~30s from that
    /// point before the button exits pairing mode.
    #[napi]
    pub async fn pair(
        &self,
        peripheral_id: String,
        find_timeout_ms: u32,
    ) -> Result<PairingCredentials> {
        let discovery = self
            .inner
            .find(&peripheral_id, Duration::from_millis(u64::from(find_timeout_ms)))
            .await
            .map_err(to_napi_err)?;
        let creds = self
            .inner
            .pair(&discovery.id)
            .await
            .map_err(to_napi_err)?;
        Ok(PairingCredentials::from_core(creds))
    }

    /// Registers a callback that receives every `FlicEvent` emitted by any
    /// active connection on this manager. Call before `connect()` so the
    /// initial Connected / EventsResumed events are observed.
    ///
    /// The callback is invoked from a Rust background task via a
    /// `ThreadsafeFunction` — it runs on the Node event loop, not off-thread.
    /// `NonBlocking` delivery: if the Node side is overwhelmed, events drop
    /// rather than block Rust. (Press rates are human-scale; this is belt-
    /// and-braces.)
    #[napi(ts_args_type = "callback: (event: FlicEvent) => void")]
    pub fn on_event(&self, callback: JsFunction) -> Result<()> {
        let tsfn: ThreadsafeFunction<FlicEvent, ErrorStrategy::Fatal> =
            callback.create_threadsafe_function(0, |ctx| Ok(vec![ctx.value]))?;

        let mut rx = self.inner.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        tsfn.call(
                            FlicEvent::from_core(ev),
                            ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Subscriber fell behind; continue.
                    }
                }
            }
        });
        Ok(())
    }

    /// Connects to a previously-paired Flic and starts the reconnect
    /// supervisor. Events flow through the callback registered with
    /// `onEvent()`. Persist `resume` on every `eventsResumed` / drainer tick.
    ///
    /// Uses the default reconnect policy (500ms initial backoff, 2x multiplier,
    /// 30s cap, retries forever). A future revision can expose the policy.
    #[napi]
    pub async fn connect(
        &self,
        peripheral_id: String,
        creds: PairingCredentials,
        resume: EventResumeState,
    ) -> Result<ConnectionHandle> {
        let core_creds = creds.to_core()?;
        let core_resume = resume.to_core();
        let handle = self
            .inner
            .listen_with_reconnect(
                peripheral_id,
                core_creds,
                core_resume,
                ReconnectPolicy::default(),
            )
            .await
            .map_err(to_napi_err)?;
        Ok(ConnectionHandle {
            handle: Mutex::new(Some(handle)),
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Maps a `FlicError` to a napi error whose message carries a stable code
/// prefix for JS narrowing. Format: `CODE: human-readable message`.
///
/// Callers on the JS side should parse the prefix up to the first `:` and
/// match against the documented code set.
fn to_napi_err(e: FlicError) -> Error {
    let code = match &e {
        FlicError::BluetoothOff => "BLUETOOTH_OFF",
        FlicError::BleAdapterUnavailable(_) => "BLE_ADAPTER_UNAVAILABLE",
        FlicError::NotFound => "NOT_FOUND",
        FlicError::PairingFailed(_) => "PAIRING_FAILED",
        FlicError::InvalidMac => "INVALID_MAC",
        FlicError::Timeout { .. } => "TIMEOUT",
        FlicError::ProtocolViolation(_) => "PROTOCOL_VIOLATION",
        FlicError::Crypto(_) => "CRYPTO",
    };
    Error::new(Status::GenericFailure, format!("{code}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_credentials_round_trip_through_js_shape() {
        let core = CorePairingCredentials {
            pairing_id: 0xDEAD_BEEF,
            pairing_key: [0x11; 16],
            serial_number: "BJ04-H88174".into(),
            button_uuid: [0x22; 16],
            firmware_version: 10,
        };
        let js = PairingCredentials::from_core(core.clone());
        assert_eq!(js.pairing_key_hex, "11".repeat(16));
        assert_eq!(js.button_uuid_hex, "22".repeat(16));

        let back = js.to_core().expect("round-trip");
        assert_eq!(back.pairing_id, core.pairing_id);
        assert_eq!(back.pairing_key, core.pairing_key);
        assert_eq!(back.serial_number, core.serial_number);
        assert_eq!(back.button_uuid, core.button_uuid);
        assert_eq!(back.firmware_version, core.firmware_version);
    }

    #[test]
    fn pairing_credentials_rejects_malformed_hex() {
        let bad = PairingCredentials {
            pairing_id: 1,
            pairing_key_hex: "not-hex".into(),
            serial_number: "x".into(),
            button_uuid_hex: "00".repeat(16),
            firmware_version: 1,
        };
        assert!(bad.to_core().is_err());
    }
}
