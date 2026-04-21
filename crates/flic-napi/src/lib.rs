//! `flic-napi` — Node.js bindings for `flic-core`.
//!
//! The binding stays deliberately thin. Rust exposes primitives (commands +
//! a typed event stream); the Node/Electron host owns all product policy
//! (press → action mapping, arming, persistence location).

#![deny(clippy::all)]

use std::sync::Arc;
use std::time::Duration;

use flic_core::{AdapterState as CoreAdapterState, FlicError, FlicManager as CoreFlicManager};
use napi::bindgen_prelude::*;
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
