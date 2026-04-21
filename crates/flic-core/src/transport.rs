//! btleplug-backed BLE transport for Flic 2 buttons.
//!
//! This module is thin glue between btleplug's async API and [`crate::Session`]. It
//! performs BLE discovery, connect, service/characteristic discovery, notification
//! subscription, writes, and disconnect — nothing protocol-level. Session state
//! (state machine, crypto, framing) is owned by [`crate::session::Session`].

use std::time::Duration;

use btleplug::api::{Central, CentralEvent, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures::stream::StreamExt;
use tracing::info;

use crate::constants::{FLIC_NOTIFY_CHAR_UUID, FLIC_SERVICE_UUID, FLIC_WRITE_CHAR_UUID};
use crate::error::FlicError;

/// A Flic peripheral discovered by a scan.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub id: PeripheralId,
    pub local_name: Option<String>,
    pub rssi: Option<i16>,
}

/// Owns the btleplug adapter; entry point for scans and connects.
pub struct BleTransport {
    adapter: Adapter,
}

impl BleTransport {
    /// Opens the first Bluetooth adapter on the system.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if no adapter is present or the OS
    /// denies access (commonly a missing permission on macOS).
    pub async fn new() -> Result<Self, FlicError> {
        let manager = Manager::new()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| FlicError::BleAdapterUnavailable("no BLE adapter found".into()))?;
        Ok(Self { adapter })
    }

    /// Returns a reference to the underlying adapter. Useful for callers who need
    /// direct access (e.g. to observe `CentralEvent::StateUpdate`).
    #[must_use]
    pub fn adapter(&self) -> &Adapter {
        &self.adapter
    }

    /// Scans for Flic 2 peripherals. Filter: advertised service UUID equals the Flic
    /// service OR the local name matches `^F2[0-9]{2}[A-Za-z0-9_-]{4}$`.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if the adapter rejects the scan
    /// request or the start/stop sequence fails.
    pub async fn scan(&self, timeout: Duration) -> Result<Vec<Discovery>, FlicError> {
        let filter = ScanFilter {
            services: vec![FLIC_SERVICE_UUID],
        };
        self.adapter
            .start_scan(filter)
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;

        tokio::time::sleep(timeout).await;

        self.adapter
            .stop_scan()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;

        let peripherals = self
            .adapter
            .peripherals()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;

        let mut results = Vec::new();
        for p in peripherals {
            let Ok(Some(props)) = p.properties().await else {
                continue;
            };
            let local_name = props.local_name.clone();
            let advertises_flic = props.services.contains(&FLIC_SERVICE_UUID);
            let name_matches = local_name.as_deref().is_some_and(is_flic_local_name);
            if advertises_flic || name_matches {
                results.push(Discovery {
                    id: p.id(),
                    local_name,
                    rssi: props.rssi,
                });
            }
        }
        Ok(results)
    }

    /// Connects to a peripheral by ID, performs GATT discovery, and subscribes to the
    /// Flic notify characteristic. Returns an open [`BleConnection`] ready to write
    /// and read frames.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::NotFound`] if the peripheral isn't known to the adapter,
    /// or [`FlicError::BleAdapterUnavailable`] for any BLE-layer failure.
    pub async fn connect(&self, id: &PeripheralId) -> Result<BleConnection, FlicError> {
        let peripheral = self
            .adapter
            .peripheral(id)
            .await
            .map_err(|_| FlicError::NotFound)?;

        if !peripheral.is_connected().await.unwrap_or(false) {
            peripheral
                .connect()
                .await
                .map_err(|e| FlicError::BleAdapterUnavailable(format!("connect: {e}")))?;
        }

        peripheral
            .discover_services()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("discover_services: {e}")))?;

        let chars = peripheral.characteristics();
        let write_char = chars
            .iter()
            .find(|c| c.uuid == FLIC_WRITE_CHAR_UUID)
            .cloned()
            .ok_or_else(|| FlicError::ProtocolViolation("write char not found".into()))?;
        let notify_char = chars
            .iter()
            .find(|c| c.uuid == FLIC_NOTIFY_CHAR_UUID)
            .cloned()
            .ok_or_else(|| FlicError::ProtocolViolation("notify char not found".into()))?;

        peripheral
            .subscribe(&notify_char)
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("subscribe: {e}")))?;

        info!(peripheral = ?id, "Flic GATT session open");

        Ok(BleConnection {
            peripheral,
            write_char,
            notify_char,
        })
    }

    /// Starts a scan and returns the moment the target peripheral is seen (by string
    /// match of its `PeripheralId`). Much faster than `scan(timeout)` when you already
    /// know which peripheral you want — typically sub-second under Public Mode.
    ///
    /// The scan is stopped on both success and timeout.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::NotFound`] if the timeout elapses before the peripheral
    /// advertises. Returns [`FlicError::BleAdapterUnavailable`] for BLE-layer failures.
    pub async fn find_peripheral(
        &self,
        peripheral_id_str: &str,
        timeout: Duration,
    ) -> Result<Discovery, FlicError> {
        let filter = ScanFilter {
            services: vec![FLIC_SERVICE_UUID],
        };
        self.adapter
            .start_scan(filter)
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("start_scan: {e}")))?;

        let events = self
            .adapter
            .events()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("events: {e}")))?;

        // Check if the adapter already knows about it (cached from a prior scan).
        if let Ok(peripherals) = self.adapter.peripherals().await {
            for p in peripherals {
                if format!("{}", p.id()) == peripheral_id_str {
                    if let Ok(Some(props)) = p.properties().await {
                        let _ = self.adapter.stop_scan().await;
                        return Ok(Discovery {
                            id: p.id(),
                            local_name: props.local_name,
                            rssi: props.rssi,
                        });
                    }
                }
            }
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut events = events;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break Err(FlicError::NotFound);
            }
            match tokio::time::timeout(remaining, events.next()).await {
                Ok(Some(CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id))) => {
                    if format!("{id}") != peripheral_id_str {
                        continue;
                    }
                    let Ok(peripheral) = self.adapter.peripheral(&id).await else {
                        continue;
                    };
                    let Ok(Some(props)) = peripheral.properties().await else {
                        continue;
                    };
                    break Ok(Discovery {
                        id,
                        local_name: props.local_name,
                        rssi: props.rssi,
                    });
                }
                Ok(Some(_)) => continue,
                Ok(None) => break Err(FlicError::Disconnected("event stream ended".into())),
                Err(_) => break Err(FlicError::NotFound),
            }
        };

        let _ = self.adapter.stop_scan().await;
        result
    }

    /// Watches for `CentralEvent::DeviceDisconnected` for the given peripheral.
    /// Returns when the event arrives; the caller should close the session.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if the event stream can't be
    /// obtained.
    pub async fn watch_disconnect(&self, id: &PeripheralId) -> Result<(), FlicError> {
        let mut events = self
            .adapter
            .events()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;
        while let Some(evt) = events.next().await {
            if let CentralEvent::DeviceDisconnected(pid) = evt {
                if &pid == id {
                    return Ok(());
                }
            }
        }
        Err(FlicError::Disconnected("event stream ended".into()))
    }
}

/// Active GATT connection to one Flic. Owns the btleplug peripheral handle + char refs.
pub struct BleConnection {
    peripheral: Peripheral,
    write_char: btleplug::api::Characteristic,
    notify_char: btleplug::api::Characteristic,
}

impl BleConnection {
    /// Sends a single ATT packet on the Flic write characteristic.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] on transport failure.
    pub async fn write(&self, packet: &[u8]) -> Result<(), FlicError> {
        self.peripheral
            .write(&self.write_char, packet, WriteType::WithoutResponse)
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("write: {e}")))
    }

    /// Returns a stream of incoming notification packets.
    ///
    /// The returned stream is `'static` (owns its state), so the caller can hold it
    /// independently of the [`BleConnection`].
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if the stream can't be established.
    pub async fn notifications(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Vec<u8>> + Send>>, FlicError> {
        let stream = self
            .peripheral
            .notifications()
            .await
            .map_err(|e| FlicError::BleAdapterUnavailable(format!("notifications: {e}")))?;
        let notify_uuid = self.notify_char.uuid;
        Ok(Box::pin(stream.filter_map(move |v| async move {
            if v.uuid == notify_uuid {
                Some(v.value)
            } else {
                None
            }
        })))
    }

    /// Closes the BLE link (sends GATT disconnect). The caller should first send
    /// `DISCONNECT_VERIFIED_LINK_IND` at the protocol layer.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if the disconnect request fails.
    pub async fn disconnect(self) -> Result<(), FlicError> {
        if self.peripheral.is_connected().await.unwrap_or(false) {
            self.peripheral
                .disconnect()
                .await
                .map_err(|e| FlicError::BleAdapterUnavailable(format!("disconnect: {e}")))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn id(&self) -> PeripheralId {
        self.peripheral.id()
    }
}

/// Validates Flic 2 local-name pattern `F2vvXXXX` (8 ASCII chars: "F2" + 2 digits +
/// 4 base64-url chars for BDA encoding).
#[must_use]
pub fn is_flic_local_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() != 8 {
        return false;
    }
    if &bytes[0..2] != b"F2" {
        return false;
    }
    if !bytes[2].is_ascii_digit() || !bytes[3].is_ascii_digit() {
        return false;
    }
    bytes[4..8]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_name_pattern_matches_real_shapes() {
        // 8 chars: literal "F2" + 2 digits (firmware version major) + 4 base64-url
        // chars (low 24 bits of BDA).
        assert!(is_flic_local_name("F217AbCd"));
        assert!(is_flic_local_name("F299_xyZ"));
        assert!(is_flic_local_name("F200-a_b"));
    }

    #[test]
    fn local_name_pattern_rejects_malformed() {
        assert!(!is_flic_local_name("F2")); // too short
        assert!(!is_flic_local_name("F2XYAbCd")); // non-digit after F2
        assert!(!is_flic_local_name("F217!bCd")); // disallowed char
        assert!(!is_flic_local_name("G217AbCd")); // wrong prefix
        assert!(!is_flic_local_name("F217AbCd!")); // too long
    }
}
