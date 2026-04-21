//! [`FlicManager`] — drives the pure [`Session`] state machine with btleplug transport.
//!
//! Consumer flow:
//!
//! 1. [`FlicManager::new`] opens the Bluetooth adapter.
//! 2. [`FlicManager::scan`] returns discovered Flics.
//! 3. For a fresh button, [`FlicManager::pair`] runs FullVerify and returns
//!    [`PairingCredentials`] to persist.
//! 4. For a known button, [`FlicManager::listen`] runs QuickVerify and then drives
//!    steady-state event delivery. Events arrive on the returned
//!    `broadcast::Receiver<FlicEvent>`.
//!
//! The manager handles a single Flic at a time in this first slice. Multi-peripheral
//! fan-out (one broadcast channel, many per-peripheral tasks) is a later slice.

use std::time::Duration;

use btleplug::platform::PeripheralId;
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::error::FlicError;
use crate::session::{
    DisconnectReason, EventResumeState, PairingCredentials, Session, SessionAction, SessionEvent,
    SessionInput,
};
use crate::transport::{BleConnection, BleTransport, Discovery};

/// Events broadcast to consumers of [`FlicManager::listen`].
#[derive(Debug, Clone)]
pub enum FlicEvent {
    Connected {
        id: PeripheralId,
        battery_voltage_mv: u16,
        firmware_version: u32,
    },
    ButtonPressed {
        id: PeripheralId,
        kind: crate::PressKind,
        timestamp_32k: u64,
        was_queued: bool,
    },
    EventsResumed {
        id: PeripheralId,
        event_count: u32,
        boot_id: u32,
        has_queued_events: bool,
    },
    Disconnected {
        id: PeripheralId,
        reason: DisconnectReason,
    },
}

const BROADCAST_CAPACITY: usize = 1024;

/// Single-peripheral manager. One instance handles one Flic at a time.
pub struct FlicManager {
    transport: BleTransport,
    event_tx: broadcast::Sender<FlicEvent>,
}

impl FlicManager {
    /// Opens the BLE adapter and prepares the event broadcast channel.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if no BLE adapter is found.
    pub async fn new() -> Result<Self, FlicError> {
        let transport = BleTransport::new().await?;
        let (event_tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            transport,
            event_tx,
        })
    }

    /// Subscribes to event broadcasts. Multiple subscribers are supported; each gets
    /// its own ring-buffered copy. Lagged subscribers log a warning and catch up by
    /// dropping oldest events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<FlicEvent> {
        self.event_tx.subscribe()
    }

    /// Scans for Flic 2 peripherals for `timeout`.
    ///
    /// # Errors
    ///
    /// Returns any error from the underlying transport.
    pub async fn scan(&self, timeout: Duration) -> Result<Vec<Discovery>, FlicError> {
        self.transport.scan(timeout).await
    }

    /// Runs the FullVerify handshake against a button in Public Mode and returns
    /// persistable credentials on success.
    ///
    /// This blocks until pairing completes or fails. Events (Paired, Connected,
    /// EventsResumed) are also broadcast on [`Self::subscribe`] receivers.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::PairingFailed`] if the handshake fails for any reason.
    pub async fn pair(&self, id: &PeripheralId) -> Result<PairingCredentials, FlicError> {
        let conn = self.transport.connect(id).await?;
        let mut session = Session::new();
        let mut creds: Option<PairingCredentials> = None;
        let initial = session.step(SessionInput::BeginPairing)?;
        self.pump(&mut session, &conn, initial, id, &mut |_, ev| {
            if let SessionEvent::Paired(c) = ev {
                creds = Some(c.clone());
            }
        })
        .await?;

        creds.ok_or_else(|| FlicError::PairingFailed("session ended before Paired event".into()))
    }

    /// Runs QuickVerify against a previously-paired button and drives the session
    /// indefinitely, broadcasting events until the connection is lost or a disconnect
    /// is requested via the returned [`ListenHandle`].
    ///
    /// # Errors
    ///
    /// Returns any error from the transport or session.
    pub async fn listen(
        &self,
        id: PeripheralId,
        creds: PairingCredentials,
        resume: EventResumeState,
    ) -> Result<ListenHandle, FlicError> {
        let conn = self.transport.connect(&id).await?;
        let mut session = Session::new();
        let initial = session.step(SessionInput::BeginReconnect(creds, resume))?;

        let (disconnect_tx, mut disconnect_rx) = tokio::sync::mpsc::channel::<()>(1);
        let event_tx = self.event_tx.clone();
        let task_id = id.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = drive_loop(
                session,
                conn,
                initial,
                &task_id,
                event_tx,
                &mut disconnect_rx,
            )
            .await
            {
                error!(?e, "session driver exited with error");
            }
        });

        Ok(ListenHandle {
            task: handle,
            disconnect_tx,
        })
    }

    async fn pump(
        &self,
        session: &mut Session,
        conn: &BleConnection,
        initial_actions: Vec<SessionAction>,
        id: &PeripheralId,
        on_event: &mut impl FnMut(&PeripheralId, &SessionEvent),
    ) -> Result<(), FlicError> {
        apply_actions(conn, initial_actions, id, &self.event_tx, on_event).await?;

        let mut notifications = conn.notifications().await?;
        while let Some(packet) = notifications.next().await {
            let actions = session.step(SessionInput::IncomingPacket(packet))?;
            let closed = apply_actions(conn, actions, id, &self.event_tx, on_event).await?;
            if closed {
                break;
            }
        }
        Ok(())
    }
}

/// Handle returned from [`FlicManager::listen`]. Drop or call
/// [`ListenHandle::disconnect`] to end the session.
pub struct ListenHandle {
    task: JoinHandle<()>,
    disconnect_tx: tokio::sync::mpsc::Sender<()>,
}

impl ListenHandle {
    /// Requests a clean disconnect. The background task will send
    /// `DISCONNECT_VERIFIED_LINK_IND`, close the link, and exit.
    pub async fn disconnect(self) {
        let _ = self.disconnect_tx.send(()).await;
        let _ = self.task.await;
    }

    /// Waits for the session to end on its own.
    pub async fn wait(self) {
        let _ = self.task.await;
    }
}

async fn drive_loop(
    mut session: Session,
    conn: BleConnection,
    initial: Vec<SessionAction>,
    id: &PeripheralId,
    event_tx: broadcast::Sender<FlicEvent>,
    disconnect_rx: &mut tokio::sync::mpsc::Receiver<()>,
) -> Result<(), FlicError> {
    let mut no_op = |_: &PeripheralId, _: &SessionEvent| {};
    let closed = apply_actions(&conn, initial, id, &event_tx, &mut no_op).await?;
    if closed {
        return conn.disconnect().await;
    }

    let mut notifications = conn.notifications().await?;

    loop {
        tokio::select! {
            packet = notifications.next() => {
                let Some(packet) = packet else {
                    warn!("notification stream ended");
                    return Ok(());
                };
                debug!(bytes = packet.len(), "incoming notification");
                let actions = match session.step(SessionInput::IncomingPacket(packet)) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(?e, "session error");
                        return Err(e);
                    }
                };
                let closed = apply_actions(&conn, actions, id, &event_tx, &mut no_op).await?;
                if closed {
                    return conn.disconnect().await;
                }
            }
            _ = disconnect_rx.recv() => {
                info!("user-requested disconnect");
                let actions = session.step(SessionInput::UserDisconnect)?;
                apply_actions(&conn, actions, id, &event_tx, &mut no_op).await?;
                return conn.disconnect().await;
            }
        }
    }
}

async fn apply_actions(
    conn: &BleConnection,
    actions: Vec<SessionAction>,
    id: &PeripheralId,
    event_tx: &broadcast::Sender<FlicEvent>,
    on_event: &mut impl FnMut(&PeripheralId, &SessionEvent),
) -> Result<bool, FlicError> {
    let mut closed = false;
    for action in actions {
        match action {
            SessionAction::WritePacket(pkt) => {
                debug!(bytes = pkt.len(), "writing packet");
                conn.write(&pkt).await?;
            }
            SessionAction::Emit(event) => {
                on_event(id, &event);
                broadcast_event(event_tx, id, &event);
            }
            SessionAction::CloseSession => {
                closed = true;
            }
        }
    }
    Ok(closed)
}

fn broadcast_event(
    event_tx: &broadcast::Sender<FlicEvent>,
    id: &PeripheralId,
    event: &SessionEvent,
) {
    let id = id.clone();
    let broadcast = match event {
        SessionEvent::Paired(_) => None, // Paired is returned to caller directly.
        SessionEvent::Connected {
            battery_voltage_mv,
            firmware_version,
        } => Some(FlicEvent::Connected {
            id,
            battery_voltage_mv: *battery_voltage_mv,
            firmware_version: *firmware_version,
        }),
        SessionEvent::ButtonPressed {
            kind,
            timestamp_32k,
            was_queued,
        } => Some(FlicEvent::ButtonPressed {
            id,
            kind: *kind,
            timestamp_32k: *timestamp_32k,
            was_queued: *was_queued,
        }),
        SessionEvent::EventsResumed {
            event_count,
            boot_id,
            has_queued_events,
        } => Some(FlicEvent::EventsResumed {
            id,
            event_count: *event_count,
            boot_id: *boot_id,
            has_queued_events: *has_queued_events,
        }),
        SessionEvent::Disconnected { reason } => Some(FlicEvent::Disconnected {
            id,
            reason: reason.clone(),
        }),
    };
    if let Some(ev) = broadcast {
        // send() returns Err only when there are zero subscribers; that's fine.
        let _ = event_tx.send(ev);
    }
}
