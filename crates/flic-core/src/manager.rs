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

use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{Central, CentralEvent, CentralState};
use btleplug::platform::PeripheralId;
use futures::stream::StreamExt;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::FlicError;
use crate::reconnect::{
    ReconnectPolicy, Supervisor, SupervisorAction, SupervisorEvent, SupervisorInput,
    SupervisorState,
};
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
    /// Reconnect supervisor is about to sleep `after` then make `attempt`.
    Reconnecting {
        id: PeripheralId,
        attempt: u32,
        after: Duration,
        last_reason: DisconnectReason,
    },
    /// BLE adapter powered off — retries paused until it returns.
    AdapterUnavailable { id: PeripheralId },
}

const BROADCAST_CAPACITY: usize = 1024;

/// How long `drive_loop` waits for *any* inbound notification before declaring
/// the link dead. Any traffic — PING, ButtonEventNotification, a random
/// unhandled opcode — resets the timer. Flic 2's idle heartbeat is ~10s; 20s
/// gives one full missed interval plus retry slack.
const PING_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(20);

/// Single-peripheral manager. One instance handles one Flic at a time.
pub struct FlicManager {
    transport: Arc<BleTransport>,
    event_tx: broadcast::Sender<FlicEvent>,
}

impl FlicManager {
    /// Opens the BLE adapter and prepares the event broadcast channel.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::BleAdapterUnavailable`] if no BLE adapter is found.
    pub async fn new() -> Result<Self, FlicError> {
        let transport = Arc::new(BleTransport::new().await?);
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

    /// Waits for a specific peripheral by ID, returning as soon as it's seen on-air.
    /// Much faster than `scan` when you already know which peripheral you want.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::NotFound`] if the timeout elapses before the peripheral
    /// advertises.
    pub async fn find(
        &self,
        peripheral_id_str: &str,
        timeout: Duration,
    ) -> Result<Discovery, FlicError> {
        self.transport
            .find_peripheral(peripheral_id_str, timeout)
            .await
    }

    /// Runs the FullVerify handshake against a button in Public Mode and returns
    /// persistable credentials on success. Exits cleanly after the `Paired` event
    /// arrives — does not maintain a long-lived session.
    ///
    /// # Errors
    ///
    /// Returns [`FlicError::PairingFailed`] if the handshake fails for any reason.
    pub async fn pair(&self, id: &PeripheralId) -> Result<PairingCredentials, FlicError> {
        let conn = self.transport.connect(id).await?;
        let mut session = Session::new();
        let mut creds: Option<PairingCredentials> = None;

        let initial = session.step(SessionInput::BeginPairing)?;
        apply_actions(&conn, initial, id, &self.event_tx, &mut |_, _| {}).await?;

        let mut notifications = conn.notifications().await?;
        while let Some(packet) = notifications.next().await {
            let actions = session.step(SessionInput::IncomingPacket(packet))?;
            for action in &actions {
                if let SessionAction::Emit(SessionEvent::Paired(c)) = action {
                    creds = Some(c.clone());
                }
            }
            let closed = apply_actions(&conn, actions, id, &self.event_tx, &mut |_, _| {}).await?;
            if creds.is_some() || closed {
                break;
            }
        }

        drop(notifications);
        let _ = conn.disconnect().await;

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
                None,
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

    /// Runs `listen` in a reconnect supervisor: retryable disconnects trigger
    /// exponential backoff; fatal disconnects stop the loop; the BLE adapter
    /// powering off pauses retries until it returns.
    ///
    /// `initial_resume` is the starting event-continuity state; the handle's
    /// `resume_state()` method reports the latest values observed from the
    /// button, suitable for persisting between restarts.
    ///
    /// # Errors
    ///
    /// Returns any error that prevents the supervisor task from spawning.
    pub async fn listen_with_reconnect(
        &self,
        id: PeripheralId,
        creds: PairingCredentials,
        initial_resume: EventResumeState,
        policy: ReconnectPolicy,
    ) -> Result<ReconnectingHandle, FlicError> {
        let transport = Arc::clone(&self.transport);
        let event_tx = self.event_tx.clone();
        let cancel = CancellationToken::new();
        let runner_cancel = cancel.clone();
        let (resume_tx, resume_rx) = watch::channel(initial_resume);

        let task = tokio::spawn(async move {
            if let Err(e) = run_supervisor(
                transport,
                id,
                creds,
                resume_tx,
                event_tx,
                policy,
                runner_cancel,
            )
            .await
            {
                error!(?e, "reconnect supervisor exited with error");
            }
        });

        Ok(ReconnectingHandle {
            task,
            cancel,
            resume_rx,
        })
    }
}

/// Handle returned from [`FlicManager::listen_with_reconnect`]. Dropping it
/// detaches the supervisor but does NOT stop it — call [`ReconnectingHandle::disconnect`]
/// for a clean shutdown.
pub struct ReconnectingHandle {
    task: JoinHandle<()>,
    cancel: CancellationToken,
    resume_rx: watch::Receiver<EventResumeState>,
}

impl ReconnectingHandle {
    /// Requests a clean disconnect and waits for the supervisor to exit.
    pub async fn disconnect(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }

    /// Waits for the supervisor to exit on its own (e.g. fatal disconnect).
    pub async fn wait(self) {
        let _ = self.task.await;
    }

    /// Current best estimate of the event-continuity state (for persistence).
    #[must_use]
    pub fn resume_state(&self) -> EventResumeState {
        *self.resume_rx.borrow()
    }

    /// Subscribe to resume-state updates for a persistence drainer.
    #[must_use]
    pub fn subscribe_resume(&self) -> watch::Receiver<EventResumeState> {
        self.resume_rx.clone()
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
    resume_tx: Option<watch::Sender<EventResumeState>>,
) -> Result<(), FlicError> {
    let mut no_op = |_: &PeripheralId, _: &SessionEvent| {};
    let closed = apply_actions(&conn, initial, id, &event_tx, &mut no_op).await?;
    if closed {
        return conn.disconnect().await;
    }

    let mut notifications = conn.notifications().await?;
    let mut inactivity = Box::pin(tokio::time::sleep(PING_INACTIVITY_TIMEOUT));

    loop {
        tokio::select! {
            packet = notifications.next() => {
                let Some(packet) = packet else {
                    warn!("notification stream ended");
                    return Ok(());
                };
                debug!(bytes = packet.len(), "incoming notification");
                inactivity
                    .as_mut()
                    .reset(tokio::time::Instant::now() + PING_INACTIVITY_TIMEOUT);
                let actions = match session.step(SessionInput::IncomingPacket(packet)) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(?e, "session error");
                        return Err(e);
                    }
                };
                let closed = apply_actions(&conn, actions, id, &event_tx, &mut no_op).await?;
                if let Some(tx) = resume_tx.as_ref() {
                    let _ = tx.send(session.resume_state());
                }
                if closed {
                    return conn.disconnect().await;
                }
            }
            () = &mut inactivity => {
                warn!(
                    timeout_secs = PING_INACTIVITY_TIMEOUT.as_secs(),
                    "no BLE traffic for inactivity window — declaring link dead"
                );
                // Drive the session into BleDisconnected so it emits the right
                // terminal events, then map that to DisconnectReason::PingTimeout
                // for subscribers (BleDisconnected produces BleTransport by default).
                let _ = session.step(SessionInput::BleDisconnected("ping_inactivity".into()))?;
                // Override what the session would have broadcast: the real reason
                // is PingTimeout so the reconnect supervisor classifies it correctly.
                let _ = event_tx.send(FlicEvent::Disconnected {
                    id: id.clone(),
                    reason: crate::session::DisconnectReason::PingTimeout,
                });
                return conn.disconnect().await;
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

/// Runs one `find → connect → listen` attempt. Returns the
/// [`DisconnectReason`] that ended the session, or an error if the setup
/// couldn't complete.
#[derive(Debug, Clone)]
struct AttemptOutcome {
    reason: DisconnectReason,
    reached_established: bool,
}

async fn run_one_attempt(
    transport: &BleTransport,
    id: &PeripheralId,
    creds: PairingCredentials,
    resume: EventResumeState,
    event_tx: broadcast::Sender<FlicEvent>,
    resume_tx: watch::Sender<EventResumeState>,
    cancel: &CancellationToken,
) -> Result<AttemptOutcome, FlicError> {
    // Scan until the peripheral advertises (or the cancel fires). Flic 2's
    // advertising is triggered by a click in Private Mode — the caller may
    // wait minutes here.
    let id_str = format!("{id}");
    let find_future = transport.find_peripheral(&id_str, Duration::from_secs(3600));
    let discovery = tokio::select! {
        () = cancel.cancelled() => {
            return Ok(AttemptOutcome {
                reason: DisconnectReason::ByUser,
                reached_established: false,
            });
        }
        d = find_future => d?,
    };

    let conn = transport.connect(&discovery.id).await?;
    let mut session = Session::new();
    let initial = session.step(SessionInput::BeginReconnect(creds, resume))?;

    // Subscribe BEFORE starting drive_loop so we don't miss the Connected/
    // Disconnected events.
    let mut rx = event_tx.subscribe();
    let (disconnect_tx, mut disconnect_rx) = tokio::sync::mpsc::channel::<()>(1);

    let drive = {
        let event_tx = event_tx.clone();
        let id = id.clone();
        let resume_tx = resume_tx.clone();
        tokio::spawn(async move {
            drive_loop(
                session,
                conn,
                initial,
                &id,
                event_tx,
                &mut disconnect_rx,
                Some(resume_tx),
            )
            .await
        })
    };

    let mut reached_established = false;
    let mut observed_reason: Option<DisconnectReason> = None;

    let exit: Result<(), FlicError> = loop {
        tokio::select! {
            () = cancel.cancelled() => {
                let _ = disconnect_tx.send(()).await;
                // Fall through and wait for drive to exit.
                break Ok(());
            }
            evt = rx.recv() => {
                match evt {
                    Ok(FlicEvent::Connected { id: eid, .. }) if &eid == id => {
                        reached_established = true;
                    }
                    Ok(FlicEvent::EventsResumed { id: eid, .. }) if &eid == id => {
                        reached_established = true;
                    }
                    Ok(FlicEvent::Disconnected { id: eid, reason }) if &eid == id => {
                        observed_reason = Some(reason);
                        break Ok(());
                    }
                    Err(broadcast::error::RecvError::Closed) => break Ok(()),
                    _ => {}
                }
            }
        }
    };

    let _ = exit;
    let drive_result = drive.await;

    let reason = observed_reason.unwrap_or_else(|| match drive_result {
        Ok(Ok(())) => DisconnectReason::BleTransport("drive_loop ended without reason".into()),
        Ok(Err(e)) => DisconnectReason::BleTransport(e.to_string()),
        Err(join_err) => DisconnectReason::BleTransport(format!("task: {join_err}")),
    });

    Ok(AttemptOutcome {
        reason,
        reached_established,
    })
}

async fn run_supervisor(
    transport: Arc<BleTransport>,
    id: PeripheralId,
    creds: PairingCredentials,
    resume_tx: watch::Sender<EventResumeState>,
    event_tx: broadcast::Sender<FlicEvent>,
    policy: ReconnectPolicy,
    cancel: CancellationToken,
) -> Result<(), FlicError> {
    let mut supervisor = Supervisor::new(policy);
    let mut actions = supervisor.step(SupervisorInput::Start);
    let mut pending_sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

    // Check adapter state once at start; if not PoweredOn, feed AdapterPowered(false).
    if transport.adapter_state().await != CentralState::PoweredOn {
        actions.extend(supervisor.step(SupervisorInput::AdapterPowered(false)));
    }

    let mut adapter_events = transport
        .adapter()
        .events()
        .await
        .map_err(|e| FlicError::BleAdapterUnavailable(e.to_string()))?;

    loop {
        // Drain all queued actions first.
        let mut maybe_attempt: Option<(PairingCredentials, EventResumeState)> = None;
        for action in actions.drain(..) {
            match action {
                SupervisorAction::InitiateConnect => {
                    let resume = *resume_tx.subscribe().borrow();
                    maybe_attempt = Some((creds.clone(), resume));
                }
                SupervisorAction::Sleep(d) => {
                    pending_sleep = Some(Box::pin(tokio::time::sleep(d)));
                }
                SupervisorAction::Emit(evt) => {
                    if let Some(flic_evt) = supervisor_event_to_flic(&id, evt) {
                        let _ = event_tx.send(flic_evt);
                    }
                }
                SupervisorAction::Stop => return Ok(()),
            }
        }

        if let Some((creds, resume)) = maybe_attempt {
            // Spawn the attempt; race it against cancel/adapter events.
            let attempt_cancel = cancel.child_token();
            let attempt = run_one_attempt(
                transport.as_ref(),
                &id,
                creds,
                resume,
                event_tx.clone(),
                resume_tx.clone(),
                &attempt_cancel,
            );
            tokio::pin!(attempt);

            let input = loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => {
                        attempt_cancel.cancel();
                        let _ = (&mut attempt).await;
                        break SupervisorInput::UserDisconnect;
                    }
                    evt = adapter_events.next() => {
                        match evt {
                            Some(CentralEvent::StateUpdate(state)) => {
                                let powered = matches!(state, CentralState::PoweredOn);
                                if !powered {
                                    attempt_cancel.cancel();
                                    let _ = (&mut attempt).await;
                                    break SupervisorInput::AdapterPowered(false);
                                }
                            }
                            None => {
                                // Adapter event stream ended — rare.
                                attempt_cancel.cancel();
                                let _ = (&mut attempt).await;
                                break SupervisorInput::AttemptFailed(DisconnectReason::BleTransport(
                                    "adapter event stream ended".into(),
                                ));
                            }
                            _ => {}
                        }
                    }
                    result = &mut attempt => {
                        break match result {
                            Ok(outcome) => {
                                if outcome.reached_established {
                                    actions.push(SupervisorAction::InitiateConnect); // sentinel
                                    let mut pre = supervisor.step(SupervisorInput::AttemptSucceeded);
                                    actions.pop();
                                    actions.extend(pre.drain(..));
                                }
                                SupervisorInput::AttemptFailed(outcome.reason)
                            }
                            Err(e) => SupervisorInput::AttemptFailed(DisconnectReason::BleTransport(
                                e.to_string(),
                            )),
                        };
                    }
                }
            };
            actions.extend(supervisor.step(input));
            continue;
        }

        // No attempt queued — wait for sleep/adapter/cancel.
        if supervisor.state() == SupervisorState::Stopped {
            return Ok(());
        }

        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                actions.extend(supervisor.step(SupervisorInput::UserDisconnect));
            }
            evt = adapter_events.next() => {
                match evt {
                    Some(CentralEvent::StateUpdate(state)) => {
                        let powered = matches!(state, CentralState::PoweredOn);
                        actions.extend(supervisor.step(SupervisorInput::AdapterPowered(powered)));
                    }
                    None => {
                        actions.extend(supervisor.step(SupervisorInput::AttemptFailed(
                            DisconnectReason::BleTransport("adapter event stream ended".into()),
                        )));
                    }
                    _ => {}
                }
            }
            () = async {
                if let Some(s) = pending_sleep.as_mut() {
                    s.as_mut().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                pending_sleep = None;
                actions.extend(supervisor.step(SupervisorInput::BackoffElapsed));
            }
        }
    }
}

fn supervisor_event_to_flic(id: &PeripheralId, evt: SupervisorEvent) -> Option<FlicEvent> {
    match evt {
        SupervisorEvent::Reconnecting {
            attempt,
            after,
            last_reason,
        } => Some(FlicEvent::Reconnecting {
            id: id.clone(),
            attempt,
            after,
            last_reason,
        }),
        SupervisorEvent::AdapterUnavailable => Some(FlicEvent::AdapterUnavailable { id: id.clone() }),
        SupervisorEvent::Stopped {
            final_reason: Some(reason),
        } => Some(FlicEvent::Disconnected {
            id: id.clone(),
            reason,
        }),
        SupervisorEvent::Stopped { final_reason: None } => Some(FlicEvent::Disconnected {
            id: id.clone(),
            reason: DisconnectReason::ByUser,
        }),
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
