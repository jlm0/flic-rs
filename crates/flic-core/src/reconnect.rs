//! Reconnect supervisor — drives `find → connect → listen` in a loop against a
//! paired Flic button, backing off between attempts and gating on the BLE
//! adapter's power state.
//!
//! The pure state machine lives here. The async runner that couples it to
//! [`crate::manager::FlicManager`] lives in `manager.rs`.

use std::time::Duration;

/// Backoff policy for the reconnect loop.
///
/// The policy is deliberately tiny: single peer + single button means there is
/// no thundering-herd concern, so no jitter; reconnect is the right thing to
/// try forever, so no `max_attempts` field. If those become necessary, they
/// live on a future version of the struct.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Delay after the first failed attempt.
    pub initial_backoff: Duration,
    /// Hard ceiling on any single backoff window.
    pub max_backoff: Duration,
    /// Per-attempt multiplier applied to `initial_backoff` until `max_backoff`.
    pub multiplier: f32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

/// Delay to wait before attempt number `attempt` (1-indexed: attempt=1 is the
/// first retry, right after the initial connect failed).
#[must_use]
pub fn delay(attempt: u32, policy: ReconnectPolicy) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let base = policy.initial_backoff.as_secs_f64();
    let mult = f64::from(policy.multiplier);
    let raw = base * mult.powi((attempt - 1) as i32);
    let capped = raw.min(policy.max_backoff.as_secs_f64());
    Duration::from_secs_f64(capped)
}

/// Inputs the supervisor reacts to. Coming from the async runner in `manager.rs`.
#[derive(Debug, Clone)]
pub enum SupervisorInput {
    /// Kick off the first connect attempt.
    Start,
    /// The current attempt reached `SessionEstablished`.
    AttemptSucceeded,
    /// The current attempt ended (either connect error, handshake error, or the
    /// live session dropped). The supervisor decides whether to retry based on
    /// [`crate::session::DisconnectReason::is_retryable`].
    AttemptFailed(crate::session::DisconnectReason),
    /// The backoff timer for the current wait has elapsed.
    BackoffElapsed,
    /// BLE adapter powered on (`true`) or off (`false`).
    AdapterPowered(bool),
    /// User asked the supervisor to stop.
    UserDisconnect,
}

/// Lifecycle events the supervisor surfaces to callers (flic-cli, napi binding).
#[derive(Debug, Clone)]
pub enum SupervisorEvent {
    /// About to sleep `after`, then make `attempt`.
    Reconnecting {
        attempt: u32,
        after: Duration,
        last_reason: crate::session::DisconnectReason,
    },
    /// BLE adapter powered off; retries are paused until it comes back.
    AdapterUnavailable,
    /// Terminal — the supervisor has stopped and will not retry.
    Stopped {
        final_reason: Option<crate::session::DisconnectReason>,
    },
}

/// Effectful actions the async runner performs on behalf of the pure state machine.
#[derive(Debug, Clone)]
pub enum SupervisorAction {
    /// Begin a single `find → connect → listen` attempt.
    InitiateConnect,
    /// Park the supervisor for `Duration`; the runner must fire `BackoffElapsed`
    /// when the timer expires.
    Sleep(Duration),
    /// Broadcast this lifecycle event to subscribers.
    Emit(SupervisorEvent),
    /// Tear down — no further inputs will be processed.
    Stop,
}

/// Pure state of the reconnect supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Idle,
    Connecting { attempt: u32 },
    Listening,
    Backoff { next_attempt: u32 },
    AdapterOff,
    Stopped,
}

/// The reconnect supervisor. Pure — no I/O, no time.
pub struct Supervisor {
    state: SupervisorState,
    policy: ReconnectPolicy,
}

impl Supervisor {
    #[must_use]
    pub fn new(policy: ReconnectPolicy) -> Self {
        Self {
            state: SupervisorState::Idle,
            policy,
        }
    }

    #[must_use]
    pub fn state(&self) -> SupervisorState {
        self.state
    }

    /// Apply an input and return the resulting actions.
    #[allow(clippy::match_same_arms)] // preserve state-transition readability over arm merging
    pub fn step(&mut self, input: SupervisorInput) -> Vec<SupervisorAction> {
        match (self.state, input) {
            (SupervisorState::Idle, SupervisorInput::Start) => {
                self.state = SupervisorState::Connecting { attempt: 1 };
                vec![SupervisorAction::InitiateConnect]
            }
            (SupervisorState::Connecting { .. }, SupervisorInput::AttemptSucceeded) => {
                self.state = SupervisorState::Listening;
                Vec::new()
            }
            (SupervisorState::Connecting { attempt }, SupervisorInput::AttemptFailed(reason))
                if reason.is_retryable() =>
            {
                let after = delay(attempt, self.policy);
                let next_attempt = attempt + 1;
                self.state = SupervisorState::Backoff { next_attempt };
                vec![
                    SupervisorAction::Emit(SupervisorEvent::Reconnecting {
                        attempt: next_attempt,
                        after,
                        last_reason: reason,
                    }),
                    SupervisorAction::Sleep(after),
                ]
            }
            (SupervisorState::Listening, SupervisorInput::AttemptFailed(reason))
                if reason.is_retryable() =>
            {
                let after = delay(1, self.policy);
                self.state = SupervisorState::Backoff { next_attempt: 2 };
                vec![
                    SupervisorAction::Emit(SupervisorEvent::Reconnecting {
                        attempt: 2,
                        after,
                        last_reason: reason,
                    }),
                    SupervisorAction::Sleep(after),
                ]
            }
            (
                SupervisorState::Connecting { .. } | SupervisorState::Listening,
                SupervisorInput::AttemptFailed(reason),
            ) => {
                // Fatal failure from either state: terminate.
                self.state = SupervisorState::Stopped;
                vec![
                    SupervisorAction::Emit(SupervisorEvent::Stopped {
                        final_reason: Some(reason),
                    }),
                    SupervisorAction::Stop,
                ]
            }
            (SupervisorState::Backoff { next_attempt }, SupervisorInput::BackoffElapsed) => {
                self.state = SupervisorState::Connecting {
                    attempt: next_attempt,
                };
                vec![SupervisorAction::InitiateConnect]
            }
            (_, SupervisorInput::AdapterPowered(false))
                if !matches!(
                    self.state,
                    SupervisorState::AdapterOff | SupervisorState::Stopped
                ) =>
            {
                self.state = SupervisorState::AdapterOff;
                vec![SupervisorAction::Emit(SupervisorEvent::AdapterUnavailable)]
            }
            (SupervisorState::AdapterOff, SupervisorInput::AdapterPowered(true)) => {
                self.state = SupervisorState::Connecting { attempt: 1 };
                vec![SupervisorAction::InitiateConnect]
            }
            (_, SupervisorInput::UserDisconnect) if self.state != SupervisorState::Stopped => {
                self.state = SupervisorState::Stopped;
                vec![
                    SupervisorAction::Emit(SupervisorEvent::Stopped { final_reason: None }),
                    SupervisorAction::Stop,
                ]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_zero_attempt_is_zero() {
        // No "attempt 0" — we only back off between attempts, not before attempt 1.
        assert_eq!(delay(0, ReconnectPolicy::default()), Duration::ZERO);
    }

    #[test]
    fn delay_grows_with_default_policy_up_to_cap() {
        let p = ReconnectPolicy::default();
        assert_eq!(delay(1, p), Duration::from_millis(500));
        assert_eq!(delay(2, p), Duration::from_secs(1));
        assert_eq!(delay(3, p), Duration::from_secs(2));
        assert_eq!(delay(4, p), Duration::from_secs(4));
        assert_eq!(delay(5, p), Duration::from_secs(8));
        assert_eq!(delay(6, p), Duration::from_secs(16));
        // 0.5 * 2^6 = 32, capped to 30.
        assert_eq!(delay(7, p), Duration::from_secs(30));
        // Past the cap, stays at the cap.
        assert_eq!(delay(20, p), Duration::from_secs(30));
    }

    #[test]
    fn start_from_idle_initiates_first_connect() {
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        assert_eq!(sup.state(), SupervisorState::Idle);
        let actions = sup.step(SupervisorInput::Start);
        assert_eq!(
            sup.state(),
            SupervisorState::Connecting { attempt: 1 },
            "Start must move the supervisor into Connecting on attempt 1"
        );
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(actions[0], SupervisorAction::InitiateConnect),
            "first action after Start is InitiateConnect"
        );
    }

    #[test]
    fn attempt_succeeded_transitions_to_listening() {
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        let actions = sup.step(SupervisorInput::AttemptSucceeded);
        assert_eq!(sup.state(), SupervisorState::Listening);
        assert!(
            actions.is_empty(),
            "no side-effects on a successful attempt — the runner is already listening"
        );
    }

    #[test]
    fn retryable_failure_from_connecting_schedules_backoff() {
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        let actions = sup.step(SupervisorInput::AttemptFailed(
            crate::session::DisconnectReason::PingTimeout,
        ));
        assert_eq!(sup.state(), SupervisorState::Backoff { next_attempt: 2 });
        assert_eq!(actions.len(), 2, "emit Reconnecting + Sleep");
        match &actions[0] {
            SupervisorAction::Emit(SupervisorEvent::Reconnecting {
                attempt,
                after,
                last_reason,
            }) => {
                assert_eq!(*attempt, 2);
                assert_eq!(*after, Duration::from_millis(500));
                assert!(matches!(
                    last_reason,
                    crate::session::DisconnectReason::PingTimeout
                ));
            }
            other => panic!("expected Reconnecting, got {other:?}"),
        }
        assert!(matches!(
            actions[1],
            SupervisorAction::Sleep(d) if d == Duration::from_millis(500)
        ));
    }

    #[test]
    fn fatal_failure_from_connecting_stops_supervisor() {
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        let actions = sup.step(SupervisorInput::AttemptFailed(
            crate::session::DisconnectReason::HandshakeFailed("quick_verify_negative".into()),
        ));
        assert_eq!(sup.state(), SupervisorState::Stopped);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            &actions[0],
            SupervisorAction::Emit(SupervisorEvent::Stopped {
                final_reason: Some(crate::session::DisconnectReason::HandshakeFailed(_))
            })
        ));
        assert!(matches!(actions[1], SupervisorAction::Stop));
    }

    #[test]
    fn retryable_failure_from_listening_resets_attempt_to_one() {
        // If we've held a good session and then lose it, start backoff at attempt 1
        // — the previous connect succeeded, so the accumulated attempt count is
        // stale. A burned-through 30s cap on every future drop is not what we want.
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        sup.step(SupervisorInput::AttemptSucceeded);
        assert_eq!(sup.state(), SupervisorState::Listening);
        let actions = sup.step(SupervisorInput::AttemptFailed(
            crate::session::DisconnectReason::PingTimeout,
        ));
        assert_eq!(sup.state(), SupervisorState::Backoff { next_attempt: 2 });
        match &actions[0] {
            SupervisorAction::Emit(SupervisorEvent::Reconnecting {
                attempt, after, ..
            }) => {
                assert_eq!(*attempt, 2);
                assert_eq!(*after, Duration::from_millis(500), "delay(1) not delay(N)");
            }
            other => panic!("expected Reconnecting, got {other:?}"),
        }
    }

    #[test]
    fn backoff_elapsed_initiates_next_connect() {
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        sup.step(SupervisorInput::AttemptFailed(
            crate::session::DisconnectReason::PingTimeout,
        ));
        let actions = sup.step(SupervisorInput::BackoffElapsed);
        assert_eq!(sup.state(), SupervisorState::Connecting { attempt: 2 });
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SupervisorAction::InitiateConnect));
    }

    #[test]
    fn adapter_off_preempts_any_active_state_and_back_on_restarts_at_one() {
        // Adapter off from Connecting.
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        let actions = sup.step(SupervisorInput::AdapterPowered(false));
        assert_eq!(sup.state(), SupervisorState::AdapterOff);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SupervisorAction::Emit(SupervisorEvent::AdapterUnavailable)
        ));

        // Adapter back on: fresh attempt 1, not resuming whatever was pending.
        let actions = sup.step(SupervisorInput::AdapterPowered(true));
        assert_eq!(sup.state(), SupervisorState::Connecting { attempt: 1 });
        assert!(matches!(actions[0], SupervisorAction::InitiateConnect));

        // Adapter off from Backoff should also preempt.
        let mut sup2 = Supervisor::new(ReconnectPolicy::default());
        sup2.step(SupervisorInput::Start);
        sup2.step(SupervisorInput::AttemptFailed(
            crate::session::DisconnectReason::PingTimeout,
        ));
        assert!(matches!(sup2.state(), SupervisorState::Backoff { .. }));
        sup2.step(SupervisorInput::AdapterPowered(false));
        assert_eq!(sup2.state(), SupervisorState::AdapterOff);
    }

    #[test]
    fn user_disconnect_is_terminal_from_any_active_state() {
        for prep in [
            |s: &mut Supervisor| {
                s.step(SupervisorInput::Start);
            },
            |s: &mut Supervisor| {
                s.step(SupervisorInput::Start);
                s.step(SupervisorInput::AttemptSucceeded);
            },
            |s: &mut Supervisor| {
                s.step(SupervisorInput::Start);
                s.step(SupervisorInput::AttemptFailed(
                    crate::session::DisconnectReason::PingTimeout,
                ));
            },
            |s: &mut Supervisor| {
                s.step(SupervisorInput::Start);
                s.step(SupervisorInput::AdapterPowered(false));
            },
        ] {
            let mut sup = Supervisor::new(ReconnectPolicy::default());
            prep(&mut sup);
            let actions = sup.step(SupervisorInput::UserDisconnect);
            assert_eq!(sup.state(), SupervisorState::Stopped);
            assert_eq!(actions.len(), 2);
            assert!(matches!(
                &actions[0],
                SupervisorAction::Emit(SupervisorEvent::Stopped { final_reason: None })
            ));
            assert!(matches!(actions[1], SupervisorAction::Stop));
        }
    }

    #[test]
    fn stopped_absorbs_all_further_inputs() {
        // Once the supervisor has stopped — whether by fatal failure or by user —
        // no further inputs should produce actions or state changes. Late-arriving
        // events from racing async tasks must be safe to feed in.
        let mut sup = Supervisor::new(ReconnectPolicy::default());
        sup.step(SupervisorInput::Start);
        sup.step(SupervisorInput::UserDisconnect);
        assert_eq!(sup.state(), SupervisorState::Stopped);

        for input in [
            SupervisorInput::Start,
            SupervisorInput::AttemptSucceeded,
            SupervisorInput::AttemptFailed(crate::session::DisconnectReason::PingTimeout),
            SupervisorInput::BackoffElapsed,
            SupervisorInput::AdapterPowered(false),
            SupervisorInput::AdapterPowered(true),
            SupervisorInput::UserDisconnect,
        ] {
            let actions = sup.step(input);
            assert_eq!(sup.state(), SupervisorState::Stopped);
            assert!(
                actions.is_empty(),
                "Stopped must be absorbing for all inputs"
            );
        }
    }

    #[test]
    fn delay_respects_custom_policy() {
        let p = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            multiplier: 3.0,
        };
        assert_eq!(delay(1, p), Duration::from_millis(100));
        assert_eq!(delay(2, p), Duration::from_millis(300));
        assert_eq!(delay(3, p), Duration::from_millis(900));
        // 0.1 * 3^3 = 2.7 s, capped to 1 s.
        assert_eq!(delay(4, p), Duration::from_secs(1));
    }
}
