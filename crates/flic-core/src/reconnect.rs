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
