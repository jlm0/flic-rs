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
