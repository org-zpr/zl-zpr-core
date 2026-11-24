//! Renewal timing for a Zode's own login ([crate::zode_login]): when a
//! silent renewal is due, and how long one attempt may wait on the
//! AuthAgent (zipline#45). Pure functions, so the timing is unit-tested
//! without a clock.

use crate::config;
use std::time::{Duration, SystemTime};

/// The effective renewal lead for a granted authentication lifetime:
/// the configured lead clamped to half the lifetime, so short
/// `expiration_seconds` values still renew ahead of expiry by a workable
/// margin instead of the lead swallowing the whole window (zipline#45).
pub fn renewal_lead(configured: Duration, granted_lifetime: Duration) -> Duration {
    configured.min(granted_lifetime / 2)
}

/// The instant renewal becomes due for an authentication granted at
/// `granted_at` and expiring at `auth_expires`:
/// `auth_expires - renewal_lead(configured, lifetime)`.
/// An already-past (or zero-length) expiry yields a deadline that is never
/// in the future, so renewal is due immediately.
pub fn renewal_deadline(
    granted_at: SystemTime,
    auth_expires: SystemTime,
    configured_lead: Duration,
) -> SystemTime {
    let lifetime = auth_expires
        .duration_since(granted_at)
        .unwrap_or(Duration::ZERO);
    let lead = renewal_lead(configured_lead, lifetime);
    auth_expires.checked_sub(lead).unwrap_or(auth_expires)
}

/// Floor for one silent-renewal attempt's wait on the AuthAgent: even with
/// (nearly) no window left, give a healthy agent a moment to answer from its
/// refresh-token cache instead of a zero-length wait.
pub const RENEWAL_ATTEMPT_TIMEOUT_FLOOR: Duration = Duration::from_secs(5);

/// How long ONE silent-renewal attempt may wait: half the time remaining
/// before `auth_expires`, clamped between [RENEWAL_ATTEMPT_TIMEOUT_FLOOR]
/// and the agent bridge's own per-call bound
/// ([config::OIDC_USER_INTERACTION_TIMEOUT]). Bounding by the remaining
/// window means a hung request cannot pin `in_flight` past the point where
/// a retry could still succeed against the current authentication — half,
/// so at least one full retry fits in the window left (PR #14 review).
pub fn renewal_attempt_timeout(now: SystemTime, auth_expires: SystemTime) -> Duration {
    let remaining = auth_expires.duration_since(now).unwrap_or(Duration::ZERO);
    (remaining / 2).clamp(
        RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        config::OIDC_USER_INTERACTION_TIMEOUT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `renewal_lead` clamps the configured lead to half the granted
    /// lifetime, so short `expiration_seconds` values still renew ahead of
    /// expiry by a workable margin (zipline#45).
    #[test]
    fn test_renewal_lead_clamps_to_half_lifetime() {
        let configured = Duration::from_secs(300);
        // Long lifetime: the configured lead stands.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(3600)),
            configured
        );
        // Lifetime of exactly 2x the lead: still the configured lead.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(600)),
            configured
        );
        // Short lifetime: clamped to half.
        assert_eq!(
            renewal_lead(configured, Duration::from_secs(120)),
            Duration::from_secs(60)
        );
        // Zero lifetime: zero lead (due at expiry, i.e. immediately).
        assert_eq!(renewal_lead(configured, Duration::ZERO), Duration::ZERO);
    }

    /// `renewal_deadline` is `auth_expires - effective lead`; an
    /// already-past expiry is due immediately (deadline not in the future).
    #[test]
    fn test_renewal_deadline_including_past_expiry() {
        let configured = Duration::from_secs(300);
        let now = SystemTime::now();

        // 1h lifetime: deadline is expiry minus the full 300s lead.
        let expires = now + Duration::from_secs(3600);
        assert_eq!(
            renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(300)
        );

        // 120s lifetime: lead clamps to 60s.
        let expires = now + Duration::from_secs(120);
        assert_eq!(
            renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(60)
        );

        // Expiry already in the past: lifetime saturates to zero, so the
        // deadline equals the (past) expiry — renewal is due immediately.
        let expires = now - Duration::from_secs(10);
        let deadline = renewal_deadline(now, expires, configured);
        assert_eq!(deadline, expires);
        assert!(deadline <= now, "past expiry must be due immediately");
    }

    /// PR #14 review: one silent-renewal attempt waits at most half the time
    /// remaining before expiry — clamped between the 5 s floor and the 300 s
    /// interaction timeout — so a hung attempt can always be retried while
    /// the current authentication is still valid.
    #[test]
    fn test_renewal_attempt_timeout_bounded_by_remaining_window() {
        let now = SystemTime::now();
        // Plenty of window: capped at the bridge's own per-call bound.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(3600)),
            config::OIDC_USER_INTERACTION_TIMEOUT,
        );
        // 600 s remaining (the default-lead case that motivated the review
        // finding): half the window, leaving room for a retry before expiry.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(600)),
            Duration::from_secs(300),
        );
        // 60 s remaining: 30 s, again half.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(60)),
            Duration::from_secs(30),
        );
        // Nearly (or already) expired: the floor keeps a healthy agent
        // answerable instead of a zero-length wait.
        assert_eq!(
            renewal_attempt_timeout(now, now + Duration::from_secs(4)),
            RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
        assert_eq!(
            renewal_attempt_timeout(now, now - Duration::from_secs(10)),
            RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
    }
}
