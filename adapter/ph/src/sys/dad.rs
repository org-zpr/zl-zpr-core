//! Waiting out IPv6 duplicate-address detection on a freshly added address
//! (zipline#162, checklist item 1 of `integration-test/windows-node-test.md`).
//!
//! Windows runs DAD on the Wintun adapter: an address added with `netsh`
//! sits in the *tentative* state for about a second (`DadTransmits` = 1,
//! `RetransmitTimeMs` = 1000), and binding a socket to it in that window
//! fails with `WSAEADDRNOTAVAIL` (10049). The node binds its VSS listener to
//! its ZPR address right after self-addressing, so it lost that race on
//! every start in the first VM run. The Windows `add_address` therefore
//! waits — bounded — until the address leaves the tentative state.
//!
//! This module is the platform-neutral half: the DAD-state model and the
//! polling loop. It is compiled on every OS so it stays unit-testable from
//! Linux builds (same pattern as `macos_ifconfig`); only Windows calls it at
//! runtime, supplying a probe that reads the state through IP Helper.

use std::io::{Error, ErrorKind, Result};
use std::time::{Duration, Instant};

/// How long `add_address` waits for DAD to finish before giving up. DAD on
/// Wintun took ~1.4 s in the first VM run; a generous bound keeps a slow
/// box from failing while still turning a stuck address into an error
/// rather than a hang.
pub const DAD_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the DAD state is re-read while waiting.
pub const DAD_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The DAD state of one address, as reported by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DadState {
    /// Not yet usable; DAD is in progress (`IpDadStateTentative`).
    Tentative,
    /// DAD found another holder of the address (`IpDadStateDuplicate`).
    Duplicate,
    /// Usable as a source and bind address (`IpDadStatePreferred` or
    /// `IpDadStateDeprecated`).
    Usable,
    /// Any other value, including `IpDadStateInvalid`; not usable yet.
    Other(i32),
}

impl DadState {
    /// Map a Win32 `NL_DAD_STATE` value onto [`DadState`]. The numeric
    /// values are fixed by the Windows SDK (`nldef.h`) and repeated here so
    /// this mapping compiles — and is tested — on every OS.
    pub fn from_nl_dad_state(raw: i32) -> Self {
        match raw {
            1 => DadState::Tentative,
            2 => DadState::Duplicate,
            3 | 4 => DadState::Usable,
            other => DadState::Other(other),
        }
    }
}

/// Poll `probe` until the address it describes is usable, sleeping
/// `interval` between reads, for at most `timeout`.
///
/// `probe` returns the address's current DAD state. A `NotFound` error is
/// treated as "not visible yet" and polled again, like `Tentative`; any
/// other probe error is returned immediately. A `Duplicate` result fails
/// with `AddrInUse` — waiting cannot fix it. Running out of time fails with
/// `TimedOut`, naming the last state seen.
pub fn wait_until_usable(
    mut probe: impl FnMut() -> Result<DadState>,
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        // `None` = the address is not visible to the OS query yet.
        let state = match probe() {
            Ok(DadState::Usable) => return Ok(()),
            Ok(DadState::Duplicate) => {
                return Err(Error::new(
                    ErrorKind::AddrInUse,
                    "duplicate-address detection found the address in use on the link",
                ));
            }
            Ok(state) => Some(state),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if Instant::now() >= deadline {
            let seen = state.map_or("not found".to_string(), |s| format!("{s:?}"));
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("address still not usable after {timeout:?} (last DAD state: {seen})"),
            ));
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that returns the given results in order, then repeats the last.
    fn scripted(results: Vec<Result<DadState>>) -> impl FnMut() -> Result<DadState> {
        let mut results = results
            .into_iter()
            .collect::<std::collections::VecDeque<_>>();
        move || {
            if results.len() > 1 {
                results.pop_front().expect("non-empty")
            } else {
                match results.front().expect("at least one scripted result") {
                    Ok(state) => Ok(*state),
                    Err(e) => Err(Error::new(e.kind(), e.to_string())),
                }
            }
        }
    }

    #[test]
    fn nl_dad_state_values_map_per_nldef() {
        assert_eq!(DadState::from_nl_dad_state(0), DadState::Other(0));
        assert_eq!(DadState::from_nl_dad_state(1), DadState::Tentative);
        assert_eq!(DadState::from_nl_dad_state(2), DadState::Duplicate);
        assert_eq!(DadState::from_nl_dad_state(3), DadState::Usable);
        assert_eq!(DadState::from_nl_dad_state(4), DadState::Usable);
        assert_eq!(DadState::from_nl_dad_state(9), DadState::Other(9));
    }

    #[test]
    fn already_usable_returns_immediately() {
        let probe = scripted(vec![Ok(DadState::Usable)]);
        wait_until_usable(probe, Duration::ZERO, Duration::ZERO).expect("usable");
    }

    #[test]
    fn tentative_then_usable_succeeds() {
        // The sequence the first VM run observed: tentative, then preferred.
        let probe = scripted(vec![
            Err(Error::from(ErrorKind::NotFound)),
            Ok(DadState::Tentative),
            Ok(DadState::Other(0)),
            Ok(DadState::Tentative),
            Ok(DadState::Usable),
        ]);
        wait_until_usable(probe, Duration::from_secs(5), Duration::ZERO).expect("usable");
    }

    #[test]
    fn stuck_tentative_times_out() {
        let probe = scripted(vec![Ok(DadState::Tentative)]);
        let err = wait_until_usable(probe, Duration::from_millis(20), Duration::ZERO)
            .expect_err("must time out");
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(err.to_string().contains("Tentative"), "{err}");
    }

    #[test]
    fn duplicate_fails_without_waiting() {
        let probe = scripted(vec![Ok(DadState::Duplicate)]);
        let err = wait_until_usable(probe, Duration::from_secs(60), Duration::from_secs(60))
            .expect_err("duplicate must fail");
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
    }

    #[test]
    fn probe_error_other_than_not_found_propagates() {
        let probe = scripted(vec![Err(Error::from(ErrorKind::PermissionDenied))]);
        let err = wait_until_usable(probe, Duration::from_secs(60), Duration::from_secs(60))
            .expect_err("probe error must propagate");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }
}
