//! Common interface for the TUN devices.
//!
//! The actual TUN implementation is platform specific and can be found in `sys/<platform>/zprtun.rs`.
//!
//!
//!
use crate::sys::TunPi;

/// The MTU of the ZPR TUN device on every platform. The overlay carries
/// IPv6 packets only up to 1480 bytes and drops larger ones without an
/// ICMPv6 Packet Too Big, so the device must not advertise more than this
/// (zl-zipline#214).
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// The MTU a newly created TUN device gets: the explicitly requested value,
/// or [`DEFAULT_TUN_MTU`] when none was requested.
///
/// PR #66 review (P2): the default must apply unconditionally — before
/// zipline#161 the macOS creation path applied it only when a create-time
/// address was supplied, and once creation stopped taking an address the
/// device would have been left at the kernel default (2000 for a utun),
/// above the 1400 overlay MTU. Platform-neutral so the rule is one place
/// and unit-tested from any host. macOS applies it at creation; Linux goes
/// through [`tun_mtu_to_apply`]; Windows sets it on the fresh Wintun
/// adapter (zl-zipline#214).
pub fn effective_tun_mtu(requested: Option<u16>) -> u16 {
    requested.unwrap_or(DEFAULT_TUN_MTU)
}

/// The MTU to set on an existing TUN device whose MTU is `current`, or
/// `None` to leave it alone.
///
/// The rule only ever lowers the MTU to [`effective_tun_mtu`]: a device
/// above it (a fresh Linux TUN comes up at 1500) black-holes packets the
/// overlay cannot carry (zl-zipline#214), while a smaller MTU an operator
/// chose on a pre-provisioned `tun_if` still fits the overlay and is kept.
/// Leaving a fitting device untouched also lets an unprivileged ph attach
/// to a pre-provisioned TUN, where setting the MTU would fail with EPERM.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn tun_mtu_to_apply(current: u32) -> Option<u16> {
    let target = effective_tun_mtu(None);
    if current > u32::from(target) {
        Some(target)
    } else {
        None
    }
}

/// Error type used by some ZprTun functions across platform implementations.
#[derive(thiserror::Error, Debug)]
pub enum ZprTunError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("platform error from TUN device: {0}")]
    PlatformError(String),
}

/// TRUE if the platform TUN implementation supports per-packet packet info.
pub const TUN_HAS_PI: bool = TunPi::PI_SIZE > 0;

#[cfg(test)]
mod tests {
    use super::*;

    /// PR #66 review (P2): the TUN MTU must not depend on an address being
    /// supplied at creation — an unspecified MTU gets `DEFAULT_TUN_MTU`,
    /// not the kernel default (2000 for a macOS utun, above the overlay's
    /// 1400).
    #[test]
    fn unspecified_mtu_defaults_to_overlay_mtu() {
        assert_eq!(effective_tun_mtu(None), DEFAULT_TUN_MTU);
    }

    #[test]
    fn explicit_mtu_wins() {
        assert_eq!(effective_tun_mtu(Some(1500)), 1500);
    }

    /// zl-zipline#214: a device above the overlay MTU (a fresh Linux TUN
    /// at 1500) is lowered to `DEFAULT_TUN_MTU`.
    #[test]
    fn mtu_above_overlay_is_lowered() {
        assert_eq!(tun_mtu_to_apply(1500), Some(DEFAULT_TUN_MTU));
        assert_eq!(tun_mtu_to_apply(65535), Some(DEFAULT_TUN_MTU));
    }

    /// A device already at the overlay MTU needs no change.
    #[test]
    fn mtu_at_overlay_is_kept() {
        assert_eq!(tun_mtu_to_apply(u32::from(DEFAULT_TUN_MTU)), None);
    }

    /// A smaller MTU an operator chose on a pre-provisioned TUN fits the
    /// overlay and is never raised.
    #[test]
    fn mtu_below_overlay_is_kept() {
        assert_eq!(tun_mtu_to_apply(1300), None);
    }
}
