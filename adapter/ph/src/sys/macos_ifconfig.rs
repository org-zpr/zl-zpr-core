//! Parsing of macOS `ifconfig <if>` output for address inspection.
//!
//! `ZprTun::has_address` shells out to `/sbin/ifconfig` and must decide
//! whether the device already carries a given IPv6 address. The output
//! prints link-local addresses with a `%<ifname>` scope suffix and
//! non-link-local addresses (ZPR ULAs such as `fd5a:5052::…`) without one:
//!
//! ```text
//! utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
//!         inet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
//!         inet6 fd5a:5052::abcd prefixlen 64
//!         nd6 options=201<PERFORMNUD,DAD>
//! ```
//!
//! PR #66 review (P1): the previous check searched for the literal
//! `inet6 <addr>%`, so a ZPR address was added successfully and then
//! immediately reported missing — `local_zpr_addrs_missing_from_tun`
//! hard-stopped every macOS node. This parser recognizes both forms by
//! parsing the address token rather than substring-matching (which would
//! also let `fd5a::1` match a line carrying `fd5a::10`).
//!
//! Platform-neutral on purpose: only
//! `sys::macos::zprtun` calls it at runtime, but compiling it on every OS
//! keeps it unit-testable from a Linux build.

use std::net::Ipv6Addr;

/// Report whether `ifconfig <if>` output shows `addr` configured.
///
/// An address line is `inet6 <addr>[%scope] prefixlen …`; the `%<ifname>`
/// scope suffix appears only on link-local addresses. The token is parsed
/// back to an [`Ipv6Addr`] and compared by value, so textual variants
/// match and a shorter address cannot substring-match a longer one.
pub fn reports_inet6_address(ifconfig_stdout: &str, addr: Ipv6Addr) -> bool {
    ifconfig_stdout.lines().any(|line| {
        let Some(rest) = line.trim_start().strip_prefix("inet6 ") else {
            return false;
        };
        let Some(token) = rest.split_whitespace().next() else {
            return false;
        };
        // Strip the %scope suffix link-local addresses carry.
        let token = token.split('%').next().unwrap_or(token);
        token.parse::<Ipv6Addr>() == Ok(addr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const IFCONFIG_OUTPUT: &str = "\
utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
\tinet6 fd5a:5052::abcd prefixlen 64
\tnd6 options=201<PERFORMNUD,DAD>
";

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// PR #66 review P1, the bug itself: ZPR ULA addresses print WITHOUT a
    /// `%scope` suffix and must still be recognized.
    #[test]
    fn unscoped_ula_address_is_recognized() {
        assert!(reports_inet6_address(
            IFCONFIG_OUTPUT,
            v6("fd5a:5052::abcd")
        ));
    }

    #[test]
    fn scoped_link_local_address_is_recognized() {
        assert!(reports_inet6_address(
            IFCONFIG_OUTPUT,
            v6("fe80::e9b0:1972:d221:2196")
        ));
    }

    #[test]
    fn absent_address_is_not_reported() {
        assert!(!reports_inet6_address(IFCONFIG_OUTPUT, v6("fd5a:5052::1")));
    }

    /// Comparison is by parsed value, not substring: `fd5a:5052::abc` must
    /// not match the line carrying `fd5a:5052::abcd`.
    #[test]
    fn prefix_substring_does_not_match() {
        assert!(!reports_inet6_address(
            IFCONFIG_OUTPUT,
            v6("fd5a:5052::abc")
        ));
    }

    /// Textual variants of the same address compare equal: the query is
    /// parsed, not formatted, so zero-expansion differences cannot miss.
    #[test]
    fn textual_variant_matches() {
        assert!(reports_inet6_address(
            IFCONFIG_OUTPUT,
            v6("fd5a:5052:0:0:0:0:0:abcd")
        ));
    }

    #[test]
    fn empty_output_reports_nothing() {
        assert!(!reports_inet6_address("", v6("fd5a:5052::abcd")));
    }
}
