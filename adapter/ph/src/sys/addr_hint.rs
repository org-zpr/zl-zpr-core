//! The manual add-address hint: the one command line `ph` tells an operator
//! to run when a node ZPR address could not be applied to — or is missing
//! from — the TUN device (zipline#161). Also the Windows `netsh` add-address
//! arguments, which the Windows `add_address` runs and the Windows hint
//! prints, so the two cannot drift apart (zl-zipline#272).
//!
//! Compiled on every OS so the per-platform strings stay unit-testable from
//! Linux builds, same pattern and reason as `macos_route`: the decision of
//! *which* command to print is pure, only the caller is platform-specific.

use std::net::IpAddr;

/// The platform whose command syntax the hint uses. Separated from the
/// `cfg` so every arm is testable on every build host.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Platform {
    Linux,
    MacOs,
    Windows,
}

/// The current platform's arm.
const CURRENT: Platform = if cfg!(target_os = "linux") {
    Platform::Linux
} else if cfg!(target_os = "macos") {
    Platform::MacOs
} else {
    Platform::Windows
};

/// The hint in `platform`'s command syntax.
fn hint_for(platform: Platform, addr: &IpAddr, prefix_len: u8, ifname: &str) -> String {
    match platform {
        Platform::Linux => format!("ip -6 addr add {addr}/{prefix_len} dev {ifname}"),
        Platform::MacOs => format!("ifconfig {ifname} inet6 {addr}/{prefix_len} alias"),
        // Exactly the arguments the Windows `add_address` runs. An argument
        // with a space (a Wintun adapter name may have one) is quoted, so the
        // copied command line passes it as one argument, as `ph` does.
        Platform::Windows => {
            let args: Vec<String> = netsh_add_address_args(ifname, addr, prefix_len, false)
                .into_iter()
                .map(|arg| {
                    if arg.contains(' ') {
                        format!("\"{arg}\"")
                    } else {
                        arg
                    }
                })
                .collect();
            format!("netsh interface ipv6 {}", args.join(" "))
        }
    }
}

/// The `netsh interface ipv6` arguments that put `addr/prefix_len` on
/// `ifname`: what the Windows `add_address` runs, and what the Windows hint
/// prints.
///
/// The prefix length is required: without it netsh applies /64, and nothing
/// outside the address's own /64 (the DNS Zode included) is on-link
/// (zl-zipline#272). With it, Windows installs the on-link route for the
/// prefix itself, as Linux and macOS do. `deprecated` adds
/// `preferredlifetime=0`, which keeps the address valid but not preferred as
/// a source (the adapter authentication address, #1410).
pub(crate) fn netsh_add_address_args(
    ifname: &str,
    addr: &IpAddr,
    prefix_len: u8,
    deprecated: bool,
) -> Vec<String> {
    let mut args = vec![
        "add".to_string(),
        "address".to_string(),
        ifname.to_string(),
        format!("{addr}/{prefix_len}"),
    ];
    if deprecated {
        args.push("preferredlifetime=0".to_string());
    }
    args
}

/// The command an operator runs to put `addr/prefix_len` on `ifname` by
/// hand, in the current platform's syntax.
pub fn manual_add_address_hint(addr: &IpAddr, prefix_len: u8, ifname: &str) -> String {
    hint_for(CURRENT, addr, prefix_len, ifname)
}

/// The manual add-route hint in `platform`'s command syntax, or `None` when
/// that platform's route-failure message carries no command (zipline#177).
///
/// Only Windows needs one: the /128 visa-service host route is a separate
/// `netsh add route` step there (see `Assembly::ensure_local_zpr_addrs_on_tun`
/// for why it is kept). On Linux and macOS no such route is installed, and
/// the failure message has never suggested a command.
fn route_hint_for(platform: Platform, addr: &IpAddr, ifname: &str) -> Option<String> {
    match platform {
        Platform::Linux | Platform::MacOs => None,
        // The interface name is quoted: Wintun adapter names may contain
        // spaces.
        Platform::Windows => Some(format!(
            "netsh interface ipv6 add route {addr}/128 \"{ifname}\""
        )),
    }
}

/// The command an operator runs to install the /128 host route to `addr` on
/// `ifname` by hand, in the current platform's syntax — `None` where no
/// manual command applies.
pub fn manual_add_route_hint(addr: &IpAddr, ifname: &str) -> Option<String> {
    route_hint_for(CURRENT, addr, ifname)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn addr() -> IpAddr {
        "fd5a:5052::a:b:c".parse().unwrap()
    }

    #[test]
    fn linux_hint_is_ip_addr_add() {
        assert_eq!(
            hint_for(Platform::Linux, &addr(), 32, "zpr0"),
            "ip -6 addr add fd5a:5052::a:b:c/32 dev zpr0"
        );
    }

    #[test]
    fn macos_hint_is_ifconfig_inet6_alias() {
        assert_eq!(
            hint_for(Platform::MacOs, &addr(), 32, "utun4"),
            "ifconfig utun4 inet6 fd5a:5052::a:b:c/32 alias"
        );
    }

    #[test]
    fn windows_hint_is_netsh_add_address() {
        // The interface name comes before the address, and the address
        // carries the prefix length: without it netsh applies /64
        // (zl-zipline#272).
        assert_eq!(
            hint_for(Platform::Windows, &addr(), 32, "zpr0"),
            "netsh interface ipv6 add address zpr0 fd5a:5052::a:b:c/32"
        );
    }

    #[test]
    fn windows_hint_quotes_an_interface_name_with_spaces() {
        // `ph` passes the name as one argument; a copied command line must
        // too (Wintun adapter names may contain spaces).
        assert_eq!(
            hint_for(Platform::Windows, &addr(), 32, "ZPR tun"),
            "netsh interface ipv6 add address \"ZPR tun\" fd5a:5052::a:b:c/32"
        );
    }

    // --- netsh add-address argv (zl-zipline#272): what the Windows
    // `add_address` runs. Without the prefix length netsh applies /64, and
    // nothing outside the Zode's own /64 (the DNS Zode included) is on-link.

    #[test]
    fn netsh_add_address_args_applies_the_prefix() {
        let addr: IpAddr = "fd5a:5052:8888::3".parse().unwrap();
        assert_eq!(
            netsh_add_address_args("zpr", &addr, 32, false),
            ["add", "address", "zpr", "fd5a:5052:8888::3/32"]
        );
    }

    #[test]
    fn netsh_add_address_args_deprecates_the_aaa() {
        // The adapter authentication address is a valid but deprecated
        // source; the flag follows the address.
        assert_eq!(
            netsh_add_address_args("zpr", &addr(), 32, true),
            [
                "add",
                "address",
                "zpr",
                "fd5a:5052::a:b:c/32",
                "preferredlifetime=0"
            ]
        );
    }

    #[test]
    fn public_fn_uses_the_current_platform_arm() {
        let expected = if cfg!(target_os = "linux") {
            hint_for(Platform::Linux, &addr(), 32, "zpr0")
        } else if cfg!(target_os = "macos") {
            hint_for(Platform::MacOs, &addr(), 32, "zpr0")
        } else {
            hint_for(Platform::Windows, &addr(), 32, "zpr0")
        };
        assert_eq!(manual_add_address_hint(&addr(), 32, "zpr0"), expected);
    }

    // --- route hint (zipline#177): the manual add-route command printed
    // when the visa-service host route could not be installed. Only
    // Windows needs one — the /128 route is a separate step there; on Linux
    // and macOS the route failure message carries no command today, and None
    // keeps it that way.

    #[test]
    fn windows_route_hint_is_netsh_add_route() {
        // Exact current main.rs string, including the quotes around the
        // interface name (Wintun adapter names may contain spaces).
        assert_eq!(
            route_hint_for(Platform::Windows, &addr(), "zpr0").as_deref(),
            Some("netsh interface ipv6 add route fd5a:5052::a:b:c/128 \"zpr0\"")
        );
    }

    #[test]
    fn linux_route_hint_is_none() {
        assert_eq!(route_hint_for(Platform::Linux, &addr(), "zpr0"), None);
    }

    #[test]
    fn macos_route_hint_is_none() {
        assert_eq!(route_hint_for(Platform::MacOs, &addr(), "utun4"), None);
    }

    #[test]
    fn public_route_fn_uses_the_current_platform_arm() {
        let expected = if cfg!(target_os = "linux") {
            route_hint_for(Platform::Linux, &addr(), "zpr0")
        } else if cfg!(target_os = "macos") {
            route_hint_for(Platform::MacOs, &addr(), "zpr0")
        } else {
            route_hint_for(Platform::Windows, &addr(), "zpr0")
        };
        assert_eq!(manual_add_route_hint(&addr(), "zpr0"), expected);
    }
}
