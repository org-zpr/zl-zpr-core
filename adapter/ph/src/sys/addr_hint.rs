//! The manual add-address hint: the one command line `ph` tells an operator
//! to run when a node ZPR address could not be applied to — or is missing
//! from — the TUN device (zipline#161). Also the Windows `netsh` add-address
//! arguments, which the Windows `add_address` runs and the Windows hint
//! prints, so the two cannot drift apart (zl-zipline#272, zl-zipline#297).
//!
//! Compiled on every OS so the per-platform strings stay unit-testable from
//! Linux builds, same pattern and reason as `macos_ifconfig`: the decision of
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
        // `prefix_len` does not apply: Windows adds a /128 (see
        // `netsh_add_address_args`).
        Platform::Windows => {
            let args: Vec<String> = netsh_add_address_args(ifname, addr, false)
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

/// The prefix length of every address `ph` puts on the Windows TUN adapter.
///
/// The ZPR prefix is not on-link on Windows: the adapter routes it through a
/// link-local next hop (`zprtun.rs`, zl-zipline#297). An on-link prefix makes
/// Windows send neighbor solicitations to every peer it talks to, and Windows
/// cannot turn neighbor unreachability detection off on a Wintun interface,
/// so those solicitations reached `ph` as traffic to the visa service.
const WINDOWS_ADDRESS_PREFIX_LEN: u8 = 128;

/// The `netsh interface ipv6` arguments that put `addr` on `ifname` as a
/// /128 ([`WINDOWS_ADDRESS_PREFIX_LEN`]): what the Windows `add_address`
/// runs, and what the Windows hint prints.
///
/// The prefix length is explicit: without it netsh applies /64
/// (zl-zipline#272). `deprecated` adds `preferredlifetime=0`, which keeps the
/// address valid but not preferred as a source (the adapter authentication
/// address, #1410).
pub(crate) fn netsh_add_address_args(ifname: &str, addr: &IpAddr, deprecated: bool) -> Vec<String> {
    let mut args = vec![
        "add".to_string(),
        "address".to_string(),
        ifname.to_string(),
        format!("{addr}/{WINDOWS_ADDRESS_PREFIX_LEN}"),
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
        // The interface name comes before the address, and the address is a
        // /128 whatever prefix length the caller names: on Windows the ZPR
        // prefix is routed through a link-local next hop, not on-link
        // (zl-zipline#297).
        assert_eq!(
            hint_for(Platform::Windows, &addr(), 32, "zpr0"),
            "netsh interface ipv6 add address zpr0 fd5a:5052::a:b:c/128"
        );
    }

    #[test]
    fn windows_hint_quotes_an_interface_name_with_spaces() {
        // `ph` passes the name as one argument; a copied command line must
        // too (Wintun adapter names may contain spaces).
        assert_eq!(
            hint_for(Platform::Windows, &addr(), 32, "ZPR tun"),
            "netsh interface ipv6 add address \"ZPR tun\" fd5a:5052::a:b:c/128"
        );
    }

    // --- netsh add-address argv: what the Windows `add_address` runs. The
    // address is always a /128. Without an explicit length netsh applies /64
    // (zl-zipline#272), and an on-link prefix makes Windows probe every peer
    // with neighbor solicitations, which ph turned into visa requests
    // (zl-zipline#297).

    #[test]
    fn netsh_add_address_args_adds_a_host_address() {
        let addr: IpAddr = "fd5a:5052:8888::3".parse().unwrap();
        assert_eq!(
            netsh_add_address_args("zpr", &addr, false),
            ["add", "address", "zpr", "fd5a:5052:8888::3/128"]
        );
    }

    #[test]
    fn netsh_add_address_args_deprecates_the_aaa() {
        // The adapter authentication address is a valid but deprecated
        // source; the flag follows the address.
        assert_eq!(
            netsh_add_address_args("zpr", &addr(), true),
            [
                "add",
                "address",
                "zpr",
                "fd5a:5052::a:b:c/128",
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
}
