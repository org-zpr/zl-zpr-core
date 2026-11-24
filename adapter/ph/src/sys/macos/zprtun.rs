use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

// TODO: This logging is used to debug the use of local commands for TUN address management. Remove once we use syscalls.
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::macos::tun;
use crate::sys::macos_ifconfig;
use crate::zprtun::ZprTunError;
use std::process::Command;

const COMMAND_IFCONFIG: &str = "/sbin/ifconfig";

pub struct ZprTun {
    inner: tun::Tun,
    mtx: std::sync::Mutex<()>,
}

impl From<tun::TunError> for ZprTunError {
    fn from(e: tun::TunError) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

/// The control socket's address family for the `address` [`ZprTun::new_mq`]
/// was given: the address's own family, or IPv6 when there is none — the
/// family of the old `ZPR_TEMP_LOCAL_ADDRESS` placeholder `main.rs` used to
/// pass before zipline#177 moved the fallback here. Pure decision, split out
/// so it is unit-testable without creating a utun.
fn control_socket_ipv(address: Option<IpAddr>) -> tun::IPV {
    address.map(tun::IPV::from).unwrap_or(tun::IPV::V6)
}

impl ZprTun {
    fn new(inner: tun::Tun) -> Self {
        ZprTun {
            inner,
            mtx: std::sync::Mutex::new(()),
        }
    }

    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// On macOS if the name is specificed, it must be of the form `utun[0-9]+`.
    ///
    /// The utun is created unaddressed — `address` is only used to pick the
    /// address family of the control socket (IPv6 when `None`, which is the
    /// ZPR case: the internal network is IPv6) — and is addressed later via
    /// [`ZprTun::add_address`], the same lifecycle as Linux and Windows
    /// (zipline#161).
    ///
    /// IPv4 ZPR addresses are not supported on macOS: `add_address` (like
    /// `has_address`, `clear_address`) returns `Unsupported`
    /// for IPv4, and no create-time path ever installed one — the old
    /// builder `with_address` was never called (PR #66 review). The ZPR
    /// internal network is IPv6 (`fd5a:5052::/32`).
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }
        let ipv = control_socket_ipv(address);
        let mut bldr = tun::Tun::builder(ipv);
        if let Some(name) = ifname {
            bldr.with_tun_name(&name);
        }
        let dev = tun::Tun::create(&bldr)?;
        Ok(vec![ZprTun::new(dev)])
    }

    /// The interface name of this utun, as the kernel assigned it — e.g.
    /// `utun7`, which can differ on every start (zipline#202).
    pub fn name(&self) -> String {
        self.inner.get_name().to_string()
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    pub fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, prefix_len, false)
    }

    pub fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        self.add_address_impl(addr, prefix_len, true)
    }

    fn add_address_impl(
        &self,
        addr: IpAddr,
        prefix_len: u8,
        authentication: bool,
    ) -> std::io::Result<()> {
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        if self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "add_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("alias");
        if authentication {
            c.arg("deprecated");
        }
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to set address on {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if !self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "clear_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("-alias"); // <-- note the MINUS here
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to clear addresses {} on {}: {}",
                    addr,
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    /// Reports whether `addr` is currently configured on this TUN device.
    ///
    /// Does not take the device mutex, so it is safe to call either with or
    /// without it held.
    pub fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        if addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "has_address with IPv4 is not supported on macos",
            ));
        }
        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        //         inet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
        //         inet6 fd5a:5052::abcd prefixlen 64
        //         nd6 options=201<PERFORMNUD,DAD>
        //
        // Note the %utun2 scope suffix on the link-local address and its
        // absence on the ZPR ULA — the parser handles both (PR #66 review).
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to show addresses for {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        let out_str = String::from_utf8_lossy(&output.stdout);
        match addr {
            IpAddr::V4(_) => unreachable!("rejected above"),
            IpAddr::V6(v6) => Ok(macos_ifconfig::reports_inet6_address(&out_str, v6)),
        }
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zipline#161: `new_mq` must create a utun with no address supplied —
    /// the device comes up unaddressed (IPv6 control socket) and is
    /// addressed later via `add_address`, as on Linux and Windows.
    ///
    /// Creating a utun needs root, so this is part of the operator's
    /// macOS gate: `sudo cargo test -p ph -- --ignored`.
    #[test]
    #[ignore = "requires root; run with sudo cargo test -- --ignored"]
    fn new_mq_without_address_creates_ipv6_utun() {
        let devs = ZprTun::new_mq(Some("utun9".into()), 1, None)
            .expect("new_mq with no address must create the utun");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].inner.get_name(), "utun9");
    }

    /// zipline#177: the ZPR_TEMP_LOCAL_ADDRESS fallback moved here from
    /// `main.rs`, which now passes `None` where it used to pass
    /// `Some(ZPR_TEMP_LOCAL_ADDRESS)` — so `None` must pick the same
    /// control-socket address family that address produced (IPv6). Pure
    /// decision, no utun created, no root needed.
    #[test]
    fn no_address_fallback_keeps_temp_address_family() {
        use zpr::addrs::ZPR_TEMP_LOCAL_ADDRESS;
        assert_eq!(
            control_socket_ipv(None),
            tun::IPV::from(IpAddr::from(ZPR_TEMP_LOCAL_ADDRESS))
        );
    }
}
