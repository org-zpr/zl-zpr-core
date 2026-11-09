use nix::ioctl_write_ptr;
use std::io::Result;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::process::Command;
use tokio_tun::{Tun, TunBuilder};

// TODO: This logging is used to debug the use of local commands for TUN address management. Remove once we use syscalls.
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::linux_route;
use crate::zprtun::ZprTunError;

const COMMAND_IP: &str = "/usr/sbin/ip";

// from /usr/include/linux/if_tun.h
ioctl_write_ptr!(tun_set_carrier, b'T', 226, libc::c_int);

pub struct ZprTun {
    ifname: String,
    owned_fd: OwnedFd,
    mtx: std::sync::Mutex<()>, // Used for single threaded operation when using the `ip` command.
}

impl From<Tun> for ZprTun {
    fn from(tun: Tun) -> Self {
        // SAFETY: the FD is live until we exit this function
        ZprTun {
            ifname: String::from(tun.name()),
            owned_fd: (unsafe { BorrowedFd::borrow_raw(tun.as_raw_fd()) })
                .try_clone_to_owned()
                .unwrap(),
            mtx: std::sync::Mutex::new(()),
        }
    }
}

/// Builder settings shared by every Linux TUN device ph opens: the
/// packet-information header, the interface name and the optional IPv4
/// address. The caller sets the queue count and builds.
fn tun_builder(
    ifname: Option<&str>,
    address: Option<IpAddr>,
) -> std::result::Result<TunBuilder, ZprTunError> {
    // ph's TUN framing reads and writes the 4-byte packet-information
    // header on Linux (zprtun::TUN_HAS_PI / sys::TunPi). tokio-tun 0.15
    // sets IFF_NO_PI unless asked (0.11 defaulted to packet info on), so
    // request it explicitly. Without it packets are silently misframed.
    let mut bldr = TunBuilder::new().packet_info();
    if let Some(ifname) = ifname {
        bldr = bldr.name(ifname);
    }
    if let Some(addr) = address {
        match addr {
            IpAddr::V4(ipa) => bldr = bldr.address(ipa),
            IpAddr::V6(_) => {
                return Err(ZprTunError::PlatformError(
                    "IPv6 address on TUN at create time not supported on linux".into(),
                ));
            }
        }
    }
    Ok(bldr)
}

impl ZprTun {
    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// For optional `address`, only IPv4 is supported currently.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        let tok_tun_devs = tun_builder(ifname.as_deref(), address)?
            .queues(concurrency)
            .build()
            .or_else(|e| Err(ZprTunError::PlatformError(e.to_string())))?;

        //let tun_ifname = String::from(tok_tun_devs[0].name());

        Ok(tok_tun_devs.into_iter().map(ZprTun::from).collect())
    }

    /// The interface name of this TUN device, as the kernel reports it
    /// (zipline#202).
    pub fn name(&self) -> String {
        self.ifname.clone()
    }

    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        // SAFETY: the temporary pointer is valid for the lifetime of the ioctl, which is sufficient
        unsafe { tun_set_carrier(self.owned_fd.as_raw_fd(), &carrier.into()) }?;
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
        if self.has_address_locked(addr)? {
            return Ok(());
        }
        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("add")
            .arg(format!("{}/{}", addr, prefix_len))
            .arg("dev")
            .arg(&self.ifname);
        if authentication {
            c.arg("preferred_lft").arg("0");
        }
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to set addresses for {} to '{}' {}",
                    self.ifname,
                    addr,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        // Set UP also:
        let mut c = Command::new(COMMAND_IP);
        c.arg("link").arg("set").arg(&self.ifname).arg("up");
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to set link up for {}: {}",
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    /// Ensure `dest/prefix_len` is routed on-link via this TUN device.
    ///
    /// `ip -6 route replace` succeeds whether or not the route is already
    /// present, so the call is idempotent — the same reason `add_address`
    /// checks first, achieved here by the kernel's own replace semantics.
    pub fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if dest.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "add_route with IPv4 is not supported on linux",
            ));
        }
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;
        let mut c = Command::new(COMMAND_IP);
        c.arg("-6")
            .arg("route")
            .arg("replace")
            .arg(format!("{}/{}", dest, prefix_len))
            .arg("dev")
            .arg(&self.ifname);
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to install route {}/{} on {}: {}",
                    dest,
                    prefix_len,
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    /// Report another live interface already carrying the route for
    /// `dest/prefix_len`, if any (zipline#101).
    ///
    /// Reads `ip -6 route show <prefix>` — an unprivileged, read-only
    /// query, so pre-provisioned `tun_if` instances running without
    /// privileges can still perform the check. A route on this TUN or on a
    /// `linkdown` interface (a persistent TUN with nobody attached, whose
    /// stale route must not block startup) is not a conflict.
    pub fn route_owner_conflict(
        &self,
        dest: IpAddr,
        prefix_len: u8,
    ) -> std::io::Result<Option<String>> {
        if dest.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "route_owner_conflict with IPv4 is not supported on linux",
            ));
        }
        let mut c = Command::new(COMMAND_IP);
        c.arg("-6")
            .arg("route")
            .arg("show")
            .arg(format!("{}/{}", dest, prefix_len));
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to show routes for {}/{}: {}",
                    dest,
                    prefix_len,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        let owners = linux_route::parse_route_show(&String::from_utf8_lossy(&output.stdout));
        Ok(
            linux_route::route_owner_conflict(&owners, &self.ifname, linux_route::Platform::Linux)
                .map(|conflict| conflict.ifname),
        )
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        if !self.has_address_locked(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("del")
            .arg(format!("{}/{}", addr, prefix_len))
            .arg("dev")
            .arg(&self.ifname);
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to clear addresses {} on {}: {}",
                    addr,
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    /// Reports whether `addr` is currently configured on this TUN device.
    ///
    /// Takes the device mutex, so callers must not already hold it; the
    /// address-mutating operations use [`Self::has_address_locked`] instead.
    pub fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;
        let result = self.has_address_locked(addr);
        drop(mtx);
        result
    }

    // Should be called while holding the mutex.
    fn has_address_locked(&self, addr: IpAddr) -> std::io::Result<bool> {
        if addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "has_address with IPv4 is not supported on linux",
            ));
        }
        let mut c = Command::new(COMMAND_IP);
        c.arg("addr")
            .arg("show")
            .arg("dev")
            .arg(self.ifname.clone());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // 5: tun9: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1400 qdisc mq state DOWN group default qlen 500
        //     link/none
        //     inet6 fd5a:5052:90de::1/32 scope global
        //        valid_lft forever preferred_lft forever
        //     inet6 fe80::bffd:4029:e0fa:806b/64 scope link stable-privacy
        //        valid_lft forever preferred_lft forever
        //
        // In our tests mode it can look like:
        //     inet6 fd5a:5052::1 peer fd5a:5052::2/128 scope global

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IP} failed to show addresses for {}: {}",
                    self.ifname,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        // First look for the pattern "inet6 <addr>" + "/" in the output.
        let out_str = String::from_utf8_lossy(&output.stdout);
        if out_str.contains(&format!("inet6 {}/", addr)) {
            return Ok(true);
        }
        // Otherwise see if it is followed by a space.
        Ok(out_str.contains(&format!("inet6 {} ", addr)))
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.owned_fd.as_fd()
    }
}

impl AsRawFd for ZprTun {
    fn as_raw_fd(&self) -> RawFd {
        self.owned_fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::Path;

    /// Set in the child process that runs this test inside
    /// `unshare -Ur -n`, where it may create a TUN device.
    const IN_NETNS_ENV: &str = "PH_ZPRTUN_TEST_IN_NETNS";

    /// Payload of the probe datagram, so the test can find it among the
    /// other packets (IPv6 router solicitations etc.) the kernel sends.
    const PROBE: &[u8] = b"zipline-204-tun-pi-probe";

    /// The child half: open a TUN device from `tun_builder`, route a UDP
    /// datagram into it, and report whether the packet the device hands to
    /// user space starts with the 4-byte packet-information header.
    async fn device_delivers_packet_info() -> bool {
        let local = Ipv4Addr::new(10, 204, 0, 1);
        let peer = Ipv4Addr::new(10, 204, 0, 2);
        let tuns = tun_builder(None, Some(IpAddr::V4(local)))
            .expect("builder")
            .netmask(Ipv4Addr::new(255, 255, 255, 0))
            .up()
            .queues(1)
            .build()
            .expect("open a TUN device in the test namespace");
        let tun = &tuns[0];

        let sock = std::net::UdpSocket::bind((local, 0)).expect("bind probe socket");
        sock.send_to(PROBE, (peer, 9)).expect("send probe datagram");

        let mut buf = [0u8; 2048];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), tun.recv(&mut buf))
                .await
                .expect("timed out waiting for the probe datagram on the TUN device")
                .expect("read from the TUN device");
            let pkt = &buf[..n];
            if !pkt.windows(PROBE.len()).any(|w| w == PROBE) {
                continue; // not our datagram
            }
            // Without PI the IPv4 header starts at byte 0; with PI it
            // follows 2 flag bytes and the ethertype 0x0800.
            if pkt[0] >> 4 == 4 {
                return false;
            }
            assert_eq!(
                &pkt[..4],
                &[0, 0, 0x08, 0x00],
                "probe packet has neither an IPv4 header nor a PI header: {:02x?}",
                &pkt[..pkt.len().min(8)]
            );
            assert_eq!(pkt[4] >> 4, 4, "no IPv4 header after the PI header");
            return true;
        }
    }

    /// The device ph opens must deliver the 4-byte packet-information
    /// header iff ph's framing expects it (`zprtun::TUN_HAS_PI`). tokio-tun
    /// 0.15 sets IFF_NO_PI unless the builder asks for packet info, and only
    /// a real device shows the framing, so the test opens one in a user+net
    /// namespace and reads a packet from it (zipline#204).
    #[tokio::test]
    async fn tun_builder_packet_info_matches_tun_has_pi() {
        if std::env::var_os(IN_NETNS_ENV).is_some() {
            let packet_info = device_delivers_packet_info().await;
            assert_eq!(
                packet_info,
                crate::zprtun::TUN_HAS_PI,
                "the TUN device delivers packet info = {packet_info}, but ph's \
                 framing has TUN_HAS_PI = {}",
                crate::zprtun::TUN_HAS_PI
            );
            return;
        }

        if !Path::new("/dev/net/tun").exists() {
            eprintln!("SKIP: /dev/net/tun is not available");
            return;
        }
        match Command::new("unshare").args(["-Ur", "-n", "true"]).status() {
            Ok(status) if status.success() => {}
            other => {
                eprintln!("SKIP: unprivileged user+net namespaces are not available: {other:?}");
                return;
            }
        }

        // Run this same test in a child inside a fresh user+net namespace.
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let name = format!("{module}::tun_builder_packet_info_matches_tun_has_pi");
        let exe = std::env::current_exe().expect("current_exe");
        let out = Command::new("unshare")
            .args(["-Ur", "-n"])
            .arg(exe)
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(IN_NETNS_ENV, "1")
            .output()
            .expect("run the test in unshare -Ur -n");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "namespaced child failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
            out.status
        );
    }

    /// The interface name ph opened must be reported back unchanged, both by
    /// `ZprTun::name` and through the `TunCtl` the admin RPC sees
    /// (zipline#202: `ph-cli tun`). Creating a TUN needs a user+net
    /// namespace, so the check runs in a child inside `unshare -Ur -n`.
    #[tokio::test]
    async fn configured_tun_name_round_trips() {
        const IFNAME: &str = "zpr202test";
        if std::env::var_os(IN_NETNS_ENV).is_some() {
            let devs = ZprTun::new_mq(Some(IFNAME.to_string()), 1, None)
                .expect("open a TUN device in the test namespace");
            assert_eq!(devs.len(), 1);
            assert_eq!(devs[0].name(), IFNAME);
            let dev = devs.into_iter().next().unwrap();
            let tun_ctl = crate::tun_ctl::TunCtlImpl::new(std::sync::Arc::new(dev));
            assert_eq!(crate::tun_ctl::TunCtl::name(&tun_ctl), IFNAME);
            return;
        }

        if !Path::new("/dev/net/tun").exists() {
            eprintln!("SKIP: /dev/net/tun is not available");
            return;
        }
        match Command::new("unshare").args(["-Ur", "-n", "true"]).status() {
            Ok(status) if status.success() => {}
            other => {
                eprintln!("SKIP: unprivileged user+net namespaces are not available: {other:?}");
                return;
            }
        }

        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let name = format!("{module}::configured_tun_name_round_trips");
        let exe = std::env::current_exe().expect("current_exe");
        let out = Command::new("unshare")
            .args(["-Ur", "-n"])
            .arg(exe)
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(IN_NETNS_ENV, "1")
            .output()
            .expect("run the test in unshare -Ur -n");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("test result: ok. 1 passed"),
            "namespaced child failed ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
            out.status
        );
    }
}
