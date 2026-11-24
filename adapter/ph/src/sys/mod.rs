#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TunPiImpl;
#[cfg(target_os = "linux")]
pub use self::linux::ZprTun;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::TunPiImpl;
#[cfg(target_os = "macos")]
pub use self::macos::ZprTun;

#[cfg(windows)]
pub(crate) mod windows;
#[cfg(windows)]
pub use self::windows::TunPiImpl;
#[cfg(windows)]
pub use self::windows::ZprTun;

// Pure parsing of macOS `ifconfig <if>` output for `has_address` (PR #66
// review P1: unscoped ULA addresses were not recognized). Compiled on every
// OS so it stays unit-testable from Linux builds; only macOS code calls it
// at runtime.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) mod macos_ifconfig;

// The manual add-address hint printed when a node ZPR address cannot be
// applied to, or is missing from, the TUN device (zipline#161). Compiled on
// every OS, same pattern and reason as `macos_ifconfig`: the per-platform
// command strings stay unit-testable from Linux builds. `main.rs` calls the
// hints, and the Windows `add_address` calls `netsh_add_address_args`
// (zl-zipline#272), so most of the library's copy is dead code by design.
#[allow(dead_code)]
pub(crate) mod addr_hint;

// Bounded wait for a freshly added address to leave the DAD tentative
// state (zipline#162). Compiled on every OS, same pattern and reason as
// `macos_ifconfig` above; only the Windows `add_address` calls it at runtime.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod dad;

// Portable substrate socket helpers (zipline#175). Compiled on every OS:
// the substrate setup in `main.rs` uses it on all three platforms.
pub mod substrate;

// Platform-neutral control-channel access helpers (zipline#154): the
// shared missing-group warning and the Windows pipe SDDL builder. Compiled
// on every OS, same pattern and reason as `macos_ifconfig` above; each arm
// uses only its half at runtime.
#[allow(dead_code)]
pub(crate) mod control_access;

// POSIX arms of the control channel and the Notify wakeup object
// (zipline#130: Windows provides the same two modules from sys/windows).
#[cfg(unix)]
pub(crate) mod posix;
#[cfg(unix)]
pub use self::posix::control;
#[cfg(unix)]
pub use self::posix::notify;

#[cfg(windows)]
pub use self::windows::control;
#[cfg(windows)]
pub use self::windows::notify;

/// Whether this platform can capture packets to a file.  Capture hands `ph`
/// a file descriptor over SCM_RIGHTS, so `ph` never opens a user-chosen
/// path as root; there is no equivalent on Windows yet (plan D7), so there
/// `setCaptureFile` answers Unsupported instead.
pub const fn capture_supported() -> bool {
    cfg!(unix)
}

// Readiness waiting over multiple OS objects (fds today, HANDLEs when the
// Windows arm lands in zipline#130). See `docs/plans/2026-09-28-windows.md`.
pub mod wait;

use bytes::buf;

/// per-packet packet info
#[derive(Clone, Copy)]
pub struct TunPi {
    // the inbound packet was truncated (ignored outbound)
    pub strip: bool,
    /// Ethertype of packet
    pub proto: u16,
}

impl TunPi {
    /// The size of a per-packet packet info structure.
    pub const PI_SIZE: usize = std::mem::size_of::<TunPiImpl>();

    /// Read per-packet packet info from a `Buf`.
    pub fn read_pi<B: buf::Buf>(buf: &mut B) -> TunPi {
        let mut os_pi = std::mem::MaybeUninit::<TunPiImpl>::uninit();
        let slice = os_pi.as_mut_ptr();
        buf.copy_to_slice(unsafe {
            /* SAFETY: we immediately initialize */
            std::slice::from_raw_parts_mut(slice as *mut u8, TunPi::PI_SIZE)
        });
        unsafe {
            /* SAFETY: was just initialized */
            os_pi.assume_init()
        }
        .into()
    }

    /// Write per-packet packet info into a `BufMut`.
    pub fn write_pi<B: buf::BufMut>(buf: &mut B, pi: TunPi) {
        let os_pi: TunPiImpl = pi.into();
        buf.put(unsafe {
            /* SAFETY: we are reading exactly the structure */
            std::slice::from_raw_parts((&os_pi as *const _) as *const u8, TunPi::PI_SIZE)
        });
    }
}
