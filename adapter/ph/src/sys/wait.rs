//! Waiting for readiness on multiple OS objects.
//!
//! This is the platform seam for the fastpath's readiness wait (master plan
//! `docs/plans/2026-09-28-windows.md`, tasks C1/C3; umbrella zipline#126).
//! On unix a [`WaitHandle`] wraps a [`BorrowedFd`] and [`WaitSet::wait`] is
//! `poll(2)`; on Windows (zipline#130) it wraps a HANDLE and
//! [`WaitSet::wait`] is `WaitForMultipleObjects`, with the substrate UDP
//! socket represented by a [`SocketWaitable`] — an Event bound to the
//! socket with `WSAEventSelect(FD_READ)`.

use std::io::Result;
use std::ops::BitOr;
use std::time::Duration;

#[cfg(unix)]
use nix::poll;
#[cfg(unix)]
use std::os::fd::BorrowedFd;

#[cfg(windows)]
use std::marker::PhantomData;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    INFINITE, WaitForMultipleObjects, WaitForSingleObject,
};

/// An opaque handle to an OS object whose readiness can be awaited in a
/// [`WaitSet`].
///
/// On unix this wraps a [`BorrowedFd`]; it carries the same lifetime, so a
/// `WaitHandle` can never outlive the object it watches.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct WaitHandle<'a>(BorrowedFd<'a>);

#[cfg(unix)]
impl<'a> WaitHandle<'a> {
    /// The underlying file descriptor (unix arm only).
    pub(crate) fn as_fd(&self) -> BorrowedFd<'a> {
        self.0
    }
}

#[cfg(unix)]
impl<'a> From<BorrowedFd<'a>> for WaitHandle<'a> {
    fn from(fd: BorrowedFd<'a>) -> Self {
        Self(fd)
    }
}

/// An opaque handle to an OS object whose readiness can be awaited in a
/// [`WaitSet`], or that batch I/O can be performed on (zipline#131).
///
/// On Windows a handle names one of three kinds of object, because —
/// unlike a unix fd — no single Win32 object is both waitable and an I/O
/// target:
///
/// - an **Event** HANDLE (a manual-reset Event, Wintun's read-wait event,
///   or a [`SocketWaitable`]'s `WSAEventSelect` event): waitable, no I/O;
/// - the substrate **socket** itself: the Windows batch_io engine's I/O
///   target. Not directly waitable — pushing it into a [`WaitSet`] panics;
///   the fastpath waits on its [`SocketWaitable`]'s Event instead;
/// - the Wintun **TUN** device: the engine's ring I/O target, waitable
///   through its read-wait event.
///
/// Win32 HANDLEs carry no lifetime of their own, so the phantom borrow
/// re-attaches one: a `WaitHandle` produced by [`Waitable::handle`] or
/// [`AsWaitSource::as_wait_handle`] cannot outlive the object it names.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub struct WaitHandle<'a>(WaitTarget<'a>, PhantomData<&'a ()>);

/// What a Windows [`WaitHandle`] names: see the type documentation.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub(crate) enum WaitTarget<'a> {
    /// A waitable Event HANDLE.
    Event(HANDLE),
    /// The substrate UDP socket, as the batch_io engine's I/O target.
    Socket(&'a std::net::UdpSocket),
    /// The Wintun TUN device, as the batch_io engine's ring I/O target.
    Tun(&'a crate::sys::ZprTun),
}

#[cfg(windows)]
impl std::fmt::Debug for WaitHandle<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            WaitTarget::Event(e) => write!(f, "WaitHandle::Event({e:?})"),
            WaitTarget::Socket(_) => write!(f, "WaitHandle::Socket"),
            WaitTarget::Tun(_) => write!(f, "WaitHandle::Tun"),
        }
    }
}

#[cfg(windows)]
impl<'a> WaitHandle<'a> {
    /// Wrap a raw Event HANDLE. Crate-private: the caller chooses the
    /// lifetime, so it must be tied to the HANDLE's owning object at the
    /// call site (as [`Waitable::handle`] implementations do).
    pub(crate) fn from_event(event: HANDLE) -> Self {
        Self(WaitTarget::Event(event), PhantomData)
    }

    /// Name the substrate socket as a batch I/O target (zipline#131).
    pub(crate) fn from_socket(socket: &'a std::net::UdpSocket) -> Self {
        Self(WaitTarget::Socket(socket), PhantomData)
    }

    /// Name the TUN device as a batch I/O target (zipline#131).
    pub(crate) fn from_tun(tun: &'a crate::sys::ZprTun) -> Self {
        Self(WaitTarget::Tun(tun), PhantomData)
    }

    /// What this handle names (Windows arm only; consumed by the
    /// `windows_unbatched` batch_io engine).
    pub(crate) fn target(&self) -> WaitTarget<'a> {
        self.0
    }

    /// The waitable Event HANDLE (Windows arm only).
    ///
    /// Panics on a [`WaitTarget::Socket`] handle: the socket itself is not
    /// waitable — wait on its [`SocketWaitable`] instead (the fastpath
    /// does; see `FastpathIo::substrate_socket_wait_handle`).
    pub(crate) fn as_handle(&self) -> HANDLE {
        match self.0 {
            WaitTarget::Event(event) => event,
            WaitTarget::Tun(tun) => match tun.handle().0 {
                WaitTarget::Event(event) => event,
                _ => unreachable!("ZprTun's Waitable yields an Event"),
            },
            WaitTarget::Socket(_) => panic!(
                "a bare socket is not waitable on Windows; \
                 wait on its SocketWaitable's Event instead"
            ),
        }
    }
}

/// Something whose readiness can be awaited in a [`WaitSet`].
pub trait Waitable {
    /// The handle to register with a [`WaitSet`].
    fn handle(&self) -> WaitHandle<'_>;
}

/// The kind(s) of readiness a [`WaitSet`] entry is interested in.
///
/// `NONE` registers the entry without asking for any events (mirroring an
/// empty `PollFlags`, which the fastpath uses to park a source it currently
/// has no buffers for).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interest(u8);

impl Interest {
    /// No events. The entry occupies a slot but cannot become ready.
    pub const NONE: Self = Self(0);
    /// Readable (unix: `POLLIN`).
    pub const READ: Self = Self(1);
    /// Writable (unix: `POLLOUT`).
    pub const WRITE: Self = Self(2);

    /// The unix `poll(2)` events these interests correspond to.
    #[cfg(unix)]
    fn poll_flags(self) -> poll::PollFlags {
        let mut flags = poll::PollFlags::empty();
        if self.0 & Self::READ.0 != 0 {
            flags |= poll::PollFlags::POLLIN;
        }
        if self.0 & Self::WRITE.0 != 0 {
            flags |= poll::PollFlags::POLLOUT;
        }
        flags
    }
}

impl BitOr for Interest {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Which entries of a [`WaitSet`] became ready, by the index `push` returned.
///
/// Owned (no borrow of the `WaitSet`), so the set can be dropped — releasing
/// its borrows of the watched objects — before the results are acted on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ready {
    readable: u32,
    writable: u32,
}

impl Ready {
    /// Whether the entry at `index` reported readable (unix: `POLLIN`).
    pub fn is_readable(&self, index: usize) -> bool {
        self.readable & (1 << index) != 0
    }

    /// Whether the entry at `index` reported writable (unix: `POLLOUT`).
    pub fn is_writable(&self, index: usize) -> bool {
        self.writable & (1 << index) != 0
    }
}

/// Maximum number of entries in a `WaitSet` (width of the `Ready` bitmasks;
/// also comfortably under Windows' MAXIMUM_WAIT_OBJECTS of 64).
const MAX_ENTRIES: usize = 32;

/// A set of [`WaitHandle`]s to wait on simultaneously.
///
/// Entries are registered with [`push`](Self::push), which returns the index
/// [`wait`](Self::wait)'s [`Ready`] result reports that entry under. A set is
/// cheap to build and is typically rebuilt for every wait, because interests
/// change between iterations (see `fastpath_worker`).
///
/// At most 32 entries per set (the `Ready` bitmask width); `push` panics
/// beyond that. The unix arm's `wait` is exactly the `nix::poll::poll` call
/// the fastpath previously made inline.
#[cfg(unix)]
pub struct WaitSet<'a> {
    entries: Vec<poll::PollFd<'a>>,
}

#[cfg(unix)]
impl<'a> WaitSet<'a> {
    /// Create an empty wait set with room for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Register `handle` with the given `interest`. Returns the index this
    /// entry is reported under in [`Ready`].
    ///
    /// Panics if the set already holds [`MAX_ENTRIES`] entries.
    pub fn push(&mut self, handle: WaitHandle<'a>, interest: Interest) -> usize {
        let index = self.entries.len();
        assert!(index < MAX_ENTRIES, "WaitSet overflow");
        self.entries
            .push(poll::PollFd::new(handle.as_fd(), interest.poll_flags()));
        index
    }

    /// Block until at least one entry is ready or `timeout` elapses
    /// (`None` = wait forever), and report which entries are ready.
    ///
    /// A timeout expiry reports an empty [`Ready`]. Interruption by a signal
    /// surfaces as an error of kind [`std::io::ErrorKind::Interrupted`],
    /// exactly as the inline `poll(2)` call did; callers retry.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Ready> {
        let timeout = match timeout {
            None => poll::PollTimeout::NONE,
            Some(duration) => poll::PollTimeout::try_from(duration)
                .expect("WaitSet timeout exceeds the platform maximum"),
        };

        let _n = poll::poll(&mut self.entries, timeout)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))?;

        let mut ready = Ready::default();
        for (index, pfd) in self.entries.iter().enumerate() {
            let revents = pfd.revents().unwrap();
            if revents.contains(poll::PollFlags::POLLIN) {
                ready.readable |= 1 << index;
            }
            if revents.contains(poll::PollFlags::POLLOUT) {
                ready.writable |= 1 << index;
            }
        }
        Ok(ready)
    }
}

/// A set of [`WaitHandle`]s to wait on simultaneously — Windows arm
/// (zipline#130, plan D3).
///
/// `wait` is `WaitForMultipleObjects` over the entries whose interest is
/// not [`Interest::NONE`] (a parked `NONE` entry must not wake the wait, so
/// it is not passed to the kernel — the unix arm gets the same effect from
/// an empty `PollFlags`). `WaitForMultipleObjects` reports only the
/// lowest-index signaled handle, so after it returns, every *other* armed
/// handle is probed with a zero-timeout `WaitForSingleObject`. The
/// manual-reset Events ([`super::notify::Notify`], `WSAEventSelect` events)
/// stay signaled until explicitly consumed, so a still-pending source is
/// seen by the probe, giving `poll(2)`'s report-everything semantics.
/// Wintun's read-wait event is the exception: it is auto-reset, so the
/// wait or the probe that reports it also consumes it, and it signals per
/// ring append rather than while the ring is non-empty. Its reader
/// re-arms it after a batch that may have left packets in the ring
/// (`batch_io::windows_unbatched::read_ring_batch`, zl-zipline#292).
///
/// A signaled entry is reported under the interest(s) it registered:
/// `WaitForMultipleObjects` itself carries no read/write distinction — the
/// direction lives in how the handle was armed (`FD_READ` on a
/// [`SocketWaitable`], a posted `Notify`), not in the wait.
#[cfg(windows)]
pub struct WaitSet<'a> {
    /// (handle, registered interest); `NONE` entries keep their slot (for
    /// index stability) but are skipped by `wait`.
    entries: Vec<(WaitHandle<'a>, Interest)>,
}

#[cfg(windows)]
impl<'a> WaitSet<'a> {
    /// Create an empty wait set with room for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Register `handle` with the given `interest`. Returns the index this
    /// entry is reported under in [`Ready`].
    ///
    /// Panics if the set already holds [`MAX_ENTRIES`] entries.
    pub fn push(&mut self, handle: WaitHandle<'a>, interest: Interest) -> usize {
        let index = self.entries.len();
        assert!(index < MAX_ENTRIES, "WaitSet overflow");
        self.entries.push((handle, interest));
        index
    }

    /// Block until at least one armed entry is signaled or `timeout`
    /// elapses (`None` = wait forever), and report which entries are ready.
    ///
    /// A timeout expiry reports an empty [`Ready`].
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Ready> {
        let timeout_ms: u32 = match timeout {
            None => INFINITE,
            Some(duration) => duration
                .as_millis()
                .try_into()
                .expect("WaitSet timeout exceeds the platform maximum"),
        };

        // Arm only the entries with a real interest, remembering which
        // WaitSet index each armed handle belongs to.
        let mut handles: Vec<HANDLE> = Vec::with_capacity(self.entries.len());
        let mut indices: Vec<usize> = Vec::with_capacity(self.entries.len());
        for (index, (handle, interest)) in self.entries.iter().enumerate() {
            if *interest != Interest::NONE {
                handles.push(handle.as_handle());
                indices.push(index);
            }
        }

        let mut ready = Ready::default();
        if handles.is_empty() {
            // Nothing armed: nothing can become ready. poll(2) over
            // event-less entries just sleeps for the timeout; do the same.
            match timeout {
                Some(duration) => std::thread::sleep(duration),
                // An infinite wait with nothing armed would deadlock;
                // no fastpath call site builds such a set. Fail loudly
                // rather than hang.
                None => panic!("WaitSet::wait forever with no armed entries"),
            }
            return Ok(ready);
        }

        // SAFETY: `handles` holds live HANDLEs — each WaitHandle's phantom
        // borrow keeps its owner alive for the life of this set.
        let rc = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms)
        };
        if rc == WAIT_TIMEOUT {
            return Ok(ready);
        }
        if rc == WAIT_FAILED || rc >= WAIT_OBJECT_0 + handles.len() as u32 {
            // WAIT_ABANDONED_* applies to mutexes only, never to the Events
            // waited on here; anything that is not a signaled index is an
            // error.
            return Err(std::io::Error::last_os_error());
        }
        let first = (rc - WAIT_OBJECT_0) as usize;

        // Report every signaled entry, not just the lowest: probe the rest
        // with a zero timeout (manual-reset sources stay signaled; an
        // auto-reset one is consumed here, as by the wait itself).
        for (pos, (&handle, &index)) in handles.iter().zip(indices.iter()).enumerate() {
            let signaled = if pos == first {
                true
            } else {
                // SAFETY: same liveness argument as above.
                unsafe { WaitForSingleObject(handle, 0) == WAIT_OBJECT_0 }
            };
            if signaled {
                let interest = self.entries[index].1;
                if interest.0 & Interest::READ.0 != 0 {
                    ready.readable |= 1 << index;
                }
                if interest.0 & Interest::WRITE.0 != 0 {
                    ready.writable |= 1 << index;
                }
            }
        }
        Ok(ready)
    }
}

/// The substrate UDP socket as a [`Waitable`] — Windows arm (plan D3).
///
/// Wraps a manual-reset WSA Event bound to the socket with
/// `WSAEventSelect(FD_READ)`: the event signals when data arrives.
/// `FD_READ` re-arming is edge-like — after a wake, [`reset`](Self::reset)
/// must be called (it runs `WSAEnumNetworkEvents`, which clears the event
/// and re-enables `FD_READ` recording) before the ready data is drained,
/// or a subsequent arrival may not re-signal. The fastpath's substrate
/// receive path (`FastpathIo::process_substrate_socket_in`) owns that call.
#[cfg(windows)]
pub struct SocketWaitable {
    socket: windows_sys::Win32::Networking::WinSock::SOCKET,
    /// A WSAEVENT (an event HANDLE spelled as isize in windows-sys).
    event: windows_sys::Win32::Networking::WinSock::WSAEVENT,
}

#[cfg(windows)]
impl SocketWaitable {
    /// Bind a fresh WSA Event to `socket` with `WSAEventSelect(FD_READ)`.
    ///
    /// Side effect inherent to `WSAEventSelect`: the socket is switched to
    /// non-blocking mode — which the fastpath requires anyway.
    ///
    /// The `SocketWaitable` borrows no lifetime from the socket, so the
    /// caller must keep the socket alive as long as the waitable (the
    /// fastpath owns both in one struct).
    pub fn new(socket: &std::net::UdpSocket) -> Result<Self> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{FD_READ, WSACreateEvent, WSAEventSelect};

        let raw = socket.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
        // SAFETY: WSACreateEvent allocates a fresh manual-reset event owned
        // by this SocketWaitable (closed in Drop). WSAEVENT is an event
        // HANDLE spelled as isize; 0 is WSA_INVALID_EVENT.
        let event = unsafe { WSACreateEvent() };
        if event == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: raw is a live socket (borrowed for this call) and event a
        // live WSA event handle.
        if unsafe { WSAEventSelect(raw, event, FD_READ as i32) } != 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: event was created above and is not otherwise shared.
            unsafe { windows_sys::Win32::Networking::WinSock::WSACloseEvent(event) };
            return Err(err);
        }
        Ok(Self { socket: raw, event })
    }

    /// Acknowledge a wake: `WSAEnumNetworkEvents` clears the event and
    /// re-enables `FD_READ` recording. Call after every wait that reported
    /// this socket ready, before draining the ready data: cleared after
    /// the drain, a datagram arriving between the last recv and the clear
    /// would be left buffered with no wakeup.
    pub fn reset(&self) -> Result<()> {
        use windows_sys::Win32::Networking::WinSock::{WSAEnumNetworkEvents, WSANETWORKEVENTS};
        // SAFETY: plain output struct, fully written by the call on success.
        let mut events: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
        // SAFETY: socket and event are the live pair bound in new().
        if unsafe { WSAEnumNetworkEvents(self.socket, self.event, &mut events) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for SocketWaitable {
    fn drop(&mut self) {
        // SAFETY: event was created by WSACreateEvent in new() and is owned
        // by this SocketWaitable.
        unsafe { windows_sys::Win32::Networking::WinSock::WSACloseEvent(self.event) };
    }
}

#[cfg(windows)]
impl Waitable for SocketWaitable {
    fn handle(&self) -> WaitHandle<'_> {
        // WSAEVENT is an event HANDLE spelled as isize; the wait arm needs
        // the pointer spelling.
        WaitHandle::from_event(self.event as HANDLE)
    }
}

/// Something batch_io can target: anything that can name the [`WaitHandle`]
/// its I/O readiness is reported on.
///
/// On unix every `AsFd` type qualifies (the handle is the fd itself), so
/// batch_io call sites keep passing sockets and TUNs directly. On Windows
/// the handle is an Event owned elsewhere, so only the types that actually
/// carry one implement this — see the impls beside `SocketWaitable` and the
/// Windows `ZprTun`.
pub trait AsWaitSource {
    fn as_wait_handle(&self) -> WaitHandle<'_>;
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> AsWaitSource for T {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        self.as_fd().into()
    }
}

/// The socket names itself as the engine's I/O target (zipline#131). Not
/// waitable — the fastpath waits on the socket's [`SocketWaitable`], and
/// [`WaitHandle::as_handle`] panics on this handle.
#[cfg(windows)]
impl AsWaitSource for std::net::UdpSocket {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        WaitHandle::from_socket(self)
    }
}

#[cfg(windows)]
impl AsWaitSource for SocketWaitable {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        self.handle()
    }
}

/// The TUN names itself as the engine's ring I/O target (zipline#131);
/// as a wait entry it resolves to its read-wait event ([`Waitable`]).
#[cfg(windows)]
impl AsWaitSource for crate::sys::ZprTun {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        WaitHandle::from_tun(self)
    }
}

/// `Arc<ZprTun>` mirrors std's `impl AsFd for Arc<T>`, which is what lets
/// the unix blanket impl accept `&Arc<ZprTun>` at the fastpath call sites.
#[cfg(windows)]
impl AsWaitSource for std::sync::Arc<crate::sys::ZprTun> {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        WaitHandle::from_tun(self.as_ref())
    }
}

/// References forward, mirroring std's `impl AsFd for &T` that the unix
/// blanket impl picks up.
#[cfg(windows)]
impl<T: AsWaitSource + ?Sized> AsWaitSource for &T {
    fn as_wait_handle(&self) -> WaitHandle<'_> {
        (**self).as_wait_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::{Interest, WaitSet};
    use crate::sys::notify::Notify;
    use crate::sys::wait::Waitable;
    use std::time::Duration;

    /// Two `Notify`s in a `WaitSet`; post one; `wait` reports exactly that
    /// one ready. (zipline#128 acceptance test; also valid on the Windows
    /// arm, where `Notify` is a manual-reset Event.)
    #[test]
    fn waitset_reports_only_posted_notify() {
        let notify1 = Notify::new().unwrap();
        let notify2 = Notify::new().unwrap();

        let mut wait_set = WaitSet::with_capacity(2);
        let idx1 = wait_set.push(notify1.handle(), Interest::READ);
        let idx2 = wait_set.push(notify2.handle(), Interest::READ);

        notify1.post();

        let ready = wait_set.wait(Some(Duration::from_secs(5))).unwrap();
        assert!(ready.is_readable(idx1));
        assert!(!ready.is_readable(idx2));
    }
}
