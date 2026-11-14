//! Batch I/O operations.
//!
//! These vary both by operating system and feature set.
//!
//! All these operations assume a file descriptor which has been set
//! non-blocking, and they perform non-blocking I/O operations.

use bytes::BufMut;
use libc;
#[cfg(unix)]
use nix::sys::socket::{self, AddressFamily, SockaddrLike, SockaddrStorage};
use std::io::Result;
#[cfg(unix)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};
use zpr_utils::net_defs::ScopedIpAddr;
#[cfg(unix)]
use zpr_utils::net_defs::ScopedIpv6Addr;

use crate::sys::wait::AsWaitSource;
use crate::sys::wait::WaitHandle;

/// Flags for socket send operations, as a platform-neutral newtype over the
/// OS flag bits (unix: the `MSG_*` bits of `sendmsg(2)`'s `flags` argument).
///
/// The constructors for flags that exist only on some platforms are no-ops
/// elsewhere, so callers need no `#[cfg]` of their own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendFlags(libc::c_int);

impl SendFlags {
    /// No flags.
    pub const fn none() -> Self {
        Self(0)
    }

    /// `MSG_CONFIRM`: tell the link layer that forward progress happened
    /// (suppresses unicast ARP/NDP re-validation). Linux only; a no-op
    /// elsewhere.
    #[cfg(target_os = "linux")]
    pub const fn confirm() -> Self {
        Self(libc::MSG_CONFIRM)
    }

    /// `MSG_CONFIRM` does not exist on this platform; no flags.
    #[cfg(not(target_os = "linux"))]
    pub const fn confirm() -> Self {
        Self(0)
    }

    /// The raw OS flag bits: the `flags` argument of `sendmsg(2)` on unix
    /// and of `WSASendMsg` on Windows.
    fn bits(self) -> libc::c_int {
        self.0
    }
}

impl std::ops::BitOr for SendFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

pub struct ReceivedPacket {
    #[allow(dead_code)]
    pub size: usize,
    pub truncated: bool,
    pub source: Option<SocketAddr>,
    pub destination: Option<ScopedIpAddr>,
}

#[cfg(unix)]
fn sockaddr_to_socket_addr(sa: SockaddrStorage) -> Option<SocketAddr> {
    match sa.family()? {
        AddressFamily::Inet => Some(SocketAddr::V4((*sa.as_sockaddr_in().unwrap()).into())),
        AddressFamily::Inet6 => Some(SocketAddr::V6((*sa.as_sockaddr_in6().unwrap()).into())),
        _ => None,
    }
}

#[cfg(unix)]
fn errno_to_error(errno: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno as i32)
}

#[cfg(unix)]
fn pktinfo_from_ipv4addr(addr: &Ipv4Addr) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: addr.to_bits().to_be(),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    }
}

#[cfg(unix)]
fn pktinfo_from_scoped_ipv6addr(addr: &ScopedIpv6Addr) -> libc::in6_pktinfo {
    libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: addr.ip().octets(),
        },
        ipi6_ifindex: addr.scope_id(),
    }
}

/// Enable the reception of packet info on a socket.  Required for
/// `try_recv_buf_from_to_batch()` to return the destination address.
/// The Windows twin is `windows_udp::set_recv_packet_info`, re-exported
/// below under the same name.
#[cfg(unix)]
pub fn set_recv_packet_info(fd: &impl AsFd, enable: bool) -> std::io::Result<()> {
    match socket::getsockname::<SockaddrStorage>(fd.as_fd().as_raw_fd())?.family() {
        Some(AddressFamily::Inet) => {
            socket::setsockopt(fd, socket::sockopt::Ipv4PacketInfo, &enable).map_err(errno_to_error)
        }
        Some(AddressFamily::Inet6) => {
            socket::setsockopt(fd, socket::sockopt::Ipv6RecvPacketInfo, &enable)
                .map_err(errno_to_error)
        }
        _ => Ok(()),
    }
}

// The Windows `set_recv_packet_info` (zipline#150): same purpose, but it
// needs a bound socket. See its doc comment.
#[cfg(windows)]
pub use windows_udp::set_recv_packet_info;

trait BatchIoImpl {
    fn engine_name(&self) -> &'static str;

    fn try_write_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_read_buf_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_from_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_to_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod io_uring {
    //! io_uring(7)-based implementation.  Only available for Linux.

    use super::{BatchIoImpl, ReceivedPacket, SendFlags, sockaddr_to_socket_addr};
    use crate::sys::wait::WaitHandle;
    use bytes::BufMut;
    use io_uring::{IoUring, Probe, cqueue, opcode, squeue, types};
    use libc;
    use nix::sys::socket::{SockaddrLike, SockaddrStorage};
    use std::io::Result;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::ptr::NonNull;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    const MAX_ENTRIES: usize = 1024;

    /// This is a very basic on-stack vector/slab.
    struct Slab<T> {
        allocated: usize,
        storage: [MaybeUninit<T>; MAX_ENTRIES],
    }

    impl<T> Slab<T> {
        fn new() -> Self {
            Self {
                allocated: 0,
                storage: [const { MaybeUninit::uninit() }; MAX_ENTRIES],
            }
        }

        fn get(&self, idx: usize) -> &T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_ref() }
        }

        fn get_mut(&mut self, idx: usize) -> &mut T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_mut() }
        }

        fn push(&mut self, val: T) -> &mut T {
            assert!(self.allocated < self.storage.len());
            let idx = self.allocated;
            self.allocated += 1;
            self.storage[idx].write(val)
        }
    }

    impl<T> Drop for Slab<T> {
        fn drop(&mut self) {
            for i in 0..self.allocated {
                // SAFETY: we've written to all entries which have been allocated
                unsafe {
                    self.storage[i].assume_init_drop();
                }
            }
        }
    }

    trait BatchOp<Item, State, Res> {
        fn new() -> Self;
        fn build_op(&mut self, fd: types::Fd, item: Item, idx: usize) -> (squeue::Entry, State);
        fn process_result(&self, idx: usize, state: State, amt: usize) -> Res;
    }

    // std::cmp::max() is not const
    const fn const_u32_max(x: u32, y: u32) -> u32 {
        if x > y { x } else { y }
    }

    const PKTINFO_CMSG_SPACE_NEEDED: usize = const_u32_max(
        // SAFETY: these const functions are erroneously marked unsafe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) },
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) },
    ) as usize;

    struct TryWriteBatchOp {}

    impl BatchOp<&[u8], (), usize> for TryWriteBatchOp {
        fn new() -> Self {
            Self {}
        }

        fn build_op(&mut self, fd: types::Fd, buf: &[u8], _idx: usize) -> (squeue::Entry, ()) {
            (
                opcode::Write::new(fd, buf.as_ptr(), buf.len() as u32)
                    .rw_flags(libc::RWF_NOWAIT)
                    .build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryReadBufBatchOp<'a> {
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, usize> for TryReadBufBatchOp<'a> {
        fn new() -> Self {
            Self {
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            _idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let chunk = buf.chunk_mut();
            (
                opcode::Read::new(fd, chunk.as_mut_ptr(), chunk.len() as u32)
                    .rw_flags(libc::RWF_NOWAIT)
                    .build(),
                buf,
            )
        }

        fn process_result(&self, _idx: usize, buf: &'a mut dyn BufMut, amt: usize) -> usize {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe { buf.advance_mut(amt) };
            amt
        }
    }

    struct TrySendToBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr, libc::c_int), (), usize> for TrySendToBatchOp {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, addr, flags): (&[u8], SocketAddr, libc::c_int),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(addr));

            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (
                opcode::SendMsg::new(fd, msghdr_ref as *const _)
                    .flags(flags as u32 | libc::MSG_DONTWAIT as u32)
                    .build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TrySendToFromBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        cmsg_slab: Slab<[u8; PKTINFO_CMSG_SPACE_NEEDED]>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr, Option<ScopedIpAddr>, libc::c_int), (), usize>
        for TrySendToFromBatchOp
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                cmsg_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, dst_addr, src_addr, flags): (
                &[u8],
                SocketAddr,
                Option<ScopedIpAddr>,
                libc::c_int,
            ),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(dst_addr));

            let cmsg_ref = self.cmsg_slab.push([0u8; PKTINFO_CMSG_SPACE_NEEDED]);

            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref as *mut _ as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            match src_addr {
                None => {
                    msghdr_ref.msg_controllen = 0;
                }

                Some(src_addr) => {
                    // SAFETY: we have enough space in cmsg_ref for a cmsg header
                    let cmsg_ptr =
                        unsafe { NonNull::new(libc::CMSG_FIRSTHDR(msghdr_ref)).unwrap_unchecked() };
                    // SAFETY: we have enough space in cmsg_ref for our cmsg
                    let cmsg_len = unsafe { scoped_ip_addr_to_cmsg(cmsg_ptr, src_addr) };
                    msghdr_ref.msg_controllen = cmsg_len;
                }
            }

            (
                opcode::SendMsg::new(fd, msghdr_ref as *const _)
                    .flags(flags as u32 | libc::MSG_DONTWAIT as u32)
                    .build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryRecvBufFromBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromBatchOp<'a>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (
                opcode::RecvMsg::new(fd, msghdr_ref as *mut _)
                    .flags(libc::MSG_DONTWAIT as u32)
                    .build(),
                buf,
            )
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination: None,
            }
        }
    }

    struct TryRecvBufFromToBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        cmsg_slab: [[u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromToBatchOp<'a>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                cmsg_slab: [[0u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let cmsg_ref = &mut self.cmsg_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            (
                opcode::RecvMsg::new(fd, msghdr_ref as *mut _)
                    .flags(libc::MSG_DONTWAIT as u32)
                    .build(),
                buf,
            )
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            // SAFETY: We know the cmsgs are valid.
            let destination = unsafe { cmsg_iter(self.msghdr_slab.get(idx)) }
                .find_map(|cmsg| unsafe { cmsg_to_scoped_ip_addr(cmsg.as_ptr()) });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination,
            }
        }
    }

    pub struct BatchIo {
        io_uring: IoUring<squeue::Entry, cqueue::Entry>,
    }

    // NOTE: Requires Linux 6.4 or later.  The TUN operations carry
    // RWF_NOWAIT, which io_uring rejects with -EOPNOTSUPP unless the file
    // has FMODE_NOWAIT; the tun driver only sets that from 6.4 on (not
    // backported to the 5.10/5.15/6.1 stable series).  `detect_support()`
    // therefore rejects older kernels, so automatic engine selection falls
    // back to another engine there (zipline#168).  Otherwise, limit io_uring
    // features used to those available in 5.10 or later.

    /// Oldest kernel whose tun driver accepts RWF_NOWAIT (see NOTE above).
    const TUN_NOWAIT_MIN_KERNEL: (u32, u32) = (6, 4);

    /// Whether a kernel release string (as in `/proc/sys/kernel/osrelease`,
    /// e.g. "6.8.0-138-generic") is at least `(major, minor)`.  Anything
    /// that does not start with `<major>.<minor>` is rejected, so an
    /// unrecognized kernel falls back to a safer engine rather than risking
    /// a fastpath panic.
    fn kernel_release_at_least(release: &str, (major, minor): (u32, u32)) -> bool {
        // Parse the leading decimal digits of one dot-separated component
        // (the minor may carry a suffix, e.g. "4-rc1").
        fn leading_number(part: Option<&str>) -> Option<u32> {
            let part = part?;
            let end = part
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(part.len());
            part[..end].parse().ok()
        }

        let mut parts = release.split('.');
        match (leading_number(parts.next()), leading_number(parts.next())) {
            (Some(have_major), Some(have_minor)) => (have_major, have_minor) >= (major, minor),
            _ => false,
        }
    }

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "io_uring";

        pub const MAX_ENTRIES: usize = MAX_ENTRIES;

        const REQUIRED_OPCODES: &[u8] = &[
            opcode::Write::CODE,
            opcode::Read::CODE,
            opcode::SendMsg::CODE,
            opcode::RecvMsg::CODE,
        ];

        pub fn detect_support() -> bool {
            // TUN I/O fails with EOPNOTSUPP on older kernels, which the
            // fastpath treats as fatal (zipline#168).
            let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
                return false;
            };
            if !kernel_release_at_least(release.trim(), TUN_NOWAIT_MIN_KERNEL) {
                return false;
            }

            let Ok(io_uring) = IoUring::new(1) else {
                return false;
            };

            let mut probe = Probe::new();
            if io_uring.submitter().register_probe(&mut probe).is_err() {
                return false;
            }

            Self::REQUIRED_OPCODES
                .iter()
                .all(|&op| probe.is_supported(op))
        }

        pub fn new(entries: usize) -> Result<Self> {
            assert!(entries <= MAX_ENTRIES);

            let io_uring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
                .dontfork()
                .build(entries as u32)?;

            Ok(Self { io_uring })
        }

        fn do_batch_op<Item, State, Res>(
            &mut self,
            mut batch_op: impl BatchOp<Item, State, Res>,
            fd: BorrowedFd<'_>,
            items: &mut dyn Iterator<Item = Item>,
            results: &mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let fd = types::Fd(fd.as_raw_fd());

            let mut submitted = 0;

            let mut squeue = self.io_uring.submission();

            let max_to_submit = squeue.capacity() - squeue.len();

            let mut state_slab = Slab::new();

            // Enter the operations into the submission queue.
            while let Some(item) = items.next() {
                if submitted >= max_to_submit {
                    break;
                }

                // Attach a unique identifier to each item in the batch, so we
                // can identify its result and correlate it with its state.
                let user_data = submitted as u64;

                // Build the operation entry, and stow any state we need for processing the result.
                let (entry, state) = batch_op.build_op(fd, item, submitted);
                state_slab.push(Some(state));

                // We rely on RWF_NOWAIT (for reads/writes) or MSG_DONTWAIT
                // (for sendmsg/recvmsg), set by each BatchOp's build_op above,
                // to make the operation fail immediately with -EAGAIN instead
                // of blocking/running asynchronously when it is not
                // immediately able to proceed.  This lets us simulate
                // nonblocking I/O without any separate cancel request.
                //
                // We previously paired each operation with a racing
                // AsyncCancel instead, since (we believed) O_NONBLOCK was
                // ignored by io_uring and RWF_NOWAIT was unsupported by TUN
                // devices.  The latter turned out to be false (TUN devices do
                // check IOCB_NOWAIT, both for reads and writes), so we no
                // longer need that workaround -- which is good, because that
                // approach suffered from a kernel bug where AsyncCancel can
                // spuriously fail to cancel an operation which is, in fact,
                // still genuinely pending, causing submit_and_wait() to block
                // indefinitely, until unrelated traffic arrived (zipline#117).
                // `tests::test_recv_stress_no_stall` guards against that
                // regression; see its comments for more detail.

                // SAFETY: the buf ptrs are valid for our entire body, and we
                // are waiting on completion before we exit.
                unsafe { squeue.push(&entry.user_data(user_data)) }.unwrap();
                submitted += 1;
            }

            drop(squeue);

            // Submit the operations and wait for completion (which should not
            // block, thanks to RWF_NOWAIT/MSG_DONTWAIT).
            let completed = self.io_uring.submit_and_wait(submitted)?;
            assert_eq!(completed, submitted);

            // Read results from the completion queue.
            let mut cqueue = self.io_uring.completion();
            let mut completions = [const { MaybeUninit::uninit() }; MAX_ENTRIES];
            let completions = cqueue.fill(&mut completions);
            assert_eq!(completions.len(), submitted);

            let results_base = results.len();
            results.reserve(submitted);

            for entry in completions {
                let result = entry.result();

                if result == -libc::EAGAIN {
                    // This operation would have blocked.  Don't append to
                    // `results`, under the assumption that the remainder of
                    // operations would have blocked as well.
                    //
                    // Note though that, because io_uring processing is racing
                    // against the rest of the system, we may see successful
                    // operations after ones that would have blocked (e.g. if
                    // more data arrives between two operations being
                    // processed). So we must `continue` here, and not
                    // `break`. Filling in the gaps in the `results` vector is
                    // handled below.

                    continue;
                }

                // Grab the unique identifier of the operation.
                let idx = entry.user_data() as usize;

                if idx >= results.len() - results_base {
                    // Note that, for some reason, results may come out of order.
                    // So, fill skipped-over results with EWOULDBLOCK.

                    results.resize_with(results_base + idx + 1, || {
                        Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                    });
                }

                // Translate the result.
                results[results_base + idx] = if result < 0 {
                    Err(std::io::Error::from_raw_os_error(-result))
                } else {
                    Ok(batch_op.process_result(
                        idx,
                        state_slab.get_mut(idx).take().unwrap(),
                        result as usize,
                    ))
                };
            }

            Ok(results.len() - results_base)
        }
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryWriteBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryReadBufBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TrySendToBatchOp::new(),
                handle.as_fd(),
                &mut bufs.map(|(buf, addr, flags)| (buf, addr, flags.bits())),
                results,
            )
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TrySendToFromBatchOp::new(),
                handle.as_fd(),
                &mut bufs.map(|(buf, dst, src, flags)| (buf, dst, src, flags.bits())),
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(TryRecvBufFromBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TryRecvBufFromToBatchOp::new(),
                handle.as_fd(),
                bufs,
                results,
            )
        }
    }

    #[cfg(test)]
    mod kernel_release_tests {
        use super::*;

        #[test]
        fn test_kernel_release_at_least_tun_nowait_floor() {
            // zipline#168 review (PR #76): io_uring must only be selected
            // on kernels whose tun driver accepts RWF_NOWAIT (6.4+).
            let at_least = |release| kernel_release_at_least(release, TUN_NOWAIT_MIN_KERNEL);

            for ok in [
                "6.4.0",
                "6.4",
                "6.8.0-138-generic",
                "6.10.1",
                "7.0.0-34-generic",
            ] {
                assert!(at_least(ok), "{ok} must be accepted");
            }
            for too_old in [
                "6.3.13",
                "6.1.150",
                "5.15.0-91-generic",
                "5.10.240",
                "4.19.0",
            ] {
                assert!(!at_least(too_old), "{too_old} must be rejected");
            }
            // Unparseable releases fail safe (fall back to another engine).
            for junk in ["", "garbage", "6", "6.x.1", ".4"] {
                assert!(!at_least(junk), "{junk:?} must be rejected");
            }
        }
    }

    fn slice_as_iovec(buf: &[u8]) -> libc::iovec {
        libc::iovec {
            iov_base: buf.as_ptr() as *mut u8 as *mut _,
            iov_len: buf.len(),
        }
    }

    fn buf_mut_as_iovec(buf: &mut dyn BufMut) -> libc::iovec {
        let chunk = buf.chunk_mut();
        libc::iovec {
            iov_base: chunk.as_mut_ptr() as *mut _,
            iov_len: chunk.len(),
        }
    }

    /// SAFETY: `msg` be initialized, and its cmsgs must outlive the returned iterator
    unsafe fn cmsg_iter(msg: &libc::msghdr) -> CmsgIterator<'_> {
        CmsgIterator(msg, std::ptr::null())
    }

    struct CmsgIterator<'a>(&'a libc::msghdr, *const libc::cmsghdr);

    impl Iterator for CmsgIterator<'_> {
        type Item = NonNull<libc::cmsghdr>;

        fn next(&mut self) -> Option<Self::Item> {
            let next;
            if self.1.is_null() {
                // SAFETY: we were constructed with a valid `msghdr`
                next = unsafe { libc::CMSG_FIRSTHDR(self.0) };
            } else {
                // SAFETY: we were constructed with a valid `msghdr`, and the `cmsghdr` is nonnull and came from a previous call
                next = unsafe { libc::CMSG_NXTHDR(self.0, self.1) };
            }

            self.1 = next;

            NonNull::new(next)
        }
    }

    /// SAFETY: `cmsg` has enough space for an `in_pktinfo` or `in6_pktinfo` message
    unsafe fn scoped_ip_addr_to_cmsg(cmsg: NonNull<libc::cmsghdr>, addr: ScopedIpAddr) -> usize {
        let in_pktinfo;
        let in6_pktinfo;
        let pktinfo_ptr;
        let pktinfo_len;
        // The level and type must match the family: an IPv6 socket ignores
        // an `IP_PKTINFO` cmsg, so an IPv6 source sent that way was silently
        // replaced by the kernel's choice (found by zl-zipline#230's
        // `send_from_vanished_source_is_a_network_change_error`).
        let (cmsg_level, cmsg_type);

        match &addr {
            ScopedIpAddr::V4(addr) => {
                in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                pktinfo_ptr = &in_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in_pktinfo);
                (cmsg_level, cmsg_type) = (libc::IPPROTO_IP, libc::IP_PKTINFO);
            }

            ScopedIpAddr::V6(addr) => {
                in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                pktinfo_ptr = &in6_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in6_pktinfo);
                (cmsg_level, cmsg_type) = (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO);
            }
        }

        // SAFETY: we were called with a valid `cmsg` with enough space
        unsafe {
            cmsg.write(libc::cmsghdr {
                cmsg_len: libc::CMSG_LEN(pktinfo_len as u32) as usize,
                cmsg_level,
                cmsg_type,
            });
            libc::CMSG_DATA(cmsg.as_ptr()).copy_from(pktinfo_ptr, pktinfo_len); // note unaligned (*u8) copy!
            return libc::CMSG_SPACE(pktinfo_len as u32) as usize;
        }
    }

    /// SAFETY: `cmsg` must point to a valid `cmsghdr`
    unsafe fn cmsg_to_scoped_ip_addr(cmsg: *const libc::cmsghdr) -> Option<ScopedIpAddr> {
        // SAFETY: `cmsg` points to a valid cmsg
        let cmsg_ref = unsafe { cmsg.as_ref()? };
        match (cmsg_ref.cmsg_level, cmsg_ref.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))))
            }

            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V6(ScopedIpv6Addr::new(
                    Ipv6Addr::from(info.ipi6_addr.s6_addr),
                    info.ipi6_ifindex,
                )))
            }

            _ => None,
        }
    }
}

#[cfg(unix)]
mod posix_unbatched {
    //! Unbatched implementation using POSIX primitives.

    use super::*;
    use crate::sys::wait::WaitHandle;
    use bytes::BufMut;
    use nix::cmsg_space;
    use nix::sys::socket::{
        self, ControlMessageOwned, MsgFlags, SockaddrStorage, sockaddr_storage,
    };
    use nix::unistd;
    use std::io::{IoSlice, IoSliceMut, Result};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use zpr_ext::std::mem::slice_assume_init_mut;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    pub struct BatchIo {
        cmsg_buffer: Vec<u8>,
    }

    macro_rules! scoped_ip_addr_to_cmsg (
        ($cmsg_id:ident : $addr:expr) => {
            let in_pktinfo;
            let in6_pktinfo;
            let $cmsg_id;
            match $addr {
                zpr_utils::net_defs::ScopedIpAddr::V4(addr) => {
                    in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv4PacketInfo(&in_pktinfo);
                },

                zpr_utils::net_defs::ScopedIpAddr::V6(addr) => {
                    in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv6PacketInfo(&in6_pktinfo);
                },
            }
        }
    );

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "posix_unbatched";

        pub const MAX_ENTRIES: usize = 1024;

        pub fn detect_support() -> bool {
            // theoretically always available
            true
        }

        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {
                cmsg_buffer: cmsg_space!(sockaddr_storage),
            })
        }

        fn do_batch_op<'a, Item, Res>(
            mut op: impl FnMut(BorrowedFd<'a>, Item) -> Result<Res>,
            fd: BorrowedFd<'a>,
            items: &mut dyn Iterator<Item = Item>,
            results: &'a mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let mut completed = 0;
            while let Some(item) = items.next() {
                let res = op(fd, item);
                if let Err(err) = res {
                    // emulate behavior of sendmmsg(2)

                    if completed == 0 {
                        return Err(err);
                    }

                    break;
                }
                results.push(res);
                completed += 1;
            }

            Ok(completed)
        }
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| unistd::write(fd, buf).map_err(errno_to_error),
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let amt = unistd::read(fd, chunk).map_err(errno_to_error)?;
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(amt as usize) };
                    Ok(amt)
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, (buf, addr, flags): (_, _, SendFlags)| {
                    socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(addr),
                        MsgFlags::from_bits_retain(flags.bits()),
                    )
                    .map_err(errno_to_error)
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, (buf, dst, src, flags): (_, _, _, SendFlags)| match src {
                    Some(src) => {
                        scoped_ip_addr_to_cmsg!(cmsg: &src);
                        socket::sendmsg(
                            fd.as_raw_fd(),
                            &[IoSlice::new(buf)],
                            &[cmsg],
                            MsgFlags::from_bits_retain(flags.bits()),
                            Some(&SockaddrStorage::from(dst)),
                        )
                        .map_err(errno_to_error)
                    }

                    None => socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(dst),
                        MsgFlags::from_bits_retain(flags.bits()),
                    )
                    .map_err(errno_to_error),
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    // NOTE: nix's `recvfrom` weirdly is missing the `flags` argument,
                    // so we're forced to use `recvmsg` here
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        None,
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination: None,
                    })
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        Some(&mut self.cmsg_buffer),
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    let destination = recvmsg
                        .cmsgs()
                        .expect("cmsgs sizing error")
                        .find_map(cmsg_to_scoped_ip_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination,
                    })
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }
    }

    fn cmsg_to_scoped_ip_addr(cmsg: ControlMessageOwned) -> Option<ScopedIpAddr> {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(ScopedIpAddr::V4(Ipv4Addr::from(
                u32::from_be(info.ipi_addr.s_addr),
            ))),

            ControlMessageOwned::Ipv6PacketInfo(info) => Some(ScopedIpAddr::V6(
                ScopedIpv6Addr::new(Ipv6Addr::from(info.ipi6_addr.s6_addr), info.ipi6_ifindex),
            )),

            _ => None,
        }
    }
}

/// The socket half of the Windows engine (zipline#131, zipline#150):
/// unbatched non-blocking `WSASendMsg`/`WSARecvMsg` on the substrate
/// `std::net::UdpSocket`.
///
/// Like the unix engines, it carries per-datagram addresses in
/// `IP_PKTINFO`/`IPV6_PKTINFO` control messages: the receive path reports
/// each datagram's real destination, and the send path honours a source
/// address chosen by the caller. That is what lets a Windows substrate
/// socket bind a wildcard address, exactly as on unix.
///
/// Batch semantics mirror `posix_unbatched::do_batch_op` (which emulates
/// `sendmmsg(2)`): the first item's failure is returned as the batch error;
/// a later item's failure ends the batch early with the successes so far.
#[cfg(windows)]
mod windows_udp {
    use super::{ReceivedPacket, SendFlags};
    use bytes::BufMut;
    use std::io::Result;
    use std::mem::{offset_of, size_of};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::os::windows::io::{AsRawSocket, AsSocket};
    use std::sync::OnceLock;
    use windows_sys::Win32::Networking::WinSock::{
        CMSGHDR, IN_PKTINFO, IN6_PKTINFO, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO,
        LPFN_WSARECVMSG, LPWSAOVERLAPPED_COMPLETION_ROUTINE, MSG_TRUNC,
        SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKET, SOCKET_ERROR, WSABUF, WSAEMSGSIZE,
        WSAID_WSARECVMSG, WSAIoctl, WSAMSG, WSASendMsg, setsockopt,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    use windows_sys::core::GUID;
    use zpr_ext::std::mem::slice_assume_init_mut;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    /// `WSA_CMSGDATA_ALIGN` / `WSA_CMSGHDR_ALIGN` from `ws2def.h`: a control
    /// message, and the data inside it, start on a pointer-size boundary.
    const fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    /// `WSA_CMSG_DATA`: where a control message's data starts, counted from
    /// its header.
    const CMSG_DATA_OFFSET: usize = cmsg_align(size_of::<CMSGHDR>());

    /// `WSA_CMSG_SPACE`: the buffer bytes that one control message with
    /// `data_len` bytes of data occupies.
    const fn cmsg_space(data_len: usize) -> usize {
        cmsg_align(CMSG_DATA_OFFSET + data_len)
    }

    /// Room for one pktinfo control message of either family, the only
    /// control message a substrate socket asks for.
    const PKTINFO_CMSG_SPACE: usize = {
        let v4 = cmsg_space(size_of::<IN_PKTINFO>());
        let v6 = cmsg_space(size_of::<IN6_PKTINFO>());
        if v4 > v6 { v4 } else { v6 }
    };

    /// A control-message buffer, aligned for the `CMSGHDR` at its start as
    /// Winsock expects. Encoded and decoded as bytes, in safe code.
    #[repr(C, align(8))]
    pub(super) struct CmsgBuffer(pub(super) [u8; PKTINFO_CMSG_SPACE]);

    const _: () = assert!(std::mem::align_of::<CmsgBuffer>() >= std::mem::align_of::<CMSGHDR>());

    impl CmsgBuffer {
        /// An all-zero buffer.
        pub(super) fn new() -> Self {
            Self([0; PKTINFO_CMSG_SPACE])
        }
    }

    /// Copy `value` into `bytes` at `offset`. Only used with offsets and
    /// sizes taken from the Winsock structs that fit in a [`CmsgBuffer`].
    fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    /// The `N` bytes of `bytes` at `offset`, or `None` if they run past the
    /// end. Lets the decoder read untrusted lengths without panicking.
    fn field<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
        bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
    }

    /// Encode one control message that names `src` as a datagram's source
    /// address into `buf`, and return the number of control bytes to send.
    ///
    /// IPv4: an `IN_PKTINFO` with the interface index left 0, so the OS
    /// picks the interface by route, as the unix engines ask. IPv6: an
    /// `IN6_PKTINFO` with the address's scope id as the interface index.
    pub(super) fn encode_source_pktinfo(src: &ScopedIpAddr, buf: &mut CmsgBuffer) -> usize {
        let (level, kind, data_len) = match src {
            ScopedIpAddr::V4(_) => (IPPROTO_IP, IP_PKTINFO, size_of::<IN_PKTINFO>()),
            ScopedIpAddr::V6(_) => (IPPROTO_IPV6, IPV6_PKTINFO, size_of::<IN6_PKTINFO>()),
        };
        let bytes = &mut buf.0;
        bytes.fill(0);
        put(
            bytes,
            offset_of!(CMSGHDR, cmsg_len),
            &(CMSG_DATA_OFFSET + data_len).to_ne_bytes(),
        );
        put(bytes, offset_of!(CMSGHDR, cmsg_level), &level.to_ne_bytes());
        put(bytes, offset_of!(CMSGHDR, cmsg_type), &kind.to_ne_bytes());
        match src {
            ScopedIpAddr::V4(ip) => {
                put(
                    bytes,
                    CMSG_DATA_OFFSET + offset_of!(IN_PKTINFO, ipi_addr),
                    &ip.octets(),
                );
            }
            ScopedIpAddr::V6(ip) => {
                put(
                    bytes,
                    CMSG_DATA_OFFSET + offset_of!(IN6_PKTINFO, ipi6_addr),
                    &ip.ip().octets(),
                );
                put(
                    bytes,
                    CMSG_DATA_OFFSET + offset_of!(IN6_PKTINFO, ipi6_ifindex),
                    &ip.scope_id().to_ne_bytes(),
                );
            }
        }
        cmsg_space(data_len)
    }

    /// Decode a received datagram's destination address from its control
    /// messages: the first `IN_PKTINFO` or `IN6_PKTINFO`, with the IPv6
    /// interface index as the scope id, as the unix engines report it.
    ///
    /// `None` when there is no pktinfo message (pktinfo is not enabled on
    /// the socket) or the messages are malformed: the walk never reads past
    /// `control`, whatever lengths it finds.
    pub(super) fn decode_destination(control: &[u8]) -> Option<ScopedIpAddr> {
        let mut rest = control;
        while !rest.is_empty() {
            let len = usize::from_ne_bytes(field(rest, offset_of!(CMSGHDR, cmsg_len))?);
            let level = i32::from_ne_bytes(field(rest, offset_of!(CMSGHDR, cmsg_level))?);
            let kind = i32::from_ne_bytes(field(rest, offset_of!(CMSGHDR, cmsg_type))?);
            let data = rest.get(CMSG_DATA_OFFSET..len)?;
            match (level, kind) {
                (IPPROTO_IP, IP_PKTINFO) => {
                    let addr = field::<4>(data, offset_of!(IN_PKTINFO, ipi_addr))?;
                    return Some(ScopedIpAddr::V4(Ipv4Addr::from(addr)));
                }
                (IPPROTO_IPV6, IPV6_PKTINFO) => {
                    let addr = field::<16>(data, offset_of!(IN6_PKTINFO, ipi6_addr))?;
                    let ifindex = field(data, offset_of!(IN6_PKTINFO, ipi6_ifindex))?;
                    return Some(ScopedIpAddr::V6(ScopedIpv6Addr::new(
                        Ipv6Addr::from(addr),
                        u32::from_ne_bytes(ifindex),
                    )));
                }
                _ => rest = rest.get(cmsg_align(len)..)?,
            }
        }
        None
    }

    /// `WSARecvMsg`'s signature: `LPFN_WSARECVMSG` without the `Option`.
    type WsaRecvMsgFn = unsafe extern "system" fn(
        SOCKET,
        *mut WSAMSG,
        *mut u32,
        *mut OVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;

    /// `WSARecvMsg`, resolved once for the process.
    ///
    /// Winsock exports `WSASendMsg`, but `WSARecvMsg` is an extension
    /// function whose address the socket's provider hands out through
    /// `SIO_GET_EXTENSION_FUNCTION_POINTER`. Every substrate socket is
    /// created the same way, a UDP socket of the base TCP/IP provider
    /// (`mswsock`, for IPv4 and IPv6 alike), and that provider hands out one
    /// function for all of them, so the first socket's answer serves every
    /// later socket.
    static WSA_RECV_MSG: OnceLock<WsaRecvMsgFn> = OnceLock::new();

    /// The `WSARecvMsg` function for `socket`: the cached one, or ask the
    /// socket's provider the first time (see [`WSA_RECV_MSG`]).
    fn wsa_recv_msg(socket: SOCKET) -> Result<WsaRecvMsgFn> {
        if let Some(func) = WSA_RECV_MSG.get() {
            return Ok(*func);
        }
        let guid: GUID = WSAID_WSARECVMSG;
        let mut func: LPFN_WSARECVMSG = None;
        let mut bytes_returned: u32 = 0;
        // SAFETY: the socket is live (the caller borrows it for this call);
        // the input buffer is a readable GUID of the size passed; the output
        // buffer is a writable LPFN_WSARECVMSG (an Option of a function
        // pointer, which Winsock fills with the function's address) of the
        // size passed; no OVERLAPPED or completion routine, so the call is
        // synchronous and keeps no pointer after it returns.
        let rc = unsafe {
            WSAIoctl(
                socket,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid as *const GUID as *const core::ffi::c_void,
                size_of::<GUID>() as u32,
                &mut func as *mut LPFN_WSARECVMSG as *mut core::ffi::c_void,
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let func =
            func.ok_or_else(|| std::io::Error::other("the socket provider has no WSARecvMsg"))?;
        Ok(*WSA_RECV_MSG.get_or_init(|| func))
    }

    /// Enable or disable per-datagram packet info on a bound socket: the
    /// Windows twin of the unix `set_recv_packet_info`. Sets `IP_PKTINFO`
    /// or `IPV6_PKTINFO` for the socket's family, so that each received
    /// datagram carries its destination address. It also resolves
    /// `WSARecvMsg`, so a socket the receive path could not serve fails
    /// here, at `open`, and not on its first datagram.
    ///
    /// Unlike unix, the socket must be bound first: Windows' `getsockname`
    /// fails on an unbound socket, and the family comes from it.
    pub fn set_recv_packet_info(socket: &impl AsSocket, enable: bool) -> Result<()> {
        let local = socket2::SockRef::from(socket).local_addr()?;
        let (level, name) = match local.as_socket() {
            Some(SocketAddr::V4(_)) => (IPPROTO_IP, IP_PKTINFO),
            Some(SocketAddr::V6(_)) => (IPPROTO_IPV6, IPV6_PKTINFO),
            None => return Ok(()),
        };
        let raw = socket.as_socket().as_raw_socket() as SOCKET;
        let value: i32 = enable.into();
        // SAFETY: the socket is live (borrowed for this call); the option
        // value is a readable i32 (a Winsock BOOL) of the size passed, and
        // Winsock copies it before returning.
        let rc = unsafe {
            setsockopt(
                raw,
                level,
                name,
                &value as *const i32 as *const u8,
                size_of::<i32>() as i32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        wsa_recv_msg(raw)?;
        Ok(())
    }

    /// `posix_unbatched::do_batch_op`'s loop shape, on a socket instead of
    /// an fd.
    fn do_batch_op<Item, Res>(
        mut op: impl FnMut(&UdpSocket, Item) -> Result<Res>,
        socket: &UdpSocket,
        items: &mut dyn Iterator<Item = Item>,
        results: &mut Vec<Result<Res>>,
    ) -> Result<usize> {
        let mut completed = 0;
        for item in items {
            let res = op(socket, item);
            if let Err(err) = res {
                // emulate behavior of sendmmsg(2)
                if completed == 0 {
                    return Err(err);
                }
                break;
            }
            results.push(res);
            completed += 1;
        }
        Ok(completed)
    }

    /// Send one datagram to `dst` with `WSASendMsg`: from `src` when it is
    /// given (an `IN_PKTINFO`/`IN6_PKTINFO` control message), otherwise from
    /// the address the OS picks, like a plain `sendto`.
    fn send_msg(
        socket: &UdpSocket,
        buf: &[u8],
        dst: SocketAddr,
        src: Option<&ScopedIpAddr>,
        flags: SendFlags,
    ) -> Result<usize> {
        let dst = socket2::SockAddr::from(dst);
        let mut control = CmsgBuffer::new();
        let control = match src {
            Some(src) => {
                let len = encode_source_pktinfo(src, &mut control);
                WSABUF {
                    len: len as u32,
                    buf: control.0.as_mut_ptr(),
                }
            }
            // No control data: Winsock wants a null buffer, not an empty one.
            None => WSABUF {
                len: 0,
                buf: std::ptr::null_mut(),
            },
        };
        let mut data = WSABUF {
            len: buf.len().min(u32::MAX as usize) as u32,
            // WSABUF has no const variant; WSASendMsg only reads the data.
            buf: buf.as_ptr().cast_mut(),
        };
        let msg = WSAMSG {
            name: dst.as_ptr().cast_mut().cast(),
            namelen: dst.len(),
            lpBuffers: &mut data,
            dwBufferCount: 1,
            Control: control,
            dwFlags: 0,
        };
        let mut sent: u32 = 0;
        // SAFETY: every pointer in `msg` names a live local or `buf`, with
        // the length passed (`dst`, `data` -> `buf`, the control buffer);
        // Winsock only reads them. There is no OVERLAPPED or completion
        // routine, so the call is synchronous and keeps no pointer after it
        // returns.
        let rc = unsafe {
            WSASendMsg(
                socket.as_raw_socket() as SOCKET,
                &msg,
                flags.bits() as u32,
                &mut sent,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        Ok(sent as usize)
    }

    /// Send datagrams to explicit destinations, each from its caller-chosen
    /// source address when one is given. The engine's plain `send_to` leg
    /// comes here too, with no source.
    pub fn send_to_from_batch(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = (&[u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        do_batch_op(
            |socket, (buf, dst, src, flags)| send_msg(socket, buf, dst, src.as_ref(), flags),
            socket,
            bufs,
            results,
        )
    }

    /// Receive one datagram into `buf` with `WSARecvMsg`, returning its
    /// size, whether it was truncated, its source address, and (with
    /// `with_dest`) its destination address from the pktinfo control
    /// message.
    ///
    /// An oversized datagram is reported as truncated, which the fastpath
    /// drops and counts, like `MSG_TRUNC` on unix: Winsock either flags it
    /// `MSG_TRUNC`, or fails with `WSAEMSGSIZE` after filling the whole
    /// buffer, in which case the addresses are lost with the error (the
    /// truncated path never reads them).
    fn recv_msg(socket: &UdpSocket, buf: &mut [u8], with_dest: bool) -> Result<ReceivedPacket> {
        let raw = socket.as_raw_socket() as SOCKET;
        let wsa_recv = wsa_recv_msg(raw)?;
        let mut control = CmsgBuffer::new();
        let mut data = WSABUF {
            len: buf.len().min(u32::MAX as usize) as u32,
            buf: buf.as_mut_ptr(),
        };
        let mut size: u32 = 0;
        let mut flags: u32 = 0;
        let mut control_len: usize = 0;
        // SAFETY: `try_init` hands the closure a zeroed, writable
        // sockaddr_storage and its length, and builds the source address
        // from what the closure leaves there. In the closure, every pointer
        // in `msg` names a live local or `buf` with the length passed
        // (`data` -> `buf`, the control buffer, the address storage);
        // there is no OVERLAPPED or completion routine, so `WSARecvMsg` is
        // synchronous and keeps no pointer after it returns.
        let received = unsafe {
            socket2::SockAddr::try_init(|storage, storage_len| {
                let mut msg = WSAMSG {
                    name: storage.cast(),
                    namelen: *storage_len,
                    lpBuffers: &mut data,
                    dwBufferCount: 1,
                    Control: WSABUF {
                        len: PKTINFO_CMSG_SPACE as u32,
                        buf: control.0.as_mut_ptr(),
                    },
                    dwFlags: 0,
                };
                let rc = wsa_recv(raw, &mut msg, &mut size, std::ptr::null_mut(), None);
                if rc == SOCKET_ERROR {
                    return Err(std::io::Error::last_os_error());
                }
                *storage_len = msg.namelen;
                flags = msg.dwFlags;
                control_len = msg.Control.len as usize;
                Ok(())
            })
        };
        match received {
            Ok(((), source)) => Ok(ReceivedPacket {
                size: size as usize,
                truncated: flags & MSG_TRUNC != 0,
                source: source.as_socket(),
                destination: if with_dest {
                    decode_destination(control.0.get(..control_len).unwrap_or(&[]))
                } else {
                    None
                },
            }),
            Err(err) if err.raw_os_error() == Some(WSAEMSGSIZE) => Ok(ReceivedPacket {
                size: buf.len(),
                truncated: true,
                source: None,
                destination: None,
            }),
            Err(err) => Err(err),
        }
    }

    /// Receive datagrams with their source addresses and, with `with_dest`,
    /// their destination addresses (see [`recv_msg`]).
    pub fn recv_from_batch(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = &mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
        with_dest: bool,
    ) -> Result<usize> {
        do_batch_op(
            |socket, buf| {
                // SAFETY: We will only be writing to the chunk.
                let chunk = unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                // A swallowed peer reset consumed no datagram, so retry
                // the receive with the same buffer (bounded) rather than
                // ending the batch per reset — see
                // `recv_retrying_connreset` (zl-zpr-core#62 review).
                let packet = recv_retrying_connreset(|| recv_msg(socket, chunk, with_dest))?;
                // SAFETY: We know we've written the given number of bytes in the BufMut.
                unsafe { buf.advance_mut(packet.size) };
                Ok(packet)
            },
            socket,
            bufs,
            results,
        )
    }

    /// Map a peer's connection reset to "no datagram" (zipline#160, plan
    /// N4). On Windows an ICMP port-unreachable from a departed peer makes
    /// a later `recvfrom` on an unconnected UDP socket fail with
    /// `WSAECONNRESET` (10054); nothing was received and the socket is
    /// fine, so surface it as `WouldBlock` — exactly as an empty socket
    /// ends a batch. The receive path retries past swallowed resets first
    /// (see [`recv_retrying_connreset`]); this mapping is its capped
    /// fallback. This is the belt-and-braces fallback behind the
    /// `SIO_UDP_CONNRESET` ioctl disabled at bind
    /// (`sys::substrate::open`'s Windows arm, zipline#176); a `trace!`
    /// counter keeps a reset storm visible.
    pub(super) fn connreset_as_wouldblock(err: std::io::Error) -> std::io::Error {
        if err.kind() == std::io::ErrorKind::ConnectionReset {
            use std::sync::atomic::{AtomicU64, Ordering};
            // Counter so a reset storm is visible at trace level without
            // flooding higher levels (resets are normal when peers leave).
            static RESETS: AtomicU64 = AtomicU64::new(0);
            let total = RESETS.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::trace!(
                target: crate::logging::targets::DATAPATH,
                "substrate recv ignored a peer connection reset ({total} total): {err}"
            );
            return std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "peer connection reset; no datagram",
            );
        }
        err
    }

    /// Consecutive-reset bound for [`recv_retrying_connreset`]: enough
    /// that a burst of departed-peer resets cannot end a batch while real
    /// datagrams sit queued behind them, small enough that a pathological
    /// reset storm cannot pin the dispatch thread in the retry loop —
    /// past the cap the receive falls back to the "no datagram" mapping,
    /// the batch ends, and the dispatcher re-polls as before.
    pub(super) const CONNRESET_RETRY_CAP: u32 = 64;

    /// Retry a receive whose failure was a peer connection reset
    /// (zl-zpr-core#62 review on zipline#160). A swallowed
    /// `WSAECONNRESET` consumed no datagram — the socket is fine and
    /// valid packets may already be queued behind the reset — so ending
    /// the batch per reset (one wake/dispatch each) can starve
    /// legitimate substrate traffic when `SIO_UDP_CONNRESET` could not
    /// be disabled. Instead the receive is retried with the same buffer,
    /// bounded by [`CONNRESET_RETRY_CAP`]; every swallowed reset is
    /// counted and traced via [`connreset_as_wouldblock`], which also
    /// supplies the capped fallback. Every other outcome — a datagram, a
    /// genuine `WouldBlock`, any other error — returns immediately.
    pub(super) fn recv_retrying_connreset<T>(
        mut recv: impl FnMut() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let mut resets = 0u32;
        loop {
            match recv() {
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                    // Count and trace the swallowed reset; the mapped
                    // WouldBlock doubles as the capped fallback.
                    let mapped = connreset_as_wouldblock(err);
                    if resets >= CONNRESET_RETRY_CAP {
                        return Err(mapped);
                    }
                    resets += 1;
                }
                other => return other,
            }
        }
    }
}

#[cfg(windows)]
mod windows_unbatched {
    //! Unbatched implementation for Windows (zipline#131).
    //!
    //! Socket side: the `windows_udp` half (non-blocking
    //! `WSASendMsg`/`WSARecvMsg` with pktinfo, zipline#150).
    //! TUN side: the Wintun ring, via `ZprTun::try_receive` /
    //! `ZprTun::send` (`WintunReceivePacket` / `WintunAllocateSendPacket` +
    //! `WintunSendPacket`), which half an operation targets is carried by
    //! the [`WaitTarget`] inside the `WaitHandle`: `read`/`write` reach the
    //! TUN ring, `send_to`/`recv_from` reach the socket.

    use super::{BatchIoImpl, ReceivedPacket, SendFlags, windows_udp};
    use crate::sys::wait::{WaitHandle, WaitTarget};
    use bytes::BufMut;
    use std::io::Result;
    use std::net::SocketAddr;
    use zpr_utils::net_defs::ScopedIpAddr;

    pub struct BatchIo {}

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "windows_unbatched";

        pub const MAX_ENTRIES: usize = 1024;

        pub fn detect_support() -> bool {
            // std sockets and the Wintun ring are always available.
            true
        }

        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {})
        }
    }

    /// The socket an I/O op targets; a TUN handle here is a caller bug.
    fn expect_socket<'a>(handle: WaitHandle<'a>, op: &str) -> &'a std::net::UdpSocket {
        match handle.target() {
            WaitTarget::Socket(socket) => socket,
            _ => panic!("windows_unbatched: {op} targets the substrate socket"),
        }
    }

    /// The TUN an I/O op targets; a socket handle here is a caller bug.
    fn expect_tun<'a>(handle: WaitHandle<'a>, op: &str) -> &'a crate::sys::ZprTun {
        match handle.target() {
            WaitTarget::Tun(tun) => tun,
            _ => panic!("windows_unbatched: {op} targets the TUN"),
        }
    }

    /// `windows_udp::do_batch_op`'s loop shape for the TUN ring legs.
    fn do_tun_batch_op<Item, Res>(
        mut op: impl FnMut(&crate::sys::ZprTun, Item) -> Result<Res>,
        tun: &crate::sys::ZprTun,
        items: &mut dyn Iterator<Item = Item>,
        results: &mut Vec<Result<Res>>,
    ) -> Result<usize> {
        let mut completed = 0;
        for item in items {
            let res = op(tun, item);
            if let Err(err) = res {
                // emulate behavior of sendmmsg(2), as the other engines do
                if completed == 0 {
                    return Err(err);
                }
                break;
            }
            results.push(res);
            completed += 1;
        }
        Ok(completed)
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        /// TUN egress: commit each packet to the Wintun send ring.
        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            let tun = expect_tun(handle, "try_write_batch");
            do_tun_batch_op(
                |tun, buf: &[u8]| tun.send(buf).map(|()| buf.len()),
                tun,
                bufs,
                results,
            )
        }

        /// TUN ingress: drain the Wintun receive ring. An empty ring ends
        /// the batch (`WouldBlock` first, per the sendmmsg(2) emulation all
        /// engines share); the fastpath re-arms on the read-wait event.
        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            let tun = expect_tun(handle, "try_read_buf_batch");
            do_tun_batch_op(
                |tun, buf: &mut dyn BufMut| match tun.try_receive()? {
                    Some(packet) => {
                        let body = packet.bytes();
                        // An oversized frame cannot arrive: the ring frame
                        // limit (u16) is far under the packet buffer size.
                        buf.put_slice(body);
                        Ok(body.len())
                    }
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "Wintun receive ring empty",
                    )),
                },
                tun,
                bufs,
                results,
            )
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            // A plain send is a send with no source address: one send path.
            windows_udp::send_to_from_batch(
                expect_socket(handle, "try_send_to_batch"),
                &mut bufs.map(|(buf, dst, flags)| (buf, dst, None, flags)),
                results,
            )
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            windows_udp::send_to_from_batch(
                expect_socket(handle, "try_send_to_from_batch"),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            windows_udp::recv_from_batch(
                expect_socket(handle, "try_recv_buf_from_batch"),
                bufs,
                results,
                false,
            )
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            windows_udp::recv_from_batch(
                expect_socket(handle, "try_recv_buf_from_to_batch"),
                bufs,
                results,
                true,
            )
        }
    }
}

// The engine registration macro: consumed by every arm of ENGINES.
macro_rules! bio {
    ($m:tt) => {
        BatchIoEngine {
            engine_name: $m::BatchIo::ENGINE_NAME,
            max_entries: $m::BatchIo::MAX_ENTRIES,
            factory: |e| $m::BatchIo::new(e).map(|bio| Box::new(bio) as Box<dyn BatchIoImpl>),
            detect_support: $m::BatchIo::detect_support,
        }
    };
}

const ENGINES: &[BatchIoEngine] = &[
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    bio!(io_uring),
    #[cfg(unix)]
    bio!(posix_unbatched),
    #[cfg(windows)]
    bio!(windows_unbatched),
];

/// List of available engine names.  Does not include automatic selection.
pub fn engine_names() -> impl Iterator<Item = &'static str> {
    ENGINES.iter().map(|e| e.engine_name)
}

/// "Engine" name which indicates an engine should be selected automatically
/// (as by `auto_select_engine()`).
pub const AUTO_ENGINE_NAME: &'static str = "auto";

/// Select an engine by name (as listed by `engine_names()`).
/// Supplying `AUTO_ENGINE_NAME` will use automatic selection
/// (as by `auto_select_engine()`).
pub fn select_engine_by_name(name: &str) -> Option<&'static BatchIoEngine> {
    if name == AUTO_ENGINE_NAME {
        Some(auto_select_engine())
    } else {
        ENGINES.iter().find(|e| e.engine_name == name)
    }
}

/// Select the best engine which is available on the current system.
pub fn auto_select_engine() -> &'static BatchIoEngine {
    ENGINES
        .iter()
        .find(|e| e.detect_support())
        .expect("no supported I/O engines!")
}

/// Represents an available batch I/O engine which may be instantiated.
pub struct BatchIoEngine {
    engine_name: &'static str,
    max_entries: usize,
    factory: fn(usize) -> Result<Box<dyn BatchIoImpl>>,
    detect_support: fn() -> bool,
}

impl BatchIoEngine {
    /// The name of this I/O engine.
    pub fn engine_name(&self) -> &'static str {
        self.engine_name
    }

    /// The maximum number of entries per batch this I/O engine supports.
    #[allow(dead_code)]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Instantiate this batch I/O engine,
    /// supporting the supplied number of entries per batch.
    pub fn instantiate(&self, entries: usize) -> Result<BatchIo> {
        Ok(BatchIo((self.factory)(entries)?))
    }

    /// Detect whether this engine is supported by the host environment.
    pub fn detect_support(&self) -> bool {
        (self.detect_support)()
    }
}

pub struct BatchIo(Box<dyn BatchIoImpl>);

impl BatchIo {
    #[allow(dead_code)]
    pub fn engine_name(&self) -> &'static str {
        self.0.engine_name()
    }

    pub fn try_write_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_write_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    pub fn try_read_buf_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_read_buf_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    #[allow(dead_code)]
    pub fn try_send_to_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    pub fn try_send_to_from_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_from_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    #[allow(dead_code)]
    pub fn try_recv_buf_from_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    pub fn try_recv_buf_from_to_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_to_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use std::io::Result;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
    use std::time::Duration;

    /// Unix only: drives `try_write_batch` through a UDP socket, but on
    /// Windows that op targets the TUN only (the Windows socket legs are
    /// covered by the `send_to`/`recv_from` engine tests).
    #[cfg(unix)]
    #[test]
    fn test_write() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let (inq, outq) = connected_udp_pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            let mut results = Vec::new();

            let n = bio.try_write_batch(&inq, msgs.iter().map(|msg| msg.as_bytes()), &mut results);
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
            }

            let mut buf = [0u8; 256];
            for i in 0..nmsgs {
                let msg_size = outq.recv(&mut buf).unwrap();
                assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
            }
        }
    }

    /// Unix only: drives `try_read_buf_batch` through a UDP socket, but on
    /// Windows that op targets the TUN only (the Windows socket legs are
    /// covered by the `send_to`/`recv_from` engine tests).
    #[cfg(unix)]
    #[test]
    fn test_read() {
        for engine in ENGINES {
            let (inq, outq) = connected_udp_pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            for msg in &msgs {
                let _ = inq.send(msg.as_bytes()).unwrap();
            }

            let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
            let mut results = Vec::new();

            let n = bio.try_read_buf_batch(&outq, bufs.iter_mut(), &mut results);
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
                assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
            }
        }
    }

    #[test]
    fn test_send() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            let mut results = Vec::new();

            let dest = outq.local_addr().unwrap();

            let n = bio.try_send_to_batch(
                &inq,
                msgs.iter()
                    .map(|msg| (msg.as_bytes(), dest, SendFlags::none())),
                &mut results,
            );
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
            }

            let mut buf = [0u8; 256];
            for i in 0..nmsgs {
                let msg_size = outq.recv(&mut buf).unwrap();
                assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
            }
        }
    }

    #[test]
    fn test_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            for msg in &msgs {
                let _ = inq.send(msg.as_bytes()).unwrap();
            }

            let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_batch(&outq, bufs.iter_mut(), &mut results);
            assert!(n.unwrap() >= nmsgs);

            let sender = inq.local_addr().unwrap();

            for i in 0..nmsgs {
                let res = results[i].as_ref().unwrap();
                assert_eq!(res.size, msgs[i].len());
                assert!(!res.truncated);
                assert_eq!(res.source, Some(sender));
                assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
            }
        }
    }

    #[test]
    fn test_oversize_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    #[test]
    fn test_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            set_recv_packet_info(&outq, true).unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = "Hello".as_bytes();

            let _ = inq.send(msg).unwrap();

            let mut buf = Vec::with_capacity(64);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, msg.len());
            assert!(!res.truncated);
            assert_eq!(res.source, Some(inq.local_addr().unwrap()));
            // NOTE: we don't have any way of testing the scope ID functionality as a unit test
            assert_eq!(
                res.destination.map(|sa| sa.ip()),
                Some(outq.local_addr().unwrap().ip())
            );
            assert_eq!(buf.as_slice(), msg);
        }
    }

    #[test]
    fn test_oversize_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    /// Receive one datagram on the nonblocking `socket` through `bio`'s
    /// `try_recv_buf_from_to_batch`, polling until it arrives, and return
    /// what the engine reported. The payload lands in `buf`.
    fn recv_one_to(bio: &mut BatchIo, socket: &UdpSocket, buf: &mut Vec<u8>) -> ReceivedPacket {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(std::time::Instant::now() < deadline, "datagram lost");
            let mut results = Vec::new();
            match bio.try_recv_buf_from_to_batch(socket, std::iter::once(&mut *buf), &mut results) {
                Ok(1) => return results.pop().unwrap().unwrap(),
                Ok(n) => panic!("one datagram was sent, the engine reported {n}"),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(err) => panic!("batch receive failed: {err}"),
            }
        }
    }

    /// zipline#150: a substrate socket opened on a wildcard address must
    /// report each datagram's real destination, read from pktinfo, and
    /// never the unspecified address it is bound to: the fastpath records
    /// the destination as the link's interface address. This also checks
    /// that `sys::substrate::open` accepts a wildcard on every OS (the
    /// Windows arm used to reject one), for both address families.
    #[test]
    fn test_wildcard_open_recv_to_reports_destination() {
        let cases = [
            (
                IpAddr::from(Ipv4Addr::UNSPECIFIED),
                IpAddr::from(Ipv4Addr::LOCALHOST),
            ),
            (
                IpAddr::from(Ipv6Addr::UNSPECIFIED),
                IpAddr::from(Ipv6Addr::LOCALHOST),
            ),
        ];
        for (wildcard, loopback) in cases {
            for engine in ENGINES {
                let receiver: UdpSocket = crate::sys::substrate::open(SocketAddr::new(wildcard, 0))
                    .unwrap_or_else(|err| panic!("open on wildcard {wildcard} failed: {err}"))
                    .into();
                let port = receiver.local_addr().unwrap().port();
                let sender = UdpSocket::bind(SocketAddr::new(loopback, 0)).unwrap();
                sender
                    .send_to(b"hello", SocketAddr::new(loopback, port))
                    .unwrap();

                let mut bio = engine.instantiate(1).unwrap();
                let mut buf = Vec::with_capacity(64);
                let packet = recv_one_to(&mut bio, &receiver, &mut buf);

                assert_eq!(packet.source, Some(sender.local_addr().unwrap()));
                assert_eq!(
                    packet.destination.map(|dst| dst.ip()),
                    Some(loopback),
                    "{}: destination must be the address the datagram was sent to",
                    engine.engine_name()
                );
                assert_eq!(buf.as_slice(), b"hello");
            }
        }
    }

    /// The IPv4 source that `test_send_from_explicit_source` asks for. On
    /// Linux all of 127.0.0.0/8 is a local source, so 127.0.0.2 is valid
    /// but never what the OS picks on its own for a send to 127.0.0.1: the
    /// receiver seeing it proves the source was honoured. macOS and Windows
    /// accept only 127.0.0.1 as a loopback source (Windows answers a
    /// 127.0.0.2 source with `WSAEINVAL`), so there the case proves that an
    /// explicit source is accepted, and
    /// `test_send_from_non_local_source_fails` proves it is not ignored.
    #[cfg(target_os = "linux")]
    const EXPLICIT_V4_SOURCE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    #[cfg(not(target_os = "linux"))]
    const EXPLICIT_V4_SOURCE: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// zipline#150: a send with an explicit source address must leave from
    /// that address, also on a wildcard-bound socket where the OS would
    /// otherwise choose the source. The receiver's `recv_from` reports the
    /// source the datagram really carried. (IPv6 has only `::1` on
    /// loopback, so that case proves the source is accepted, not chosen.)
    #[test]
    fn test_send_from_explicit_source() {
        let cases = [
            (
                IpAddr::from(Ipv4Addr::UNSPECIFIED),
                IpAddr::from(EXPLICIT_V4_SOURCE),
                IpAddr::from(Ipv4Addr::LOCALHOST),
            ),
            (
                IpAddr::from(Ipv6Addr::UNSPECIFIED),
                IpAddr::from(Ipv6Addr::LOCALHOST),
                IpAddr::from(Ipv6Addr::LOCALHOST),
            ),
        ];
        for (wildcard, source, loopback) in cases {
            for engine in ENGINES {
                let sender: UdpSocket = crate::sys::substrate::open(SocketAddr::new(wildcard, 0))
                    .unwrap_or_else(|err| panic!("open on wildcard {wildcard} failed: {err}"))
                    .into();
                let sender_port = sender.local_addr().unwrap().port();
                let receiver = UdpSocket::bind(SocketAddr::new(loopback, 0)).unwrap();
                receiver
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();

                let mut bio = engine.instantiate(1).unwrap();
                let mut results = Vec::new();
                let n = bio.try_send_to_from_batch(
                    &sender,
                    std::iter::once((
                        b"hello".as_slice(),
                        receiver.local_addr().unwrap(),
                        Some(ScopedIpAddr::from(source)),
                        SendFlags::none(),
                    )),
                    &mut results,
                );
                let n = n.unwrap_or_else(|err| {
                    panic!("{}: send from {source} failed: {err}", engine.engine_name())
                });
                assert_eq!(n, 1);
                assert_eq!(*results[0].as_ref().unwrap(), 5);

                let mut buf = [0u8; 64];
                let (size, from) = receiver.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..size], b"hello");
                assert_eq!(
                    from,
                    SocketAddr::new(source, sender_port),
                    "{}: the datagram must carry the requested source",
                    engine.engine_name()
                );
            }
        }
    }

    /// zipline#150: an explicit source that is not a local address must
    /// make the send fail, on every OS and engine. An engine that ignored
    /// the source (as the Windows engine did before pktinfo) would send
    /// from an address of its own choosing and succeed. The error differs
    /// by OS (Linux `EINVAL`, macOS `EADDRNOTAVAIL`, Windows `WSAEINVAL`),
    /// so only the failure is checked. 192.0.2.1 is TEST-NET-1, never a
    /// local address.
    #[test]
    fn test_send_from_non_local_source_fails() {
        for engine in ENGINES {
            let sender: UdpSocket =
                crate::sys::substrate::open(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                    .unwrap()
                    .into();
            let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut bio = engine.instantiate(1).unwrap();
            let mut results = Vec::new();
            let res = bio.try_send_to_from_batch(
                &sender,
                std::iter::once((
                    b"hello".as_slice(),
                    receiver.local_addr().unwrap(),
                    Some(ScopedIpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    SendFlags::none(),
                )),
                &mut results,
            );
            // The failure is the batch error (the unbatched engines) or the
            // packet's own result (io_uring reports per-packet results).
            let failed = res.is_err() || results.first().is_some_and(|r| r.is_err());
            assert!(
                failed,
                "{}: a send from a non-local source must fail, got {res:?} {results:?}",
                engine.engine_name()
            );
        }
    }

    #[test]
    fn test_send_backlog_over_slab_capacity() {
        // zipline#117 review (PR #43): the io_uring engine's per-operation
        // slabs (batch state, sockaddrs, cmsgs) hold only MAX_ENTRIES, so
        // the submission limit derived from the ring capacity must never
        // exceed that.  A backlog larger than MAX_ENTRIES must come back as
        // a partial batch, not panic on the (MAX_ENTRIES + 1)-th push.
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            let dest = outq.local_addr().unwrap();

            let max = engine.max_entries();
            let nmsgs = max + max / 2;

            // Instantiate at the engine's advertised maximum, the
            // configuration under which the limit overshoots the slabs.
            let mut bio = engine.instantiate(max).unwrap();

            let msg = [42u8; 8];
            let mut results = Vec::new();

            let n = bio
                .try_send_to_batch(
                    &inq,
                    (0..nmsgs).map(|_| (&msg[..], dest, SendFlags::none())),
                    &mut results,
                )
                .unwrap();

            assert!(
                n >= 1 && n <= nmsgs,
                "[{}] expected a (possibly partial) batch, got {n} of {nmsgs}",
                engine.engine_name()
            );

            if engine.engine_name() == "io_uring" {
                // The io_uring engine must clamp the batch to its slab
                // capacity and return the remainder to the caller.
                assert_eq!(
                    n, max,
                    "[io_uring] a backlog over the slab capacity must return \
                     a partial batch of exactly the slab capacity"
                );
            }
        }
    }

    /// Batch size of every `run_recv_stress` receive call.
    #[cfg(unix)]
    const RECV_STRESS_BATCH: usize = 64;

    /// Number of sequenced datagrams one `run_recv_stress` run sends.
    #[cfg(unix)]
    const RECV_STRESS_DATAGRAMS: u64 = 1000;

    /// The datagram count after which a `FaultyEngine` fires its one fault:
    /// midway through a `run_recv_stress` run.
    #[cfg(unix)]
    const RECV_STRESS_FAULT_AFTER: usize = RECV_STRESS_DATAGRAMS as usize / 2;

    /// What a `FaultyEngine` does in its one faulty batch receive call.
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum Fault {
        /// Receive the batch, sleep for the given time, then return it
        /// normally.  This simulates scheduler preemption of the calling
        /// thread on a loaded runner: slow, but not stalled.
        SlowOnce(Duration),
        /// Receive the batch, then block until the given number (at least
        /// one) of further datagrams has arrived on the socket, then return
        /// the batch.  This simulates the zipline#117 stall: an op left in
        /// flight makes the call return only when unrelated traffic
        /// arrives.  `StallOnce(1)` is one op left in flight: the first new
        /// datagram releases the call and stays queued for the next call.
        /// `StallOnce(n)` is n ops left in flight: each of the first n - 1
        /// new datagrams completes (and so consumes) one of them, and only
        /// the n-th releases the call and stays queued.
        StallOnce(usize),
    }

    /// Test-only batch I/O engine: `posix_unbatched` with one injected fault.
    ///
    /// Every operation delegates to `posix_unbatched`.  The first
    /// `try_recv_buf_from_batch` call that brings the number of received
    /// datagrams to `fault_after` or more applies `fault` (see `Fault`) to
    /// that call; every other call is unchanged.  It lets the stress test
    /// prove both that a slow call is tolerated and that a real stall is
    /// detected, without timing-dependent behaviour of a real engine.
    #[cfg(unix)]
    struct FaultyEngine {
        inner: posix_unbatched::BatchIo,
        fault: Fault,
        fault_after: usize,
        received: usize,
        fired: bool,
    }

    #[cfg(unix)]
    impl FaultyEngine {
        /// Wrap a new `posix_unbatched` engine of `entries` entries that
        /// applies `fault` once, after `fault_after` received datagrams.
        fn new(entries: usize, fault: Fault, fault_after: usize) -> Self {
            Self {
                inner: posix_unbatched::BatchIo::new(entries).unwrap(),
                fault,
                fault_after,
                received: 0,
                fired: false,
            }
        }

        /// Wrap a new faulty engine as a `BatchIo`, the type the stress test
        /// drives.
        fn instantiate(entries: usize, fault: Fault, fault_after: usize) -> BatchIo {
            BatchIo(Box::new(Self::new(entries, fault, fault_after)))
        }

        /// Apply the fault to the current call if it is due: called after
        /// the inner receive returned `new` datagrams on `handle`.
        fn maybe_fire(&mut self, handle: WaitHandle<'_>, new: usize) {
            self.received += new;
            if self.fired || new == 0 || self.received < self.fault_after {
                return;
            }
            self.fired = true;
            match self.fault {
                Fault::SlowOnce(delay) => std::thread::sleep(delay),
                Fault::StallOnce(datagrams) => {
                    assert!(datagrams >= 1, "a stall needs at least one datagram");
                    // Hold the received batch.  Each of the first
                    // `datagrams - 1` new datagrams is consumed, as a
                    // leftover in-flight op would consume it.
                    for _ in 1..datagrams {
                        Self::wait_readable(handle);
                        let mut discard = [0u8; 64];
                        nix::sys::socket::recv(
                            handle.as_fd().as_raw_fd(),
                            &mut discard,
                            nix::sys::socket::MsgFlags::empty(),
                        )
                        .unwrap();
                    }
                    // The last one releases the call and stays queued for
                    // the next call.
                    Self::wait_readable(handle);
                }
            }
        }

        /// Block in `poll(2)`, with no timeout, until a datagram is readable
        /// on `handle`.
        fn wait_readable(handle: WaitHandle<'_>) {
            let mut fds = [nix::poll::PollFd::new(
                handle.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            nix::poll::poll(&mut fds, nix::poll::PollTimeout::NONE).unwrap();
        }
    }

    #[cfg(unix)]
    impl BatchIoImpl for FaultyEngine {
        fn engine_name(&self) -> &'static str {
            match self.fault {
                Fault::SlowOnce(_) => "posix_unbatched+slow_once",
                Fault::StallOnce(_) => "posix_unbatched+stall_once",
            }
        }

        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.inner.try_write_batch(handle, bufs, results)
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.inner.try_read_buf_batch(handle, bufs, results)
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.inner.try_send_to_batch(handle, bufs, results)
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.inner.try_send_to_from_batch(handle, bufs, results)
        }

        /// Delegate, then apply the fault if this call is the faulty one.
        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            let n = self.inner.try_recv_buf_from_batch(handle, bufs, results)?;
            self.maybe_fire(handle, n);
            Ok(n)
        }

        /// Delegate, then apply the fault if this call is the faulty one.
        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            let n = self
                .inner
                .try_recv_buf_from_to_batch(handle, bufs, results)?;
            self.maybe_fire(handle, n);
            Ok(n)
        }
    }

    /// What one successful `run_recv_stress` run measured.
    #[cfg(unix)]
    #[derive(Debug)]
    struct RecvStressStats {
        /// The longest single batch receive call of the run.  Informational
        /// only: a slow call is not a failure (zl-zipline#261).
        max_call: Duration,
    }

    /// Value of `run_recv_stress`'s shared timed-out sequence number while
    /// no ack has timed out.
    #[cfg(unix)]
    const RECV_STRESS_NO_TIMEOUT: u64 = u64::MAX;

    /// Payload of the datagrams `run_recv_stress`'s sender sends after an
    /// ack timed out, so that a blocked batch call can return.  It is never a
    /// valid sequence number.
    #[cfg(unix)]
    const RECV_STRESS_WAKE: u64 = u64::MAX;

    /// How often `run_recv_stress`'s sender repeats the `WAKE` datagram
    /// after an ack timed out, until the receiver has finished.
    #[cfg(unix)]
    const RECV_STRESS_WAKE_INTERVAL: Duration = Duration::from_millis(100);

    /// Overall bound of one `run_recv_stress` run.  The receiver checks it
    /// between batch calls, and the sender stops repeating `WAKE` datagrams
    /// at it, so the sender can never run forever.
    #[cfg(unix)]
    const RECV_STRESS_DEADLINE: Duration = Duration::from_secs(120);

    /// Drive `bio` through the receive stress run of zipline#117 and report
    /// the first failure as `Err`, naming the engine.
    ///
    /// The sender sends sequenced datagrams one at a time at randomized
    /// sub-millisecond offsets while the receiver busy-loops
    /// `RECV_STRESS_BATCH`-op batch receives on the otherwise empty socket,
    /// so datagrams keep arriving inside a batch call.  The receiver acks
    /// each newly-seen datagram, and the sender sends the next one only
    /// after that ack.
    ///
    /// The failure signal is liveness, not latency.  While the sender waits
    /// for the ack of datagram k it sends nothing, so a batch call that is
    /// not stalled returns k with no new traffic, however slow the call is.
    /// A stalled call (an op left in flight) returns only when another
    /// datagram arrives, which never happens during the wait.  So if no ack
    /// comes within `liveness`, the sender records k and then sends a `WAKE`
    /// datagram every `RECV_STRESS_WAKE_INTERVAL` until the receiver has
    /// finished, so that a blocked call can return even when several ops
    /// were left in flight and each one consumes a wake (core#116 review).
    /// The receiver ends the run at the first `WAKE` it sees, and reports a
    /// stall if k arrived, or a lost datagram if it never arrived.  If k is
    /// the last datagram, the released call completes the run before any
    /// `WAKE` is seen, so the recorded timeout is checked again after the
    /// sender is joined and fails the run all the same.  A false
    /// failure needs the receiver thread to make no progress at all for the
    /// whole `liveness` bound.
    ///
    /// Both threads also keep the overall `RECV_STRESS_DEADLINE`: the
    /// receiver as a backstop for a lost datagram that no wake reveals, the
    /// sender as the upper bound of its wake loop.
    #[cfg(unix)]
    fn run_recv_stress(
        bio: &mut BatchIo,
        liveness: Duration,
    ) -> std::result::Result<RecvStressStats, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::mpsc::RecvTimeoutError;

        let engine_name = bio.engine_name();

        let inq = udp_socket().unwrap();
        let outq = udp_socket().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();
        inq.connect(outq.local_addr().unwrap()).unwrap();

        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<u64>();
        // The sequence number whose ack timed out, or RECV_STRESS_NO_TIMEOUT.
        // The sender stores it before it sends the first wake datagram, so
        // the receiver always sees it once it has received a wake.
        let timed_out = std::sync::Arc::new(AtomicU64::new(RECV_STRESS_NO_TIMEOUT));
        // The overall deadline, shared by both threads.
        let deadline = std::time::Instant::now() + RECV_STRESS_DEADLINE;

        let sender_timed_out = timed_out.clone();
        let sender = std::thread::spawn(move || {
            let mut rng = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as u64
                | 1;

            for seq in 0..RECV_STRESS_DATAGRAMS {
                // One datagram at a randomized sub-millisecond offset, to
                // land it at an arbitrary point of the receiver's batch
                // calls; then stay silent until its ack.
                std::thread::sleep(Duration::from_micros(xorshift(&mut rng) % 700));
                inq.send(&seq.to_le_bytes()).unwrap();
                match ack_rx.recv_timeout(liveness) {
                    Ok(acked) => assert_eq!(acked, seq, "acks arrive in send order"),
                    Err(RecvTimeoutError::Timeout) => {
                        // No progress without new traffic: record k, then
                        // wake a possibly blocked call until the receiver
                        // has finished.
                        sender_timed_out.store(seq, Ordering::SeqCst);
                        send_wakes_until_done(&inq, &ack_rx, deadline);
                        return;
                    }
                    // The receiver gave up (it reported a failure).
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        });

        let mut seen = vec![false; RECV_STRESS_DATAGRAMS as usize];
        let mut nseen = 0usize;
        let mut wake_seen = false;
        let mut max_elapsed = Duration::ZERO;
        let mut bufs = vec![Vec::with_capacity(64); RECV_STRESS_BATCH];
        let mut results = Vec::new();

        let outcome = loop {
            if nseen == RECV_STRESS_DATAGRAMS as usize {
                break Ok(RecvStressStats {
                    max_call: max_elapsed,
                });
            }

            // Once the wake datagram is in, every datagram the sender sent
            // has had its chance to arrive: classify the timeout.
            if wake_seen {
                let k = timed_out.load(Ordering::SeqCst);
                if k == RECV_STRESS_NO_TIMEOUT {
                    break Err(format!(
                        "[{engine_name}] received a wake datagram, but no ack timed out"
                    ));
                }
                break Err(recv_stress_timeout_error(engine_name, k, &seen, liveness));
            }

            if std::time::Instant::now() >= deadline {
                break Err(format!(
                    "[{engine_name}] lost datagram(s): only {nseen} of \
                     {RECV_STRESS_DATAGRAMS} received"
                ));
            }

            bufs.iter_mut().for_each(|b| b.clear());
            results.clear();

            let start = std::time::Instant::now();
            match bio.try_recv_buf_from_batch(&outq, bufs.iter_mut(), &mut results) {
                Ok(_) => (),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(err) => break Err(format!("[{engine_name}] batch receive failed: {err}")),
            }
            max_elapsed = max_elapsed.max(start.elapsed());

            for (buf, result) in bufs.iter().zip(results.drain(..)) {
                let Ok(packet) = result else { continue };
                assert_eq!(packet.size, 8, "[{engine_name}] short datagram");
                let seq = u64::from_le_bytes(buf[..8].try_into().unwrap());
                if seq == RECV_STRESS_WAKE {
                    wake_seen = true;
                    continue;
                }
                if seq as usize >= seen.len() {
                    continue;
                }
                if !seen[seq as usize] {
                    seen[seq as usize] = true;
                    nseen += 1;
                    let _ = ack_tx.send(seq);
                }
            }
        };

        // Dropping the ack channel stops a sender still waiting for an ack.
        drop(ack_tx);
        sender.join().unwrap();

        // A stall on the last datagram ends the loop with every datagram
        // received, before it looks at the wake: the wake released the
        // stalled call, which returned that last datagram.  So a recorded
        // timeout fails the run even when every datagram arrived.  The
        // sender has been joined, so its store is visible here.
        let k = timed_out.load(Ordering::SeqCst);
        let outcome = match outcome {
            Ok(_) if k != RECV_STRESS_NO_TIMEOUT => {
                Err(recv_stress_timeout_error(engine_name, k, &seen, liveness))
            }
            outcome => outcome,
        };

        if let Ok(stats) = &outcome {
            println!(
                "engine {engine_name}: received all {RECV_STRESS_DATAGRAMS} datagrams, \
                 max batch call {:?}",
                stats.max_call
            );
        }
        outcome
    }

    /// `run_recv_stress`'s failure message once the ack of datagram `k`
    /// timed out after `liveness`: a stall if `k` arrived later (only after
    /// a wake datagram), or a lost datagram if it never arrived.  `seen`
    /// marks every datagram the receiver received.
    #[cfg(unix)]
    fn recv_stress_timeout_error(
        engine_name: &str,
        k: u64,
        seen: &[bool],
        liveness: Duration,
    ) -> String {
        if seen[k as usize] {
            format!(
                "[{engine_name}] stall: datagram {k} of {RECV_STRESS_DATAGRAMS} \
                 was not received within {liveness:?} while the sender was \
                 silent, and arrived only after a wake datagram: a batch call \
                 returned only when new traffic arrived (an operation was left \
                 in flight, zipline#117)"
            )
        } else {
            format!(
                "[{engine_name}] lost datagram {k} of {RECV_STRESS_DATAGRAMS}: \
                 not received within {liveness:?}, nor after a wake datagram"
            )
        }
    }

    /// `run_recv_stress`'s sender after an ack timed out: send a `WAKE`
    /// datagram on `inq` every `RECV_STRESS_WAKE_INTERVAL` until the receiver
    /// has finished, which it signals by dropping its end of `ack_rx`, or
    /// until `deadline`, whichever comes first.  One wake is not enough: if
    /// several ops of a stalled batch call are in flight, each one can
    /// consume a wake, and the call returns only after the last of them
    /// completes (core#116 review).  Acks that still arrive (the late ack of
    /// the timed-out datagram) are ignored.  A full receive queue is not an
    /// error here: it already holds wakes for the receiver to find.
    #[cfg(unix)]
    fn send_wakes_until_done(
        inq: &UdpSocket,
        ack_rx: &std::sync::mpsc::Receiver<u64>,
        deadline: std::time::Instant,
    ) {
        use std::sync::mpsc::RecvTimeoutError;

        while std::time::Instant::now() < deadline {
            match inq.send(&RECV_STRESS_WAKE.to_le_bytes()) {
                Ok(_) => (),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(err) => panic!("sending a wake datagram failed: {err}"),
            }
            match ack_rx.recv_timeout(RECV_STRESS_WAKE_INTERVAL) {
                // The receiver is still running: wake it again.
                Ok(_) | Err(RecvTimeoutError::Timeout) => (),
                // The receiver has finished.
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// The liveness bound of `test_recv_stress_no_stall` and
    /// `test_recv_stress_tolerates_slow_call` (gate g107, q2).  It is not a
    /// latency bound: a stalled call never returns without traffic, so any
    /// value detects a stall; the bound only sets how long the receiver
    /// thread must make no progress before the run fails.
    #[cfg(unix)]
    const RECV_STRESS_LIVENESS: Duration = Duration::from_secs(10);

    /// zipline#117: a batch receive must never leave an operation in flight
    /// that makes the call wait for traffic that has not arrived.  Unix only:
    /// `windows_unbatched` is a loop of non-blocking `recv_from` calls with
    /// nothing in flight, so it cannot stall this way.  The test checks
    /// liveness, not latency: a slow call on a loaded runner passes (see
    /// `test_recv_stress_tolerates_slow_call`, zl-zipline#261).
    #[cfg(unix)]
    #[test]
    fn test_recv_stress_no_stall() {
        // On the io_uring engine, each batch op was paired with an
        // AsyncCancel and the engine waited for every completion, relying on
        // each cancel finding its op.  A cancel can return -ENOENT while its
        // op is still pending (e.g. the op was woken by a datagram that a
        // sibling op then consumed, and re-armed its poll), leaving
        // submit_and_wait() blocked until the next unrelated datagram
        // completes the op -- observed as ~600 ms fastpath stalls in the
        // netns integration tier.  `run_recv_stress` reproduces that load
        // and fails if a call returns only when new traffic arrives.

        // Iterate posix_unbatched (the control engine) first, so an io_uring
        // failure does not mask its result.
        for engine in ENGINES.iter().rev() {
            let mut bio = engine.instantiate(RECV_STRESS_BATCH).unwrap();
            if let Err(err) = run_recv_stress(&mut bio, RECV_STRESS_LIVENESS) {
                panic!("{err}");
            }
        }
    }

    /// A slow batch call is not a stall: a call that takes 150 ms (simulated
    /// preemption on a loaded runner, as macOS CI saw) but then returns
    /// without new traffic must pass the stress run (zl-zipline#261).
    #[cfg(unix)]
    #[test]
    fn test_recv_stress_tolerates_slow_call() {
        let mut bio = FaultyEngine::instantiate(
            RECV_STRESS_BATCH,
            Fault::SlowOnce(Duration::from_millis(150)),
            RECV_STRESS_FAULT_AFTER,
        );
        if let Err(err) = run_recv_stress(&mut bio, RECV_STRESS_LIVENESS) {
            panic!("a slow but live batch call must not fail the run: {err}");
        }
    }

    /// A real stall must still fail: a call that returns its batch only when
    /// the next datagram arrives (the zipline#117 signature) must make the
    /// stress run report a stall.  A stalled call never returns without
    /// traffic, so a short liveness bound detects it as surely as a long one.
    #[cfg(unix)]
    #[test]
    fn test_recv_stress_detects_stall() {
        let mut bio = FaultyEngine::instantiate(
            RECV_STRESS_BATCH,
            Fault::StallOnce(1),
            RECV_STRESS_FAULT_AFTER,
        );
        match run_recv_stress(&mut bio, Duration::from_millis(500)) {
            Ok(stats) => panic!("an injected stall went undetected: {stats:?}"),
            Err(err) => assert!(
                err.contains("] stall: datagram"),
                "the run must fail with a stall, not: {err}"
            ),
        }
    }

    /// How long a watched stall-injection run (`run_faulty_watched`) may
    /// take before its test fails instead of hanging.
    #[cfg(unix)]
    const RECV_STRESS_WATCHDOG: Duration = Duration::from_secs(30);

    /// Run `run_recv_stress` with a 500 ms liveness bound on a
    /// `FaultyEngine` that applies `fault` after `fault_after` datagrams.
    /// The run happens on its own thread under `RECV_STRESS_WATCHDOG`, so a
    /// run that never returns fails the calling test cleanly; the blocked
    /// thread is left behind.  Returns the run's outcome.
    #[cfg(unix)]
    fn run_faulty_watched(
        fault: Fault,
        fault_after: usize,
    ) -> std::result::Result<RecvStressStats, String> {
        let (outcome_tx, outcome_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bio = FaultyEngine::instantiate(RECV_STRESS_BATCH, fault, fault_after);
            let _ = outcome_tx.send(run_recv_stress(&mut bio, Duration::from_millis(500)));
        });
        match outcome_rx.recv_timeout(RECV_STRESS_WATCHDOG) {
            Ok(outcome) => outcome,
            Err(_) => panic!(
                "the stress run with fault {fault:?} after {fault_after} datagrams did not \
                 finish within {RECV_STRESS_WATCHDOG:?}: the run hangs"
            ),
        }
    }

    /// Assert that a stall-injection run reported a stall.
    #[cfg(unix)]
    fn assert_stall_reported(outcome: std::result::Result<RecvStressStats, String>) {
        match outcome {
            Ok(stats) => panic!("an injected stall went undetected: {stats:?}"),
            Err(err) => assert!(
                err.contains("] stall: datagram"),
                "the run must fail with a stall, not: {err}"
            ),
        }
    }

    /// A stall with more than one op left in flight must still be reported,
    /// not hang (core#116 review): when several ops stay pending, one wake
    /// datagram completes only one of them and the call stays blocked.  The
    /// injected fault needs three new datagrams before the call returns.
    #[cfg(unix)]
    #[test]
    fn test_recv_stress_detects_multi_op_stall() {
        assert_stall_reported(run_faulty_watched(
            Fault::StallOnce(3),
            RECV_STRESS_FAULT_AFTER,
        ));
    }

    /// A stall on the last datagram must still be reported (core#116
    /// review): there the wake releases the call, the run has then
    /// received every datagram, and that must not count as success.
    #[cfg(unix)]
    #[test]
    fn test_recv_stress_detects_stall_on_last_datagram() {
        assert_stall_reported(run_faulty_watched(
            Fault::StallOnce(1),
            RECV_STRESS_DATAGRAMS as usize,
        ));
    }

    /// Minimal PRNG for `run_recv_stress`'s send jitter.
    #[cfg(unix)]
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// zipline#160 (plan N4): a peer's ICMP port-unreachable surfaces on
    /// Windows as `WSAECONNRESET` on a later `recvfrom` of an unconnected
    /// UDP socket. Nothing was received and the socket is fine, so the
    /// mapping seam must turn `ConnectionReset` into `WouldBlock` — the
    /// "stop this batch, return what was received" error every engine
    /// already handles — and leave every other error untouched.
    #[cfg(windows)]
    #[test]
    fn test_connreset_mapped_to_wouldblock() {
        use std::io::{Error, ErrorKind};

        // The Windows reset becomes "no datagram".
        let mapped = windows_udp::connreset_as_wouldblock(Error::new(
            ErrorKind::ConnectionReset,
            "peer departed (WSAECONNRESET)",
        ));
        assert_eq!(
            mapped.kind(),
            ErrorKind::WouldBlock,
            "ConnectionReset must map to WouldBlock, got {mapped:?}"
        );

        // Anything else passes through unchanged — the fastpath's
        // "unrecoverable substrate socket error" expect still fires for
        // real faults.
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::BrokenPipe,
            ErrorKind::InvalidInput,
        ] {
            let passed = windows_udp::connreset_as_wouldblock(Error::new(kind, "other"));
            assert_eq!(passed.kind(), kind, "{kind:?} must pass through");
        }
    }

    /// zl-zpr-core#62 review (zipline#160): a swallowed reset consumed no
    /// datagram, so the receive must be retried with the same buffer —
    /// datagrams queued behind a departed peer's reset are delivered in
    /// the same batch instead of costing one wake/dispatch per reset.
    #[cfg(windows)]
    #[test]
    fn test_recv_retried_after_connreset() {
        use std::io::{Error, ErrorKind};

        // Two resets queued ahead of a real datagram: the receive seam
        // must swallow both and return the datagram.
        let mut calls = 0u32;
        let res = windows_udp::recv_retrying_connreset(|| {
            calls += 1;
            if calls <= 2 {
                Err(Error::new(ErrorKind::ConnectionReset, "peer departed"))
            } else {
                Ok(7usize)
            }
        });
        assert_eq!(
            res.expect("datagram behind resets must be delivered"),
            7,
            "retry must return the datagram received after the resets"
        );
        assert_eq!(calls, 3, "one retry per swallowed reset, then the datagram");
    }

    /// zl-zpr-core#62 review (zipline#160): the retry is bounded — a
    /// pathological storm of consecutive resets ends the batch as "no
    /// datagram" after `CONNRESET_RETRY_CAP` retries instead of pinning
    /// the dispatch thread in the retry loop.
    #[cfg(windows)]
    #[test]
    fn test_recv_retry_bounded_on_reset_storm() {
        use std::io::{Error, ErrorKind};

        let mut calls = 0u32;
        let res = windows_udp::recv_retrying_connreset(|| -> std::io::Result<usize> {
            calls += 1;
            Err(Error::new(ErrorKind::ConnectionReset, "reset storm"))
        });
        assert_eq!(
            res.expect_err("an unbroken reset storm must end the batch")
                .kind(),
            ErrorKind::WouldBlock,
            "capped storm must surface as WouldBlock (no datagram)"
        );
        assert_eq!(
            calls,
            windows_udp::CONNRESET_RETRY_CAP + 1,
            "the receive must stop after the retry cap"
        );
    }

    /// zl-zpr-core#62 review (zipline#160): only `ConnectionReset` is
    /// retried — a genuine `WouldBlock` (empty socket) and real faults
    /// return on the first call, unchanged.
    #[cfg(windows)]
    #[test]
    fn test_recv_retry_other_errors_return_immediately() {
        use std::io::{Error, ErrorKind};

        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::BrokenPipe,
            ErrorKind::InvalidInput,
        ] {
            let mut calls = 0u32;
            let res = windows_udp::recv_retrying_connreset(|| -> std::io::Result<usize> {
                calls += 1;
                Err(Error::new(kind, "not a reset"))
            });
            assert_eq!(res.expect_err("error must surface").kind(), kind);
            assert_eq!(calls, 1, "{kind:?} must not be retried");
        }
    }

    /// zipline#160 (plan N4), the end-to-end shape on the real OS: send
    /// from a bound UDP socket to a closed local port — Windows queues the
    /// resulting ICMP port-unreachable as a `WSAECONNRESET` for a later
    /// receive on that socket — then receive, and assert the batch comes
    /// back clean ("nothing received", not an error and not a panic).
    /// Windows-only by nature: unix never surfaces a reset on an
    /// unconnected UDP socket, so there is nothing to observe there. Runs
    /// in the Windows core-gate run (plan C2/C3).
    #[cfg(windows)]
    #[test]
    fn test_windows_recv_tolerates_connreset() {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();

        // A port with nothing behind it: bind a throwaway socket, note its
        // port, drop it.
        let closed_port = {
            let dead = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            dead.local_addr().unwrap().port()
        };

        // Provoke the reset, then give the stack a moment to queue it.
        socket
            .send_to(b"ping", (std::net::Ipv4Addr::LOCALHOST, closed_port))
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // One batch receive. Every outcome except ConnectionReset/panic is
        // a pass: WouldBlock (reset already mapped or ioctl-suppressed) or an
        // empty batch; a datagram cannot arrive (nothing sends to us).
        let mut bufs = vec![Vec::with_capacity(64); 4];
        let mut results: Vec<Result<ReceivedPacket>> = Vec::new();
        match windows_udp::recv_from_batch(
            &socket,
            &mut bufs.iter_mut().map(|b| b as &mut dyn BufMut),
            &mut results,
            true,
        ) {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("reset must not surface as a batch error: {err}"),
            Ok(0) => {}
            Ok(_) => panic!("received a datagram nobody sent"),
        }
    }

    /// zipline#150: the control message the Windows send path writes for a
    /// source address decodes back to that address, for both families and
    /// with the IPv6 scope carried as the interface index. The send and
    /// receive messages share one layout (`IN_PKTINFO`/`IN6_PKTINFO`), so
    /// this checks the encoder and decoder against each other; the socket
    /// tests above check them against Winsock.
    #[cfg(windows)]
    #[test]
    fn test_windows_pktinfo_round_trip() {
        let v6 = zpr_utils::net_defs::ScopedIpv6Addr::new("fe80::7".parse().unwrap(), 7);
        for addr in [
            ScopedIpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            ScopedIpAddr::V6(v6),
        ] {
            let mut buf = windows_udp::CmsgBuffer::new();
            let len = windows_udp::encode_source_pktinfo(&addr, &mut buf);
            assert_eq!(
                windows_udp::decode_destination(&buf.0[..len]),
                Some(addr),
                "round trip of {addr:?}"
            );
        }
    }

    /// zipline#150: the decoder reads lengths it gets from the OS, so a
    /// malformed or truncated control buffer must give `None`, never a
    /// panic or a read past the buffer; and a message of another kind is
    /// skipped to reach the pktinfo message behind it.
    #[cfg(windows)]
    #[test]
    fn test_windows_pktinfo_decode_malformed_and_skip() {
        let addr = ScopedIpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let mut buf = windows_udp::CmsgBuffer::new();
        let len = windows_udp::encode_source_pktinfo(&addr, &mut buf);
        let message = buf.0[..len].to_vec();

        // Empty, or cut anywhere inside the message.
        for cut in 0..len {
            assert_eq!(windows_udp::decode_destination(&message[..cut]), None);
        }

        // A cmsg_len shorter than the header, or longer than the buffer.
        let usize_len = std::mem::size_of::<usize>();
        for bad_len in [0usize, 1, len + 1, usize::MAX] {
            let mut bad = message.clone();
            bad[..usize_len].copy_from_slice(&bad_len.to_ne_bytes());
            assert_eq!(
                windows_udp::decode_destination(&bad),
                None,
                "cmsg_len {bad_len}"
            );
        }

        // An unrelated message (another cmsg_type) ahead of the pktinfo one
        // is skipped. Its type field follows `cmsg_len` and `cmsg_level`.
        let mut unrelated = message.clone();
        let type_offset = usize_len + 4;
        unrelated[type_offset..type_offset + 4].copy_from_slice(&999i32.to_ne_bytes());
        let mut both = unrelated;
        both.extend_from_slice(&message);
        assert_eq!(windows_udp::decode_destination(&both), Some(addr));
    }

    /// Two localhost UDP sockets connected to each other: a portable
    /// stand-in for a datagram socketpair, so the TUN-side `read`/`write`
    /// batch calls can be exercised without AF_UNIX (zipline#129). Unix
    /// only, like those tests.
    #[cfg(unix)]
    fn connected_udp_pair() -> Result<(UdpSocket, UdpSocket)> {
        let a = udp_socket()?;
        let b = udp_socket()?;
        a.connect(b.local_addr()?)?;
        b.connect(a.local_addr()?)?;
        Ok((a, b))
    }

    fn udp_socket() -> Result<UdpSocket> {
        UdpSocket::bind(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))
    }
}
