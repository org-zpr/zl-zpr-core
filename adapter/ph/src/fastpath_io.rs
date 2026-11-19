use crate::batch_io::{self, BatchIo};
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig, QueuedEgressPacket};
use crate::logging::targets::DATAPATH;
use crate::packet_queue;
#[cfg(windows)]
use crate::sys::wait::SocketWaitable;
use crate::sys::wait::{AsWaitSource, WaitHandle, Waitable};
use crate::sys::{TunPi, ZprTun};
use crate::zprtun;
use std::io::{ErrorKind, Result};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;
use zpr_utils::net_defs;

#[allow(unused_imports)]
use crate::packet::{self, Packet, flags};

pub struct FastpathIo {
    batch_io: BatchIo,
    actor_tun: Arc<ZprTun>,
    substrate_socket: UdpSocket,
    /// The substrate socket's waitable Event (`WSAEventSelect(FD_READ)`,
    /// plan D3): the socket itself is not waitable on Windows. Owned here
    /// beside the socket it is bound to.
    #[cfg(windows)]
    substrate_waitable: SocketWaitable,
    pub requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    pub mgmt_substrate_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,

    /// temporary packet storage during I/O batch operations
    packets: Vec<Packet>,
    /// temporary read result storage during I/O batch operations
    io_results: Vec<Result<usize>>,
    /// temporary recv result storage during I/O batch operations
    recv_results: Vec<Result<batch_io::ReceivedPacket>>,
    /// When this worker last warned of a substrate send dropped after a
    /// network change (see [warn_send_dropped]).
    send_drop_warned_at: Option<Instant>,
}

impl FastpathIo {
    pub fn new(
        config: FastpathWorkerConfig,
        substrate_socket: UdpSocket,
        actor_tun: Arc<ZprTun>,
        requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
        maybe_mgmt_substrate_outq: Option<packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>>,
    ) -> Self {
        // HACK: nix does not support disabling an FD, so instead, make a dummy mgmt_substrate_outq socket
        // if we weren't given one
        let mgmt_substrate_outq;
        match maybe_mgmt_substrate_outq {
            Some(outq) => mgmt_substrate_outq = outq,
            None => {
                let (_, outq) = packet_queue::packet_queue(1);
                mgmt_substrate_outq = outq;
            }
        }

        Self {
            batch_io: config
                .batch_io_engine
                .instantiate(config.batch_size)
                .unwrap(),
            actor_tun,
            #[cfg(windows)]
            substrate_waitable: SocketWaitable::new(&substrate_socket)
                .expect("unable to bind a wait event to the substrate socket"),
            substrate_socket,
            requeue_outq,
            mgmt_substrate_outq,
            packets: Vec::with_capacity(config.batch_size),
            io_results: Vec::with_capacity(config.batch_size),
            recv_results: Vec::with_capacity(config.batch_size),
            send_drop_warned_at: None,
        }
    }

    /// Substrate socket wait handle for the fastpath wait set.
    ///
    /// Unix: the socket's own fd. Windows: the socket is not waitable, so
    /// this is its [`SocketWaitable`]'s Event (plan D3) — distinct from the
    /// I/O-target handle `process_substrate_socket_in` passes to batch_io.
    pub fn substrate_socket_handle(&self) -> WaitHandle<'_> {
        #[cfg(unix)]
        {
            self.substrate_socket.as_wait_handle()
        }
        #[cfg(windows)]
        {
            self.substrate_waitable.handle()
        }
    }

    /// Actor TUN wait handle for the fastpath wait set.
    pub fn actor_tun_handle(&self) -> WaitHandle<'_> {
        self.actor_tun.as_wait_handle()
    }

    /// Requeue queue wait handle for the fastpath wait set.
    pub fn requeue_handle(&self) -> WaitHandle<'_> {
        self.requeue_outq.handle()
    }

    /// Mgmt substrate queue wait handle for the fastpath wait set.
    pub fn mgmt_substrate_handle(&self) -> WaitHandle<'_> {
        self.mgmt_substrate_outq.handle()
    }

    /// Process an input-ready notification on the substrate socket (substrate ingress).
    pub fn process_substrate_socket_in(&mut self, worker: &mut FastpathWorker) {
        // Acknowledge the wake BEFORE draining (Windows, plan D3):
        // `WSAEnumNetworkEvents` clears the Event and the FD_READ record.
        // Cleared first, a datagram that arrives mid-drain is either
        // consumed by this drain or re-posts FD_READ after the final
        // WouldBlock recv re-enables it. Cleared after, a datagram arriving
        // between the last recv and the clear would leave data buffered
        // with FD_READ posting disabled — a lost wakeup.
        #[cfg(windows)]
        self.substrate_waitable
            .reset()
            .expect("WSAEnumNetworkEvents failed on the substrate socket");

        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_recv_buf_from_to_batch(
            &self.substrate_socket,
            self.packets.iter_mut(),
            &mut self.recv_results,
        ))
        .expect("unrecoverable substrate socket error");

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (pkt, result) in self.packets.drain(..).zip(self.recv_results.drain(..)) {
            let (mut sender, dest) = match result {
                Ok(res) if res.truncated => {
                    worker.drop_and_count(pkt, FastpathCounterType::DroppedOversize);
                    continue;
                }

                Ok(res) => (
                    res.source
                        .expect("received from non-IP address, should not happen!"),
                    res.destination
                        .expect("unknown recipient, should not happen!"),
                ),

                Err(err) => {
                    match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        // FIXME: do something with this later...
                        ErrorKind::ConnectionRefused => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        _ => panic!("got socket error {err}"),
                    }
                }
            };

            // SocketAddrV6 distinguishes addresses also by `flowinfo` which
            // we do not want -- only the 5-tuple.  So clear it.
            clear_flowinfo(&mut sender);

            worker.batch_counters[FastpathCounterType::InPacksRec].increment();
            worker.substrate_ingress(&sender, &dest, pkt);
        }
    }

    /// Process an output-ready notification on the substrate socket
    /// (substrate egress of PRIORITY packets).
    pub fn process_substrate_socket_out(&mut self, worker: &mut FastpathWorker) {
        self.process_substrate_egress_queue(worker);
    }

    /// Process an input-ready notification on the actor TUN (actor output).
    pub fn process_actor_tun_in(&mut self, worker: &mut FastpathWorker) {
        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_read_buf_batch(
            &self.actor_tun,
            self.packets.iter_mut(),
            &mut self.io_results,
        ))
        .expect("unrecoverable TUN error");

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (mut pkt, result) in self.packets.drain(..).zip(self.io_results.drain(..)) {
            if let Err(err) = result {
                match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                        worker.buffers.push(pkt.destroy());
                        continue;
                    }

                    _ => panic!("unrecoverable I/O error {err}"),
                }
            }

            if zprtun::TUN_HAS_PI {
                let pi = TunPi::read_pi(&mut pkt);
                if pi.strip || !is_ip(pi) {
                    // packet was too large or non-IP; drop
                    worker.drop_and_count(pkt, FastpathCounterType::OutPacksDrop);
                    continue;
                }
            } else {
                // No packet info, permit IP and IPv6 only (for now?)
                if pkt.body()[0] >> 4 != 4 && pkt.body()[0] >> 4 != 6 {
                    worker.drop_and_count(pkt, FastpathCounterType::OutPacksDrop);
                    continue;
                }
            }

            worker.batch_counters[FastpathCounterType::OutPacksRec].increment();
            worker.actor_output(pkt);
        }
    }

    /// Process an input-ready notification on the requeue socket.
    pub fn process_requeue_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.requeue_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.batch_counters[FastpathCounterType::RequeuedPacketsReceived].increment();
                worker.actor_output_post_classify(pkt, /* allow_bind_request */ false);
            },
        );
    }

    /// Process an input-ready notification on the mgmt substrate socket.
    pub fn process_mgmt_substrate_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.mgmt_substrate_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.batch_counters[FastpathCounterType::MgmtPacketsSent].increment();
                worker.substrate_egress(pkt);
            },
        );
    }

    /// Egress any queued packets, or drop if there is no space in the system queues.
    ///
    /// After this call, the actor input queue will be empty, and the substrate egress queue
    /// will contain only PRIORITY packets.
    pub fn process_out_queues(&mut self, worker: &mut FastpathWorker) {
        self.process_actor_input_queue(worker);
        self.process_substrate_egress_queue(worker);
    }

    /// Egress queued actor input packets only.
    fn process_actor_input_queue(&mut self, worker: &mut FastpathWorker) {
        // Add TUN PI header.
        match TunPi::PI_SIZE {
            0 => (),
            sz => {
                for pkt in &mut worker.actor_input_q {
                    let proto = net_defs::ip_ethertype(net_defs::ip_version(pkt.body()));
                    let mut hdr = pkt.alloc_zeroed_headroom(sz);
                    TunPi::write_pi(
                        &mut hdr,
                        TunPi {
                            strip: false,
                            proto,
                        },
                    );
                }
            }
        }

        // (Try to) send packets.
        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_write_batch(
            &self.actor_tun,
            worker.actor_input_q.iter().map(|pkt| pkt.body()),
            &mut self.io_results,
        ))
        .expect("unrecoverable TUN error");

        // Tally results.
        let mut dropped = worker.actor_input_q.len() - n;
        for res in self.io_results.drain(..) {
            match res {
                Ok(_) => (),
                Err(err) if err.kind() == ErrorKind::WouldBlock => dropped += 1,
                Err(err) => panic!("unrecoverable TUN error: {}", err),
            }
        }
        worker.batch_counters[FastpathCounterType::InPacksSent]
            .increase_by((worker.actor_input_q.len() - dropped) as u64);
        worker.batch_counters[FastpathCounterType::InPacksDrop].increase_by(dropped as u64);

        // Return buffers to buffer stack.
        worker
            .buffers
            .extend(worker.actor_input_q.drain(..).map(|pkt| pkt.destroy()));
    }

    /// Egress queued substrate egress packets only.
    fn process_substrate_egress_queue(&mut self, worker: &mut FastpathWorker) {
        send_substrate_egress_queue(
            &mut self.batch_io,
            &self.substrate_socket,
            &mut self.io_results,
            worker,
            &mut self.send_drop_warned_at,
        );
    }
}

/// Send flags for a substrate egress packet: `MSG_CONFIRM` when the
/// packet's metadata asks for link-layer confirmation (a no-op off
/// Linux, where the flag does not exist).
fn get_confirm_flag(pkt: &Packet) -> batch_io::SendFlags {
    match pkt.metadata().flags & flags::CONFIRM != 0 {
        true => batch_io::SendFlags::confirm(),
        false => batch_io::SendFlags::none(),
    }
}

/// The shortest gap between two "send dropped after a network change"
/// warnings from one fastpath worker: a dead source address fails every
/// packet until the keep-alive closes the link, and one line a second is
/// enough to show it.
const SEND_DROP_WARN_INTERVAL: Duration = Duration::from_secs(1);

/// Send the worker's queued substrate egress packets and tally the results:
/// sent packets count in `OutPacksSent`, dropped ones in `OutPacksDrop`, and
/// un-sent PRIORITY packets stay at the head of the queue for the next call.
///
/// A send that fails because the network changed under it, or because the
/// host refused it (see [classify_send_error]), drops its packet, even a
/// PRIORITY one, which would only fail the same way again. A batch-level
/// error of that kind drops the first packet, the one that failed, and
/// sends the rest. Any other send error is fatal.
///
/// An engine that sends a prefix of the queue and then fails reports only
/// the prefix (`Ok(n)`), not the error. The unsent rest is then handled as
/// for any partial send, such as one that would block: PRIORITY packets
/// stay queued, the others are dropped and counted. This was so before
/// zl-zipline#230, and it is kept: retrying the rest at once would spin on
/// a full socket. A vanished-source or refused PRIORITY packet kept that
/// way fails as the batch error on the next call, and is dropped and
/// logged there.
///
/// This is a free function rather than a [FastpathIo] method so a test can
/// drive it with a real socket and no TUN.
fn send_substrate_egress_queue(
    batch_io: &mut BatchIo,
    substrate_socket: &UdpSocket,
    io_results: &mut Vec<Result<usize>>,
    worker: &mut FastpathWorker,
    send_drop_warned_at: &mut Option<Instant>,
) {
    // Every queued packet names its link's local address as the source
    // (`Some(pkt.src)` below), which matters to the classifier.
    const SENDS_CARRY_SOURCE: bool = true;

    // (Try to) send packets.
    let n = loop {
        io_results.clear();
        let batch = wouldblock_as_empty_batch(batch_io.try_send_to_from_batch(
            substrate_socket,
            worker.substrate_egress_q.iter().map(|pkt| {
                (
                    pkt.pkt.body(),
                    pkt.dst,
                    Some(pkt.src),
                    get_confirm_flag(&pkt.pkt),
                )
            }),
            io_results,
        ));
        match batch {
            Ok(n) => break n,
            Err(err) => {
                if classify_send_error(&err, SENDS_CARRY_SOURCE).is_none() {
                    panic!("unrecoverable I/O error: {err}");
                }
                // The engines that emulate sendmmsg(2) report a failed first
                // packet as the batch error, with nothing sent. Drop only that
                // packet and send the rest: they may leave from other, live
                // addresses (a multi-homed Zode) or go to peers the host
                // does not refuse. Each pass drops one packet, so the loop
                // ends.
                let first = worker.substrate_egress_q.remove(0);
                warn_send_dropped(send_drop_warned_at, &first, &err);
                worker.batch_counters[FastpathCounterType::OutPacksDrop].increase_by(1);
                worker.buffers.push(first.pkt.destroy());
                if worker.substrate_egress_q.is_empty() {
                    return;
                }
            }
        }
    };

    // Tally results.
    let mut dropped = 0;
    let mut retained = 0;

    for i in 0..worker.substrate_egress_q.len() {
        // Determine whether the packet was in fact sent.
        // If it was, leave it in place and skip to the next packet.
        if i < n {
            match &io_results[i] {
                Ok(_) => continue,
                Err(err) if err.kind() == ErrorKind::WouldBlock => (),
                Err(err) if classify_send_error(err, SENDS_CARRY_SOURCE).is_some() => {
                    // Dropped, PRIORITY or not: leave it in place to be freed.
                    warn_send_dropped(send_drop_warned_at, &worker.substrate_egress_q[i], err);
                    dropped += 1;
                    continue;
                }
                // TODO: pending <https://github.com/rust-lang/rust/issues/86442>, provide more info to user
                Err(err) => panic!("unrecoverable I/O error: {err}"),
            }
        }

        // Packet was not sent.

        if worker.substrate_egress_q[i].pkt.metadata().flags & packet::flags::PRIORITY != 0 {
            // This was a priority packet.  Move it to the front of the queue.
            worker.substrate_egress_q.swap(i, retained);
            retained += 1;
        } else {
            // This was a normal packet.  Leave it to get dropped.
            dropped += 1;
        }
    }
    io_results.clear();

    // Now all un-sent priority packets are at the head of the queue.

    worker.batch_counters[FastpathCounterType::OutPacksSent]
        .increase_by((worker.substrate_egress_q.len() - dropped - retained) as u64);
    worker.batch_counters[FastpathCounterType::OutPacksDrop].increase_by(dropped as u64);

    // Return buffers to buffer stack, except for un-sent priority packets, which are retained for next time.
    worker.buffers.extend(
        worker
            .substrate_egress_q
            .drain(retained..)
            .map(|pkt| pkt.pkt.destroy()),
    );
}

/// Why a substrate send failed in a way that drops its packet instead of
/// stopping `ph` (see [classify_send_error]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendDropCause {
    /// The network changed under the Zode: the send's source address is
    /// gone, or there is no route or interface to the peer
    /// (zl-zipline#230).
    NetworkChange,
    /// The host refused the send (`PermissionDenied`): a firewall rule, an
    /// LSM, or a missing socket permission such as `SO_BROADCAST`
    /// (zl-zipline#270).
    Refused,
}

/// Classify a substrate send error: `Some(cause)` if the packet is dropped
/// and `ph` goes on, `None` if the error is fatal. `had_source` says whether
/// the send named a source address (`IP_PKTINFO`/`IPV6_PKTINFO`).
///
/// [SendDropCause::NetworkChange] (zl-zipline#230, gate g114 q6): after a
/// Wi-Fi switch, the link's local address, which every egress packet
/// carries as its source, is gone until the keep-alive closes the link and
/// the redial picks the new one. Measured for a send from a source address
/// that is not local (p39):
///
/// - Linux IPv4: `ENETUNREACH` (`NetworkUnreachable`).
/// - Linux IPv6: `EINVAL` (`InvalidInput`). That is also what a malformed
///   send returns, so it counts only when the send carried a source.
/// - macOS 26.5.2, both families: `EADDRNOTAVAIL` (`AddrNotAvailable`).
///
/// `HostUnreachable` and `NetworkDown` are the same event seen from the
/// route or the interface: no route to the peer from here, or the interface
/// went down.
///
/// [SendDropCause::Refused] (zl-zipline#270): the host refused this one
/// send. Linux returns `EPERM` when a netfilter rule (nftables, iptables)
/// or an LSM drops it, and `EACCES` for a broadcast from a socket without
/// `SO_BROADCAST`; Rust reports both as `PermissionDenied`, as it does
/// `WSAEACCES` on Windows. The socket still works, and other peers may be
/// allowed, so the verdict is the packet's, not the socket's.
///
/// Every other error is a bug or a broken socket, and stays fatal.
fn classify_send_error(err: &std::io::Error, had_source: bool) -> Option<SendDropCause> {
    match err.kind() {
        ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkDown
        | ErrorKind::AddrNotAvailable => Some(SendDropCause::NetworkChange),
        ErrorKind::InvalidInput if had_source => Some(SendDropCause::NetworkChange),
        ErrorKind::PermissionDenied => Some(SendDropCause::Refused),
        _ => None,
    }
}

/// Log a send dropped by [classify_send_error], at most once per
/// [SEND_DROP_WARN_INTERVAL] per worker (`warned_at` is the worker's last
/// warning). Every drop is counted in `OutPacksDrop` either way.
fn warn_send_dropped(
    warned_at: &mut Option<Instant>,
    pkt: &QueuedEgressPacket,
    err: &std::io::Error,
) {
    let now = Instant::now();
    if warned_at.is_some_and(|at| now.duration_since(at) < SEND_DROP_WARN_INTERVAL) {
        return;
    }
    *warned_at = Some(now);
    warn!(
        target: DATAPATH,
        "dropping substrate send from {} to {}: {err} (the local address may be gone after a network change; the link's keep-alive will close it)",
        pkt.src, pkt.dst
    );
}

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

/// Classify a batch I/O call's batch-level result: a first-item
/// `WouldBlock` means "nothing to do right now", so it comes back as an
/// empty batch (`Ok(0)`). Every engine returns a first-item error as the
/// batch error (the sendmmsg(2) emulation they share), and on Windows that
/// case is routine, not exceptional:
///
/// * TUN write: `ZprTun::send` maps a full Wintun send ring
///   (`ERROR_BUFFER_OVERFLOW`) to `WouldBlock` (zipline#131 PR #52 review
///   round 1, thread 2).
/// * Substrate receive and TUN read: the wait Event is reset before the
///   drain (see `process_substrate_socket_in`), so a wake can find nothing
///   to read (zipline#133 Windows smoke test).
/// * Substrate send: a full socket send buffer.
///
/// Everything else stays an error for the caller to treat as fatal.
fn wouldblock_as_empty_batch(res: Result<usize>) -> Result<usize> {
    match res {
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
        res => res,
    }
}

fn clear_flowinfo(addr: &mut SocketAddr) {
    match addr {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(addr) => addr.set_flowinfo(0),
    }
}

fn batch_process_packet_queue(
    worker: &mut FastpathWorker,
    queue: &mut packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    limit: usize,
    mut process_fn: impl FnMut(&mut FastpathWorker, Packet),
) {
    for _i in 0..limit {
        let Some(buf) = worker.buffers.pop() else {
            break;
        };

        match queue.try_recv(buf) {
            Ok(pkt) => {
                process_fn(worker, pkt);
            }

            Err(packet_queue::TryRecvError::Empty(buf)) => {
                worker.buffers.push(buf);
                break;
            }

            Err(err) => {
                panic!("unrecoverable I/O error {err:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wouldblock_as_empty_batch;
    use crate::batch_io;
    use std::io::{Error, ErrorKind};
    use std::net::UdpSocket;

    /// zipline#131 PR #52 review round 1 (thread 2): a batch-level
    /// `WouldBlock` from the TUN write — the Wintun send ring full on the
    /// FIRST packet of a batch — is ordinary backpressure and must come
    /// back as "zero sent" (the whole batch then reaches the drop tally),
    /// not as an error the caller's `expect` turns into a fastpath panic.
    #[test]
    fn tun_write_first_item_wouldblock_is_zero_sent() {
        let res = wouldblock_as_empty_batch(Err(Error::new(
            ErrorKind::WouldBlock,
            "Wintun send ring full",
        )));
        assert_eq!(
            res.unwrap(),
            0,
            "a first-item WouldBlock must be nonfatal backpressure"
        );
    }

    /// A successful batch result passes through unchanged.
    #[test]
    fn tun_write_success_passes_through() {
        assert_eq!(wouldblock_as_empty_batch(Ok(7)).unwrap(), 7);
    }

    /// Anything that is not `WouldBlock` stays a batch-level error, so the
    /// caller's `expect("unrecoverable TUN error")` still fires on a real
    /// TUN failure.
    #[test]
    fn tun_write_real_error_stays_fatal() {
        let err = wouldblock_as_empty_batch(Err(Error::new(ErrorKind::BrokenPipe, "TUN gone")))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    /// zipline#133 Windows smoke test: a substrate-socket wake that finds
    /// no datagram (on Windows the wait Event is reset before the drain, so
    /// such wakes are expected) makes every engine's batch receive fail
    /// its FIRST item with `WouldBlock`, which the batch loop returns as
    /// the batch error. That must classify as an empty batch — the smoke
    /// test's `ph.exe` panicked here (`fastpath_io.rs` `.unwrap()`, os
    /// error 10035) right after its link came up.
    #[test]
    fn substrate_recv_on_empty_socket_is_empty_batch() {
        for name in batch_io::engine_names() {
            let mut bio = batch_io::select_engine_by_name(name)
                .unwrap()
                .instantiate(4)
                .unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();

            let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| Vec::with_capacity(64)).collect();
            let mut results = Vec::new();
            let n = wouldblock_as_empty_batch(bio.try_recv_buf_from_to_batch(
                &socket,
                bufs.iter_mut(),
                &mut results,
            ))
            .unwrap_or_else(|err| {
                panic!("engine {name}: empty socket must be an empty batch, got {err}")
            });
            // Engines differ in shape (io_uring completes every item with
            // a per-item `WouldBlock`; the unbatched engines fail the first
            // item), but none may yield a packet.
            assert!(
                results[..n]
                    .iter()
                    .all(|r| matches!(r, Err(e) if e.kind() == ErrorKind::WouldBlock)),
                "engine {name}: nothing to receive"
            );
        }
    }

    // ---- zl-zipline#230 gap 1: send errors after a network change ----

    use super::{SendDropCause, classify_send_error, send_substrate_egress_queue};

    /// The raw OS error codes with which the host refuses a send: `EPERM`
    /// (a netfilter or LSM verdict) and `EACCES` (for example, a broadcast
    /// without `SO_BROADCAST`) on Unix, `WSAEACCES` on Windows.
    fn refused_send_os_errors() -> Vec<i32> {
        #[cfg(unix)]
        {
            vec![libc::EPERM, libc::EACCES]
        }
        #[cfg(windows)]
        {
            vec![windows_sys::Win32::Networking::WinSock::WSAEACCES]
        }
    }

    /// The classifier maps exactly the errors a vanished source address or a
    /// changed network causes to `NetworkChange` (zl-zipline#230), with
    /// `InvalidInput` only for a send that named its source (the Linux IPv6
    /// `EINVAL`); a send the host refuses (`PermissionDenied`: `EPERM`,
    /// `EACCES`) to `Refused` (zl-zipline#270); and nothing else.
    #[test]
    fn send_errors_are_classified() {
        for had_source in [true, false] {
            for kind in [
                ErrorKind::NetworkUnreachable,
                ErrorKind::HostUnreachable,
                ErrorKind::NetworkDown,
                ErrorKind::AddrNotAvailable,
            ] {
                assert_eq!(
                    classify_send_error(&Error::from(kind), had_source),
                    Some(SendDropCause::NetworkChange),
                    "{kind:?}, source {had_source}"
                );
            }

            assert_eq!(
                classify_send_error(&Error::from(ErrorKind::PermissionDenied), had_source),
                Some(SendDropCause::Refused),
                "PermissionDenied, source {had_source}"
            );
            for code in refused_send_os_errors() {
                let err = Error::from_raw_os_error(code);
                assert_eq!(
                    classify_send_error(&err, had_source),
                    Some(SendDropCause::Refused),
                    "os error {code} ({err}), source {had_source}"
                );
            }

            for kind in [ErrorKind::BrokenPipe, ErrorKind::Other] {
                assert_eq!(
                    classify_send_error(&Error::from(kind), had_source),
                    None,
                    "{kind:?} must stay fatal, source {had_source}"
                );
            }
        }

        let einval = Error::from(ErrorKind::InvalidInput);
        assert_eq!(
            classify_send_error(&einval, true),
            Some(SendDropCause::NetworkChange)
        );
        assert_eq!(
            classify_send_error(&einval, false),
            None,
            "EINVAL without a source is a malformed send, not a network change"
        );
    }

    /// A wildcard-bound socket, a receiver it can reach, and a source
    /// address that is not local (a documentation prefix): IPv6 if `v6`,
    /// else IPv4.
    fn vanished_source_setup(
        v6: bool,
    ) -> (UdpSocket, UdpSocket, zpr_utils::net_defs::ScopedIpAddr) {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let (any, loopback, gone): (std::net::IpAddr, std::net::IpAddr, std::net::IpAddr) = if v6 {
            (
                Ipv6Addr::UNSPECIFIED.into(),
                Ipv6Addr::LOCALHOST.into(),
                "2001:db8::1".parse::<Ipv6Addr>().unwrap().into(),
            )
        } else {
            (
                Ipv4Addr::UNSPECIFIED.into(),
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::new(192, 0, 2, 1).into(),
            )
        };
        let sender = UdpSocket::bind((any, 0)).unwrap();
        sender.set_nonblocking(true).unwrap();
        let receiver = UdpSocket::bind((loopback, 0)).unwrap();
        (sender, receiver, gone.into())
    }

    /// A send's error from engine `name`: the batch error, or the first
    /// packet's own result (io_uring reports per packet).
    fn first_send_error(
        name: &str,
        sender: &UdpSocket,
        dst: std::net::SocketAddr,
        src: zpr_utils::net_defs::ScopedIpAddr,
    ) -> Error {
        let mut bio = batch_io::select_engine_by_name(name)
            .unwrap()
            .instantiate(4)
            .unwrap();
        let mut results = Vec::new();
        let payload = b"keep-alive";
        match bio.try_send_to_from_batch(
            sender,
            [(&payload[..], dst, Some(src), batch_io::SendFlags::none())],
            &mut results,
        ) {
            Err(err) => err,
            Ok(n) => match results.into_iter().take(n).next() {
                Some(Err(err)) => err,
                other => panic!("engine {name}: a send from {src} must fail, got {other:?}"),
            },
        }
    }

    /// zl-zipline#230 gap 1: a send whose source address is no longer
    /// local, as after a Wi-Fi switch, fails with an error the classifier
    /// accepts, for both families and every engine. This pins the real
    /// errno of each platform (Linux, macOS, Windows).
    #[test]
    fn send_from_vanished_source_is_a_network_change_error() {
        for name in batch_io::engine_names() {
            for v6 in [false, true] {
                let (sender, receiver, gone) = vanished_source_setup(v6);
                let err = first_send_error(name, &sender, receiver.local_addr().unwrap(), gone);
                assert_eq!(
                    classify_send_error(&err, true),
                    Some(SendDropCause::NetworkChange),
                    "engine {name}: a send from {gone} failed with {err} ({:?}, errno {:?}), \
                     which the classifier does not accept as a network change",
                    err.kind(),
                    err.raw_os_error()
                );
            }
        }
    }

    // ---- zl-zipline#270: a send the host refuses ----

    /// zl-zipline#270: the drop warning names the cause. A refused send
    /// points at the host (a firewall rule); a network-change drop keeps the
    /// #230 wording about a vanished local address. Both name the source,
    /// the destination and the error.
    #[test]
    fn send_drop_message_names_the_cause() {
        use super::send_drop_message;

        let src: zpr_utils::net_defs::ScopedIpAddr =
            std::net::IpAddr::from(std::net::Ipv4Addr::new(192, 0, 2, 1)).into();
        let dst: std::net::SocketAddr = "198.51.100.7:4433".parse().unwrap();
        let err = Error::from(ErrorKind::PermissionDenied);

        let refused = send_drop_message(SendDropCause::Refused, &src, &dst, &err);
        assert_eq!(
            refused,
            format!(
                "dropping substrate send from 192.0.2.1 to 198.51.100.7:4433: {err} \
                 (refused by the host, for example by a firewall rule)"
            )
        );

        let changed = send_drop_message(SendDropCause::NetworkChange, &src, &dst, &err);
        assert_eq!(
            changed,
            format!(
                "dropping substrate send from 192.0.2.1 to 198.51.100.7:4433: {err} \
                 (the local address may be gone after a network change; \
                 the link's keep-alive will close it)"
            )
        );
    }

    /// The destination of a send the host refuses without any firewall
    /// setup: the IPv4 limited broadcast address, which a socket without
    /// `SO_BROADCAST` may not send to (Linux and macOS: `EACCES`; Windows:
    /// `WSAEACCES`). The source is loopback, a local address.
    fn refused_send_addrs() -> (std::net::SocketAddr, zpr_utils::net_defs::ScopedIpAddr) {
        use std::net::Ipv4Addr;
        (
            (Ipv4Addr::BROADCAST, 9).into(),
            std::net::IpAddr::from(Ipv4Addr::LOCALHOST).into(),
        )
    }

    /// zl-zipline#270: a send the host refuses fails, on every engine, with
    /// an error the classifier maps to `Refused`. This pins the real errno
    /// each engine reports, as the vanished-source test does for #230.
    #[test]
    fn send_refused_by_host_is_classified() {
        for name in batch_io::engine_names() {
            let sender = UdpSocket::bind("0.0.0.0:0").unwrap();
            sender.set_nonblocking(true).unwrap();
            let (dst, src) = refused_send_addrs();
            let err = first_send_error(name, &sender, dst, src);
            assert_eq!(
                classify_send_error(&err, true),
                Some(SendDropCause::Refused),
                "engine {name}: a refused send to {dst} failed with {err} ({:?}, errno {:?}), \
                 which the classifier does not accept as refused",
                err.kind(),
                err.raw_os_error()
            );
        }
    }

    /// zl-zipline#230 gap 1: with a packet from a vanished source address
    /// in the substrate egress queue, the fastpath drops and counts it in
    /// `OutPacksDrop` instead of panicking, and frees its buffer. A
    /// PRIORITY packet is dropped too: it would only fail again.
    #[tokio::test(flavor = "local")]
    async fn substrate_send_from_vanished_source_drops_and_counts() {
        for name in batch_io::engine_names() {
            for priority in [false, true] {
                let engine = batch_io::select_engine_by_name(name).unwrap();
                let mut worker = test_worker(engine);
                let (sender, receiver, gone) = vanished_source_setup(false);
                let buffers_before = worker.buffers.len();
                queue_test_packet(
                    &mut worker,
                    b"a keep-alive",
                    receiver.local_addr().unwrap(),
                    gone,
                    priority,
                );

                let warned_at = send_test_queue(engine, &sender, &mut worker);

                assert_one_packet_dropped(
                    &worker,
                    buffers_before,
                    warned_at,
                    &format!("engine {name}, priority {priority}"),
                );
            }
        }
    }

    /// zl-zipline#270: with a packet the host refuses to send in the
    /// substrate egress queue, the fastpath drops and counts it in
    /// `OutPacksDrop` instead of panicking ("unrecoverable I/O error:
    /// Permission denied"), frees its buffer and logs the drop. A PRIORITY
    /// packet is dropped too: it would only be refused again.
    #[tokio::test(flavor = "local")]
    async fn substrate_send_refused_drops_and_counts() {
        for name in batch_io::engine_names() {
            for priority in [false, true] {
                let engine = batch_io::select_engine_by_name(name).unwrap();
                let mut worker = test_worker(engine);
                let sender = UdpSocket::bind("0.0.0.0:0").unwrap();
                sender.set_nonblocking(true).unwrap();
                let (dst, src) = refused_send_addrs();
                let buffers_before = worker.buffers.len();
                queue_test_packet(&mut worker, b"a refused packet", dst, src, priority);

                let warned_at = send_test_queue(engine, &sender, &mut worker);

                assert_one_packet_dropped(
                    &worker,
                    buffers_before,
                    warned_at,
                    &format!("engine {name}, priority {priority}"),
                );
            }
        }
    }

    /// Queue a packet with body `body`, from `src` to `dst`, on `worker`'s
    /// substrate egress queue, flagged PRIORITY if `priority`.
    fn queue_test_packet(
        worker: &mut crate::fastpath::FastpathWorker,
        body: &[u8],
        dst: std::net::SocketAddr,
        src: zpr_utils::net_defs::ScopedIpAddr,
        priority: bool,
    ) {
        use crate::fastpath::QueuedEgressPacket;
        use crate::packet::{Packet, flags};
        use bytes::BufMut as _;

        let mut pkt = Packet::new(worker.buffers.pop().unwrap(), 64);
        pkt.put(body);
        if priority {
            pkt.metadata_mut().flags |= flags::PRIORITY;
        }
        worker
            .substrate_egress_q
            .push(QueuedEgressPacket { pkt, dst, src });
    }

    /// Run [send_substrate_egress_queue] once over `worker`'s queue on a
    /// fresh instance of `engine`, from `sender`. Returns the time of the
    /// drop warning, if one was logged.
    fn send_test_queue(
        engine: &'static batch_io::BatchIoEngine,
        sender: &UdpSocket,
        worker: &mut crate::fastpath::FastpathWorker,
    ) -> Option<std::time::Instant> {
        let mut bio = engine.instantiate(4).unwrap();
        let mut results = Vec::new();
        let mut warned_at = None;
        send_substrate_egress_queue(&mut bio, sender, &mut results, worker, &mut warned_at);
        warned_at
    }

    /// Assert that the one queued packet was dropped: counted in
    /// `OutPacksDrop`, not sent, not retained, its buffer freed (the pool is
    /// back to `buffers_before`), and the drop logged. `what` names the case.
    fn assert_one_packet_dropped(
        worker: &crate::fastpath::FastpathWorker,
        buffers_before: usize,
        warned_at: Option<std::time::Instant>,
        what: &str,
    ) {
        use crate::counters::FastpathCounterType;

        assert_eq!(
            worker.batch_counters[FastpathCounterType::OutPacksDrop].get_count(),
            1,
            "{what}: the packet is counted as dropped"
        );
        assert_eq!(
            worker.batch_counters[FastpathCounterType::OutPacksSent].get_count(),
            0,
            "{what}: nothing was sent"
        );
        assert!(
            worker.substrate_egress_q.is_empty(),
            "{what}: nothing is retained"
        );
        assert_eq!(
            worker.buffers.len(),
            buffers_before,
            "{what}: the buffer is freed"
        );
        assert!(warned_at.is_some(), "{what}: the drop is logged");
    }

    /// A fastpath worker with four buffers and a batch of four, on engine
    /// `engine`, for the substrate egress tests.
    fn test_worker(engine: &'static batch_io::BatchIoEngine) -> crate::fastpath::FastpathWorker {
        use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
        use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
        use std::sync::Arc;

        FastpathWorker::new(
            FastpathWorkerConfig {
                batch_io_engine: engine,
                buffer_count: 4,
                batch_size: 4,
                #[cfg(feature = "enable-security-testing")]
                mangle_forwarded_pings: false,
                #[cfg(feature = "enable-security-testing")]
                unkeyed_a2a_micv: false,
                #[cfg(feature = "enable-security-testing")]
                recompute_micvs: false,
            },
            0,
            Arc::new(create_assembly(TestAssemblyBuilder::new())),
        )
    }

    /// A send from a vanished address drops only its own packet: the next
    /// packet in the queue, from an address that is still there (another
    /// interface of a multi-homed Zode), is still sent, PRIORITY or not.
    /// The engines that emulate sendmmsg(2) report a failed first packet as
    /// the batch error.
    #[tokio::test(flavor = "local")]
    async fn substrate_send_from_vanished_source_spares_the_rest_of_the_queue() {
        use std::net::Ipv4Addr;

        for name in batch_io::engine_names() {
            for priority in [false, true] {
                let engine = batch_io::select_engine_by_name(name).unwrap();
                let mut worker = test_worker(engine);
                let (sender, receiver, gone) = vanished_source_setup(false);
                receiver
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();
                let buffers_before = worker.buffers.len();
                for (body, src) in [
                    (&b"from the old address"[..], gone),
                    (
                        &b"from a live address"[..],
                        std::net::IpAddr::from(Ipv4Addr::LOCALHOST).into(),
                    ),
                ] {
                    queue_test_packet(
                        &mut worker,
                        body,
                        receiver.local_addr().unwrap(),
                        src,
                        priority,
                    );
                }

                send_test_queue(engine, &sender, &mut worker);

                assert_first_dropped_second_sent(
                    &worker,
                    &receiver,
                    buffers_before,
                    b"from a live address",
                    &format!("engine {name}, priority {priority}"),
                );
            }
        }
    }

    /// zl-zipline#270: a send the host refuses drops only its own packet:
    /// the next packet in the queue, to a peer the host allows, is still
    /// sent, PRIORITY or not. The engines that emulate sendmmsg(2) report a
    /// refused first packet as the batch error.
    #[tokio::test(flavor = "local")]
    async fn substrate_send_refused_spares_the_rest_of_the_queue() {
        for name in batch_io::engine_names() {
            for priority in [false, true] {
                let engine = batch_io::select_engine_by_name(name).unwrap();
                let mut worker = test_worker(engine);
                let (sender, receiver, _) = vanished_source_setup(false);
                receiver
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();
                let (refused_dst, src) = refused_send_addrs();
                let buffers_before = worker.buffers.len();
                queue_test_packet(&mut worker, b"refused", refused_dst, src, priority);
                queue_test_packet(
                    &mut worker,
                    b"to an allowed peer",
                    receiver.local_addr().unwrap(),
                    src,
                    priority,
                );

                send_test_queue(engine, &sender, &mut worker);

                assert_first_dropped_second_sent(
                    &worker,
                    &receiver,
                    buffers_before,
                    b"to an allowed peer",
                    &format!("engine {name}, priority {priority}"),
                );
            }
        }
    }

    /// Assert that of two queued packets the first was dropped and the
    /// second sent: `receiver` gets `sent_body`, one packet each is counted
    /// in `OutPacksDrop` and `OutPacksSent`, nothing is retained, and both
    /// buffers are freed (the pool is back to `buffers_before`). `what`
    /// names the case.
    fn assert_first_dropped_second_sent(
        worker: &crate::fastpath::FastpathWorker,
        receiver: &UdpSocket,
        buffers_before: usize,
        sent_body: &[u8],
        what: &str,
    ) {
        use crate::counters::FastpathCounterType;

        let mut buf = [0u8; 64];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("{what}: the second packet arrives: {e}"));
        assert_eq!(&buf[..len], sent_body, "{what}");
        assert_eq!(
            worker.batch_counters[FastpathCounterType::OutPacksDrop].get_count(),
            1,
            "{what}: only the first packet is dropped"
        );
        assert_eq!(
            worker.batch_counters[FastpathCounterType::OutPacksSent].get_count(),
            1,
            "{what}: the second packet is sent"
        );
        assert!(
            worker.substrate_egress_q.is_empty(),
            "{what}: nothing is retained"
        );
        assert_eq!(
            worker.buffers.len(),
            buffers_before,
            "{what}: both buffers are freed"
        );
    }
}
