use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::fastpath_io::FastpathIo;
use crate::packet_queue;
use crate::prelude::*;
use crate::sys::ZprTun;
use crate::sys::wait::{Interest, WaitSet, Waitable};
use std::net::UdpSocket;

pub fn launch(
    config: FastpathWorkerConfig,
    worker_index: usize,
    asm: Arc<Assembly>,
    substrate_socket: UdpSocket,
    actor_input_tun: Arc<ZprTun>,
    requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    mgmt_substrate_outq: Option<packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>>,
) -> impl FnOnce() {
    move || {
        let worker = FastpathWorker::new(config, worker_index, asm.clone());
        let io = FastpathIo::new(
            config,
            substrate_socket,
            actor_input_tun,
            requeue_outq,
            mgmt_substrate_outq,
        );
        fastpath_main(worker, io);
    }
}

fn fastpath_main(mut worker: FastpathWorker, mut io: FastpathIo) {
    // See discussion on fairness below for the reason for this assertion
    // and the magic constant used in it.
    assert!(worker.config.buffer_count >= 5 * worker.config.batch_size);

    loop {
        // try to immediately output anything we've queued up;
        // if we can't, drop it, unless it's on the substrate and marked PRIORITY
        io.process_out_queues(&mut worker);

        let recv_interest;
        if worker.buffers.is_empty() {
            // If we have no buffers, let's not get woken up to receive packets.
            recv_interest = Interest::NONE;
        } else {
            recv_interest = Interest::READ;
        }

        let send_interest;
        if worker.substrate_egress_packets_queued() {
            send_interest = Interest::WRITE;
        } else {
            send_interest = Interest::NONE;
        }

        let mut wait_set = WaitSet::with_capacity(5);
        let substrate = wait_set.push(io.substrate_socket_handle(), recv_interest | send_interest);
        let tun = wait_set.push(io.actor_tun_handle(), recv_interest);
        let requeue = wait_set.push(io.requeue_handle(), recv_interest);
        let mgmt_substrate = wait_set.push(io.mgmt_substrate_handle(), recv_interest);
        let returns = wait_set.push(worker.return_q.handle(), Interest::READ);

        let ready = match wait_set.wait(None) {
            Ok(ready) => ready,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            ret @ Err(_) => ret.unwrap(),
        };

        // Dropping the wait set here releases its borrows of things in
        // `worker`, which we need `&mut` access to below.  (`ready` is an
        // owned snapshot of the results.)
        drop(wait_set);

        // One clock read for every packet this wakeup handles: the
        // per-packet visa-expiry check compares against it.
        worker.refresh_clock();

        // FAIRNESS
        //
        // There are two types of resources these I/O routines contend for:
        // packet buffers, and system I/O output queues.
        //
        // Memory is cheap, so we solve the problem of packet buffer
        // contention simply by making sure there are at least as many
        // packet buffers existing as there can be outstanding.
        //
        // Packet buffers can be outstanding only while they are queued for
        // egress.  Buffers holding non-priority packets, as produced by the
        // Requeue, Substrate, Tun, and (possibly) MgmtSubstrate I/O
        // routines, are recovered at the end of every I/O cycle.
        // Therefore, it is sufficient that we have a number of packet
        // buffers available equal to the sum of the batch sizes for these
        // four paths.
        //
        // Buffers holding priority packets however are only recovered on
        // successful submission of the packet to the OS.  Though we do not
        // care if these starve non-priority paths, we do care that said
        // paths are starved of buffers fairly.  It suffices that we reserve
        // an additional number of packet buffers (beyond those already
        // reserved on behalf of MgmtSubstrate, the only source of priority
        // packets) equal to the batch size, corresponding to those priority
        // packets which were held from the last cycle.  (If priority
        // packets are held for two cycles, this implies that we are not
        // sending any non-priority packets and thus dropping them.)
        //
        // These buffer count requirements are enforced by the assert at the
        // top of this function.
        //
        // Regarding contention for system I/O output queues.  Only packets
        // from Substrate and Tun will ever be high enough rate to actually
        // matter.  So we statically give priority to packets Requeue and
        // MgmtSubstrate packets (the latter of which are almost certainly
        // actually marked as such).  For packets from Substrate and Tun, we
        // consider separately the adapter and node cases.
        //
        // On the adapter, traffic from Substrate always flows out the Tun
        // interface, and vice-versa.  So there is no contention between these
        // for the system I/O output queues.
        //
        // On the node, traffic to or from the Tun is management (typically
        // Visa-related) traffic, and thus typically lower rate than traffic
        // which only transits the Substrate, and also more important.  So
        // we can safely statically prioritize this traffic, which also
        // ensures that it doesn't get starved.

        // First, get any returned buffers, so we have them immediately to work with.
        if ready.is_readable(returns) {
            worker
                .return_q
                .try_recv_many_returns(&mut worker.buffers, worker.config.buffer_count);
        }

        // Now, try to send queued PRIORITY packets, possibly freeing their buffers also.
        if ready.is_writable(substrate) {
            io.process_substrate_socket_out(&mut worker);
        }

        // Next, read and process any substrate traffic from mgmt.  This is
        // typically/always marked PRIORITY, but even if not, it's low rate
        // and we don't want it to get starved.
        if ready.is_readable(mgmt_substrate) {
            io.process_mgmt_substrate_in(&mut worker);
        }

        // Now, read and process any requeued agent traffic.  Typically this
        // is from mgmt.  It is not priority, but it is low rate, so we want
        // to process it first.
        if ready.is_readable(requeue) {
            io.process_requeue_in(&mut worker);
        }

        // Now we read and process agent traffic from the TUN device.
        // On the adapter, this may be high rate, so we process it after all low-rate sources.
        // On the node, this is likely low rate, so we process it before substrate traffic.
        if ready.is_readable(tun) {
            io.process_actor_tun_in(&mut worker);
        }

        // Finally, read and process agent traffic from the substrate.
        // This is likely high rate, so process it after all other sources.
        if ready.is_readable(substrate) {
            // read from socket
            io.process_substrate_socket_in(&mut worker);
        }
        worker.aggregate()
    }
}
