//! Code which handles active aspects of ZDPR (namely, retries).

use crate::counters;
use crate::mgmt;
use crate::prelude::*;
use tokio::select;
use tokio::time;

/// The ZDP-R worker of the link `link_id`: resends what its peer has not
/// acknowledged in time, until that peer leaves the peer table (`own_peer`).
///
/// It takes a peer-table guard only for synchronous work, never across an
/// `await`. With the default `rcu-crossbeam-epoch` backend a guard pins the
/// epoch of the thread every `spawn_local` task runs on, and a worker idles
/// for as long as its link has nothing to retry: a guard held while it
/// waits keeps every RCU table from freeing what it retired, so an unbound
/// DLT slot would never come back (zl-zipline#283).
pub async fn launch(asm: Arc<Assembly>, link_id: LinkId) {
    let mut retry_interval = time::interval(config::DEFAULT_ZDPR_RETRY_TIMER);
    retry_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    // This worker's peer is the one at `link_id` now; it is told apart from
    // a later peer that reuses the link ID by its retry-reset `Notify`.
    let Some(retry_timer_reset) = asm
        .peer_table
        .get(link_id)
        .map(|peer_state| peer_state.zdpr_retry_timer_reset.clone())
    else {
        return; // peer removed before we started
    };

    loop {
        let retry_needed = {
            let Some(peer_state) = own_peer(&asm, link_id, &retry_timer_reset) else {
                // peer removed; we're done
                break;
            };
            peer_state.zdpr_send.lock().unwrap().retry_needed()
        };

        select! {
            _ = retry_interval.tick(), if retry_needed => {
                let Some(peer_state) = own_peer(&asm, link_id, &retry_timer_reset) else {
                    // peer removed while we waited; we're done
                    break;
                };
                let mut zdpr_send = peer_state.zdpr_send.lock().unwrap();
                let mut count = 0;

                // Resend any packets which must be resent.
                zdpr_send.age_retries().for_each(drop);
                let packets = zdpr_send.retry_packets();
                let packets = packets.inspect(|_| count += 1);
                mgmt::core::build_and_egress_packets(&asm, link_id, packets);
                mgmt::core::count_events(&asm, counters::ManagementCounterType::ResentPacket, count);

                // Resend any cancels which must be resent.
                zdpr_send.retry_cancels().for_each(|sn| mgmt::core::send_cancel(&asm, link_id, sn));
            }

            () = retry_timer_reset.notified() => retry_interval.reset(),
        };
    }
}

/// The peer at `link_id`, if it is still the one whose retry-reset
/// `Notify` is `retry_timer_reset`. Once a worker's peer has left, its
/// link ID can be reused by another peer, which has a worker of its own;
/// the old worker gets `None` and stops (zl-zipline#283).
fn own_peer<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    retry_timer_reset: &Arc<tokio::sync::Notify>,
) -> Option<crate::peer_table::PeerTableEntryGuard<'a>> {
    asm.peer_table
        .get(link_id)
        .filter(|peer_state| Arc::ptr_eq(&peer_state.zdpr_retry_timer_reset, retry_timer_reset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};

    /// zl-zipline#283 (local Codex review): an idle worker must not hold a
    /// peer-table RCU guard while it waits. With the default
    /// `rcu-crossbeam-epoch` backend that guard pins the epoch of the
    /// thread every `spawn_local` task runs on, so no RCU table frees what
    /// it retired: an unbound DLT slot never comes back, and the DLT fills
    /// up however often the node unbinds. Here a worker for the dock link
    /// waits with nothing to retry, on this test's thread; the thread must
    /// not be pinned. (The epoch is global, so whether retired slots are
    /// reused also depends on every other thread, including other tests';
    /// this thread's pin is the part a worker controls.)
    /// zl-zipline#283 (Copilot review): a worker serves only the peer it
    /// was started for. Once that peer leaves, its link ID can be reused
    /// by another peer, which gets a worker of its own; the old worker
    /// must stop rather than also resend for the new peer. A peer is
    /// told apart by its retry-reset `Notify`, which no other peer shares.
    #[tokio::test(flavor = "local")]
    async fn test_a_worker_serves_only_its_own_peer() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let (_, dock) = asm
            .peer_table
            .insert_internal_peer_pair(|_, _| std::future::pending::<()>());
        let dock = dock.get();
        let own = asm
            .peer_table
            .get(dock)
            .unwrap()
            .zdpr_retry_timer_reset
            .clone();

        assert!(own_peer(&asm, dock, &own).is_some(), "its own peer");
        // Another peer now at this link ID has a `Notify` of its own.
        let replacement = Arc::new(tokio::sync::Notify::new());
        assert!(
            own_peer(&asm, dock, &replacement).is_none(),
            "a peer that reused the link ID"
        );
        assert!(own_peer(&asm, dock + 100, &own).is_none(), "no peer");
    }

    #[cfg(feature = "rcu-crossbeam-epoch")]
    #[tokio::test(flavor = "local")]
    async fn test_an_idle_worker_does_not_pin_the_rcu_epoch() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let (_, dock) = asm
            .peer_table
            .insert_internal_peer_pair(|_, _| std::future::pending::<()>());
        assert!(
            !crossbeam_epoch::is_pinned(),
            "pinned before the worker runs"
        );

        tokio::task::spawn_local(launch(asm.clone(), dock.get()));
        tokio::task::yield_now().await; // the worker now waits in `select!`

        assert!(
            !crossbeam_epoch::is_pinned(),
            "an idle ZDP-R worker pins the RCU epoch, so retired DLT slots are never freed"
        );
    }
}
