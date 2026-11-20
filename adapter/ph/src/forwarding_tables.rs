//! Forwarding tables
//!
//! RFC 6.5 § 5.1 (but needs alignment)

#![allow(dead_code)]

use crate::config::STREAM_ID_REUSE_GRACE;
use cslab::{RcuCslab, RcuCslabReader};
use rcu::{RcuBox, RcuCslabEntryGuard};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering, fence};
use std::sync::{Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zpr::packet_info::{ForwardingEntry, LinkId, StreamId, VisaId};

const PEER_FORWARDING_TABLE_SIZE: usize = 1 << 20; // 1 million

// TODO: figure out whether a more complex PEP is warranted,
// which can map a single tether ID to possibly different visa IDs
// and recompress
// (necessary since (a) adapter can choose compression level, and (b)
// visas may be more narrowly scoped than what can be compressed out)
/// One PFT entry: where a stream arriving on this link goes, and under
/// which visa.
///
/// The fields are atomics so that a J11 rebind (zl-zipline#252) can move
/// the stream onto a superseding visa's next-hop stream **in place**,
/// keeping the stream ID the requestor already sends with. The slab gives
/// readers shared references only, so an entry cannot be replaced by a new
/// one under the same key. `next_hop` packs the link and stream IDs into
/// one word, so a reader never sees half of an old target and half of a
/// new one.
///
/// `expires` is a copy of the bound visa's expiry (zl-zipline#274): the
/// fast path checks it on every packet ([PftPep::target]) without taking
/// the visa-table lock. The visa itself is never edited; a rebind copies
/// the new visa's expiry in with its target.
///
/// A rebind changes three words, and a reader must see all three from one
/// binding. `version` makes that so, as a sequence lock: odd while a
/// rebind is writing, and bumped again when it is done; a reader that saw
/// it odd, or changed across its loads, reads again.
pub struct PftPep {
    /// The sequence-lock version: even when the entry is stable.
    version: AtomicU64,
    /// The next hop's `ForwardingEntry`, packed by [pack_forwarding_entry].
    next_hop: AtomicU64,
    visa_id: AtomicU64,
    /// The bound visa's expiry, in milliseconds since the UNIX epoch
    /// ([unix_ms]). From this instant on, the stream forwards nothing.
    expires: AtomicU64,
    /// Set once, when the entry's stream is removed and its slot goes
    /// into quarantine ([PeerForwardingTable::quarantine],
    /// zl-zipline#282). A quarantined entry is invisible to lookups and
    /// never set back.
    quarantined: AtomicBool,
}

/// `time` in milliseconds since the UNIX epoch, the unit of a PFT entry's
/// expiry and of the fast path's clock. A time before the epoch is 0 (long
/// past), and one too far ahead for 64 bits saturates (never), so neither
/// can panic.
pub fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

/// Pack a `ForwardingEntry` (two 32-bit IDs) into one 64-bit word: the
/// link ID in the high half, the stream ID in the low half.
fn pack_forwarding_entry(entry: ForwardingEntry) -> u64 {
    (u64::from(entry.0) << 32) | u64::from(entry.1)
}

/// The inverse of [pack_forwarding_entry].
fn unpack_forwarding_entry(packed: u64) -> ForwardingEntry {
    ForwardingEntry((packed >> 32) as LinkId, packed as u32 as StreamId)
}

impl PftPep {
    /// An entry forwarding to `next_hop` under the visa `visa_id`, which
    /// expires at `expires`.
    pub fn new(next_hop: ForwardingEntry, visa_id: VisaId, expires: SystemTime) -> Self {
        Self {
            version: AtomicU64::new(0),
            next_hop: AtomicU64::new(pack_forwarding_entry(next_hop)),
            visa_id: AtomicU64::new(visa_id),
            expires: AtomicU64::new(unix_ms(expires)),
            quarantined: AtomicBool::new(false),
        }
    }

    /// Where a stream arriving on this entry is forwarded to.
    pub fn next_hop(&self) -> ForwardingEntry {
        unpack_forwarding_entry(self.next_hop.load(AtomicOrdering::Acquire))
    }

    /// The visa the stream is bound under.
    pub fn visa_id(&self) -> VisaId {
        self.visa_id.load(AtomicOrdering::Acquire)
    }

    /// When the bound visa expires, in milliseconds since the UNIX epoch
    /// ([unix_ms]), and where the stream is forwarded to: what the fast
    /// path reads for each packet, which it drops at or after the expiry.
    ///
    /// Both come from one binding, never the expiry of one and the next
    /// hop of another: a reader racing a J11 rebind ([PftPep::rebind])
    /// reads again. A rebind is a few stores, so the retry is short and
    /// rare.
    pub fn target(&self) -> (u64, ForwardingEntry) {
        loop {
            let before = self.version.load(AtomicOrdering::Acquire);
            if before % 2 == 1 {
                // A rebind is writing.
                std::hint::spin_loop();
                continue;
            }
            let expires_ms = self.expires.load(AtomicOrdering::Relaxed);
            let next_hop = self.next_hop.load(AtomicOrdering::Relaxed);
            // Keeps the loads above before the version check below.
            fence(AtomicOrdering::Acquire);
            if self.version.load(AtomicOrdering::Relaxed) == before {
                return (expires_ms, unpack_forwarding_entry(next_hop));
            }
        }
    }

    /// Move this entry onto `visa_id`, which expires at `expires`,
    /// forwarding to `next_hop` (J11 commit). The only writer after
    /// [PftPep::new]; the visa table calls it under its write lock, so
    /// rebinds never overlap. The version is odd while the words change,
    /// so a reader never takes a mix of two bindings (see
    /// [PftPep::target]).
    pub fn rebind(&self, next_hop: ForwardingEntry, visa_id: VisaId, expires: SystemTime) {
        let version = self.version.load(AtomicOrdering::Relaxed);
        self.version.store(version + 1, AtomicOrdering::Relaxed);
        // Keeps the stores below after the odd version.
        fence(AtomicOrdering::Release);
        self.visa_id.store(visa_id, AtomicOrdering::Relaxed);
        self.next_hop
            .store(pack_forwarding_entry(next_hop), AtomicOrdering::Relaxed);
        self.expires
            .store(unix_ms(expires), AtomicOrdering::Relaxed);
        self.version.store(version + 2, AtomicOrdering::Release);
    }

    /// Whether the entry's stream has been removed and its slot is in
    /// quarantine (zl-zipline#282).
    pub fn is_quarantined(&self) -> bool {
        self.quarantined.load(AtomicOrdering::Acquire)
    }

    /// Mark the entry quarantined and make it forward nothing: under the
    /// sequence lock, its visa ID becomes 0 and its expiry the UNIX epoch,
    /// so a reader that found the entry just before it was quarantined
    /// drops its packet as expired. Returns false, and changes nothing,
    /// if the entry was quarantined already. Like [PftPep::rebind], called
    /// only under the visa table's write lock.
    fn tombstone(&self) -> bool {
        if self.quarantined.swap(true, AtomicOrdering::AcqRel) {
            return false;
        }
        let version = self.version.load(AtomicOrdering::Relaxed);
        self.version.store(version + 1, AtomicOrdering::Relaxed);
        // Keeps the stores below after the odd version.
        fence(AtomicOrdering::Release);
        self.visa_id.store(0, AtomicOrdering::Relaxed);
        self.expires.store(0, AtomicOrdering::Relaxed);
        self.version.store(version + 2, AtomicOrdering::Release);
        true
    }
}

/// The table of one link's streams: for each stream ID a peer sends with
/// on that link, where the stream goes ([PftPep]).
///
/// A removed stream's ID is not handed out again at once: its slot goes
/// into quarantine for [STREAM_ID_REUSE_GRACE] ([Self::quarantine],
/// zl-zipline#282), because the peer may still send on the old ID for a
/// while (it processes a withdrawal asynchronously, and an upstream
/// Zode's clock may lag). Without the quarantine a new stream could get
/// the ID and receive the old stream's late packets.
///
/// Lock order: `table`, then `quarantine`.
pub struct PeerForwardingTable {
    table: Mutex<RcuCslab<PftPep>>,
    reader: RcuBox<RcuCslabReader<PftPep>>,
    /// Quarantined stream IDs with the instant each may be freed, oldest
    /// first. The grace is a constant, so the queue is sorted by release
    /// instant.
    quarantine: Mutex<VecDeque<(Instant, StreamId)>>,
}

pub type PftPepGuard<'a> = RcuCslabEntryGuard<'a, PftPep>;

impl PeerForwardingTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(PEER_FORWARDING_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
            quarantine: Mutex::new(VecDeque::new()),
        }
    }

    /// Run `inspector` on the live entry for `tether_id`. None if there is
    /// no entry, or if it is quarantined: a quarantined stream is gone.
    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&PftPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .filter(|pep| !pep.is_quarantined())
                .map(inspector)
        })
    }

    /// The live entry for `tether_id`. None if there is no entry, or if it
    /// is quarantined: a quarantined stream is gone.
    pub fn get(&self, tether_id: StreamId) -> Option<PftPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
            .filter(|pep| !pep.is_quarantined())
    }

    /// Reserve the slot of the next stream ID, after freeing the
    /// quarantined slots whose grace has passed. The table stays locked
    /// until the returned entry is filled or dropped.
    pub fn vacant_entry(&self) -> Result<VacantPeerForwardingTableEntry<'_>, ()> {
        self.release_quarantined_at(Instant::now());
        let table_guard = self.table.lock().unwrap();

        if matches!(table_guard.vacant_key(), Err(_)) {
            return Err(());
        };

        Ok(VacantPeerForwardingTableEntry { table_guard })
    }

    /// Insert `pep` under the next stream ID ([Self::vacant_entry]).
    pub fn insert(&self, pep: PftPep) -> Result<StreamId, ()> {
        Ok(self.vacant_entry()?.insert(pep))
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove((tether_id as usize).wrapping_sub(1));
        std::mem::drop(table);
        self.reader.write(new_reader);
    }

    /// Remove the stream `tether_id` and put its slot into quarantine
    /// until `now` + [STREAM_ID_REUSE_GRACE] (zl-zipline#282). From now on
    /// the stream forwards nothing and lookups do not find it
    /// ([PftPep::tombstone]), but the slot stays occupied, so the ID is
    /// not handed to a new stream before the grace has passed. Freed
    /// later by [Self::release_quarantined_at]. An ID with no entry, or
    /// one quarantined already, changes nothing.
    pub fn quarantine(&self, tether_id: StreamId, now: Instant) {
        let table = self.table.lock().unwrap();
        let Some(pep) = table.get((tether_id as usize).wrapping_sub(1)) else {
            return;
        };
        if pep.tombstone() {
            self.quarantine
                .lock()
                .unwrap()
                .push_back((now + STREAM_ID_REUSE_GRACE, tether_id));
        }
    }

    /// Free the slot of every quarantined stream ID whose grace has
    /// passed at `now`, so the slab can hand the ID out again. Called
    /// before each allocation ([Self::vacant_entry]), so the quarantine
    /// needs no timer of its own.
    pub fn release_quarantined_at(&self, now: Instant) {
        let mut table = self.table.lock().unwrap();
        let mut released_any = false;
        {
            let mut quarantine = self.quarantine.lock().unwrap();
            while let Some(&(release_at, tether_id)) = quarantine.front() {
                if release_at > now {
                    break;
                }
                quarantine.pop_front();
                table.mark_removed((tether_id as usize).wrapping_sub(1));
                released_any = true;
            }
        }
        if !released_any {
            return;
        }
        let new_reader = table.schedule_finalization();
        std::mem::drop(table);
        self.reader.write(new_reader);
    }

    /// The number of live entries: quarantined slots are not counted.
    pub fn len(&self) -> usize {
        let table = self.table.lock().unwrap();
        let quarantined = self.quarantine.lock().unwrap().len();
        table.len() - quarantined
    }

    /// The number of slots in quarantine (zl-zipline#282).
    pub fn quarantined_len(&self) -> usize {
        self.quarantine.lock().unwrap().len()
    }

    pub fn clear(&self) {
        // TODO
    }
}

pub struct VacantPeerForwardingTableEntry<'a> {
    table_guard: MutexGuard<'a, RcuCslab<PftPep>>,
}

impl VacantPeerForwardingTableEntry<'_> {
    pub fn key(&self) -> StreamId {
        (self.table_guard.vacant_key().unwrap() + 1) as StreamId
    }

    pub fn insert(mut self, pep: PftPep) -> StreamId {
        (self.table_guard.insert(pep).unwrap() + 1) as StreamId
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::STREAM_ID_REUSE_GRACE;
    use std::time::{Duration, Instant};

    /// zl-zipline#274 (D5): a J11 rebind moves the entry onto the new
    /// visa's expiry together with its next hop and visa ID, so a renewed
    /// stream keeps forwarding past the old visa's expiry and stops at the
    /// new one's.
    #[test]
    fn test_rebind_moves_the_expiry_with_the_target() {
        let old_expiry = UNIX_EPOCH + Duration::from_secs(1_000);
        let new_expiry = UNIX_EPOCH + Duration::from_secs(2_000);
        let pep = PftPep::new(ForwardingEntry(3, 42), 7100, old_expiry);
        assert_eq!(pep.target().0, 1_000_000);

        pep.rebind(ForwardingEntry(4, 43), 7101, new_expiry);

        assert!(pep.next_hop() == ForwardingEntry(4, 43));
        assert_eq!(pep.visa_id(), 7101);
        assert_eq!(pep.target().0, 2_000_000);
    }

    /// Local Codex review (t320 and t321, P2): a J11 rebind races the fast
    /// path, which must read the expiry and the next hop of one and the
    /// same binding. A new expiry with the old next hop lets a packet of
    /// an expired visa pass on its successor's expiry; the old expiry with
    /// the new next hop lets a packet pass on the predecessor's expiry to
    /// a successor that expires sooner. A writer rebinds in a tight loop
    /// onto ever newer targets, each expiring at its own number (in ms); a
    /// concurrent reader must only ever see a target with its own expiry.
    #[test]
    fn test_a_racing_reader_reads_the_expiry_and_next_hop_of_one_binding() {
        const REBINDS: u32 = 2_000_000;
        let pep = PftPep::new(ForwardingEntry(1, 0), 0, UNIX_EPOCH);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                for i in 1..=REBINDS {
                    let expires = UNIX_EPOCH + Duration::from_millis(u64::from(i));
                    pep.rebind(ForwardingEntry(1, i), VisaId::from(i), expires);
                }
            });
            while !writer.is_finished() {
                let (expires_ms, next_hop) = pep.target();
                assert_eq!(
                    u64::from(next_hop.1),
                    expires_ms,
                    "next hop {} read with the expiry of target {expires_ms}",
                    next_hop.1
                );
            }
        });
    }

    // ---- Stream-ID quarantine (zl-zipline#282) ----

    /// A PFT entry forwarding to stream 9 on link 2, under visa 7000,
    /// which never expires within a test run.
    fn live_pep() -> PftPep {
        PftPep::new(
            ForwardingEntry(2, 9),
            7000,
            SystemTime::now() + Duration::from_secs(3600),
        )
    }

    /// zl-zipline#282: a quarantined stream ID is not handed out again
    /// before the grace has passed. Its slot stays occupied, so no
    /// vacant entry can get it, while lookups no longer find it.
    #[test]
    fn test_a_quarantined_id_is_not_handed_out_again() {
        let pft = PeerForwardingTable::new();
        let quarantined = pft.insert(live_pep()).unwrap();
        let start = Instant::now();

        pft.quarantine(quarantined, start);
        pft.release_quarantined_at(start + STREAM_ID_REUSE_GRACE - Duration::from_millis(1));

        assert_ne!(pft.vacant_entry().unwrap().key(), quarantined);
        assert!(pft.get(quarantined).is_none(), "the stream is gone");
        assert_eq!(pft.quarantined_len(), 1, "still in quarantine");
    }

    /// zl-zipline#282: once the grace has passed, the next release frees
    /// the slot, and the slab hands the stream ID out again.
    #[test]
    fn test_a_quarantined_id_is_released_after_the_grace() {
        let pft = PeerForwardingTable::new();
        let quarantined = pft.insert(live_pep()).unwrap();
        let start = Instant::now();
        pft.quarantine(quarantined, start);

        pft.release_quarantined_at(start + STREAM_ID_REUSE_GRACE);

        assert_eq!(pft.quarantined_len(), 0);
        assert_eq!(pft.len(), 0);
        // The slab frees a slot once no reader of an older generation
        // is left (RCU), so the ID comes back after some churn, not
        // necessarily on the very next insert.
        let mut reused = false;
        for _ in 0..100_000 {
            let other = pft.insert(live_pep()).unwrap();
            if other == quarantined {
                reused = true;
                break;
            }
            pft.quarantine(other, start);
            pft.release_quarantined_at(start + STREAM_ID_REUSE_GRACE);
        }
        assert!(reused, "stream ID {quarantined} is never handed out again");
    }

    /// zl-zipline#282: a quarantined entry forwards nothing. Lookups do
    /// not find it, and a reader that already holds it reads an expiry
    /// at the UNIX epoch, which the fast path drops.
    #[test]
    fn test_a_quarantined_entry_forwards_nothing() {
        let pft = PeerForwardingTable::new();
        let quarantined = pft.insert(live_pep()).unwrap();
        let held = pft.get(quarantined).unwrap();

        pft.quarantine(quarantined, Instant::now());

        assert!(held.is_quarantined());
        assert_eq!(held.target().0, 0, "expired since the epoch");
        drop(held);
        assert!(pft.get(quarantined).is_none());
        assert!(pft.inspect(quarantined, |pep| pep.visa_id()).is_none());
    }

    /// zl-zipline#282: `len()` counts live entries only; a quarantined
    /// slot is counted by `quarantined_len()`.
    #[test]
    fn test_len_counts_live_entries_only() {
        let pft = PeerForwardingTable::new();
        let quarantined = pft.insert(live_pep()).unwrap();
        let _live = pft.insert(live_pep()).unwrap();

        pft.quarantine(quarantined, Instant::now());

        assert_eq!(pft.len(), 1);
        assert_eq!(pft.quarantined_len(), 1);
    }

    /// zl-zipline#282: quarantining an ID twice, or an ID with no entry,
    /// changes nothing: the slot is queued for release once only.
    #[test]
    fn test_a_second_quarantine_of_an_id_is_a_no_op() {
        let pft = PeerForwardingTable::new();
        let quarantined = pft.insert(live_pep()).unwrap();
        let start = Instant::now();

        pft.quarantine(quarantined, start);
        pft.quarantine(quarantined, start);
        pft.quarantine(quarantined + 100, start); // never allocated

        assert_eq!(pft.quarantined_len(), 1);
        pft.release_quarantined_at(start + STREAM_ID_REUSE_GRACE);
        assert_eq!(pft.quarantined_len(), 0);
        assert_eq!(pft.len(), 0);
    }

    /// An expiry before the UNIX epoch, which no granted visa has, counts
    /// as long past, not as a panic.
    #[test]
    fn test_unix_ms_of_a_time_before_the_epoch_is_zero() {
        assert_eq!(unix_ms(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert_eq!(unix_ms(UNIX_EPOCH + Duration::from_millis(1_500)), 1_500);
    }
}
