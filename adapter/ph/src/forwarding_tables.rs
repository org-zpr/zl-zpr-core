//! Forwarding tables
//!
//! RFC 6.5 § 5.1 (but needs alignment)

#![allow(dead_code)]

use cslab::{RcuCslab, RcuCslabReader};
use rcu::{RcuBox, RcuCslabEntryGuard};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
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
/// fast path checks it on every packet ([PftPep::expires_ms]) without
/// taking the visa-table lock. The visa itself is never edited; a rebind
/// copies the new visa's expiry in with its target.
pub struct PftPep {
    /// The next hop's `ForwardingEntry`, packed by [pack_forwarding_entry].
    next_hop: AtomicU64,
    visa_id: AtomicU64,
    /// The bound visa's expiry, in milliseconds since the UNIX epoch
    /// ([unix_ms]). From this instant on, the stream forwards nothing.
    expires: AtomicU64,
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
            next_hop: AtomicU64::new(pack_forwarding_entry(next_hop)),
            visa_id: AtomicU64::new(visa_id),
            expires: AtomicU64::new(unix_ms(expires)),
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
    /// A J11 rebind may run between the two loads. The expiry is loaded
    /// first, and [PftPep::rebind] stores it last, so a reader that sees a
    /// rebind's expiry also sees its next hop (Release/Acquire). The one
    /// mixed pair a reader can get is the old expiry with the new next
    /// hop: a packet the old visa still admits goes to the successor's
    /// target, which the J11 commit checked is live. Never the reverse,
    /// which would let a packet of an expired visa pass on its successor's
    /// expiry.
    pub fn target(&self) -> (u64, ForwardingEntry) {
        let expires_ms = self.expires.load(AtomicOrdering::Acquire);
        (expires_ms, self.next_hop())
    }

    /// Move this entry onto `visa_id`, which expires at `expires`,
    /// forwarding to `next_hop` (J11 commit). The only writer after
    /// [PftPep::new]; the visa table calls it under its write lock. The
    /// expiry is stored last, so a reader that sees the new expiry also
    /// sees the new visa ID and next hop (see [PftPep::target]).
    pub fn rebind(&self, next_hop: ForwardingEntry, visa_id: VisaId, expires: SystemTime) {
        self.visa_id.store(visa_id, AtomicOrdering::Release);
        self.next_hop
            .store(pack_forwarding_entry(next_hop), AtomicOrdering::Release);
        self.expires
            .store(unix_ms(expires), AtomicOrdering::Release);
    }
}

pub struct PeerForwardingTable {
    table: Mutex<RcuCslab<PftPep>>,
    reader: RcuBox<RcuCslabReader<PftPep>>,
}

pub type PftPepGuard<'a> = RcuCslabEntryGuard<'a, PftPep>;

impl PeerForwardingTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(PEER_FORWARDING_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
        }
    }

    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&PftPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .map(inspector)
        })
    }

    pub fn get(&self, tether_id: StreamId) -> Option<PftPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
    }

    pub fn vacant_entry(&self) -> Result<VacantPeerForwardingTableEntry<'_>, ()> {
        let table_guard = self.table.lock().unwrap();

        if matches!(table_guard.vacant_key(), Err(_)) {
            return Err(());
        };

        Ok(VacantPeerForwardingTableEntry { table_guard })
    }

    pub fn insert(&self, pep: PftPep) -> Result<StreamId, ()> {
        Ok(self.vacant_entry()?.insert(pep))
    }

    pub fn remove(&self, tether_id: StreamId) {
        let mut table = self.table.lock().unwrap();
        let new_reader = table.remove((tether_id as usize).wrapping_sub(1));
        std::mem::drop(table);
        self.reader.write(new_reader);
    }

    pub fn len(&self) -> usize {
        self.table.lock().unwrap().len()
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
    use std::time::Duration;

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

    /// Local Codex review (t320, P2): a J11 rebind races the fast path,
    /// which must never pair the expiry of the visa a rebind moves the
    /// stream onto with the next hop of the visa it moves it off: the old
    /// visa may have expired, and its packets must not pass on the new
    /// visa's expiry. A writer rebinds in a tight loop onto ever newer
    /// targets, each expiring at its own number (in ms); a concurrent reader
    /// must never see a next hop older than the expiry it read with it.
    #[test]
    fn test_a_racing_reader_never_pairs_a_new_expiry_with_an_old_next_hop() {
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
                assert!(
                    u64::from(next_hop.1) >= expires_ms,
                    "next hop {} read with the expiry of target {expires_ms}",
                    next_hop.1
                );
            }
        });
    }

    /// An expiry before the UNIX epoch, which no granted visa has, counts
    /// as long past, not as a panic.
    #[test]
    fn test_unix_ms_of_a_time_before_the_epoch_is_zero() {
        assert_eq!(unix_ms(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert_eq!(unix_ms(UNIX_EPOCH + Duration::from_millis(1_500)), 1_500);
    }
}
