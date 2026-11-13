//! Forwarding tables
//!
//! RFC 6.5 § 5.1 (but needs alignment)

#![allow(dead_code)]

use cslab::{RcuCslab, RcuCslabReader};
use rcu::{RcuBox, RcuCslabEntryGuard};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Mutex, MutexGuard};
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
pub struct PftPep {
    /// The next hop's `ForwardingEntry`, packed by [pack_forwarding_entry].
    next_hop: AtomicU64,
    visa_id: AtomicU64,
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
    /// An entry forwarding to `next_hop` under the visa `visa_id`.
    pub fn new(next_hop: ForwardingEntry, visa_id: VisaId) -> Self {
        Self {
            next_hop: AtomicU64::new(pack_forwarding_entry(next_hop)),
            visa_id: AtomicU64::new(visa_id),
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

    /// Move this entry onto `visa_id`, forwarding to `next_hop` (J11
    /// commit). The only writer after [PftPep::new]; the visa table calls it
    /// under its write lock. The visa ID is stored first, so a reader that
    /// sees the new next hop also sees the new visa ID.
    pub fn rebind(&self, next_hop: ForwardingEntry, visa_id: VisaId) {
        self.visa_id.store(visa_id, AtomicOrdering::Release);
        self.next_hop
            .store(pack_forwarding_entry(next_hop), AtomicOrdering::Release);
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
