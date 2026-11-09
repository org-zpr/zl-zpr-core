//! Adapter lookup tables
//!
//! These tables hold the state of all tethers on an adapter, outbound (ELT) or inbound (DLT).
//!
//! RFC 6.5 § 5.1

#![allow(dead_code)]

use crate::defs::FiveTuple;
use crate::mgmt::txn_mgr::TxnHandle;
use crate::packet::Packet;
use crate::tc;
use crate::zdp;
use cslab::{RcuCslab, RcuCslabReader};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashMapEntry;
use dashmap::mapref::one::Ref as DashMapRef;
use rcu::{RcuBox, RcuCslabEntryGuard};
use std::sync::Mutex;
use zpr::packet_info::{CompressionMode, StreamId};

const DOCK_LOOKUP_TABLE_SIZE: usize = 1 << 20; // 1 million

pub struct EltPep {
    pub compression_mode: CompressionMode,
    pub tether_id: StreamId,
    pub a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    pub a2a_micv_key: Option<[u8; blake3::KEY_LEN]>,
}

impl EltPep {
    /// Constructor for an EltPep. The a2a_micv_key is derived from the a2a_shared_secret, if present.
    pub fn new(
        compression_mode: CompressionMode,
        tether_id: StreamId,
        a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    ) -> Self {
        let a2a_micv_key = a2a_shared_secret
            .as_ref()
            .map(|secret| blake3::derive_key(zdp::ZDP_A2A_MICV_KEY_CONTEXT, secret.as_bytes()));
        Self {
            compression_mode,
            tether_id,
            a2a_shared_secret,
            a2a_micv_key,
        }
    }
}

pub enum EltEntry {
    /// We've requested a tether ID for this flow, but haven't received one yet.
    Pending(Packet, TxnHandle),
    /// There is currently a tether allocated for this flow.
    Active(EltPep),
}

/// The Endpoint Lookup Table (ELT) holds all state of outbound tethers.
///
/// It is used to map five-tuples (from the endpoint) to compression
/// specifications and tether IDs (for the dock).
pub struct EndpointLookupTable {
    table: DashMap<FiveTuple, EltEntry>,
    pending: DashMap<TxnHandle, FiveTuple>,
}

pub struct EltEntryGuard<'a>(DashMapRef<'a, FiveTuple, EltEntry>);

impl std::ops::Deref for EltEntryGuard<'_> {
    type Target = EltEntry;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

pub enum InsertPendingError {
    AlreadyPending(Packet),
    DuplicateTransaction(Packet),
}

impl std::fmt::Debug for InsertPendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::AlreadyPending(_) => write!(f, "AlreadyPending"),
            Self::DuplicateTransaction(_) => write!(f, "DuplicateTransaction"),
        }
    }
}

#[derive(Debug)]
pub enum LookupPendingError {
    NotFound,
    NotPending,
}

#[derive(Debug)]
pub enum RemoveError {
    NotFound,
}

pub enum SetActiveError {
    NotFound(EltPep),
    NotPending(EltPep),
}

impl std::fmt::Debug for SetActiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::NotFound(_) => write!(f, "NotFound"),
            Self::NotPending(_) => write!(f, "NotPending"),
        }
    }
}

impl EndpointLookupTable {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            pending: DashMap::new(),
        }
    }

    pub fn insert_pending(
        &self,
        five_tuple: FiveTuple,
        init_packet: Packet,
        txn: &TxnHandle,
    ) -> Result<(), InsertPendingError> {
        match self.table.entry(five_tuple) {
            DashMapEntry::Occupied(_) => Err(InsertPendingError::AlreadyPending(init_packet)),

            DashMapEntry::Vacant(entry) => {
                if self.pending.insert(txn.clone(), five_tuple).is_some() {
                    return Err(InsertPendingError::DuplicateTransaction(init_packet));
                }
                entry.insert(EltEntry::Pending(init_packet, txn.clone()));
                Ok(())
            }
        }
    }

    pub fn lookup_pending(&self, txn: &TxnHandle) -> Result<FiveTuple, LookupPendingError> {
        Ok(*self.pending.get(txn).ok_or(LookupPendingError::NotFound)?)
    }

    pub fn set_active(
        &self,
        five_tuple: &FiveTuple,
        pep: EltPep,
    ) -> Result<Packet, SetActiveError> {
        let Some(mut entry) = self.table.get_mut(five_tuple) else {
            return Err(SetActiveError::NotFound(pep));
        };

        if !matches!(entry.value(), EltEntry::Pending(..)) {
            return Err(SetActiveError::NotPending(pep));
        }

        let EltEntry::Pending(packet, txn) =
            std::mem::replace(entry.value_mut(), EltEntry::Active(pep))
        else {
            unreachable!();
        };

        assert!(
            matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
            "ELT consistency error"
        );

        Ok(packet)
    }

    // TODO: figure out whether we want to perform partial matching
    pub fn inspect<T>(
        &self,
        five_tuple: &FiveTuple,
        inspector: impl FnOnce(&EltEntry) -> T,
    ) -> Option<T> {
        self.table.get(five_tuple).map(|entry| inspector(&*entry))
    }

    pub fn get(&self, five_tuple: &FiveTuple) -> Option<EltEntryGuard<'_>> {
        self.table.get(five_tuple).map(EltEntryGuard)
    }

    pub fn remove(&self, five_tuple: &FiveTuple) -> Result<EltEntry, RemoveError> {
        let (_, entry) = self.table.remove(five_tuple).ok_or(RemoveError::NotFound)?;

        match &entry {
            EltEntry::Pending(_, txn) => assert!(
                matches!(self.pending.remove(&txn), Some((_txn, ft)) if &ft == five_tuple),
                "ELT consistency error"
            ),
            EltEntry::Active(_) => (),
        }

        Ok(entry)
    }

    /// Remove the Active entry whose tether id matches `tether_id`, if any,
    /// returning its five-tuple. Used when a peer withdraws a stream id
    /// (`StreamIdWithdrawal`): the withdrawn id is the tether id we send
    /// with, so it identifies an *outbound* (ELT) entry, keyed here by
    /// five-tuple rather than by id. Pending entries have no tether id yet
    /// and never match (zipline#21).
    pub fn remove_by_tether_id(&self, tether_id: StreamId) -> Option<FiveTuple> {
        // Find the key first and drop the iterator before removing:
        // removing while holding a DashMap ref deadlocks.
        let five_tuple = self.table.iter().find_map(|entry| match entry.value() {
            EltEntry::Active(pep) if pep.tether_id == tether_id => Some(*entry.key()),
            _ => None,
        })?;

        self.remove(&five_tuple).ok().map(|_| five_tuple)
    }

    /// Remove every entry, Active and Pending, along with the pending
    /// transaction index. Used when the dock link goes down: every tether id
    /// in the table was issued by the node on that docking session, so none
    /// is valid on the next one, and a Pending entry's bind request died
    /// with the link (zipline#170). Pending entries' queued initial packets
    /// are dropped, as if they had been dropped awaiting bind.
    pub fn clear(&self) {
        // Snapshot the keys and drop the iterator before removing: removing
        // while holding a DashMap ref deadlocks. Going through `remove()`
        // keeps `table` and `pending` consistent entry by entry; an entry
        // inserted after the snapshot belongs to a newer bind and survives.
        let five_tuples: Vec<FiveTuple> = self.table.iter().map(|entry| *entry.key()).collect();
        for five_tuple in five_tuples {
            // NotFound means a bind response removed it concurrently.
            let _ = self.remove(&five_tuple);
        }
    }
}

pub struct DltPep {
    pub tc: tc::Ip5TupleTc,
    pub a2a_shared_secret: Option<x25519_dalek::SharedSecret>,
    pub a2a_micv_key: Option<[u8; blake3::KEY_LEN]>,
}

impl DltPep {
    /// Constructor for a DltPep. The a2a_micv_key is derived from the a2a_shared_secret, if present.
    pub fn new(tc: tc::Ip5TupleTc, a2a_shared_secret: Option<x25519_dalek::SharedSecret>) -> Self {
        let a2a_micv_key = a2a_shared_secret
            .as_ref()
            .map(|secret| blake3::derive_key(zdp::ZDP_A2A_MICV_KEY_CONTEXT, secret.as_bytes()));
        Self {
            tc,
            a2a_shared_secret,
            a2a_micv_key,
        }
    }
}

/// The Dock Lookup Table (DLT) holds all state of inbound tethers.
///
/// It is used to map tether IDs (from the dock) to decompression
/// specifications and five-tuples (for the endpoint).
pub struct DockLookupTable {
    table: Mutex<RcuCslab<DltPep>>,
    reader: RcuBox<RcuCslabReader<DltPep>>,
}

pub type DltPepGuard<'a> = RcuCslabEntryGuard<'a, DltPep>;

impl DockLookupTable {
    pub fn new() -> Self {
        let table = RcuCslab::with_fixed_capacity(DOCK_LOOKUP_TABLE_SIZE);
        let reader = table.reader();

        Self {
            table: Mutex::new(table),
            reader: RcuBox::new(reader),
        }
    }

    pub fn inspect<T>(
        &self,
        tether_id: StreamId,
        inspector: impl FnOnce(&DltPep) -> T,
    ) -> Option<T> {
        self.reader.inspect(|reader| {
            reader
                .get((tether_id as usize).wrapping_sub(1))
                .map(inspector)
        })
    }

    pub fn get(&self, tether_id: StreamId) -> Option<DltPepGuard<'_>> {
        self.reader
            .get_guarded((tether_id as usize).wrapping_sub(1))
    }

    pub fn insert(&self, pep: DltPep) -> Result<StreamId, ()> {
        Ok((self.table.lock().unwrap().insert(pep)? + 1) as StreamId)
    }

    /// Remove the entry for `tether_id`. An id with no entry is ignored:
    /// the id comes from the node, and the underlying slab panics on
    /// removing an empty slot, so an unknown, duplicate, or already-flushed
    /// id (see `clear()`) must not reach it.
    pub fn remove(&self, tether_id: StreamId) {
        let idx = (tether_id as usize).wrapping_sub(1);
        let mut table = self.table.lock().unwrap();
        if table.get(idx).is_none() {
            return;
        }
        let new_reader = table.remove(idx);
        std::mem::drop(table);
        self.reader.write(new_reader);
    }

    /// Remove every entry. Used when the dock link goes down: each entry
    /// describes an inbound tether the node set up on that docking session,
    /// and a restarted node will bind its flows afresh (zipline#170).
    ///
    /// All removals are published in a single new RCU generation, so readers
    /// see either the old table or an empty one.
    pub fn clear(&self) {
        let mut table = self.table.lock().unwrap();
        // Collect the indices first: `mark_removed` needs `&mut table`.
        let indices: Vec<usize> = table.iter().map(|(idx, _)| idx).collect();
        for idx in indices {
            table.mark_removed(idx);
        }
        let new_reader = table.schedule_finalization();
        std::mem::drop(table);
        self.reader.write(new_reader);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mgmt::core::new_heap_packet;
    use crate::mgmt::txn_mgr::TxnMgr;
    use std::sync::Arc;

    /// A five-tuple distinguished by source port (everything else default).
    fn five_tuple(src_port: u16) -> FiveTuple {
        FiveTuple {
            src_port,
            ..FiveTuple::default()
        }
    }

    /// Insert an Active ELT entry for `five_tuple` bound to `tether_id`,
    /// going through the real Pending -> Active lifecycle.
    fn insert_active(
        elt: &EndpointLookupTable,
        txn_mgr: &Arc<TxnMgr>,
        five_tuple: FiveTuple,
        tether_id: StreamId,
    ) {
        let txn = txn_mgr.try_open().unwrap();
        elt.insert_pending(five_tuple, new_heap_packet(), &txn)
            .unwrap();
        elt.set_active(
            &five_tuple,
            EltPep::new(CompressionMode::default(), tether_id, None),
        )
        .unwrap();
    }

    /// Removing by tether id must remove exactly the Active entry bound to
    /// that tether, return its five-tuple, and leave other entries alone
    /// (zipline#21).
    #[test]
    fn test_remove_by_tether_id_removes_matching_active_entry() {
        let elt = EndpointLookupTable::new();
        let txn_mgr = Arc::new(TxnMgr::new());
        let ft_a = five_tuple(1000);
        let ft_b = five_tuple(2000);
        insert_active(&elt, &txn_mgr, ft_a, 10);
        insert_active(&elt, &txn_mgr, ft_b, 20);

        assert_eq!(elt.remove_by_tether_id(10), Some(ft_a));
        assert!(elt.get(&ft_a).is_none(), "matched entry must be removed");
        assert!(elt.get(&ft_b).is_some(), "other entries must survive");
    }

    /// An unknown tether id must remove nothing and return None.
    #[test]
    fn test_remove_by_tether_id_returns_none_on_miss() {
        let elt = EndpointLookupTable::new();
        let txn_mgr = Arc::new(TxnMgr::new());
        let ft = five_tuple(1000);
        insert_active(&elt, &txn_mgr, ft, 10);

        assert_eq!(elt.remove_by_tether_id(99), None);
        assert!(elt.get(&ft).is_some(), "non-matching entry must survive");
    }

    /// Pending entries have no tether id yet and must never match — even if
    /// a numeric value collides with an unrelated id.
    #[test]
    fn test_remove_by_tether_id_ignores_pending_entries() {
        let elt = EndpointLookupTable::new();
        let txn_mgr = Arc::new(TxnMgr::new());
        let ft = five_tuple(1000);
        let txn = txn_mgr.try_open().unwrap();
        elt.insert_pending(ft, new_heap_packet(), &txn).unwrap();

        assert_eq!(elt.remove_by_tether_id(10), None);
        assert!(elt.get(&ft).is_some(), "pending entry must survive");
    }

    /// `clear()` must remove Active and Pending entries alike, and forget
    /// the Pending entries' transactions, so a fresh bind of the same
    /// five-tuple starts cleanly (zipline#170).
    #[test]
    fn test_elt_clear_removes_active_and_pending_entries() {
        let elt = EndpointLookupTable::new();
        let txn_mgr = Arc::new(TxnMgr::new());
        let ft_active = five_tuple(1000);
        let ft_pending = five_tuple(2000);
        insert_active(&elt, &txn_mgr, ft_active, 10);
        let txn = txn_mgr.try_open().unwrap();
        elt.insert_pending(ft_pending, new_heap_packet(), &txn)
            .unwrap();

        elt.clear();

        assert!(
            elt.get(&ft_active).is_none(),
            "Active entry must be removed"
        );
        assert!(
            elt.get(&ft_pending).is_none(),
            "Pending entry must be removed"
        );
        assert!(
            elt.lookup_pending(&txn).is_err(),
            "pending transaction must be forgotten"
        );

        // The same five-tuple binds again from scratch.
        insert_active(&elt, &txn_mgr, ft_active, 11);
        assert!(
            elt.get(&ft_active).is_some(),
            "re-bind after clear must work"
        );
    }

    /// DLT `clear()` must remove every entry, and the table must keep
    /// accepting inserts afterwards (zipline#170).
    #[test]
    fn test_dlt_clear_removes_all_entries() {
        let dlt = DockLookupTable::new();
        let tc = || tc::Ip5TupleTc::new(five_tuple(1000));
        let id_a = dlt.insert(DltPep::new(tc(), None)).unwrap();
        let id_b = dlt.insert(DltPep::new(tc(), None)).unwrap();

        dlt.clear();

        assert!(dlt.get(id_a).is_none(), "first entry must be removed");
        assert!(dlt.get(id_b).is_none(), "second entry must be removed");
        let id_c = dlt.insert(DltPep::new(tc(), None)).unwrap();
        assert!(dlt.get(id_c).is_some(), "insert after clear must work");
    }

    /// A guard taken before `clear()` must stay valid after it: clearing
    /// publishes a fresh reader, and readers still holding the old one keep
    /// reading the entry until they drop it (RCU). From upstream #1410.
    #[test]
    fn test_dlt_clear_keeps_old_guards_valid() {
        let dlt = DockLookupTable::new();
        let id = dlt
            .insert(DltPep::new(tc::Ip5TupleTc::new(five_tuple(1000)), None))
            .unwrap();
        let old_guard = dlt.get(id).unwrap();

        dlt.clear();

        assert!(dlt.get(id).is_none(), "entry must be gone for new readers");
        assert_eq!(old_guard.tc.five_tuple(), &five_tuple(1000));
        drop(old_guard);
    }

    /// Removing a tether id that is not in the DLT must be a no-op, not a
    /// panic: the id comes from the node (`unbind_stream`), and after a dock
    /// link teardown flushed the table (zipline#170) a late or duplicate
    /// unbind must not take the adapter down.
    #[test]
    fn test_dlt_remove_absent_id_is_noop() {
        let dlt = DockLookupTable::new();
        let id = dlt
            .insert(DltPep::new(tc::Ip5TupleTc::new(five_tuple(1000)), None))
            .unwrap();
        dlt.clear();

        dlt.remove(id); // flushed
        dlt.remove(id + 100); // never allocated
        dlt.remove(0); // below the 1-based id range
    }
}
