//! Node/dock API.
//!
//! These functions operate the local node and dock state at a high level.
//!
//! They are meant to be invoked either from [super::handlers] by a node in
//! response to a message from an adapter, or directly by a node managing
//! its local adapter.

use super::requests;
use super::txn_mgr::{TxnHandle, TxnId};
use crate::classifier;
use crate::counters::ManagementCounterType;
use crate::defs::FiveTuple;
use crate::forwarding_tables;
use crate::peer_table::PeerType;
use crate::prelude::*;
use crate::visa_mgmt;
use crate::visa_table::VisaTableError;

use dashmap::DashMap;
use std::num::NonZero;
use zpr::vsapi_types::{CommFlag, PacketDesc, VisaRequest, VsapiFiveTuple, vsapi_ip_number};

/// State of an in-progress inbound bind or stream ID request.
enum BindRequestState {
    /// We have issued a visa request and are currently awaiting a response.
    /// The parameter is a join handle for the task which is performing the
    /// visa request.  Note that this join handle is mostly only useful for
    /// monitoring, since the subsequent state transitions are issued from
    /// within the task it references, so we can't usefully join it.
    AwaitingVisaResponse(#[allow(dead_code)] tokio::task::JoinHandle<()>),

    /// We have issued a visa ID request for the indicated visa and are
    /// currently awaiting a response or racing push.  The join handle is for
    /// the task which is issuing the request and awaiting the push.  Note
    /// that this join handle is mostly only useful for monitoring, since
    /// the subsequent state transitions are issued from within the task it
    /// references, so we can't usefully join it.
    AwaitingVisaPush {
        #[allow(dead_code)]
        visa_id: VisaId,
        #[allow(dead_code)]
        worker: tokio::task::JoinHandle<()>,
    },

    /// We have a visa with the indicated ID, and are now waiting
    /// on completion of the next-hop bind request issued on the indicated
    /// next-hop link and identified by the indicated transaction handle.
    AwaitingNextHopBind {
        visa_id: VisaId,
        egress_link_id: NonZero<LinkId>,
        egress_bind_txn: TxnHandle,
    },
}

/// Per-peer state related to the docking session or node peer link and
/// managed by the code in this module.
pub struct NodePeerState {
    /// In-progress inbound bind requests from this peer.  The key is the ID
    /// of a transaction opened by the peer; the value is the state of that
    /// bind request.
    bind_request_state: DashMap<TxnId, BindRequestState>,

    /// In-progress outbound bind requests to this peer.  The key is the handle
    /// of a transaction we opened; the value is a link ID × transaction ID
    /// pair identifying the in-progress inbound bind request this request
    /// was issued on behalf of.
    awaiting_next_hop_bind_table: DashMap<TxnHandle, (NonZero<LinkId>, TxnId)>,
}

impl NodePeerState {
    pub fn new() -> Self {
        Self {
            bind_request_state: DashMap::new(),
            awaiting_next_hop_bind_table: DashMap::new(),
        }
    }
}

/// Request to bind a stream which ingresses to this dock from an attached adapter.
///
/// `ingress_link_id` indicates the adapter which has made this request.
///
/// `txn_id` is used when issuing responses to the adapter to link them to this request.
///
/// `packet_body` is a prefix of the body of the packet which triggered this request which
/// will be presented to the Visa service to categorize and authorize this flow.
///
/// This launches a state machine associated with the indicated ingress link
/// and transaction which transitions through the following steps:
///
/// ```
///           ↓            [← bind_actor_address()]
///   AwaitingVisaResponse [→ issue visa request]
///           ↓            [← requested_visa_granted()]
///   AwaitingNextHopBind  [→ request next hop tether]
///           ↓            [← requested_tether_granted()]
///         Active         [create entry in visa table]
/// ```
///
/// `AwaitingVisaResponse` is skipped if a matching visa is already present.
///
/// `requested_visa_denied()` and `deny_tether()`, as well as various other errors,
/// result in the bind request being denied.
///
/// On completion of the state machine, a success response (containing the
/// tether ID and traffic classifier) or error response (in the event that
/// the bind request was denied) is then issued to the adapter, where these
/// responses are handled by [`adapter::install_tether()`] and [`adapter::deny_tether()`]
/// respectively.
pub fn bind_actor_address(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    _l3_type: L3Type,
    packet_body: &[u8],
) {
    debug!(
        target: FLOW_MGMT,
        "bind_actor_address(ingress_link_id={}, txn_id={txn_id})", asm.formatted_link_id(ingress_link_id.get()));

    // Determine five-tuple of the initial packet.

    let mut five_tuple = FiveTuple::default();

    let classifier_options =
        classifier::ClassifierOptions::default().ignore_truncated_packets(true);

    match classifier::classify_with_options(&mut five_tuple, packet_body, &classifier_options) {
        Ok(classifier::ClassifierResult::OK) => (),
        Ok(classifier::ClassifierResult::UnclassifiedL4) => {
            warn!(target: FLOW_MGMT, "{}: bind request: unsupported IP protocol {}", asm.formatted_link_id(ingress_link_id.get()), five_tuple.l4_protocol);
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
        _ => {
            warn!(target: FLOW_MGMT, "{}: bind request: invalid initial packet", asm.formatted_link_id(ingress_link_id.get()));
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
    }

    let Some(peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Ensure this adapter actually owns this source address.

    if !peer_state.actor_auth.owns_address(&five_tuple.src_address)
        && peer_state.link_state_machine.aaa_address() != Some(five_tuple.src_address)
    {
        warn!(target: FLOW_MGMT, "{}: bind request: source address {} does not match actor address", asm.formatted_link_id(ingress_link_id.get()), &five_tuple.src_address);
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    }

    // Check if we already have a visa which matches this traffic.

    let visa_table = asm.visa_table.read().unwrap();

    if let Some(matched) = visa_table.match_traffic(&five_tuple) {
        // We matched a visa we already have.

        let matched_visa_id = matched;
        drop(visa_table);

        let egress_link_id_query = visa_mgmt::get_egress_link_for_visa(asm, matched_visa_id);
        match egress_link_id_query {
            Ok(link_id) => {
                debug!(
                    target: FLOW_MGMT,
                    "matched existing visa {matched_visa_id} for {five_tuple}, egress_link_id = {}", asm.formatted_link_id(link_id.get())
                );
                // This visa is valid; treat as an immediate grant.
                return requested_visa_granted(asm, ingress_link_id, txn_id, matched_visa_id);
            }

            Err(VisaTableError::NotFound(_)) => {
                // The visa disappeared.
                // This could happen if visa is somehow removed before we get here. In this case we
                // can just proceed with a request.
                debug!(
                    target: FLOW_MGMT,
                    "visa request matching error: visa {matched_visa_id} for {five_tuple} racily deleted, proceeding with request"
                );
            }

            Err(VisaTableError::DestNotFound(addr)) => {
                // A visa exists, but we have no egress path for this destination address.
                // Treat as an immediate denial.
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
                error!(target: FLOW_MGMT, "visa request matching error: destination address {addr} not found so no egress link");
                return requested_visa_denied(asm, ingress_link_id, txn_id);
            }

            Err(e) => {
                panic!("Got unexpected error type {e}");
            }
        }
    }

    // We do not have an existing visa.  Request one.

    debug!(
        target: FLOW_MGMT,
        "issuing visa request for {five_tuple} from ingress_link_id {} packet_body.len() = {}",
        asm.formatted_link_id(ingress_link_id.get()),
        packet_body.len()
    );

    let comm_flags = match five_tuple.l4_protocol {
        p if p == vsapi_ip_number::ICMP || p == vsapi_ip_number::IPV6_ICMP => {
            CommFlag::UniDirectional
        }
        _ => CommFlag::BiDirectional,
    };
    let visa_req = VisaRequest {
        pdesc: PacketDesc {
            five_tuple: VsapiFiveTuple::new(
                five_tuple.l3_type,
                five_tuple.src_address.into(),
                five_tuple.dst_address.into(),
                five_tuple.l4_protocol,
                five_tuple.src_port,
                five_tuple.dst_port,
            ),
            comm_flags,
        },
        previous_id: None,
    };

    asm.counters.management[ManagementCounterType::VisaRequested].increment();

    // We need to ensure the visa-request task (spawned below) doesn't try
    // to access the docking session state before this entry is in place.
    // Since the task is spawned with `spawn_local()`, it will not start
    // until after we yield somehow, which we don't between now and when we
    // add this entry.  Nonetheless, to ensure this behavior isn't broken should
    // the task be changed to spawn with `spawn()`, we begin instantiating the
    // bind request state machine entry (i.e., take a lock on it) up here.
    let bind_st_entry = peer_state.node_state.bind_request_state.entry(txn_id);

    // Launch the visa-request task while holding a lock on its corresponding entry.
    let jh = tokio::task::spawn_local(visa_request_task(
        asm.clone(),
        ingress_link_id,
        txn_id,
        visa_req,
    ));

    // Finish instantiating the bind request state.
    bind_st_entry.insert(BindRequestState::AwaitingVisaResponse(jh));
}

/// Request a visa, on behalf of a bind request from the given link and transaction ID.
///
/// On completion, advances the bind-request state machine via
/// `requested_visa_granted()` or `requested_visa_denied()` as appropriate.
async fn visa_request_task(
    asm: Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    visa_req: VisaRequest,
) {
    match asm.vsconn.as_ref().unwrap().visa_request(visa_req).await {
        Ok(zpr::vsapi_types::VisaDecision::Allowed(visa)) => {
            let visa_id = match visa_mgmt::insert_visa(&asm, visa) {
                Ok(vid) => vid,

                // A malformed visa, or a forward-only visa while forwarding
                // is off: refuse the bind rather than panic.
                Err(e) => {
                    error!(target: FLOW_MGMT, "could not install visa: {e}");
                    return requested_visa_denied(&asm, ingress_link_id, txn_id);
                }
            };

            asm.counters.management[ManagementCounterType::VisaRequestSuccess].increment();
            debug!(target: FLOW_MGMT, "visa request succeeds, visa_id = {visa_id}");

            requested_visa_granted(&asm, ingress_link_id, txn_id, visa_id);
        }

        Ok(zpr::vsapi_types::VisaDecision::Denied(deny_code)) => {
            asm.counters.management[ManagementCounterType::VisaRequestDenied].increment();
            debug!(target: FLOW_MGMT, "visa request denied: {deny_code:?}");
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }

        Err(err) => {
            asm.counters.management[ManagementCounterType::VisaRequestError].increment();
            error!(target: FLOW_MGMT, "visa request error: {err}");
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }
    }
}

pub fn request_stream(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    visa_id: VisaId,
) {
    debug!(
        target: FLOW_MGMT,
        "request_stream(ingress_link_id={}, txn_id={txn_id}, visa_id={visa_id})",
        asm.formatted_link_id(ingress_link_id.get()));

    let Some(peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Check if we already have the indicated visa.
    let visa_table = asm.visa_table.read().unwrap();
    if visa_table.table.get(&visa_id).is_some() {
        // Visa found.
        return requested_visa_granted(asm, ingress_link_id, txn_id, visa_id);
    }

    // We do not have an existing visa.  Request one.

    debug!(
        target: FLOW_MGMT,
        "issuing visa request for {visa_id} from ingress_link_id {}",
        asm.formatted_link_id(ingress_link_id.get()),
    );

    asm.counters.management[ManagementCounterType::VisaByIdRequested].increment();

    // We need to ensure the visa-request task (spawned below) doesn't try
    // to access the docking session state before this entry is in place.
    // Since the task is spawned with `spawn_local()`, it will not start
    // until after we yield somehow, which we don't between now and when we
    // add this entry.  Nonetheless, to ensure this behavior isn't broken should
    // the task be changed to spawn with `spawn()`, we begin instantiating the
    // bind request state machine entry (i.e., take a lock on it) up here.
    let bind_st_entry = peer_state.node_state.bind_request_state.entry(txn_id);

    // Launch the visa-request task while holding a lock on its corresponding entry.
    let jh = tokio::task::spawn_local(visa_push_request_task(
        asm.clone(),
        ingress_link_id,
        txn_id,
        visa_id,
    ));

    // Finish instantiating the bind request state.
    bind_st_entry.insert(BindRequestState::AwaitingVisaPush {
        visa_id,
        worker: jh,
    });
}

/// State of an in-progress inbound bind (stream ID) request.
/// Request a visa by ID, on behalf of a stream ID request from the given link and transaction ID.
///
/// On completion, advances the bind-request state machine via
/// `requested_visa_granted()` or `requested_visa_denied()` as appropriate.
async fn visa_push_request_task(
    asm: Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    req_visa_id: VisaId,
) {
    // TODO: optimization: concurrently await any visas pushed by the VS
    match asm
        .vsconn
        .as_ref()
        .unwrap()
        .visa_by_id_request(vec![req_visa_id])
        .await
    {
        Ok(visas) => {
            // `visas` should only have the visa we requested, or none, but let's confirm that
            let Some(visa) = visas.into_iter().find(|visa| visa.issuer_id == req_visa_id) else {
                asm.counters.management[ManagementCounterType::VisaRequestDenied].increment();
                debug!(target: FLOW_MGMT, "visa {req_visa_id} not found");
                return requested_visa_denied(&asm, ingress_link_id, txn_id);
            };

            match visa_mgmt::insert_visa(&asm, visa) {
                Ok(_vid) => (),

                // A malformed visa, or a forward-only visa while forwarding
                // is off: refuse the bind rather than panic.
                Err(e) => {
                    error!(target: FLOW_MGMT, "could not install visa {req_visa_id}: {e}");
                    return requested_visa_denied(&asm, ingress_link_id, txn_id);
                }
            };

            asm.counters.management[ManagementCounterType::VisaRequestSuccess].increment();
            debug!(target: FLOW_MGMT, "visa request for {req_visa_id} succeeded");

            requested_visa_granted(&asm, ingress_link_id, txn_id, req_visa_id);
        }

        Err(err) => {
            asm.counters.management[ManagementCounterType::VisaRequestError].increment();
            error!(target: FLOW_MGMT, "visa request error: {err}");
            requested_visa_denied(&asm, ingress_link_id, txn_id)
        }
    }
}

/// Notify the bind-request state machine that the visa it requested
/// on behalf of transaction `txn_id` from adapter `ingress_link_id`
/// is now available with the specified visa ID.
///
/// Advances the bind-request state machine from AwaitingVisaResponse to
/// AwaitingNextHopBind by issuing a bind request to the next hop.
fn requested_visa_granted(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    visa_id: VisaId,
) {
    debug!(
        target: FLOW_MGMT,
        "requested_visa_granted(ingress_link_id={ingress_link_id}, txn_id={txn_id}, visa_id={visa_id})");

    // Look up the egress link for this visa.

    let Ok(egress_link_id) = visa_mgmt::get_egress_link_for_visa(asm, visa_id) else {
        // visa or egress link was deleted; consider visa denied
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };

    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        // egress link was racily deleted; consider visa denied
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };

    // adapter next-hops require the TC; node next-hops require the visa ID
    let tc;
    let peer_a2a_dh_pubkey;

    match egress_peer_state.peer_type() {
        PeerType::Node => {
            tc = None;
            peer_a2a_dh_pubkey = None;
        }

        PeerType::Adapter => {
            // Look up the traffic classifier for this visa.
            let visa_table = asm.visa_table.read().unwrap();
            let Some(visa) = visa_table.table.get(&visa_id) else {
                // Visa was either never granted or has already been removed
                // Route is no longer valid
                return requested_visa_denied(asm, ingress_link_id, txn_id);
            };
            // An adapter binds by traffic classifier, which a forward-only
            // visa does not have: it can only join two node links.
            let Some(visa_tc) = visa.get_tc() else {
                error!(target: FLOW_MGMT, "visa {visa_id} is forward-only but its next hop {} is an adapter",
                    asm.formatted_link_id(egress_link_id.get()));
                return requested_visa_denied(asm, ingress_link_id, txn_id);
            };
            tc = Some(visa_tc);
            peer_a2a_dh_pubkey = visa.get_ingress_a2a_dh_pubkey(); // Egress adapter needs ingress adapter's pubkey for DH
        }

        PeerType::Dock | PeerType::Unknown => {
            error!(target: FLOW_MGMT, "invalid egress link {}",
                asm.formatted_link_id(egress_link_id.get()));
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
    }

    // Open a transaction on the egress link and move into AwaitingNextHopBind state.

    let egress_bind_txn = egress_peer_state
        .txn_mgr
        .try_open()
        .expect("FIXME TODO: bind backpressure #1176");

    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        // requestor went away, bail!
        return;
    };
    ingress_peer_state.node_state.bind_request_state.insert(
        txn_id,
        BindRequestState::AwaitingNextHopBind {
            visa_id,
            egress_link_id,
            egress_bind_txn: egress_bind_txn.clone(),
        },
    );
    drop(ingress_peer_state);

    // Issue a bind request on the next-hop link (first
    // noting in the `awaiting_next_hop_bind_table` on the egress link
    // how to route the reply).

    let egress_bind_txn_id = egress_bind_txn.id();
    egress_peer_state
        .node_state
        .awaiting_next_hop_bind_table
        .insert(egress_bind_txn, (ingress_link_id, txn_id));

    match tc {
        None => {
            requests::send_stream_id_request(
                asm,
                egress_link_id.get(),
                egress_bind_txn_id,
                visa_id,
            )
            .enqueue();
        }

        Some(tc) => {
            requests::send_bind_egress_stream_request(
                asm,
                egress_link_id.get(),
                egress_bind_txn_id,
                tc,
                peer_a2a_dh_pubkey.as_ref(), // peer key passes through stream request
            )
            .enqueue();
        }
    }
}

/// Notify the bind-request state machine that the visa it requested
/// on behalf of transaction `txn_id` from adapter `ingress_link_id`
/// was denied.
///
/// Terminates the bind-request state machine by sending a policy error
/// back to the adapter which initiated the request.
fn requested_visa_denied(asm: &Arc<Assembly>, ingress_link_id: NonZero<LinkId>, txn_id: TxnId) {
    bind_reject(asm, ingress_link_id, txn_id, "policy error")
}

/// Install the given tether into the PFT.
///
/// Essentially this is the core implementation of `install_tether()`,
/// except (a) it's indexed by the link and transaction ID of the bind request
/// which owns the state machine, and (b) it assumes the reverse mapping
/// in the egress link has already been cleaned up.
fn requested_tether_granted(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    egress_tether_id: StreamId,
) {
    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Lookup (and hold locked) the bind-request state, to retrieve the
    // associated egress information.  (It's a little redundant that we
    // already have the egress information in our only caller
    // (`install_tether()`), but retrieving it again here lets us maintain a
    // clean API on this state machine.)

    let dashmap::mapref::entry::Entry::Occupied(bind_st) = ingress_peer_state
        .node_state
        .bind_request_state
        .entry(txn_id)
    else {
        error!(target: FLOW_MGMT, "requested_tether_granted() called when no request outstanding (txn_id={txn_id})");
        return;
    };

    let &BindRequestState::AwaitingNextHopBind {
        visa_id,
        egress_link_id,
        ref egress_bind_txn,
    } = bind_st.get()
    else {
        // should never happen; we check this in our only caller
        error!(target: FLOW_MGMT, "requested_tether_granted() called in wrong state (txn_id={txn_id})");
        return;
    };

    // Confirm that any associated next-hop-bind state no longer exists,
    // since we're about to make it invalid.

    if let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) {
        assert!(
            !egress_peer_state
                .node_state
                .awaiting_next_hop_bind_table
                .contains_key(&egress_bind_txn)
        );
    }

    // Remove the bind-request state -- the state machine is now complete.

    bind_st.remove();

    // Reserve & lock a slot for (but do not yet insert) the ingress link's PFT.
    // (This lets us query the tether ID which will be assigned before
    // committing to an insert.)

    let Ok(ingress_tether_entry) = ingress_peer_state.pft.vacant_entry() else {
        // PFT full; respond with error message
        // TODO: maybe tick a counter somewhere?
        bind_reject(asm, ingress_link_id, txn_id, "PFT full");
        return;
    };

    // Look up the visa (while holding the lock on the PFT entry).

    let mut visa_table = asm.visa_table.write().unwrap();

    let Some(visa) = visa_table.table.get_mut(&visa_id) else {
        // Visa was either never granted or has already been removed
        // Route is no longer valid
        requested_visa_denied(asm, ingress_link_id, txn_id);
        return;
    };

    // Retrieve the traffic classifier from the visa.

    // adapter requestors require the TC; node requestors do not
    let tc;
    let peer_a2a_dh_pubkey;

    match ingress_peer_state.peer_type() {
        PeerType::Node => {
            tc = None;
            peer_a2a_dh_pubkey = None;
        }

        PeerType::Adapter => {
            // An adapter binds by traffic classifier, which a forward-only
            // visa does not have: it can only join two node links.
            let Some(visa_tc) = visa.get_tc() else {
                error!(target: FLOW_MGMT, "visa {visa_id} is forward-only but its requestor {} is an adapter",
                    asm.formatted_link_id(ingress_link_id.get()));
                return requested_visa_denied(asm, ingress_link_id, txn_id);
            };
            tc = Some(visa_tc);
            peer_a2a_dh_pubkey = visa.get_egress_a2a_dh_pubkey(); // Ingress adapter needs egress adapter's pubkey for DH
        }

        PeerType::Dock | PeerType::Unknown => {
            error!(target: FLOW_MGMT, "invalid ingress link {}",
                asm.formatted_link_id(ingress_link_id.get()));
            return requested_visa_denied(asm, ingress_link_id, txn_id);
        }
    }

    // Only now that the bind will go ahead, link the PFT entry into the
    // visa, so a refused bind leaves no stale forwarding entry behind.
    visa.link_forwarding_entry(ForwardingEntry(
        ingress_link_id.get(),
        ingress_tether_entry.key(),
    ));

    drop(visa_table);

    // Form the PEP and insert into the PFT slot we reserved (producing a tether ID).

    let pep = forwarding_tables::PftPep {
        next_hop: ForwardingEntry(egress_link_id.get(), egress_tether_id),
        visa_id,
    };

    let ingress_tether_id = ingress_tether_entry.insert(pep);

    // Send a success response to the requestor with the tether ID.
    match tc {
        None => requests::send_stream_id_success_response(
            asm,
            ingress_link_id.get(),
            txn_id,
            ingress_tether_id,
        )
        .enqueue(),

        Some(tc) => requests::send_bind_actor_address_success_response(
            asm,
            ingress_link_id.get(),
            txn_id,
            ingress_tether_id,
            tc,
            peer_a2a_dh_pubkey.as_ref(), // peer key passes through success response
        )
        .enqueue(),
    }
}

/// Common functionality for exiting the bind request state machine with an error.
///
/// Removes this bind request from the `bind_request_state` table, and
/// sends an error reply back to the requestor.
///
/// It is invalid and racy to call this while a next-hop-bind request is outstanding,
/// as there is neither mechanism to discard replies to such a request, or to
/// synchronize replies with termination of this state machine.
fn bind_reject(asm: &Arc<Assembly>, ingress_link_id: NonZero<LinkId>, txn_id: TxnId, reason: &str) {
    debug!(
        target: FLOW_MGMT,
        "bind_reject(ingress_link_id={}, txn_id={txn_id})", asm.formatted_link_id(ingress_link_id.get()));

    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Remove state from the bind-request state table.

    if let Some((_, bind_st)) = ingress_peer_state
        .node_state
        .bind_request_state
        .remove(&txn_id)
    {
        // If we were awaiting the next-hop-bind...
        if let BindRequestState::AwaitingNextHopBind {
            egress_link_id,
            egress_bind_txn,
            ..
        } = bind_st
        {
            // ...ensure we haven't left a lingering next-hop-bind entry.
            // If we did, then we'd leave it referencing a no-longer-valid
            // transaction.  This should never happen, and we can only check
            // this racily since there's no synchronization between these
            // flows, but check nonetheless.
            if let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) {
                assert!(
                    !egress_peer_state
                        .node_state
                        .awaiting_next_hop_bind_table
                        .contains_key(&egress_bind_txn)
                );
            }
        };
    }

    // Send an error response to the requestor.
    match ingress_peer_state.peer_type() {
        PeerType::Adapter => requests::send_bind_actor_address_error_response(
            asm,
            ingress_link_id.get(),
            txn_id,
            reason,
        )
        .enqueue(),

        PeerType::Node => {
            requests::send_stream_id_error_response(asm, ingress_link_id.get(), txn_id, reason)
                .enqueue()
        }

        PeerType::Dock | PeerType::Unknown => error!(target: FLOW_MGMT, "invalid ingress link {}",
                asm.formatted_link_id(ingress_link_id.get())),
    }
}

#[derive(Debug)]
pub enum InstallTetherError {
    /// The indicated egress transaction does not exist.
    NoSuchTransaction,
    /// The indicated egress link does not exist.
    LinkClosed,
}

/// Install the given tether into the PFT.
///
/// `egress_link_id` indicates the adapter to which this tether is made.
///
/// `egress_txn` must refer to an active transaction on the adapter link which had
/// previously requested a tether to the indicated adapter (e.g. via
/// BindEgressStream).
///
/// `egress_tether_id` is the ID to be used to refer to this tether.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn install_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    egress_tether_id: StreamId,
) -> Result<(), InstallTetherError> {
    let (ingress_link_id, ingress_txn_id) =
        resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)?;
    Ok(requested_tether_granted(
        asm,
        ingress_link_id,
        ingress_txn_id,
        egress_tether_id,
    ))
}

/// Deny the given tether request, removing it from the ALT.
///
/// `egress_link_id` indicates the adapter to which this tether is made.
///
/// `egress_txn` must refer to an active transaction on the adapter link
/// which had previously requested a tether.
///
/// `reason` is a human-readable reason why the tether was denied.
///
/// Completes the indicated transaction.
///
/// Returns an error only if the transaction is invalid.
pub fn deny_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    reason: &str,
) -> Result<(), InstallTetherError> {
    let (ingress_link_id, ingress_txn_id) =
        resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)?;
    Ok(bind_reject(asm, ingress_link_id, ingress_txn_id, reason))
}

/// Resolve the originating bind-request state machine
/// for the given next-hop-bind transaction.
///
/// Removes next-hop-bind state from the docking session state,
/// and completes the indicated transaction.
fn resolve_next_hop_bind_originator(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
) -> Result<(NonZero<LinkId>, TxnId), InstallTetherError> {
    // Find & remove the backlink to the inbound bind-request which
    // initiated this next-hop-bind.

    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        return Err(InstallTetherError::LinkClosed);
    };
    let Some((_, (ingress_link_id, ingress_txn_id))) = egress_peer_state
        .node_state
        .awaiting_next_hop_bind_table
        .remove(egress_txn)
    else {
        return Err(InstallTetherError::NoSuchTransaction);
    };

    if let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) {
        // If originator still exists, check consistency
        // (don't bother if originator no longer exists).

        let Some(bind_st) = ingress_peer_state
            .node_state
            .bind_request_state
            .get(&ingress_txn_id)
        else {
            // should never happen
            panic!(
                "dock state consistency error; {ingress_txn_id} referenced by awaiting_next_hop_bind_table but is not an active bind request"
            );
        };

        let &BindRequestState::AwaitingNextHopBind {
            egress_link_id: expected_egress_link_id,
            egress_bind_txn: ref expected_egress_txn,
            ..
        } = &*bind_st
        else {
            // should never happen
            panic!(
                "dock state consistency error; {ingress_txn_id} referenced by awaiting_next_hop_bind_table but not in AwaitingNextHopBind state"
            );
        };

        assert_eq!(
            expected_egress_link_id, egress_link_id,
            "dock state consistency error"
        );
        assert_eq!(
            expected_egress_txn, egress_txn,
            "dock state consistency error"
        );
    }

    Ok((ingress_link_id, ingress_txn_id))
}

pub fn unbind_stream(asm: &Arc<Assembly>, ingress_link_id: NonZero<LinkId>, stream_id: StreamId) {
    let Some(peer_table) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Get visa id of next hop
    let Some(pft_pep) = peer_table.pft.get(stream_id) else {
        warn!(target: FLOW_MGMT, "{}: unbind request: no pft pep for stream {stream_id}", asm.formatted_link_id(ingress_link_id.get()));
        return;
    };

    // Remove entry from peer forwarding table
    peer_table.pft.remove(stream_id);

    // Remove stream id from visa
    match asm
        .visa_table
        .write()
        .unwrap()
        .unlink_forwarding_entry(pft_pep.visa_id, &pft_pep.next_hop)
    {
        Ok(b) => {
            if !b {
                warn!(target: FLOW_MGMT, "{}: stream {} not found in visa {}", asm.formatted_link_id(ingress_link_id.get()), pft_pep.next_hop.1, pft_pep.visa_id)
            }
        }
        Err(e) => {
            warn!(target: FLOW_MGMT, "{}: error removing stream from visa: {}", asm.formatted_link_id(ingress_link_id.get()), e)
        }
    }

    // Issue unbind request to next hop
    requests::send_unbind_egress_stream_request(asm, pft_pep.next_hop.0, stream_id).enqueue();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::PhMode;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::link_state::LinkType;
    use crate::packet::Packet;
    use crate::packet_queue;
    use crate::peer_table::test::create_dummy_peer_state;
    use crate::queues::MgmtSubstrateEgress;
    use crate::visa_table::VisaTable;
    use crate::visa_table::tests::{never_expires, new_vsapi_visa_forward_only};
    use crate::zdp;
    use std::net::{IpAddr, Ipv4Addr};
    use zerocopy::FromBytes;
    use zpr::packet_info::SubstrateAddr;
    use zpr_utils::net_defs::{self, IpAddress};

    /// The forward-only visa every test in this module binds.
    const VISA_ID: VisaId = 9000;

    /// The ZPR address the forward-only visa names as its next hop.
    const NEXT_HOP: &str = "fd5a:5052:8::99";

    type EgressRx = packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>;

    /// Build a middle node: a Node-mode assembly whose management egress we
    /// can read back, an upstream node peer on link A, and a downstream peer
    /// of type `downstream` on link B that owns [NEXT_HOP] (so
    /// `find_egress_link` resolves the visa's next hop to link B). The
    /// forward-only visa [VISA_ID] is already in the visa table.
    ///
    /// Returns (asm, egress queue receiver, link A, link B).
    fn middle_node(downstream: LinkType) -> (Arc<Assembly>, EgressRx, LinkId, LinkId) {
        let (egress_tx, egress_rx) = packet_queue::packet_queue(8);
        let mut builder = TestAssemblyBuilder::new();
        builder.ph_mode = Some(PhMode::Node);
        builder.visa_table = Some(VisaTable::new());
        builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
        let asm = Arc::new(create_assembly(builder));

        let link_a = add_peer(&asm, LinkType::NodeToNode, 1);
        let link_b = add_peer(&asm, downstream, 2);
        let next_hop: IpAddr = NEXT_HOP.parse().unwrap();
        asm.peer_table
            .get(link_b)
            .unwrap()
            .actor_auth
            .test_set_addresses(vec![IpAddress::new_from_std(&next_hop)]);

        asm.visa_table
            .write()
            .unwrap()
            .insert_visa(new_vsapi_visa_forward_only(
                VISA_ID,
                never_expires(),
                next_hop,
            ))
            .unwrap();
        (asm, egress_rx, link_a, link_b)
    }

    /// Add a dummy peer of the given link type and return its link ID.
    fn add_peer(asm: &Assembly, link_type: LinkType, last_octet: u8) -> LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let key = entry.key();
        entry
            .insert(create_dummy_peer_state(
                key,
                link_type,
                SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), 5000),
                net_defs::ScopedIpAddr::V4(Ipv4Addr::new(10, 0, 1, last_octet)),
            ))
            .get()
    }

    /// Take the next management packet off the egress queue, if any.
    fn try_recv_packet(rx: &mut EgressRx) -> Option<Packet> {
        let buf = vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice();
        match rx.try_recv(buf) {
            Ok(pkt) => Some(pkt),
            Err(packet_queue::TryRecvError::Empty(_)) => None,
            Err(err) => panic!("unexpected queue error: {err:?}"),
        }
    }

    /// A per-flow transaction management packet, decoded: its type, its
    /// per-flow stream ID and its payload.
    struct MgmtPacket {
        packet_type: zdp::ZdpPacketType,
        stream_id: StreamId,
        payload: Vec<u8>,
    }

    /// Decode the headers `core::send_per_flow_txn_mgmt` writes: base,
    /// management, per-flow, transaction, then the payload.
    fn decode_per_flow_txn(pkt: &Packet) -> MgmtPacket {
        let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
        let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
        let (per_flow_hdr, rest) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
        let (_txn_hdr, rest) = zdp::ZdpTransactionHeader::ref_from_prefix(rest).unwrap();
        MgmtPacket {
            packet_type: base_hdr.packet_type,
            stream_id: per_flow_hdr.stream_id.into(),
            payload: rest.to_vec(),
        }
    }

    /// The middle node of a path binds a forward-only visa from one node link
    /// to the next (zl-zipline#219): a StreamIdRequest from the upstream node
    /// produces a StreamIdRequest for the same visa to the next hop; the next
    /// hop's grant installs a PFT entry on the upstream link pointing at the
    /// next hop's stream, and the upstream node gets its stream ID back.
    /// Revoking the visa then removes that entry.
    #[tokio::test]
    async fn test_middle_node_binds_forward_only_visa_between_node_links() {
        let (asm, mut egress_rx, link_a, link_b) = middle_node(LinkType::NodeToNode);
        let upstream_txn: TxnId = 7;

        request_stream(&asm, NonZero::new(link_a).unwrap(), upstream_txn, VISA_ID);

        // The next hop is asked for a stream for the same visa.
        let pkt = try_recv_packet(&mut egress_rx).expect("a StreamIdRequest to the next hop");
        assert_eq!(pkt.metadata().egress_link_id, link_b);
        let req = decode_per_flow_txn(&pkt);
        assert_eq!(req.packet_type, zdp::ZdpPacketType::StreamIdRequest);
        let (body, _) = zdp::ZdpStreamIdRequest::ref_from_prefix(&req.payload).unwrap();
        let requested_visa: VisaId = body.visa_id.into();
        assert_eq!(requested_visa, VISA_ID);

        // The next hop grants stream 42.
        let egress_txn = asm
            .peer_table
            .get(link_b)
            .unwrap()
            .node_state
            .awaiting_next_hop_bind_table
            .iter()
            .next()
            .expect("the next-hop bind is outstanding")
            .key()
            .clone();
        let next_hop_stream: StreamId = 42;
        install_tether(
            &asm,
            NonZero::new(link_b).unwrap(),
            &egress_txn,
            next_hop_stream,
        )
        .unwrap();

        // The upstream node gets a success response naming its stream...
        let pkt = try_recv_packet(&mut egress_rx).expect("a StreamIdResponse upstream");
        assert_eq!(pkt.metadata().egress_link_id, link_a);
        let rsp = decode_per_flow_txn(&pkt);
        assert_eq!(rsp.packet_type, zdp::ZdpPacketType::StreamIdResponse);
        let (rsp_hdr, _) = zdp::ZdpStreamIdResponseHeader::ref_from_prefix(&rsp.payload).unwrap();
        assert_eq!(rsp_hdr.status_code, zdp::ResponseCode::Success);
        let upstream_stream = rsp.stream_id;

        // ...and its stream forwards to the next hop's stream on link B.
        let pep = asm
            .peer_table
            .get(link_a)
            .unwrap()
            .pft
            .inspect(upstream_stream, |pep| (pep.next_hop.clone(), pep.visa_id))
            .expect("a PFT entry for the upstream stream");
        assert!(pep == (ForwardingEntry(link_b, next_hop_stream), VISA_ID));

        // Revoking the visa removes the upstream stream's PFT entry, which
        // shows the entry was linked into the visa. (Sending the withdrawal
        // itself is covered by the assembly tests.)
        visa_mgmt::handle_revocation(&asm, VISA_ID).unwrap();
        assert_eq!(asm.peer_table.get(link_a).unwrap().pft.len(), 0);
        assert!(!asm.visa_table.read().unwrap().table.contains_key(&VISA_ID));
    }

    /// A forward-only visa has no traffic classifier, so it cannot bind to an
    /// adapter. The bind is refused with an error response upstream instead
    /// of a panic, and nothing is sent to the adapter.
    #[tokio::test]
    async fn test_forward_only_visa_toward_adapter_is_refused() {
        let (asm, mut egress_rx, link_a, _link_b) = middle_node(LinkType::NodeToAdapter);

        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);

        let pkt = try_recv_packet(&mut egress_rx).expect("an error response upstream");
        assert_eq!(pkt.metadata().egress_link_id, link_a);
        let rsp = decode_per_flow_txn(&pkt);
        assert_eq!(rsp.packet_type, zdp::ZdpPacketType::StreamIdResponse);
        let (rsp_hdr, _) = zdp::ZdpStreamIdResponseHeader::ref_from_prefix(&rsp.payload).unwrap();
        assert_ne!(rsp_hdr.status_code, zdp::ResponseCode::Success);
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "nothing goes to the adapter"
        );
    }
}
