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
use crate::visa_table::{StreamBinding, VisaTable, VisaTableError};

use dashmap::DashMap;
use std::num::NonZero;
use zpr::vsapi_types::{CommFlag, PacketDesc, VisaRequest, VsapiFiveTuple, vsapi_ip_number};

/// State of an in-progress inbound bind or stream ID request.
enum BindRequestState {
    /// We have issued a visa request and are currently awaiting a response.
    /// The parameter is a join handle for the task which is performing the
    /// visa request.  The subsequent state transitions are issued from within
    /// that task, so it is never joined; its task ID tells the task whether
    /// this request is still the one it serves (`bind_awaits_visa`).
    AwaitingVisaResponse(tokio::task::JoinHandle<()>),

    /// We have issued a visa ID request for the indicated visa and are
    /// currently awaiting a response or racing push.  The join handle is for
    /// the task which is issuing the request and awaiting the push.  It is
    /// never joined; its task ID tells the task whether this request is
    /// still the one it serves (`bind_awaits_visa`).
    AwaitingVisaPush {
        #[allow(dead_code)]
        visa_id: VisaId,
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
    /// of a transaction we opened; the value names the in-progress inbound
    /// bind request this request was issued on behalf of, if it is still
    /// there.
    awaiting_next_hop_bind_table: DashMap<TxnHandle, NextHopBindOriginator>,
}

/// The inbound bind request a next-hop bind was issued on behalf of, or
/// the J11 rebind it serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NextHopBindOriginator {
    /// The inbound bind request on this link with this transaction ID.
    Bind(NonZero<LinkId>, TxnId),

    /// J11 (zl-zipline#252): the rebind of stream `ingress_stream_id` on
    /// `ingress_link_id` from visa `old` onto its successor `new`.
    Rebind {
        old: VisaId,
        new: VisaId,
        ingress_link_id: NonZero<LinkId>,
        ingress_stream_id: StreamId,
    },

    /// The inbound bind request is gone: refused, replaced, or its link was
    /// lost (rule 9). The transaction stays open so the next hop's answer,
    /// when it comes, is recognized and ignored. Refusing it as an unknown
    /// transaction would close the next hop's link, which did nothing wrong.
    Abandoned,
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

            // Any other error (a visa without a next hop, which
            // `Visa::new` already refuses): refuse the bind, never panic on
            // a peer's request.
            Err(e) => {
                asm.counters.management[ManagementCounterType::VisaRequestError].increment();
                error!(target: FLOW_MGMT, "visa request matching error for visa {matched_visa_id}: {e}");
                return requested_visa_denied(asm, ingress_link_id, txn_id);
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
    wait_for_loss_reports(&asm).await;
    let result = asm.vsconn.as_ref().unwrap().visa_request(visa_req).await;
    if !bind_awaits_visa(&asm, ingress_link_id, txn_id) {
        return;
    }
    match result {
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

/// F6 (zl-zipline#251): wait until every Zode link loss registered so far
/// has been reported to the visa service. A visa request made after a loss
/// must not overtake that loss's `down` report on the shared VS-API
/// session, or the visa service could plan the new route over the dead
/// link. Returns at once when no loss is pending.
async fn wait_for_loss_reports(asm: &Assembly) {
    asm.zode_links.wait_for_loss_reports().await;
}

/// Whether the inbound bind request `txn_id` on `link_id` is still waiting
/// for the visa that THIS visa-request task (the caller) is fetching: the
/// bind state must name the calling task as its worker. It does not if the
/// link was lost meanwhile (rule 9), even if a new peer has since taken the
/// link ID and reused the transaction ID, nor if the requestor reused the
/// transaction ID for a newer request (core#110 review). The task then drops
/// its result, so it never advances or answers a request it did not serve.
fn bind_awaits_visa(asm: &Assembly, link_id: NonZero<LinkId>, txn_id: TxnId) -> bool {
    let this_task = tokio::task::id();
    let awaits = asm.peer_table.get(link_id.get()).is_some_and(|peer| {
        peer.node_state
            .bind_request_state
            .get(&txn_id)
            .is_some_and(|st| match &*st {
                BindRequestState::AwaitingVisaResponse(worker)
                | BindRequestState::AwaitingVisaPush { worker, .. } => worker.id() == this_task,
                BindRequestState::AwaitingNextHopBind { .. } => false,
            })
    });
    if !awaits {
        debug!(target: FLOW_MGMT, "bind request {txn_id} on {} is gone; dropping its visa result",
            asm.formatted_link_id(link_id.get()));
    }
    awaits
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

    // Check if we already have the indicated visa. The visa-table lock is
    // released before the bind goes on: `requested_visa_granted` looks up
    // the egress link and sends, neither of which may run under it.
    let have_visa = asm.visa_table.read().unwrap().contains(visa_id);
    if have_visa {
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
    wait_for_loss_reports(&asm).await;
    let result = asm
        .vsconn
        .as_ref()
        .unwrap()
        .visa_by_id_request(vec![req_visa_id])
        .await;
    if !bind_awaits_visa(&asm, ingress_link_id, txn_id) {
        return;
    }
    match result {
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

    let Ok(next_hop_bind) = prepare_next_hop_bind(asm, ingress_link_id, visa_id) else {
        return requested_visa_denied(asm, ingress_link_id, txn_id);
    };

    // Move into AwaitingNextHopBind state.
    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        // requestor went away, bail!
        return;
    };
    ingress_peer_state.node_state.bind_request_state.insert(
        txn_id,
        BindRequestState::AwaitingNextHopBind {
            visa_id,
            egress_link_id: next_hop_bind.egress_link_id,
            egress_bind_txn: next_hop_bind.txn.clone(),
        },
    );
    drop(ingress_peer_state);

    send_next_hop_bind(
        asm,
        visa_id,
        next_hop_bind,
        NextHopBindOriginator::Bind(ingress_link_id, txn_id),
    );
}

/// A bind request for a visa, ready to go to the next hop: the egress link,
/// the transaction opened on it, and, for an adapter next hop, the traffic
/// classifier and the A2A public key the request carries.
struct NextHopBind<'a> {
    egress_link_id: NonZero<LinkId>,
    egress_peer_state: crate::peer_table::PeerTableEntryGuard<'a>,
    txn: TxnHandle,
    adapter_request: Option<(crate::tc::Ip5TupleTc, Option<x25519_dalek::PublicKey>)>,
}

/// Prepare the next-hop bind of the visa `visa_id` for a stream that
/// arrives on `ingress_link_id`: find the egress link, apply the F2 guards,
/// work out what the request carries, and open a transaction on the egress
/// link. Shared by a bind (F2) and a J11 rebind.
///
/// Refused, and logged, if the visa or its egress link is gone, the bind
/// would loop back out the ingress link, the visa does not fit the
/// requestor or the next hop, or the egress link has no free transaction
/// ID.
fn prepare_next_hop_bind(
    asm: &Assembly,
    ingress_link_id: NonZero<LinkId>,
    visa_id: VisaId,
) -> Result<NextHopBind<'_>, ()> {
    // Look up the egress link for this visa.

    let Ok(egress_link_id) = visa_mgmt::get_egress_link_for_visa(asm, visa_id) else {
        // visa or egress link was deleted; consider visa denied
        debug!(target: FLOW_MGMT, "visa {visa_id}: no visa or no egress link; refusing the bind");
        return Err(());
    };

    // F2 loop guard (zl-zipline#251): a bind that would go back out the
    // link it came in on is a loop. Asking the requestor for a stream for
    // its own request would burn transaction IDs on both Zodes, request
    // after request, and it means the visa or the route is bad. Refuse it.
    if egress_link_id == ingress_link_id {
        error!(target: FLOW_MGMT, "visa {visa_id}: next hop is the requestor {} itself; refusing the bind",
            asm.formatted_link_id(ingress_link_id.get()));
        return Err(());
    }

    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        // egress link was racily deleted; consider visa denied
        return Err(());
    };

    // An adapter binds by traffic classifier, which a forward-only visa does
    // not have: such a visa can only join two node links. Refuse an adapter
    // requestor here, before a stream is requested from the next hop --
    // refusing later would leave the stream the next hop grants allocated.
    // (A next-hop adapter is refused below.)
    let ingress_is_adapter = asm
        .peer_table
        .get(ingress_link_id.get())
        .is_some_and(|peer| matches!(peer.peer_type(), PeerType::Adapter));
    let forward_only = asm
        .visa_table
        .read()
        .unwrap()
        .get(visa_id)
        .is_some_and(|visa| visa.get_tc().is_none());
    if ingress_is_adapter && forward_only {
        error!(target: FLOW_MGMT, "visa {visa_id} is forward-only but its requestor {} is an adapter",
            asm.formatted_link_id(ingress_link_id.get()));
        return Err(());
    }

    // adapter next-hops require the TC; node next-hops require the visa ID
    let adapter_request = match egress_peer_state.peer_type() {
        PeerType::Node => None,

        PeerType::Adapter => {
            // Look up the traffic classifier for this visa.
            let visa_table = asm.visa_table.read().unwrap();
            let Some(visa) = visa_table.get(visa_id) else {
                // Visa was either never granted or has already been removed
                // Route is no longer valid
                return Err(());
            };
            // An adapter binds by traffic classifier, which a forward-only
            // visa does not have: it can only join two node links.
            let Some(visa_tc) = visa.get_tc() else {
                error!(target: FLOW_MGMT, "visa {visa_id} is forward-only but its next hop {} is an adapter",
                    asm.formatted_link_id(egress_link_id.get()));
                return Err(());
            };
            // Egress adapter needs ingress adapter's pubkey for DH
            Some((visa_tc, visa.get_ingress_a2a_dh_pubkey()))
        }

        PeerType::Dock | PeerType::Unknown => {
            error!(target: FLOW_MGMT, "invalid egress link {}",
                asm.formatted_link_id(egress_link_id.get()));
            return Err(());
        }
    };

    // Open a transaction on the egress link.

    // F2 (zl-zipline#251): with every transaction ID on the egress link in
    // use, refuse the bind. Never panic or block: the request comes from a
    // peer, and a refused flow is simply requested again by its next
    // packet, so real backpressure is not needed.
    let Some(txn) = egress_peer_state.txn_mgr.try_open() else {
        error!(target: FLOW_MGMT, "visa {visa_id}: no free transaction ID on {}; refusing the bind",
            asm.formatted_link_id(egress_link_id.get()));
        return Err(());
    };

    Ok(NextHopBind {
        egress_link_id,
        egress_peer_state,
        txn,
        adapter_request,
    })
}

/// Send the prepared next-hop bind of the visa `visa_id`, first noting in
/// the egress link's `awaiting_next_hop_bind_table` who the answer is for.
fn send_next_hop_bind(
    asm: &Assembly,
    visa_id: VisaId,
    next_hop_bind: NextHopBind<'_>,
    originator: NextHopBindOriginator,
) {
    let NextHopBind {
        egress_link_id,
        egress_peer_state,
        txn,
        adapter_request,
    } = next_hop_bind;
    let txn_id = txn.id();
    egress_peer_state
        .node_state
        .awaiting_next_hop_bind_table
        .insert(txn, originator);

    match adapter_request {
        None => {
            requests::send_stream_id_request(asm, egress_link_id.get(), txn_id, visa_id).enqueue();
        }

        Some((tc, peer_a2a_dh_pubkey)) => {
            requests::send_bind_egress_stream_request(
                asm,
                egress_link_id.get(),
                txn_id,
                tc,
                peer_a2a_dh_pubkey.as_ref(), // peer key passes through stream request
            )
            .enqueue();
        }
    }
}

/// J11 (zl-zipline#252): the visa `new` supersedes the visa `old`, which
/// still has live streams here. Rebind each stream this Zode is the
/// ingress of, that is each one that arrives from an adapter (the local
/// actor included), onto `new`.
///
/// Each rebind asks the next hop for a stream for `new`, exactly as a bind
/// does (F2, guards included); every hop down the path binds `new` the same
/// way. The stream keeps its old binding until the answer comes back, and
/// [rebind_granted] then moves it in one step. A stream that arrives from
/// another Zode is not rebound here: its own ingress rebinds it, and this
/// Zode binds `new` when asked (gate question 10).
///
/// A stream bound under `old` after this call (its bind was on its way)
/// is rebound when its binding is recorded: [VisaTable::bind] names the
/// successor.
///
/// Sends, so never call it under the visa-table lock (zipline#9).
pub fn rebind_ingress_streams(asm: &Assembly, old: VisaId, new: VisaId) {
    let ingresses: Vec<ForwardingEntry> = asm
        .visa_table
        .read()
        .unwrap()
        .bindings(old)
        .iter()
        .map(|binding| binding.ingress.clone())
        .collect();
    for ingress in ingresses {
        rebind_stream(asm, old, new, ingress);
    }
}

/// J11: rebind the stream `ingress` from visa `old` onto visa `new`, if
/// this Zode is its ingress (the stream arrives from an adapter or the
/// local actor). Otherwise do nothing: the stream's own ingress rebinds it.
/// A successor with other A2A session keys is refused: the requestor would
/// not know them.
///
/// Sends, so never call it under the visa-table lock (zipline#9).
fn rebind_stream(asm: &Assembly, old: VisaId, new: VisaId, ingress: ForwardingEntry) {
    let Some(ingress_link_id) = NonZero::new(ingress.0) else {
        return;
    };
    let from_adapter = asm
        .peer_table
        .get(ingress.0)
        .is_some_and(|peer| matches!(peer.peer_type(), PeerType::Adapter));
    if !from_adapter {
        return;
    }
    // The requestor keeps the A2A keys it got from the old visa, and the
    // far adapter gets the new visa's: a rebind is silent only if they are
    // the same.
    let same_keys = {
        let visa_table = asm.visa_table.read().unwrap();
        match (visa_table.get(old), visa_table.get(new)) {
            (Some(old_visa), Some(new_visa)) => old_visa.has_same_session_keys(new_visa),
            _ => false,
        }
    };
    if !same_keys {
        return rebind_failed(
            asm,
            old,
            new,
            &ingress,
            "the visas' session keys differ, or one is gone",
        );
    }
    info!(target: FLOW_MGMT, "rebinding stream {} on {} from visa {old} onto visa {new}",
        ingress.1, asm.formatted_link_id(ingress.0));
    match prepare_next_hop_bind(asm, ingress_link_id, new) {
        Ok(next_hop_bind) => send_next_hop_bind(
            asm,
            new,
            next_hop_bind,
            NextHopBindOriginator::Rebind {
                old,
                new,
                ingress_link_id,
                ingress_stream_id: ingress.1,
            },
        ),
        Err(()) => rebind_failed(asm, old, new, &ingress, "no next-hop bind"),
    }
}

/// J11: the next hop granted `new_egress` for the rebind of the stream
/// `ingress` from visa `old` onto visa `new`. Commit it: from the next
/// packet the stream forwards to `new_egress` under `new`
/// ([VisaTable::commit_supersede]).
///
/// If the commit is refused (the old binding or the successor is gone
/// meanwhile), the stream stays as it is, and the stream the next hop just
/// granted goes unused until `new` expires or is revoked there.
fn rebind_granted(
    asm: &Assembly,
    old: VisaId,
    new: VisaId,
    ingress: ForwardingEntry,
    new_egress: ForwardingEntry,
) {
    let committed = asm.visa_table.write().unwrap().commit_supersede(
        &asm.peer_table,
        old,
        new,
        ingress.clone(),
        new_egress,
    );
    if let Err(e) = committed {
        rebind_failed(asm, old, new, &ingress, &e.to_string());
    }
}

/// J11: the rebind of the stream `ingress` from visa `old` onto visa `new`
/// failed (a denial, no egress, a refused commit). The stream keeps its old
/// binding until the old visa expires; there is no retry. If losing it
/// then breaks the VS-API session, J10's rejoin recovers.
fn rebind_failed(
    asm: &Assembly,
    old: VisaId,
    new: VisaId,
    ingress: &ForwardingEntry,
    reason: &str,
) {
    asm.counters.management[ManagementCounterType::RebindFailed].increment();
    warn!(target: FLOW_MGMT, "stream {} on {} stays on visa {old}: its rebind onto visa {new} failed: {reason}",
        ingress.1, asm.formatted_link_id(ingress.0));
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
/// in the egress link has already been cleaned up (which
/// `resolve_next_hop_bind_originator` did, after checking that this bind
/// request is the one the next-hop bind served).
fn requested_tether_granted(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<LinkId>,
    txn_id: TxnId,
    egress_tether_id: StreamId,
) {
    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Take the bind-request state out, to retrieve the associated egress
    // information. The state machine is now complete.
    let Some((_, bind_st)) = ingress_peer_state
        .node_state
        .bind_request_state
        .remove(&txn_id)
    else {
        error!(target: FLOW_MGMT, "requested_tether_granted() called when no request outstanding (txn_id={txn_id})");
        return;
    };
    let BindRequestState::AwaitingNextHopBind {
        visa_id,
        egress_link_id,
        ..
    } = bind_st
    else {
        // should never happen; resolve_next_hop_bind_originator checks this
        error!(target: FLOW_MGMT, "requested_tether_granted() called in wrong state (txn_id={txn_id})");
        return;
    };

    // Reserve & lock a slot for (but do not yet insert) the ingress link's PFT.
    // (This lets us query the tether ID which will be assigned before
    // committing to an insert.)

    let Ok(ingress_tether_entry) = ingress_peer_state.pft.vacant_entry() else {
        // PFT full; respond with error message
        // TODO: maybe tick a counter somewhere?
        bind_reject(asm, ingress_link_id, txn_id, "PFT full");
        return;
    };

    // Under the visa-table write lock: read what the response needs from
    // the visa, then record the binding (F3) and fill the PFT slot, so no
    // revocation can fall between the two. Nothing is sent under the lock
    // (zipline#9): a refusal is sent once it is released.
    let granted: Result<_, &str> = {
        let mut visa_table = asm.visa_table.write().unwrap();
        match response_classifier(
            asm,
            &visa_table,
            visa_id,
            ingress_link_id,
            &ingress_peer_state,
        ) {
            Err(reason) => Err(reason),
            Ok((tc, peer_a2a_dh_pubkey)) => {
                // Only now that the bind will go ahead is it recorded, so a
                // refused bind leaves no binding and no PFT entry behind.
                let binding = StreamBinding {
                    ingress: ForwardingEntry(ingress_link_id.get(), ingress_tether_entry.key()),
                    egress: ForwardingEntry(egress_link_id.get(), egress_tether_id),
                };
                match visa_table.bind(visa_id, binding.clone()) {
                    Err(_) => Err("policy error"),
                    Ok(successor) => {
                        let ingress_tether_id = ingress_tether_entry
                            .insert(forwarding_tables::PftPep::new(binding.egress, visa_id));
                        Ok((ingress_tether_id, tc, peer_a2a_dh_pubkey, successor))
                    }
                }
            }
        }
    };

    let (ingress_tether_id, tc, peer_a2a_dh_pubkey, successor) = match granted {
        Ok(granted) => granted,
        Err(reason) => return bind_reject(asm, ingress_link_id, txn_id, reason),
    };

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

    // J11: the visa was superseded while this bind was on its way, so the
    // new stream moves onto the successor like every other live stream.
    if let Some(new) = successor {
        rebind_stream(
            asm,
            visa_id,
            new,
            ForwardingEntry(ingress_link_id.get(), ingress_tether_id),
        );
    }
}

/// What the success response to the requestor on `ingress_link_id` carries
/// for the visa `visa_id`: an adapter (or the local actor) requestor needs
/// the traffic classifier and the egress adapter's A2A public key; a node
/// requestor needs neither. Returns the reason to refuse the bind instead,
/// if the visa is gone or does not fit the requestor.
#[allow(clippy::type_complexity)]
fn response_classifier(
    asm: &Assembly,
    visa_table: &VisaTable,
    visa_id: VisaId,
    ingress_link_id: NonZero<LinkId>,
    ingress_peer_state: &crate::peer_table::PeerState,
) -> Result<
    (
        Option<crate::tc::Ip5TupleTc>,
        Option<x25519_dalek::PublicKey>,
    ),
    &'static str,
> {
    let Some(visa) = visa_table.get(visa_id) else {
        // Visa was either never granted or has already been removed
        // Route is no longer valid
        return Err("policy error");
    };
    match ingress_peer_state.peer_type() {
        PeerType::Node => Ok((None, None)),

        PeerType::Adapter => {
            // A forward-only visa has no traffic classifier. An adapter
            // requestor is refused in requested_visa_granted before the
            // next-hop bind; this guard only keeps that invariant panic-free.
            let Some(visa_tc) = visa.get_tc() else {
                error!(target: FLOW_MGMT, "visa {visa_id} is forward-only but its requestor {} is an adapter",
                    asm.formatted_link_id(ingress_link_id.get()));
                return Err("policy error");
            };
            // Ingress adapter needs egress adapter's pubkey for DH
            Ok((Some(visa_tc), visa.get_egress_a2a_dh_pubkey()))
        }

        PeerType::Dock | PeerType::Unknown => {
            error!(target: FLOW_MGMT, "invalid ingress link {}",
                asm.formatted_link_id(ingress_link_id.get()));
            Err("policy error")
        }
    }
}

/// Common functionality for exiting the bind request state machine with an error.
///
/// Removes this bind request from the `bind_request_state` table, and
/// sends an error reply back to the requestor.
///
/// If the request was still waiting on its next hop, that next-hop bind is
/// marked abandoned, so the next hop's answer is ignored when it comes
/// (see [NextHopBindOriginator::Abandoned]). A peer can get here with a
/// next-hop bind outstanding, for example by reusing the transaction ID of
/// a bind that is still pending.
fn bind_reject(asm: &Arc<Assembly>, ingress_link_id: NonZero<LinkId>, txn_id: TxnId, reason: &str) {
    debug!(
        target: FLOW_MGMT,
        "bind_reject(ingress_link_id={}, txn_id={txn_id})", asm.formatted_link_id(ingress_link_id.get()));

    let Some(ingress_peer_state) = asm.peer_table.get(ingress_link_id.get()) else {
        return;
    };

    // Remove state from the bind-request state table.

    if let Some((
        _,
        BindRequestState::AwaitingNextHopBind {
            egress_link_id,
            egress_bind_txn,
            ..
        },
    )) = ingress_peer_state
        .node_state
        .bind_request_state
        .remove(&txn_id)
    {
        abandon_next_hop_bind(asm, egress_link_id, &egress_bind_txn);
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

/// Mark the next-hop bind `egress_bind_txn` on `egress_link_id` abandoned,
/// if it is still outstanding: the inbound bind it served is gone.
fn abandon_next_hop_bind(
    asm: &Assembly,
    egress_link_id: NonZero<LinkId>,
    egress_bind_txn: &TxnHandle,
) {
    if let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get())
        && let Some(mut originator) = egress_peer_state
            .node_state
            .awaiting_next_hop_bind_table
            .get_mut(egress_bind_txn)
    {
        debug!(target: FLOW_MGMT, "abandoning next-hop bind {} on {}",
            egress_bind_txn.id(), asm.formatted_link_id(egress_link_id.get()));
        *originator = NextHopBindOriginator::Abandoned;
    }
}

/// Rule 9 for pending binds (F3, zl-zipline#251): link `lost` is going
/// away, so clear every pending bind on other links that involves it, in
/// both directions. Called by `Assembly::drop_peer` while `lost` is still
/// in the peer table. `lost`'s own bind tables go with its peer entry.
///
/// - A bind on another link waiting on `lost` as its next hop is refused:
///   its requestor gets an error at once, instead of never hearing back.
///   Its visa is revoked locally as well (F3: losing either side revokes),
///   exactly as a finished binding over `lost` is by `revoke_for_link`.
///   The visa has no binding yet, so `revoke_for_link` did not see it; left
///   cached, it would match the requestor's next bind, which would then be
///   refused for want of an egress link instead of asking for a new visa
///   (F6). The visa itself is never edited, only removed.
/// - A J11 rebind waiting on `lost` as its next hop revokes its new visa,
///   for the same reason.
/// - A next-hop bind on another link issued for a bind from `lost`, or
///   for a J11 rebind of a stream from `lost`, is marked abandoned, so its
///   answer cannot reach whatever peer takes the link ID next.
///
/// Sends, so never call it under the visa-table lock (zipline#9).
pub fn clear_pending_binds_for_lost_link(asm: &Arc<Assembly>, lost: LinkId) {
    let mut refuse = Vec::new();
    let mut revoke = Vec::new();
    asm.peer_table.for_each(|(link_id, peer)| {
        if link_id.get() == lost {
            // A J11 rebind waiting on `lost` as its next hop has the same
            // fate as a pending bind: its new visa is revoked. The old
            // visa had a binding over `lost`, so `revoke_for_link` already
            // revoked it, and with it the stream. Nothing to refuse: the
            // stream's requestor never asked for the rebind.
            for originator in peer.node_state.awaiting_next_hop_bind_table.iter() {
                if let NextHopBindOriginator::Rebind { new, .. } = *originator {
                    revoke.push(new);
                }
            }
            return;
        }
        for st in peer.node_state.bind_request_state.iter() {
            if let BindRequestState::AwaitingNextHopBind {
                visa_id,
                egress_link_id,
                ..
            } = st.value()
                && egress_link_id.get() == lost
            {
                refuse.push((link_id, *st.key()));
                revoke.push(*visa_id);
            }
        }
        for mut originator in peer.node_state.awaiting_next_hop_bind_table.iter_mut() {
            let from_lost = match *originator {
                NextHopBindOriginator::Bind(from, _) => from.get() == lost,
                NextHopBindOriginator::Rebind {
                    ingress_link_id, ..
                } => ingress_link_id.get() == lost,
                NextHopBindOriginator::Abandoned => false,
            };
            if from_lost {
                *originator = NextHopBindOriginator::Abandoned;
            }
        }
    });
    // Revoke before refusing, so a requestor that retries at once already
    // misses. This node's own visas (below MIN_VISA_ID) are spared, as in
    // `revoke_for_link`. Revoke under the visa-table write lock, but
    // withdraw only after it is released: the send path takes the peer's
    // `zdpr_send` mutex, which must never nest under it (zipline#9). A
    // pending bind has no binding of its own, so anything withdrawn here
    // belongs to another binding of the same visa.
    revoke.retain(|visa_id| *visa_id >= config::MIN_VISA_ID);
    if !revoke.is_empty() {
        let mut withdrawn = Vec::new();
        {
            let mut visa_table = asm.visa_table.write().unwrap();
            for visa_id in revoke {
                info!(target: FLOW_MGMT, "revoking visa {visa_id}: its pending bind lost next hop {}",
                    asm.formatted_link_id(lost));
                // `revoke` treats a visa that is already gone as revoked.
                if let Ok(entries) = visa_table.revoke(&asm.peer_table, visa_id) {
                    withdrawn.extend(entries);
                }
            }
        }
        asm.withdraw_streams(withdrawn, Some(lost));
    }
    // Refuse outside the peer-table walk: bind_reject looks peers up and
    // sends.
    for (link_id, txn_id) in refuse {
        bind_reject(asm, link_id, txn_id, "next hop link lost");
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
/// Completes the indicated transaction. A grant for a next-hop bind whose
/// inbound bind is gone is ignored. A grant for a J11 rebind commits it.
///
/// Returns an error only if the transaction is invalid.
pub fn install_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    egress_tether_id: StreamId,
) -> Result<(), InstallTetherError> {
    match resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)? {
        NextHopBindOriginator::Bind(ingress_link_id, ingress_txn_id) => {
            requested_tether_granted(asm, ingress_link_id, ingress_txn_id, egress_tether_id)
        }
        NextHopBindOriginator::Rebind {
            old,
            new,
            ingress_link_id,
            ingress_stream_id,
        } => rebind_granted(
            asm,
            old,
            new,
            ForwardingEntry(ingress_link_id.get(), ingress_stream_id),
            ForwardingEntry(egress_link_id.get(), egress_tether_id),
        ),
        NextHopBindOriginator::Abandoned => {}
    }
    Ok(())
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
/// Completes the indicated transaction. A denial for a next-hop bind whose
/// inbound bind is gone is ignored. A denied J11 rebind leaves the stream
/// on its old visa.
///
/// Returns an error only if the transaction is invalid.
pub fn deny_tether(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
    reason: &str,
) -> Result<(), InstallTetherError> {
    match resolve_next_hop_bind_originator(asm, egress_link_id, egress_txn)? {
        NextHopBindOriginator::Bind(ingress_link_id, ingress_txn_id) => {
            bind_reject(asm, ingress_link_id, ingress_txn_id, reason)
        }
        NextHopBindOriginator::Rebind {
            old,
            new,
            ingress_link_id,
            ingress_stream_id,
        } => rebind_failed(
            asm,
            old,
            new,
            &ForwardingEntry(ingress_link_id.get(), ingress_stream_id),
            reason,
        ),
        NextHopBindOriginator::Abandoned => {}
    }
    Ok(())
}

/// Resolve the originating bind-request state machine
/// for the given next-hop-bind transaction.
///
/// Removes next-hop-bind state from the docking session state,
/// and completes the indicated transaction.
///
/// Returns [NextHopBindOriginator::Abandoned] when there is no inbound bind
/// left to answer: the next-hop bind was abandoned, or the inbound bind
/// request it names is no longer waiting on it (the requestor reused its
/// transaction ID). Both are logged and the answer is ignored. The next hop
/// sent it in good faith, so neither is an error that would close its
/// link. A J11 rebind is returned as it is: its commit checks the visa
/// table itself.
fn resolve_next_hop_bind_originator(
    asm: &Arc<Assembly>,
    egress_link_id: NonZero<LinkId>,
    egress_txn: &TxnHandle,
) -> Result<NextHopBindOriginator, InstallTetherError> {
    // Find & remove the backlink to the inbound bind-request which
    // initiated this next-hop-bind.

    let Some(egress_peer_state) = asm.peer_table.get(egress_link_id.get()) else {
        return Err(InstallTetherError::LinkClosed);
    };
    let Some((_, originator)) = egress_peer_state
        .node_state
        .awaiting_next_hop_bind_table
        .remove(egress_txn)
    else {
        return Err(InstallTetherError::NoSuchTransaction);
    };

    let (ingress_link_id, ingress_txn_id) = match originator {
        NextHopBindOriginator::Bind(ingress_link_id, ingress_txn_id) => {
            (ingress_link_id, ingress_txn_id)
        }
        NextHopBindOriginator::Rebind { .. } => return Ok(originator),
        NextHopBindOriginator::Abandoned => {
            debug!(target: FLOW_MGMT, "{}: answer to abandoned next-hop bind {} ignored",
                asm.formatted_link_id(egress_link_id.get()), egress_txn.id());
            return Ok(originator);
        }
    };

    // The inbound bind must still be waiting on exactly this next-hop bind.
    let waiting = asm
        .peer_table
        .get(ingress_link_id.get())
        .is_some_and(|ingress_peer_state| {
            ingress_peer_state
                .node_state
                .bind_request_state
                .get(&ingress_txn_id)
                .is_some_and(|bind_st| {
                    matches!(
                        &*bind_st,
                        BindRequestState::AwaitingNextHopBind {
                            egress_link_id: expected_link,
                            egress_bind_txn: expected_txn,
                            ..
                        } if *expected_link == egress_link_id && expected_txn == egress_txn
                    )
                })
        });
    if !waiting {
        warn!(target: FLOW_MGMT, "{}: answer to next-hop bind {} ignored: bind request {ingress_txn_id} on {} no longer waits on it",
            asm.formatted_link_id(egress_link_id.get()), egress_txn.id(),
            asm.formatted_link_id(ingress_link_id.get()));
        return Ok(NextHopBindOriginator::Abandoned);
    }

    Ok(originator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::PhMode;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::link_state::LinkType;
    use crate::packet::Packet;
    use crate::packet_queue;
    use crate::peer_table::test::{create_dummy_peer_state, insert_up_zode_link};
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

    /// A Node-mode assembly whose management egress we can read back, with
    /// the forward-only visa [VISA_ID] (next hop [NEXT_HOP]) in its visa
    /// table and no links yet.
    fn node_with_visa() -> (Arc<Assembly>, EgressRx) {
        let (asm, egress_rx, _hairpin_rx) = node_with_visa_and_hairpin();
        (asm, egress_rx)
    }

    /// [node_with_visa], plus the receiving end of the management hairpin,
    /// where packets sent on an internal link (such as the local actor
    /// link) arrive.
    fn node_with_visa_and_hairpin() -> (Arc<Assembly>, EgressRx, tokio::sync::mpsc::Receiver<Packet>)
    {
        node_assembly(None)
    }

    /// [node_with_visa], with a VS-API handle whose session is gone: every
    /// visa request fails at once with `ConnClosed`, so a bind that needs
    /// one is refused upstream, which shows when the request was made.
    fn node_with_visa_and_no_vs_session() -> (Arc<Assembly>, EgressRx) {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let vsconn = libnode::vsconn::VSConn::new(
            4,
            "127.0.0.1:1".parse().unwrap(),
            "test-node".to_string(),
            key,
            "127.0.0.1:5000".parse().unwrap(),
        );
        let (asm, egress_rx, _hairpin_rx) = node_assembly(Some(vsconn.handle()));
        (asm, egress_rx)
    }

    /// The assembly behind [node_with_visa_and_hairpin], with VS-API handle
    /// `vsconn`.
    fn node_assembly(
        vsconn: Option<libnode::vsconn::VSConnHandle>,
    ) -> (Arc<Assembly>, EgressRx, tokio::sync::mpsc::Receiver<Packet>) {
        let (egress_tx, egress_rx) = packet_queue::packet_queue(8);
        let (hairpin_tx, hairpin_rx) = tokio::sync::mpsc::channel(8);
        let mut builder = TestAssemblyBuilder::new();
        builder.ph_mode = Some(PhMode::Node);
        builder.visa_table = Some(VisaTable::new());
        builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
        builder.mgmt_hairpin_dispatch = Some(crate::queues::MgmtHairpinDispatch::new(hairpin_tx));
        builder.vsconn = Some(vsconn);
        let asm = Arc::new(create_assembly(builder));
        asm.visa_table
            .write()
            .unwrap()
            .insert_visa(new_vsapi_visa_forward_only(
                VISA_ID,
                never_expires(),
                next_hop(),
            ))
            .unwrap();
        (asm, egress_rx, hairpin_rx)
    }

    /// [NEXT_HOP] as an address.
    fn next_hop() -> IpAddr {
        NEXT_HOP.parse().unwrap()
    }

    /// Build a middle node ([node_with_visa]) with an upstream peer of type
    /// `upstream` on link A and a downstream peer of type `downstream` on
    /// link B that `find_egress_link` resolves [NEXT_HOP] to. A downstream
    /// Zode is reached the way F1 says (zl-zipline#251): an up Zode link
    /// whose CN has [NEXT_HOP] in the topology. A downstream adapter owns
    /// [NEXT_HOP] as an actor address.
    ///
    /// Returns (asm, egress queue receiver, link A, link B).
    fn middle_node(
        upstream: LinkType,
        downstream: LinkType,
    ) -> (Arc<Assembly>, EgressRx, LinkId, LinkId) {
        let (asm, egress_rx) = node_with_visa();
        let link_a = add_peer(&asm, upstream, 1);
        let link_b = if downstream == LinkType::NodeToNode {
            insert_up_zode_link(&asm, "next-hop.zpr", next_hop())
        } else {
            let link_b = add_peer(&asm, downstream, 2);
            asm.peer_table
                .get(link_b)
                .unwrap()
                .actor_auth
                .test_set_addresses(vec![IpAddress::new_from_std(&next_hop())]);
            link_b
        };
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
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
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
            .inspect(upstream_stream, |pep| (pep.next_hop(), pep.visa_id()))
            .expect("a PFT entry for the upstream stream");
        assert!(pep == (ForwardingEntry(link_b, next_hop_stream), VISA_ID));

        // Revoking the visa removes the upstream stream's PFT entry, which
        // shows the entry was linked into the visa. (Sending the withdrawal
        // itself is covered by the assembly tests.)
        visa_mgmt::handle_revocation(&asm, VISA_ID).unwrap();
        assert_eq!(asm.peer_table.get(link_a).unwrap().pft.len(), 0);
        assert!(!asm.visa_table.read().unwrap().contains(VISA_ID));
    }

    /// A forward-only visa has no traffic classifier, so it cannot bind to an
    /// adapter. The bind is refused with an error response upstream instead
    /// of a panic, and nothing is sent to the adapter.
    #[tokio::test]
    async fn test_forward_only_visa_toward_adapter_is_refused() {
        let (asm, mut egress_rx, link_a, _link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToAdapter);

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

    /// An adapter cannot bind a forward-only visa either: it binds by traffic
    /// classifier. The bind must be refused BEFORE a stream is requested from
    /// the next hop, or the stream the next hop grants is never released
    /// (Codex review on zl-zpr-core#100).
    #[tokio::test]
    async fn test_forward_only_visa_from_adapter_is_refused_before_next_hop_bind() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToAdapter, LinkType::NodeToNode);

        requested_visa_granted(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);

        let pkt = try_recv_packet(&mut egress_rx).expect("an error response to the adapter");
        assert_eq!(pkt.metadata().egress_link_id, link_a);
        let (base_hdr, _) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
        assert_eq!(
            base_hdr.packet_type,
            zdp::ZdpPacketType::BindActorAddressResponse
        );
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "no stream may be requested from the next hop"
        );
        assert!(
            asm.peer_table
                .get(link_b)
                .unwrap()
                .node_state
                .awaiting_next_hop_bind_table
                .is_empty()
        );
    }

    /// The error response a bind on link `link` got: the next packet on the
    /// egress queue must be a failed StreamIdResponse on `link`, and nothing
    /// may follow it.
    fn assert_only_stream_id_error_response(rx: &mut EgressRx, link: LinkId) {
        let pkt = try_recv_packet(rx).expect("an error response to the requestor");
        assert_eq!(pkt.metadata().egress_link_id, link);
        let rsp = decode_per_flow_txn(&pkt);
        assert_eq!(rsp.packet_type, zdp::ZdpPacketType::StreamIdResponse);
        let (rsp_hdr, _) = zdp::ZdpStreamIdResponseHeader::ref_from_prefix(&rsp.payload).unwrap();
        assert_ne!(rsp_hdr.status_code, zdp::ResponseCode::Success);
        assert!(try_recv_packet(rx).is_none(), "nothing else is sent");
    }

    /// Whether link `link` holds no bind state: no inbound bind request and
    /// no outstanding next-hop bind.
    fn no_bind_state(asm: &Assembly, link: LinkId) -> bool {
        let peer = asm.peer_table.get(link).unwrap();
        peer.node_state.bind_request_state.is_empty()
            && peer.node_state.awaiting_next_hop_bind_table.is_empty()
    }

    /// F2 loop guard (zl-zipline#251): a StreamIdRequest on Zode link A for
    /// a visa whose next hop resolves (F1) back to A is refused with an
    /// error response. No StreamIdRequest goes back out on A, and no bind
    /// state is left.
    #[tokio::test]
    async fn test_bind_back_out_the_ingress_link_is_refused() {
        let (asm, mut egress_rx) = node_with_visa();
        let link_a = insert_up_zode_link(&asm, "a.zpr", next_hop());

        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);

        assert_only_stream_id_error_response(&mut egress_rx, link_a);
        assert!(no_bind_state(&asm, link_a));
    }

    /// F2 (zl-zipline#251): when every transaction ID on the egress link is
    /// open, the bind is refused with an error response instead of a panic,
    /// nothing is sent on the egress link, and the ingress bind state is
    /// gone.
    #[tokio::test]
    async fn test_bind_is_refused_when_egress_transaction_ids_run_out() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        let txn_mgr = asm.peer_table.get(link_b).unwrap().txn_mgr.clone();
        let open: Vec<_> = std::iter::from_fn(|| txn_mgr.try_open()).collect();
        assert_eq!(open.len(), usize::from(TxnId::MAX) + 1);

        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);

        assert_only_stream_id_error_response(&mut egress_rx, link_a);
        assert!(no_bind_state(&asm, link_a));
        assert!(no_bind_state(&asm, link_b));
    }

    /// F8 (zl-zipline#251): a Zode's own traffic, bound by its local actor
    /// link, leaves through a Zode link under F1. The visa's next hop is the
    /// topology address of an up Zode link: the StreamIdRequest goes out on
    /// that link, and its grant points the local actor link's PFT entry at
    /// the link's stream.
    #[tokio::test(flavor = "local")]
    async fn test_own_traffic_binds_out_a_zode_link() {
        use crate::visa_table::tests::new_vsapi_visa_tcp_default;
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;

        let (asm, mut egress_rx, mut hairpin_rx) = node_with_visa_and_hairpin();
        let (local_actor, _dock) = asm
            .peer_table
            .insert_internal_peer_pair(|_, _| std::future::pending::<()>());
        assert_eq!(local_actor.get(), LOCAL_ACTOR_LINK_ID);
        let zode_link = insert_up_zode_link(&asm, "b.zpr", next_hop());

        // A full visa (it has a traffic classifier, as the local actor
        // binds by one) whose forwarding PEP names the Zode as next hop.
        let own_visa: VisaId = VISA_ID + 1;
        let mut visa = new_vsapi_visa_tcp_default(own_visa, never_expires());
        visa.fwd_pep = Some(zpr::vsapi_types::FwdPep {
            next_hop: next_hop(),
            style: zpr::vsapi_types::FwdPepStyle::OneWay,
        });
        asm.visa_table.write().unwrap().insert_visa(visa).unwrap();

        requested_visa_granted(&asm, local_actor, 7, own_visa);

        let pkt = try_recv_packet(&mut egress_rx).expect("a StreamIdRequest to the Zode");
        assert_eq!(pkt.metadata().egress_link_id, zode_link);
        let req = decode_per_flow_txn(&pkt);
        assert_eq!(req.packet_type, zdp::ZdpPacketType::StreamIdRequest);
        let (body, _) = zdp::ZdpStreamIdRequest::ref_from_prefix(&req.payload).unwrap();
        assert_eq!(VisaId::from(body.visa_id), own_visa);

        let egress_txn = asm
            .peer_table
            .get(zode_link)
            .unwrap()
            .node_state
            .awaiting_next_hop_bind_table
            .iter()
            .next()
            .expect("the next-hop bind is outstanding")
            .key()
            .clone();
        // The stream the grant installs on the local actor link is the
        // next free PFT slot there.
        let local_stream = asm
            .peer_table
            .get(LOCAL_ACTOR_LINK_ID)
            .unwrap()
            .pft
            .vacant_entry()
            .unwrap()
            .key();
        install_tether(&asm, NonZero::new(zode_link).unwrap(), &egress_txn, 42).unwrap();

        // The local actor is told its bind succeeded, with that stream.
        let rsp = hairpin_rx
            .try_recv()
            .expect("a bind response to the local actor");
        let (base_hdr, _) = zdp::ZdpBaseHeader::ref_from_prefix(rsp.body()).unwrap();
        assert_eq!(
            base_hdr.packet_type,
            zdp::ZdpPacketType::BindActorAddressResponse
        );
        assert_eq!(decode_per_flow_txn(&rsp).stream_id, local_stream);

        let local_peer = asm.peer_table.get(LOCAL_ACTOR_LINK_ID).unwrap();
        assert_eq!(local_peer.pft.len(), 1);
        let pep = local_peer
            .pft
            .inspect(local_stream, |pep| (pep.next_hop(), pep.visa_id()))
            .expect("a PFT entry on the local actor link");
        assert!(pep == (ForwardingEntry(zode_link, 42), own_visa));
    }

    // ---- F3 and R9: link loss (zl-zipline#251) ----

    /// The transaction this node opened on `link` for its one outstanding
    /// next-hop bind there.
    fn outstanding_next_hop_txn(asm: &Assembly, link: LinkId) -> TxnHandle {
        asm.peer_table
            .get(link)
            .unwrap()
            .node_state
            .awaiting_next_hop_bind_table
            .iter()
            .next()
            .expect("the next-hop bind is outstanding")
            .key()
            .clone()
    }

    /// Bind [VISA_ID] from link A to link B on a [middle_node]: A asks for a
    /// stream, B grants stream 42. Drains the StreamIdRequest to B and the
    /// response to A from the egress queue, and returns A's stream.
    fn bind_a_to_b(
        asm: &Arc<Assembly>,
        rx: &mut EgressRx,
        link_a: LinkId,
        link_b: LinkId,
    ) -> StreamId {
        request_stream(asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);
        assert!(try_recv_packet(rx).is_some(), "a StreamIdRequest to B");
        let egress_txn = outstanding_next_hop_txn(asm, link_b);
        install_tether(asm, NonZero::new(link_b).unwrap(), &egress_txn, 42).unwrap();
        let rsp = try_recv_packet(rx).expect("a StreamIdResponse to A");
        decode_per_flow_txn(&rsp).stream_id
    }

    /// Whether any PFT entry on any link forwards to `link`.
    fn any_pft_entry_points_at(asm: &Assembly, link: LinkId) -> bool {
        let mut found = false;
        asm.peer_table.for_each(|(_, peer)| {
            for stream in 0..=u16::MAX as StreamId {
                if peer
                    .pft
                    .inspect(stream, |pep| pep.next_hop().0 == link)
                    .unwrap_or(false)
                {
                    found = true;
                }
            }
        });
        found
    }

    /// F3, egress side (zl-zipline#251): on the middle Zode of A -> B, losing
    /// B revokes the visa locally and removes A's PFT entry, which pointed
    /// at B. Nothing is sent on A: it is a Zode link (F5).
    #[tokio::test]
    async fn test_losing_the_egress_link_revokes_the_visa() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        bind_a_to_b(&asm, &mut egress_rx, link_a, link_b);

        asm.drop_peer(link_b);

        assert!(!asm.visa_table.read().unwrap().contains(VISA_ID));
        assert_eq!(asm.peer_table.get(link_a).unwrap().pft.len(), 0);
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "nothing is sent on A"
        );
    }

    /// F3, ingress side (zl-zipline#251): losing A revokes the visa and
    /// sends nothing on B.
    #[tokio::test]
    async fn test_losing_the_ingress_link_revokes_the_visa() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        bind_a_to_b(&asm, &mut egress_rx, link_a, link_b);

        asm.drop_peer(link_a);

        assert!(!asm.visa_table.read().unwrap().contains(VISA_ID));
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "nothing is sent on B"
        );
    }

    /// F3 and rule 9 (zl-zipline#251): once B is lost, no PFT entry and no
    /// binding refers to B's link ID, so nothing can send traffic to the
    /// peer that takes that ID next. (The RCU slab defers reclaiming a slot,
    /// so a unit test cannot make a real reuse happen; the state is checked
    /// directly instead.)
    #[tokio::test]
    async fn test_no_forwarding_entry_or_binding_refers_to_a_lost_link() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        bind_a_to_b(&asm, &mut egress_rx, link_a, link_b);

        asm.drop_peer(link_b);

        assert!(!any_pft_entry_points_at(&asm, link_b));
        assert!(
            asm.visa_table
                .read()
                .unwrap()
                .visas_bound_over(link_b)
                .is_empty()
        );
    }

    /// F3 at the flow's first Zode (zl-zipline#251): an adapter's flow bound
    /// out a Zode link. Losing the Zode link revokes the visa, so the
    /// adapter's next packet matches no visa and asks for one (F6), and the
    /// adapter gets exactly one withdrawal for its stream.
    #[tokio::test]
    async fn test_losing_the_zode_link_at_the_first_zode_withdraws_from_the_adapter() {
        use crate::visa_table::tests::new_vsapi_visa_tcp_default;

        let (asm, mut egress_rx, adapter, zode_link) =
            middle_node(LinkType::NodeToAdapter, LinkType::NodeToNode);
        let own_visa: VisaId = VISA_ID + 1;
        let mut visa = new_vsapi_visa_tcp_default(own_visa, never_expires());
        visa.fwd_pep = Some(zpr::vsapi_types::FwdPep {
            next_hop: next_hop(),
            style: zpr::vsapi_types::FwdPepStyle::OneWay,
        });
        // The adapter's stream bound out the Zode link, as a completed bind
        // leaves it (the bind itself is covered above). Set up directly: a
        // bind response would sit unacknowledged in the adapter's reliable
        // send window and hold the withdrawal back.
        let mut visa_table = asm.visa_table.write().unwrap();
        visa_table.insert_visa(visa).unwrap();
        let adapter_stream = asm
            .peer_table
            .get(adapter)
            .unwrap()
            .pft
            .insert(forwarding_tables::PftPep::new(
                ForwardingEntry(zode_link, 42),
                own_visa,
            ))
            .unwrap();
        visa_table
            .bind(
                own_visa,
                StreamBinding {
                    ingress: ForwardingEntry(adapter, adapter_stream),
                    egress: ForwardingEntry(zode_link, 42),
                },
            )
            .unwrap();
        drop(visa_table);

        asm.drop_peer(zode_link);

        assert!(!asm.visa_table.read().unwrap().contains(own_visa));
        let pkt = try_recv_packet(&mut egress_rx).expect("a withdrawal to the adapter");
        assert_eq!(pkt.metadata().egress_link_id, adapter);
        let msg = decode_per_flow(&pkt);
        assert_eq!(msg.0, zdp::ZdpPacketType::StreamIdWithdrawal);
        assert_eq!(msg.1, adapter_stream);
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "exactly one withdrawal"
        );
    }

    /// The type and per-flow stream ID of a per-flow management packet
    /// without a transaction header, such as a StreamIdWithdrawal.
    fn decode_per_flow(pkt: &Packet) -> (zdp::ZdpPacketType, StreamId) {
        let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
        let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
        let (per_flow_hdr, _) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
        (base_hdr.packet_type, per_flow_hdr.stream_id.into())
    }

    /// R9, pending binds toward a lost link (zl-zipline#251): A's bind is
    /// waiting on B when B is lost. A's requestor gets an error at once and
    /// no bind state is left on A.
    #[tokio::test]
    async fn test_losing_the_next_hop_link_refuses_the_pending_bind() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);
        assert!(
            try_recv_packet(&mut egress_rx).is_some(),
            "a StreamIdRequest to B"
        );

        asm.drop_peer(link_b);

        assert_only_stream_id_error_response(&mut egress_rx, link_a);
        assert!(no_bind_state(&asm, link_a));
    }

    /// F3 for a bind that has not finished (core#110 review, g93): when a
    /// pending bind is refused because its next hop B was lost, its visa is
    /// revoked locally too, as a finished binding's would be. The visa had
    /// no binding yet, so `revoke_for_link` alone left it cached, and every
    /// later bind matched it and was refused for want of an egress link.
    /// Now the next bind misses and asks the visa service for a visa (F6).
    #[tokio::test]
    async fn test_losing_the_next_hop_link_revokes_the_pending_binds_visa() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = node_with_visa_and_no_vs_session();
                let link_a = NonZero::new(add_peer(&asm, LinkType::NodeToNode, 1)).unwrap();
                let link_b = insert_up_zode_link(&asm, "next-hop.zpr", next_hop());
                request_stream(&asm, link_a, 7, VISA_ID);
                assert!(
                    try_recv_packet(&mut egress_rx).is_some(),
                    "a StreamIdRequest to B"
                );

                asm.drop_peer(link_b);

                assert_only_stream_id_error_response(&mut egress_rx, link_a.get());
                assert!(!asm.visa_table.read().unwrap().contains(VISA_ID));

                let asked = &asm.counters.management[ManagementCounterType::VisaByIdRequested];
                let before = asked.get_count();
                request_stream(&asm, link_a, 8, VISA_ID);
                assert_eq!(
                    asked.get_count(),
                    before + 1,
                    "the next bind asks the visa service"
                );
            })
            .await
    }

    /// R9, pending binds from a lost link (zl-zipline#251): A's bind is
    /// waiting on B when A is lost. B's next-hop bind no longer names A's
    /// link ID, which a new peer may take, and B's late grant is ignored: no
    /// panic, no error that would close B, nothing sent, and no bind state
    /// left on B.
    #[tokio::test]
    async fn test_late_grant_for_a_lost_requestor_is_ignored() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);
        assert!(
            try_recv_packet(&mut egress_rx).is_some(),
            "a StreamIdRequest to B"
        );
        let egress_txn = outstanding_next_hop_txn(&asm, link_b);

        asm.drop_peer(link_a);
        let originator = *asm
            .peer_table
            .get(link_b)
            .unwrap()
            .node_state
            .awaiting_next_hop_bind_table
            .get(&egress_txn)
            .unwrap();
        assert_eq!(originator, NextHopBindOriginator::Abandoned);

        install_tether(&asm, NonZero::new(link_b).unwrap(), &egress_txn, 42)
            .expect("a late grant is not an error");
        assert!(try_recv_packet(&mut egress_rx).is_none(), "nothing is sent");
        assert!(no_bind_state(&asm, link_b));
    }

    /// A requestor that reuses the transaction ID of a bind still waiting on
    /// the next hop, for a bind that is refused at once (here: by the F2
    /// loop guard), must not crash the node. The first bind's late grant is
    /// then ignored.
    #[tokio::test]
    async fn test_reused_transaction_id_of_a_pending_bind_does_not_panic() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        // A is a Zode link whose topology address is the next hop of a
        // second visa: a bind of that visa from A loops back to A.
        let a_addr: IpAddr = "fd5a:5052:8::aa".parse().unwrap();
        crate::peer_table::test::set_verified_peer_cn(&asm, link_a, "a.zpr");
        asm.topology
            .write()
            .unwrap()
            .push(crate::peer_table::test::topology_link_at("a.zpr", a_addr));
        asm.zode_links.test_put(
            "a.zpr",
            crate::zode_link_record::RecordState::Up,
            Some(link_a),
        );
        let loop_visa: VisaId = VISA_ID + 2;
        asm.visa_table
            .write()
            .unwrap()
            .insert_visa(new_vsapi_visa_forward_only(
                loop_visa,
                never_expires(),
                a_addr,
            ))
            .unwrap();

        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, VISA_ID);
        assert!(
            try_recv_packet(&mut egress_rx).is_some(),
            "a StreamIdRequest to B"
        );
        let egress_txn = outstanding_next_hop_txn(&asm, link_b);

        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, loop_visa);
        assert_only_stream_id_error_response(&mut egress_rx, link_a);

        install_tether(&asm, NonZero::new(link_b).unwrap(), &egress_txn, 42)
            .expect("a late grant is not an error");
        assert!(try_recv_packet(&mut egress_rx).is_none(), "nothing is sent");
        assert_eq!(asm.peer_table.get(link_a).unwrap().pft.len(), 0);
        assert!(no_bind_state(&asm, link_b));
    }

    // ---- F6: visa requests wait for the loss report (zl-zipline#251) ----

    /// A visa ID this node does not hold, so a StreamIdRequest for it makes
    /// the node ask the visa service.
    const UNKNOWN_VISA: VisaId = VISA_ID + 50;

    /// F6: a visa request made right after a Zode link is lost reaches the
    /// VS-API only once the snapshot listing that link `down` has been sent
    /// and its send returned. Here the request fails at once (no session),
    /// so the refusal it causes upstream marks when it was made.
    #[tokio::test(start_paused = true)]
    async fn test_visa_request_after_a_zode_link_loss_waits_for_the_down_report() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = node_with_visa_and_no_vs_session();
                let link_a = add_peer(&asm, LinkType::NodeToNode, 1);
                let link_b = insert_up_zode_link(&asm, "b.zpr", next_hop());

                type Log =
                    std::rc::Rc<std::cell::RefCell<Vec<Vec<zpr::vsapi_types::LinkStateReport>>>>;
                let sent: Log = Default::default();
                let release = std::rc::Rc::new(tokio::sync::Notify::new());
                let (log, gate) = (sent.clone(), release.clone());
                tokio::task::spawn_local(crate::zode_links::run_link_state_reporter(
                    asm.clone(),
                    move |reports| {
                        log.borrow_mut().push(reports);
                        let gate = gate.clone();
                        async move {
                            gate.notified().await;
                            Ok(())
                        }
                    },
                ));

                asm.drop_peer(link_b);
                request_stream(&asm, NonZero::new(link_a).unwrap(), 7, UNKNOWN_VISA);

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                assert!(
                    sent.borrow()
                        .last()
                        .is_some_and(|reports| reports.iter().any(|r| {
                            r.peer_cn == "b.zpr" && r.state == zpr::vsapi_types::LinkState::Down
                        })),
                    "the down report is being sent"
                );
                assert!(
                    try_recv_packet(&mut egress_rx).is_none(),
                    "no visa request while the down report is in flight"
                );

                release.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                assert_only_stream_id_error_response(&mut egress_rx, link_a);
            })
            .await
    }

    /// Rule 9 on the requestor side: a visa request still in flight when
    /// its requestor's link is lost has its result dropped, even when a new
    /// peer has taken the link ID meanwhile. Nothing is sent to that peer.
    ///
    /// The RCU slab defers reclaiming a slot, so a unit test cannot make a
    /// real reuse happen. What the task finds at a reused ID is a peer that
    /// holds no such bind request, so that is set up directly: the request
    /// is removed from A's table while its visa request is in flight.
    #[tokio::test(start_paused = true)]
    async fn test_visa_result_for_a_lost_requestor_is_dropped() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = node_with_visa_and_no_vs_session();
                let link_a = add_peer(&asm, LinkType::NodeToNode, 1);
                request_stream(&asm, NonZero::new(link_a).unwrap(), 7, UNKNOWN_VISA);

                asm.peer_table
                    .get(link_a)
                    .unwrap()
                    .node_state
                    .bind_request_state
                    .remove(&7);

                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                assert!(try_recv_packet(&mut egress_rx).is_none(), "nothing is sent");
                assert!(no_bind_state(&asm, link_a));
            })
            .await
    }

    /// A visa result belongs to the request that asked for it (core#110
    /// review). If the requestor reuses the transaction ID of a bind whose
    /// visa request is still in flight, the bind state names the newer
    /// request's worker, and the older worker's result must not advance it.
    /// The guard passes only for the worker the bind state names.
    #[tokio::test]
    async fn test_visa_result_only_advances_the_request_that_asked_for_it() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (asm, _egress_rx) = node_with_visa();
                let link_a = NonZero::new(add_peer(&asm, LinkType::NodeToNode, 1)).unwrap();

                // Each worker records its task ID and the guard's verdict.
                let verdicts: std::rc::Rc<std::cell::RefCell<Vec<(tokio::task::Id, bool)>>> =
                    Default::default();
                let worker = || {
                    let (asm, verdicts) = (asm.clone(), verdicts.clone());
                    async move {
                        let verdict = bind_awaits_visa(&asm, link_a, 7);
                        verdicts.borrow_mut().push((tokio::task::id(), verdict));
                    }
                };
                let older = tokio::task::spawn_local(worker());
                let newer = tokio::task::spawn_local(worker());
                let (older_id, newer_id) = (older.id(), newer.id());
                asm.peer_table
                    .get(link_a.get())
                    .unwrap()
                    .node_state
                    .bind_request_state
                    .insert(7, BindRequestState::AwaitingVisaResponse(newer));

                older.await.unwrap();
                tokio::task::yield_now().await;

                let verdicts = verdicts.borrow();
                assert!(
                    verdicts.contains(&(older_id, false)),
                    "the older result is dropped"
                );
                assert!(
                    verdicts.contains(&(newer_id, true)),
                    "the named worker's result is used"
                );
            })
            .await
    }

    // ---- J11: rebind a live stream onto a superseding visa (zl-zipline#252) ----

    /// The visa a live stream is bound under in the J11 tests.
    const OLD_VISA: VisaId = VISA_ID + 100;

    /// The newer visa, with the same five-tuple, that supersedes [OLD_VISA].
    const NEW_VISA: VisaId = VISA_ID + 101;

    /// The receiving end of the management hairpin.
    type HairpinRx = tokio::sync::mpsc::Receiver<Packet>;

    /// A full visa for this node's own traffic, leaving toward [NEXT_HOP].
    /// Every visa this makes has the same five-tuple.
    fn own_visa(visa_id: VisaId) -> zpr::vsapi_types::Visa {
        let mut visa =
            crate::visa_table::tests::new_vsapi_visa_tcp_default(visa_id, never_expires());
        visa.fwd_pep = Some(zpr::vsapi_types::FwdPep {
            next_hop: next_hop(),
            style: zpr::vsapi_types::FwdPepStyle::OneWay,
        });
        visa
    }

    /// The ingress of a flow: a node whose local actor has a stream bound
    /// under [OLD_VISA] out a Zode link, which granted stream 42 for it.
    /// `binds` such streams are bound (transactions 7, 8, ...).
    ///
    /// Returns (asm, egress queue, hairpin, Zode link, the local actor's
    /// streams).
    fn ingress_with_live_streams(
        binds: usize,
    ) -> (Arc<Assembly>, EgressRx, HairpinRx, LinkId, Vec<StreamId>) {
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;

        let (asm, mut egress_rx, mut hairpin_rx) = node_with_visa_and_hairpin();
        let (local_actor, _dock) = asm
            .peer_table
            .insert_internal_peer_pair(|_, _| std::future::pending::<()>());
        assert_eq!(local_actor.get(), LOCAL_ACTOR_LINK_ID);
        let zode_link = insert_up_zode_link(&asm, "b.zpr", next_hop());
        widen_zdpr_window(&asm, zode_link);
        widen_zdpr_window(&asm, local_actor.get());
        visa_mgmt::insert_visa(&asm, own_visa(OLD_VISA)).unwrap();

        let mut streams = Vec::new();
        for txn_id in (7..).take(binds) {
            requested_visa_granted(&asm, local_actor, txn_id, OLD_VISA);
            assert!(
                try_recv_packet(&mut egress_rx).is_some(),
                "a StreamIdRequest to the Zode"
            );
            let egress_txn = outstanding_next_hop_txn(&asm, zode_link);
            install_tether(&asm, NonZero::new(zode_link).unwrap(), &egress_txn, 42).unwrap();
            let rsp = hairpin_rx
                .try_recv()
                .expect("a bind response to the local actor");
            streams.push(decode_per_flow_txn(&rsp).stream_id);
        }
        (asm, egress_rx, hairpin_rx, zode_link, streams)
    }

    /// Let several management packets go out on `link` unacknowledged:
    /// nothing acknowledges them in these tests, and with the initial ZDP-R
    /// window of one, a second request or response on a link would wait
    /// behind the first.
    fn widen_zdpr_window(asm: &Assembly, link: LinkId) {
        asm.peer_table
            .get(link)
            .unwrap()
            .zdpr_send
            .lock()
            .unwrap()
            .adjust_window_size(16);
    }

    /// Where the local actor's stream `stream` is forwarded, and under which
    /// visa.
    fn local_actor_entry(asm: &Assembly, stream: StreamId) -> Option<(ForwardingEntry, VisaId)> {
        asm.peer_table
            .get(zpr::packet_info::LOCAL_ACTOR_LINK_ID)
            .unwrap()
            .pft
            .inspect(stream, |pep| (pep.next_hop(), pep.visa_id()))
    }

    /// Take the StreamIdRequest the rebind sent off the egress queue, check
    /// that it asks the Zode for [NEW_VISA], and return its transaction.
    fn expect_rebind_request(asm: &Assembly, rx: &mut EgressRx, zode_link: LinkId) -> TxnHandle {
        let pkt = try_recv_packet(rx).expect("a StreamIdRequest for the new visa");
        assert_eq!(pkt.metadata().egress_link_id, zode_link);
        let req = decode_per_flow_txn(&pkt);
        assert_eq!(req.packet_type, zdp::ZdpPacketType::StreamIdRequest);
        let (body, _) = zdp::ZdpStreamIdRequest::ref_from_prefix(&req.payload).unwrap();
        assert_eq!(VisaId::from(body.visa_id), NEW_VISA);
        outstanding_next_hop_txn(asm, zode_link)
    }

    /// J11: at the ingress, a successor for a visa with a live stream sends
    /// a StreamIdRequest for the new visa down the path. Until the answer
    /// the stream keeps forwarding under the old visa; the answer swaps it
    /// onto the new visa's stream in one step, under the same stream ID, so
    /// the stream is never without a forwarding entry and the local actor is
    /// told nothing. Installing the successor again starts nothing, and the
    /// old visa going later leaves the new binding alone.
    #[tokio::test(flavor = "local")]
    async fn test_a_rebind_moves_a_live_stream_without_a_gap() {
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;

        let (asm, mut egress_rx, mut hairpin_rx, zode_link, streams) = ingress_with_live_streams(1);
        let stream = streams[0];

        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        let egress_txn = expect_rebind_request(&asm, &mut egress_rx, zode_link);
        assert!(
            local_actor_entry(&asm, stream) == Some((ForwardingEntry(zode_link, 42), OLD_VISA))
        );

        // A held ID is a no-op: no second rebind.
        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        assert!(
            try_recv_packet(&mut egress_rx).is_none(),
            "one rebind per stream"
        );

        install_tether(&asm, NonZero::new(zode_link).unwrap(), &egress_txn, 43).unwrap();

        assert!(
            local_actor_entry(&asm, stream) == Some((ForwardingEntry(zode_link, 43), NEW_VISA))
        );
        {
            let visa_table = asm.visa_table.read().unwrap();
            assert!(visa_table.bindings(OLD_VISA).is_empty());
            assert_eq!(
                visa_table.bindings(NEW_VISA),
                &[StreamBinding {
                    ingress: ForwardingEntry(LOCAL_ACTOR_LINK_ID, stream),
                    egress: ForwardingEntry(zode_link, 43),
                }]
            );
        }
        assert!(
            hairpin_rx.try_recv().is_err(),
            "the local actor is told nothing"
        );
        assert!(try_recv_packet(&mut egress_rx).is_none());

        // The old visa goes (revocation takes the same path as expiry).
        visa_mgmt::handle_revocation(&asm, OLD_VISA).unwrap();
        assert!(
            local_actor_entry(&asm, stream) == Some((ForwardingEntry(zode_link, 43), NEW_VISA))
        );
        assert_eq!(asm.visa_table.read().unwrap().bindings(NEW_VISA).len(), 1);
        assert!(hairpin_rx.try_recv().is_err(), "nothing is withdrawn");
    }

    /// J11 is per stream: every live stream of the old visa at the ingress
    /// gets its own rebind and commits on its own answer.
    #[tokio::test(flavor = "local")]
    async fn test_every_live_stream_of_the_old_visa_is_rebound() {
        let (asm, mut egress_rx, _hairpin_rx, zode_link, streams) = ingress_with_live_streams(2);

        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        for _ in &streams {
            let pkt = try_recv_packet(&mut egress_rx).expect("a StreamIdRequest per stream");
            assert_eq!(pkt.metadata().egress_link_id, zode_link);
        }
        assert!(try_recv_packet(&mut egress_rx).is_none());
        let egress_txns: Vec<TxnHandle> = asm
            .peer_table
            .get(zode_link)
            .unwrap()
            .node_state
            .awaiting_next_hop_bind_table
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(egress_txns.len(), 2);
        for (granted, egress_txn) in (43..).zip(&egress_txns) {
            install_tether(&asm, NonZero::new(zode_link).unwrap(), egress_txn, granted).unwrap();
        }

        for stream in streams {
            let (next_hop, visa_id) = local_actor_entry(&asm, stream).unwrap();
            assert_eq!(visa_id, NEW_VISA);
            assert!(next_hop.1 == 43 || next_hop.1 == 44);
        }
        let visa_table = asm.visa_table.read().unwrap();
        assert!(visa_table.bindings(OLD_VISA).is_empty());
        assert_eq!(visa_table.bindings(NEW_VISA).len(), 2);
        assert_eq!(visa_table.successor_of(OLD_VISA), None);
    }

    /// J11: a denied rebind keeps the old binding, logs and counts the
    /// failure, and tells the local actor nothing.
    #[tokio::test(flavor = "local")]
    async fn test_a_denied_rebind_keeps_the_old_binding() {
        let (asm, mut egress_rx, mut hairpin_rx, zode_link, streams) = ingress_with_live_streams(1);
        let stream = streams[0];
        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        let egress_txn = expect_rebind_request(&asm, &mut egress_rx, zode_link);

        deny_tether(
            &asm,
            NonZero::new(zode_link).unwrap(),
            &egress_txn,
            "policy error",
        )
        .unwrap();

        assert!(
            local_actor_entry(&asm, stream) == Some((ForwardingEntry(zode_link, 42), OLD_VISA))
        );
        let visa_table = asm.visa_table.read().unwrap();
        assert_eq!(visa_table.bindings(OLD_VISA).len(), 1);
        assert!(visa_table.bindings(NEW_VISA).is_empty());
        assert_eq!(
            asm.counters.management[ManagementCounterType::RebindFailed].get_count(),
            1
        );
        assert!(hairpin_rx.try_recv().is_err());
        assert!(try_recv_packet(&mut egress_rx).is_none());
    }

    /// J11 and F3: losing the next-hop link while a rebind is in flight
    /// revokes the old visa with its binding, as any loss does, and the new
    /// visa too, as for any pending bind that loses its next hop (rule 9).
    /// Left held, the new visa would take over the lookup and match the
    /// next packet, whose bind would then be refused for want of an egress
    /// instead of asking for a new visa (F6).
    #[tokio::test(flavor = "local")]
    async fn test_losing_the_next_hop_during_a_rebind_clears_the_bindings() {
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;

        let (asm, mut egress_rx, _hairpin_rx, zode_link, _streams) = ingress_with_live_streams(1);
        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        expect_rebind_request(&asm, &mut egress_rx, zode_link);

        asm.drop_peer(zode_link);

        let visa_table = asm.visa_table.read().unwrap();
        assert!(!visa_table.contains(OLD_VISA));
        assert!(!visa_table.contains(NEW_VISA));
        assert_eq!(
            asm.peer_table.get(LOCAL_ACTOR_LINK_ID).unwrap().pft.len(),
            0
        );
    }

    /// J11 and rule 9: once the stream's ingress link is lost, the rebind
    /// for it is abandoned, so its late grant changes nothing.
    #[tokio::test(flavor = "local")]
    async fn test_a_rebind_for_a_lost_ingress_link_is_abandoned() {
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;

        let (asm, mut egress_rx, _hairpin_rx, zode_link, streams) = ingress_with_live_streams(1);
        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
        let egress_txn = expect_rebind_request(&asm, &mut egress_rx, zode_link);

        clear_pending_binds_for_lost_link(&asm, LOCAL_ACTOR_LINK_ID);
        install_tether(&asm, NonZero::new(zode_link).unwrap(), &egress_txn, 43)
            .expect("a late grant is not an error");

        assert!(
            local_actor_entry(&asm, streams[0]) == Some((ForwardingEntry(zode_link, 42), OLD_VISA))
        );
        assert!(asm.visa_table.read().unwrap().bindings(NEW_VISA).is_empty());
    }

    /// J11: a Zode that is not the ingress of the old visa's stream sends
    /// nothing when the successor arrives. The upstream ingress's rebind
    /// binds the new visa here under F2, and the old binding stays until the
    /// old visa goes (gate question 10).
    #[tokio::test]
    async fn test_a_hop_that_is_not_the_ingress_does_not_rebind() {
        let (asm, mut egress_rx, link_a, link_b) =
            middle_node(LinkType::NodeToNode, LinkType::NodeToNode);
        widen_zdpr_window(&asm, link_b);
        visa_mgmt::insert_visa(&asm, own_visa(OLD_VISA)).unwrap();
        request_stream(&asm, NonZero::new(link_a).unwrap(), 7, OLD_VISA);
        assert!(
            try_recv_packet(&mut egress_rx).is_some(),
            "a StreamIdRequest to B"
        );
        let egress_txn = outstanding_next_hop_txn(&asm, link_b);
        install_tether(&asm, NonZero::new(link_b).unwrap(), &egress_txn, 42).unwrap();
        let a_stream = decode_per_flow_txn(&try_recv_packet(&mut egress_rx).unwrap()).stream_id;

        visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();

        assert!(try_recv_packet(&mut egress_rx).is_none(), "nothing is sent");
        let entry = asm
            .peer_table
            .get(link_a)
            .unwrap()
            .pft
            .inspect(a_stream, |pep| (pep.next_hop(), pep.visa_id()));
        assert!(entry == Some((ForwardingEntry(link_b, 42), OLD_VISA)));
        assert_eq!(
            asm.visa_table.read().unwrap().successor_of(OLD_VISA),
            Some(NEW_VISA)
        );
    }

    /// J11 (local Codex review): a bind of the old visa that completes
    /// after its successor arrived is rebound too, whether the successor
    /// was waiting on other live streams or took over at once.
    #[tokio::test(flavor = "local")]
    async fn test_a_bind_completing_after_the_successor_is_rebound() {
        use zpr::packet_info::LOCAL_ACTOR_LINK_ID;
        let local_actor = NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap();

        for live_streams in [0, 1] {
            let (asm, mut egress_rx, mut hairpin_rx, zode_link, _streams) =
                ingress_with_live_streams(live_streams);
            requested_visa_granted(&asm, local_actor, 20, OLD_VISA);
            assert!(
                try_recv_packet(&mut egress_rx).is_some(),
                "the bind's StreamIdRequest"
            );
            let bind_txn = outstanding_next_hop_txn(&asm, zode_link);

            visa_mgmt::insert_visa(&asm, own_visa(NEW_VISA)).unwrap();
            for _ in 0..live_streams {
                expect_rebind_request(&asm, &mut egress_rx, zode_link);
            }

            install_tether(&asm, NonZero::new(zode_link).unwrap(), &bind_txn, 60).unwrap();
            let stream =
                decode_per_flow_txn(&hairpin_rx.try_recv().expect("the bind response")).stream_id;
            let pkt = try_recv_packet(&mut egress_rx)
                .unwrap_or_else(|| panic!("a rebind of the late stream ({live_streams} live)"));
            let req = decode_per_flow_txn(&pkt);
            let (body, _) = zdp::ZdpStreamIdRequest::ref_from_prefix(&req.payload).unwrap();
            assert_eq!(VisaId::from(body.visa_id), NEW_VISA);

            // Grant it: the late stream moves onto the new visa.
            let rebind_txn = asm
                .peer_table
                .get(zode_link)
                .unwrap()
                .node_state
                .awaiting_next_hop_bind_table
                .iter()
                .find(|entry| {
                    matches!(*entry.value(), NextHopBindOriginator::Rebind { ingress_stream_id, .. }
                        if ingress_stream_id == stream)
                })
                .expect("the late stream's rebind is outstanding")
                .key()
                .clone();
            install_tether(&asm, NonZero::new(zode_link).unwrap(), &rebind_txn, 61).unwrap();
            assert!(
                local_actor_entry(&asm, stream) == Some((ForwardingEntry(zode_link, 61), NEW_VISA))
            );
        }
    }

    /// J11 (local Codex review): the requestor keeps the A2A keys it got
    /// from the old visa when its stream is rebound, so a successor with
    /// other session keys cannot take the stream over silently: nothing is
    /// sent, the failure is counted, and the stream stays on the old visa.
    #[tokio::test(flavor = "local")]
    async fn test_a_successor_with_other_session_keys_is_not_rebound_onto() {
        let (asm, mut egress_rx, _hairpin_rx, zode_link, streams) = ingress_with_live_streams(1);
        let mut successor = own_visa(NEW_VISA);
        successor.dock_pep.as_mut().unwrap().session_key.egress_key = vec![7; 32];

        visa_mgmt::insert_visa(&asm, successor).unwrap();

        assert!(try_recv_packet(&mut egress_rx).is_none(), "nothing is sent");
        assert!(
            local_actor_entry(&asm, streams[0]) == Some((ForwardingEntry(zode_link, 42), OLD_VISA))
        );
        assert_eq!(
            asm.counters.management[ManagementCounterType::RebindFailed].get_count(),
            1
        );
    }
}
