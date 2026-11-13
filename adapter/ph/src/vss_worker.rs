use crate::address_pool::AddressPool;
use crate::prelude::*;
use crate::{visa_mgmt, visa_table};

use libnode::vss::{ConfigureResponse, ListProcessingResponse, SetTopologyResponse, VSSMessage};
use tokio::sync::mpsc;
use zpr::vsapi_types::{ApiResponseError, ErrorCode, Link, Param, ParamValue, VisaOp, pname};

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            VSSMessage::PushVisaOp(ops, resp_tx) => {
                let mut processed = 0u32;
                let mut failed = false;
                for op in ops {
                    match process_visaop(&asm, op) {
                        Ok(()) => processed += 1,
                        Err(e) => {
                            error!(target: VISA_MGMT, "error processing pushed visa op: {e}");
                            failed = true;
                            break;
                        }
                    }
                }
                let resp = if failed {
                    ListProcessingResponse::Failed {
                        processed,
                        e: ErrorCode::Internal,
                    }
                } else {
                    ListProcessingResponse::Ack { processed }
                };
                let _ = resp_tx.send(resp);
            }

            VSSMessage::RevokeAuth(addrs, resp_tx) => {
                // zipline#45 C5: for each revoked ZPR address docked on this
                // node, terminate the actor's link via the existing close
                // path (which deregisters the actor's addresses and removes
                // its visas — see deregister_actor_addresses /
                // clean_up_link_state). Unknown addresses are a no-op: the
                // VS may broadcast revocations for actors docked elsewhere.
                let processed = process_revoke_auth(&asm, &addrs);
                let _ = resp_tx.send(ListProcessingResponse::Ack { processed });
            }

            VSSMessage::RequestAuthentication(addrs, resp_tx) => {
                // zipline#121 K1: classify each address and start re-auth
                // where we can; the ack reports what was accepted, never the
                // outcome — outcomes reach the VS as authenticate/reauthorize
                // calls in their own time.
                let outcome = process_request_authentication(&asm, &addrs);
                if outcome.start_self_reauth {
                    spawn_self_reauth(&asm);
                }
                let _ = resp_tx.send(ListProcessingResponse::Ack {
                    processed: outcome.processed,
                });
            }

            VSSMessage::SetServices(services, resp_tx) => {
                debug!(target: VSS_RPC, "received services update with {} entries", services.len());
                let mut svcs = asm.vs_auth_services.write().unwrap();
                svcs.update(None, services);
                let _ = resp_tx.send(Ok(()));
            }

            VSSMessage::Configure(params, resp_tx) => {
                debug!(target: VSS_RPC, "received VSS configuration update with {} entries", params.len());
                let resp = process_configuration(&asm, params);
                let _ = resp_tx.send(resp);
            }

            VSSMessage::SetTopology(links, resp_tx) => {
                debug!(target: VSS_RPC, "received topology update with {} links", links.len());
                let resp = process_topology(&asm, links);
                let _ = resp_tx.send(resp);
            }
        }
    }
}

pub fn process_visaop(asm: &Arc<Assembly>, op: VisaOp) -> Result<(), visa_table::VisaTableError> {
    match op {
        VisaOp::Grant(visa) => {
            let visa_id = visa.issuer_id;
            debug!(target: VISA_MGMT, "received pushed visa, id={visa_id}");
            match visa_mgmt::insert_visa(asm, visa) {
                Ok(_) => {}
                // A forward-only visa on a node with forwarding off is
                // dropped (insert_visa has logged it) but the op still
                // counts as processed: failing the push would make the VS
                // retry it and block every visa queued behind it
                // (zl-zipline#219).
                Err(visa_table::VisaTableError::ForwardingDisabled(_)) => {}
                Err(e) => return Err(e),
            }
        }
        VisaOp::RevokeVisaId(id) => {
            debug!(target: VISA_MGMT, "received pushed revocation, id={id}");
            visa_mgmt::handle_revocation(asm, id as VisaId)?;
        }
    }
    Ok(())
}

/// Terminate the link of every actor in `addrs` that is docked on this node
/// (zipline#45 C5). Termination runs the normal close path, which notifies
/// the VS of the disconnect and clears the actor's visas; addresses not
/// docked here are counted but otherwise ignored (no-op ack). Returns the
/// number of addresses processed (all of them: a revocation for an unknown
/// address is *successfully* processed as a no-op).
pub fn process_revoke_auth(asm: &Arc<Assembly>, addrs: &[std::net::IpAddr]) -> u32 {
    use crate::link_state::LinkEvent;
    use crate::zdp::TerminateReason;

    for addr in addrs {
        let addr = zpr_utils::net_defs::IpAddress::new_from_std(addr);
        // Only peer links dock actors; a match against a local/self address
        // is not a docked actor, so search the peer table directly.
        let docked_link = asm
            .peer_table
            .find(|(_id, peer)| peer.actor_auth.owns_address(&addr));
        match docked_link {
            Some((link_id, _peer)) => {
                let link_id = link_id.get();
                warn!(target: VSS_RPC,
                    "revoke_auth: terminating {} (actor {addr} revoked by the visa service)",
                    asm.formatted_link_id(link_id));
                // Shutdown quells restart behavior; the close path
                // deregisters the actor's addresses (removing visas).
                if let Err(e) = asm
                    .process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Shutdown))
                {
                    error!(target: VSS_RPC,
                        "revoke_auth: failed to terminate {}: {e}",
                        asm.formatted_link_id(link_id));
                }
            }
            None => {
                debug!(target: VSS_RPC,
                    "revoke_auth: {addr} is not docked on this node (no-op)");
            }
        }
    }
    addrs.len() as u32
}

/// What [process_request_authentication] decided: how many addresses were
/// accepted for the ack (K1), and whether the caller should start the node's
/// in-place self re-auth. Splitting decision from action keeps the
/// classification synchronously testable.
pub struct RequestAuthOutcome {
    pub processed: u32,
    pub start_self_reauth: bool,
}

/// Classify each address of a VSS `requestAuthentication` (zipline#121, K1).
///
/// - The node's own address: start an in-place self re-auth against the VS —
///   counted, and coalesced onto a running attempt if one is in flight
///   ([Assembly::self_reauth_in_flight] stays set until that attempt
///   resolves; a coalesced address is still counted, because re-auth for it
///   *is* underway).
/// - A docked adapter's address: start the on-demand ZDP renewal on its
///   link (zipline#122, [crate::actor_renewal::request_renewal_now]) — counted,
///   and coalesced onto an in-flight renewal attempt if one is outstanding
///   (a coalesced address is still counted: its re-auth is underway).
/// - An unknown address: skipped and not counted.
///
/// Sets [Assembly::self_reauth_in_flight] when it decides to start a self
/// re-auth; the caller must then actually spawn it (see [spawn_self_reauth])
/// and that task clears the flag when done.
pub fn process_request_authentication(
    asm: &Arc<Assembly>,
    addrs: &[std::net::IpAddr],
) -> RequestAuthOutcome {
    use std::sync::atomic::Ordering;

    let local_addrs = asm.get_local_zpr_addrs_std();
    let mut processed = 0u32;
    let mut start_self_reauth = false;

    for addr in addrs {
        if local_addrs.contains(addr) {
            // Our own address: re-authenticate ourselves to the VS (K2).
            // swap(true) is the claim: false -> we start one; true -> one is
            // already in flight and this request coalesces onto it.
            if !start_self_reauth && !asm.self_reauth_in_flight.swap(true, Ordering::SeqCst) {
                start_self_reauth = true;
            } else {
                debug!(target: VSS_RPC,
                    "request_auth: self re-auth already in flight, coalescing request for {addr}");
            }
            processed += 1;
            continue;
        }

        let addr_ip = zpr_utils::net_defs::IpAddress::new_from_std(addr);
        let docked_link = asm
            .peer_table
            .find(|(_id, peer)| peer.actor_auth.owns_address(&addr_ip));
        match docked_link {
            Some((link_id, peer)) => {
                // A docked adapter (zipline#122, K1/K4): start the on-demand
                // ZDP renewal on its link. Count only what actually started:
                // Accepted (new attempt) and Coalesced (already underway)
                // count; Ignored — the link left `Active` during shutdown
                // while still holding its actor address, so the state guard
                // refused — must not be acknowledged as underway (Codex
                // review, zl-zpr-core#45).
                let link_id = link_id.get();
                drop(peer);
                match crate::actor_renewal::request_renewal_now(asm, link_id) {
                    crate::actor_renewal::RenewalStart::Accepted
                    | crate::actor_renewal::RenewalStart::Coalesced => {
                        info!(target: VSS_RPC,
                            "request_auth: on-demand re-auth underway for {addr} on {}",
                            asm.formatted_link_id(link_id));
                        processed += 1;
                    }
                    crate::actor_renewal::RenewalStart::Ignored => {
                        debug!(target: VSS_RPC,
                            "request_auth: {addr} resolves to {} but no renewal could start; not counted",
                            asm.formatted_link_id(link_id));
                    }
                }
            }
            None => {
                // Unknown address: skipped, not counted (K1).
                debug!(target: VSS_RPC,
                    "request_auth: {addr} is not this node and not docked here; skipping");
            }
        }
    }

    RequestAuthOutcome {
        processed,
        start_self_reauth,
    }
}

/// Spawn the in-place self re-authentication decided by
/// [process_request_authentication] (zipline#121, K2): re-run
/// connect/challenge/authenticate on the existing VS session via
/// [libnode::vsconn::VSConnHandle::reauthenticate]. Failure is logged and
/// nothing else — the old handle stays in place and the VS deadline decides.
/// Always clears [Assembly::self_reauth_in_flight] when the attempt
/// resolves. Runs on the local set (the VSS worker runs there too).
pub fn spawn_self_reauth(asm: &Arc<Assembly>) {
    use libnode::vsconn::{NodeConnect, StateFlag};
    use std::sync::atomic::Ordering;

    let Some(vsconn) = asm.vsconn.as_ref().cloned() else {
        error!(target: VSS_RPC, "request_auth: no VS connection on this assembly; cannot self re-auth");
        asm.self_reauth_in_flight.store(false, Ordering::SeqCst);
        return;
    };

    let zpr_addr = asm.get_local_dock_addr();
    let a2a_dh_pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);
    let asm = asm.clone();

    tokio::task::spawn_local(async move {
        let req = NodeConnect {
            zpr_addr,
            // We hold session state with the VS; K2's Reconnect keeps docked
            // adapters, visas and router links undisturbed.
            state: StateFlag::HasState,
            a2a_dh_pubkey,
        };
        match vsconn.reauthenticate(req).await {
            Ok(()) => {
                info!(target: VSS_RPC, "self re-authentication with the visa service succeeded");
            }
            Err(e) => {
                // Keep the old handle (the run loop already did); the VS
                // re-auth deadline decides whether we are revoked.
                error!(target: VSS_RPC, "self re-authentication with the visa service failed: {e:?}");
            }
        }
        asm.self_reauth_in_flight.store(false, Ordering::SeqCst);
    });
}

/// Visa service sends configuration info here. Currently includes:
/// - AAA network to use (will be updated on the assembly).
fn process_configuration(asm: &Arc<Assembly>, params: Vec<Param>) -> ConfigureResponse {
    let mut aaa_ipnet_str = None;

    for param in params {
        match param.name.as_str() {
            pname::AAA_PREFIX => match param.value {
                ParamValue::StrParam(s) => {
                    if aaa_ipnet_str.is_some() {
                        error!(target: VSS_RPC, "multiple AAA_PREFIX parameters received");
                        return Err(ApiResponseError {
                            code: ErrorCode::ParamError,
                            message: "multiple AAA_PREFIX parameters".into(),
                            retry_in: 0,
                        });
                    }
                    aaa_ipnet_str = Some(s);
                }
                _ => {
                    error!(target: VSS_RPC, "invalid value type for AAA_PREFIX param");
                    return Err(ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: "invalid type for AAA_PREFIX".into(),
                        retry_in: 0,
                    });
                }
            },
            _ => {
                info!(target: VSS_RPC, "unrecognized configuration parameter: {}", param.name);
            }
        }
    }

    if let Some(net) = aaa_ipnet_str {
        match net.parse() {
            Ok(ipnet) => {
                let pool = AddressPool::new(ipnet).map_err(|e| {
                    error!(target: VSS_RPC, "rejected AAA_PREFIX value: {e}");
                    ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: format!("AAA_PREFIX rejected"),
                        retry_in: 0,
                    }
                })?;

                debug!(target: VSS_RPC, "updating local AAA address pool with network {}", ipnet);
                asm.address_pool.lock().unwrap().replace(pool);
            }
            Err(e) => {
                error!(target: VSS_RPC, "invalid AAA_PREFIX value: {e}");
                return Err(ApiResponseError {
                    code: ErrorCode::ParamError,
                    message: format!("invalid AAA_PREFIX"),
                    retry_in: 0,
                });
            }
        }
    }

    Ok(())
}

/// Store the topology the visa service pushed and apply it to the Zode link
/// records (zl-zipline#250, ZODE_LINKS.md rules 12 and 13).
fn process_topology(asm: &Arc<Assembly>, links: Vec<Link>) -> SetTopologyResponse {
    info!(target: VSS_RPC, "received topology update with {} links", links.len());
    for (i, link) in links.iter().enumerate() {
        info!(target: VSS_RPC, "[link {i}]-> peer {:?}, zpr addr {}, peer cn {:?}", link.peer, link.zpr_addr, link.peer_cn);
    }
    *asm.topology.write().unwrap() = links;
    crate::zode_links::apply_topology(asm);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::link_state::{LinkState, LinkType};
    use crate::peer_table;
    use std::net::IpAddr;
    use tokio::task::LocalSet;
    use zpr_utils::net_defs::{self, IpAddress};

    /// With `forwarding` off, a pushed forward-only visa is refused and
    /// dropped, but the op is still acked so the visa service's push queue
    /// keeps flowing; the next op in the batch is processed
    /// (zl-zipline#219, g26 q3).
    #[test]
    fn test_pushed_forward_only_visa_is_dropped_and_acked_when_forwarding_off() {
        use crate::visa_table::tests::{
            never_expires, new_vsapi_visa_forward_only, new_vsapi_visa_tcp_default,
        };
        let mut builder = node_builder("10.1.1.1".parse().unwrap());
        builder.visa_table = Some(visa_table::VisaTable::new());
        let asm = Arc::new(create_assembly(builder));
        assert!(!asm.config.get().forwarding);

        let next_hop: IpAddr = "fd5a:5052:8::99".parse().unwrap();
        let fwd_only = VisaOp::Grant(new_vsapi_visa_forward_only(8001, never_expires(), next_hop));
        let full = VisaOp::Grant(new_vsapi_visa_tcp_default(8002, never_expires()));

        assert!(
            process_visaop(&asm, fwd_only).is_ok(),
            "a refused push is acked"
        );
        assert!(process_visaop(&asm, full).is_ok());

        let table = asm.visa_table.read().unwrap();
        assert!(!table.contains(8001), "the refused visa is not stored");
        assert!(table.contains(8002), "later ops are still processed");
    }

    /// A visa ID always names the same visa (operator, g88 q4; ZODE_LINKS.md
    /// "visas are immutable"). A pushed grant for an ID this Zode already
    /// holds is acked and dropped: the stored visa, its bindings and the
    /// timeout queue stay exactly as they were, and the two visas' contents
    /// are never compared.
    #[test]
    fn test_pushed_grant_for_a_held_visa_id_is_acked_and_dropped() {
        use crate::visa_table::StreamBinding;
        use crate::visa_table::tests::{never_expires, new_vsapi_visa_tcp_default};
        use zpr::packet_info::ForwardingEntry;
        let mut builder = node_builder("10.1.1.1".parse().unwrap());
        builder.visa_table = Some(visa_table::VisaTable::new());
        let asm = Arc::new(create_assembly(builder));

        let original = new_vsapi_visa_tcp_default(8101, never_expires());
        process_visaop(&asm, VisaOp::Grant(original.clone())).unwrap();
        let binding = StreamBinding {
            ingress: ForwardingEntry(1, 5),
            egress: ForwardingEntry(2, 6),
        };
        asm.visa_table
            .write()
            .unwrap()
            .bind(8101, binding.clone())
            .unwrap();

        // Same ID, different contents: another configuration, a next hop,
        // and an expiry already past. (A full visa: a forward-only one
        // would be refused earlier, with forwarding off on this node.)
        let mut other = new_vsapi_visa_tcp_default(8101, crate::visa_table::tests::ALREADY_EXPIRED);
        other.fwd_pep = Some(zpr::vsapi_types::FwdPep {
            next_hop: "fd5a:5052:8::99".parse().unwrap(),
            style: zpr::vsapi_types::FwdPepStyle::OneWay,
        });
        other.config = original.config + 1;
        assert!(
            process_visaop(&asm, VisaOp::Grant(other)).is_ok(),
            "the duplicate push is acked"
        );

        let table = asm.visa_table.read().unwrap();
        assert_eq!(table.get(8101).unwrap().visa(), &original);
        assert_eq!(table.bindings(8101), &[binding]);
        assert_eq!(table.timeout_queue.len(), 1, "no second timeout entry");
    }

    /// A node-mode assembly whose own (configured) ZPR address is `own`:
    /// a node's local addresses are its configured `zpr_addr`.
    /// zl-zipline#220: a topology update that drops a peer's CN closes its
    /// live Zode link; links to peers still in the topology stay up. Both
    /// peers dialed this Zode, which sits above them (fd5a:5052::10).
    #[tokio::test]
    async fn test_topology_update_closes_zode_link_whose_cn_left() {
        use crate::link_state::ZodeEnd;
        use crate::peer_table::test::{insert_zode_peer_with_verified_cn, topology_link};
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(node_builder(
                    "fd5a:5052::10".parse().unwrap(),
                )));
                process_topology(&asm, vec![topology_link("a.zpr"), topology_link("b.zpr")])
                    .unwrap();
                let answered = |cn| {
                    let id = insert_zode_peer_with_verified_cn(&asm, cn, LinkState::Active);
                    let peer = asm.peer_table.get(id).unwrap();
                    peer.link_state_machine
                        .set_zode_end(ZodeEnd::Answerer)
                        .unwrap();
                    id
                };
                let a = answered("a.zpr");
                let b = answered("b.zpr");

                process_topology(&asm, vec![topology_link("a.zpr")]).unwrap();

                let state = |id| {
                    asm.peer_table
                        .get(id)
                        .unwrap()
                        .link_state_machine
                        .get_state()
                };
                assert_eq!(state(a), LinkState::Active);
                assert_eq!(state(b), LinkState::Closing);
            })
            .await
    }

    fn node_builder(own: IpAddr) -> TestAssemblyBuilder {
        TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            config: Some(rcu::RcuBox::new(crate::config::Config {
                zpr_addr: vec![own],
                ..Default::default()
            })),
            ..TestAssemblyBuilder::new()
        }
    }

    fn add_active_peer_with_actor(asm: &Arc<Assembly>, actor: IpAddr) -> zpr::packet_info::LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::AdapterToNode,
            SubstrateAddr::from(([127, 0, 0, 1], 9000 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        entry.insert(ps);
        let peer = asm.peer_table.get(link_id.get()).unwrap();
        peer.link_state_machine.test_set_state(LinkState::Active);
        peer.actor_auth
            .test_set_addresses(vec![IpAddress::new_from_std(&actor)]);
        link_id.get()
    }

    /// Like [add_active_peer_with_actor] but node-side (NodeToAdapter), the
    /// link type the on-demand renewal hook (zipline#122) requires.
    fn add_node_peer_with_actor(asm: &Arc<Assembly>, actor: IpAddr) -> zpr::packet_info::LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::NodeToAdapter,
            SubstrateAddr::from(([127, 0, 0, 1], 9200 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        entry.insert(ps);
        let peer = asm.peer_table.get(link_id.get()).unwrap();
        peer.link_state_machine.test_set_state(LinkState::Active);
        peer.actor_auth
            .test_set_addresses(vec![IpAddress::new_from_std(&actor)]);
        link_id.get()
    }

    /// C5 (zipline#45): revoke_auth for an actor docked here terminates the
    /// actor's link via the existing close path; an unknown address is a
    /// no-op — both count as processed in the ack.
    #[tokio::test]
    async fn test_revoke_auth_terminates_docked_actor_and_ignores_unknown() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let unknown: IpAddr = "10.0.0.99".parse().unwrap();
                let link_id = add_active_peer_with_actor(&asm, docked);

                let processed = process_revoke_auth(&asm, &[docked, unknown]);
                assert_eq!(processed, 2, "both addresses count as processed");

                let state = asm
                    .peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .get_state();
                assert!(
                    !matches!(state, LinkState::Active),
                    "docked actor's link must leave Active after revoke_auth, got {state:?}"
                );
            })
            .await
    }

    /// C5 (zipline#45): revoke_auth with only unknown addresses changes no
    /// link state and still acks every address.
    #[tokio::test]
    async fn test_revoke_auth_unknown_address_is_noop() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let unknown: IpAddr = "10.0.0.99".parse().unwrap();
                let link_id = add_active_peer_with_actor(&asm, docked);

                let processed = process_revoke_auth(&asm, &[unknown]);
                assert_eq!(processed, 1);
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active,
                    "an unrelated link must not be disturbed"
                );
            })
            .await
    }

    /// zipline#121 K1: the node's own address in a `requestAuthentication`
    /// starts exactly one self re-auth and counts in the ack; an unknown
    /// address is skipped and NOT counted.
    #[tokio::test]
    async fn test_request_auth_own_address_starts_self_reauth_unknown_not_counted() {
        LocalSet::new()
            .run_until(async {
                let own: IpAddr = "10.1.1.1".parse().unwrap();
                let unknown: IpAddr = "10.0.0.99".parse().unwrap();
                let asm = Arc::new(create_assembly(node_builder(own)));

                let outcome = process_request_authentication(&asm, &[own, unknown]);
                assert_eq!(
                    outcome.processed, 1,
                    "own address counted, unknown skipped (K1)"
                );
                assert!(
                    outcome.start_self_reauth,
                    "own address must start a self re-auth"
                );
                assert!(
                    asm.self_reauth_in_flight
                        .load(std::sync::atomic::Ordering::SeqCst),
                    "the in-flight flag must be claimed for the started re-auth"
                );
            })
            .await
    }

    /// zipline#121 K1/K2: a second `requestAuthentication` naming the node's
    /// own address while a self re-auth is already in flight is coalesced —
    /// still counted in the ack (re-auth for it IS underway) but no second
    /// attempt is started. Once the attempt resolves (flag cleared), the
    /// next request starts a fresh one.
    #[tokio::test]
    async fn test_request_auth_second_own_address_in_flight_is_coalesced() {
        LocalSet::new()
            .run_until(async {
                let own: IpAddr = "10.1.1.1".parse().unwrap();
                let asm = Arc::new(create_assembly(node_builder(own)));

                let first = process_request_authentication(&asm, &[own]);
                assert!(first.start_self_reauth, "first request starts the re-auth");
                assert_eq!(first.processed, 1);

                // The attempt is still in flight (flag set): coalesce.
                let second = process_request_authentication(&asm, &[own]);
                assert!(
                    !second.start_self_reauth,
                    "second request while in flight must be coalesced, not started"
                );
                assert_eq!(
                    second.processed, 1,
                    "a coalesced own-address is still counted: its re-auth is underway"
                );

                // The attempt resolves; the next request starts a new one.
                asm.self_reauth_in_flight
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                let third = process_request_authentication(&asm, &[own]);
                assert!(
                    third.start_self_reauth,
                    "after the attempt resolves a new request must start again"
                );
            })
            .await
    }

    /// zipline#122 (N2): a docked adapter's address in a
    /// `requestAuthentication` starts an on-demand ZDP renewal on the
    /// adapter's link — counted in the ack (K1) — while the link stays
    /// Active and visas are untouched. A second request while the renewal
    /// is in flight is coalesced but still counted: re-auth IS underway.
    #[tokio::test]
    async fn test_request_auth_adapter_address_starts_renewal_and_is_counted() {
        use crate::visa_table::tests::new_vsapi_visa_tcp_default;
        use std::time::{Duration, SystemTime};

        LocalSet::new()
            .run_until(async {
                let (egress_tx, mut egress_rx) = crate::packet_queue::packet_queue(8);
                let own: IpAddr = "10.1.1.1".parse().unwrap();
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let mut builder = node_builder(own);
                builder.mgmt_substrate_egress =
                    Some(crate::queues::MgmtSubstrateEgress::new(egress_tx));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_node_peer_with_actor(&asm, docked);
                asm.visa_table
                    .write()
                    .unwrap()
                    .insert_visa(new_vsapi_visa_tcp_default(
                        77,
                        SystemTime::now() + Duration::from_secs(3600),
                    ))
                    .unwrap();

                let outcome = process_request_authentication(&asm, &[docked]);
                assert_eq!(
                    outcome.processed, 1,
                    "an adapter address with a started renewal counts in the ack (K1)"
                );
                assert!(!outcome.start_self_reauth);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    peer.actor_auth.renewal.test_in_flight(),
                    "the adapter's link must have a renewal in flight"
                );
                let pkt = egress_rx
                    .try_recv(vec![0u8; 2048].into_boxed_slice())
                    .expect("a RenewAuthenticationRequest must go out");
                assert_eq!(
                    pkt.body()[0],
                    crate::zdp::ZdpPacketType::RenewAuthenticationRequest.0,
                    "expected a RenewAuthenticationRequest (144)"
                );
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "the adapter's link must stay Active"
                );
                assert!(
                    asm.visa_table.read().unwrap().contains(77),
                    "visas must be untouched"
                );

                // Coalescing: a second request is counted but sends nothing.
                let second = process_request_authentication(&asm, &[docked]);
                assert_eq!(
                    second.processed, 1,
                    "a coalesced adapter address still counts: its re-auth is underway"
                );
                assert!(
                    egress_rx
                        .try_recv(vec![0u8; 2048].into_boxed_slice())
                        .is_err(),
                    "no second request while the renewal is in flight"
                );
            })
            .await
    }

    /// Codex review (zl-zpr-core#45, P2): a docked link that has left
    /// `Active` (shutdown race) but still retains its actor address must
    /// NOT be counted in the ack — `request_renewal_now`'s state guard
    /// returns without sending, so no re-authentication attempt started
    /// and reporting one as underway would be a lie.
    #[tokio::test]
    async fn test_request_auth_non_active_docked_link_not_counted() {
        LocalSet::new()
            .run_until(async {
                let (egress_tx, mut egress_rx) = crate::packet_queue::packet_queue(8);
                let own: IpAddr = "10.1.1.1".parse().unwrap();
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let mut builder = node_builder(own);
                builder.mgmt_substrate_egress =
                    Some(crate::queues::MgmtSubstrateEgress::new(egress_tx));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_node_peer_with_actor(&asm, docked);
                let peer = asm.peer_table.get(link_id).unwrap();
                // The link is being torn down: it has left Active but its
                // actor address is still in the table.
                peer.link_state_machine.test_set_state(LinkState::Closing);

                let outcome = process_request_authentication(&asm, &[docked]);
                assert_eq!(
                    outcome.processed, 0,
                    "an ignored renewal (state guard) must not count as underway"
                );
                assert!(!outcome.start_self_reauth);
                assert!(
                    !peer.actor_auth.renewal.test_in_flight(),
                    "no renewal attempt may be in flight on a non-Active link"
                );
                assert!(
                    egress_rx
                        .try_recv(vec![0u8; 2048].into_boxed_slice())
                        .is_err(),
                    "no request may go out on a non-Active link"
                );
            })
            .await
    }
}
