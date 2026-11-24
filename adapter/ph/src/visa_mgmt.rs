use crate::prelude::*;
use crate::visa_table;

use std::num::NonZero;
use zpr::vsapi_types;

/// Insert visa into table.
///
/// A visa whose next hop has no egress link yet is still stored, with a
/// warning. The VS legitimately sends such visas -- e.g. a bootstrap visa for
/// a policy-declared peer node that has not linked up yet -- and the egress
/// link is resolved again at forwarding time (see [get_egress_link_for_visa]),
/// so the visa becomes usable once the link comes up.
///
/// A forward-only visa makes this node carry other nodes' traffic. It is
/// refused with [VisaTableError::ForwardingDisabled], and logged, unless the
/// node's `forwarding` setting is on (zl-zipline#219; zl-zpr-dev-context
/// docs/SECURITY_MODEL.md, Design decisions, "Non-transit has two halves").
/// The visa service's non-transit routing is the primary check; this one is
/// defence in depth, and it catches a misconfigured relay early.
///
/// This is the single entry point for visas from the visa service, pushed or
/// pulled, so it is also where a newer visa for a live flow's five-tuple
/// starts the J11 supersede and rebind (zl-zipline#252). A visa whose shape does not match its type is refused with
/// [VisaTableError::ParseError].
///
/// [VisaTableError::ForwardingDisabled]: visa_table::VisaTableError::ForwardingDisabled
/// [VisaTableError::ParseError]: visa_table::VisaTableError::ParseError
pub fn insert_visa(
    asm: &Assembly,
    visa: vsapi_types::Visa,
) -> Result<VisaId, visa_table::VisaTableError> {
    // The forwarding PEP's next hop if there is one, else the flow's
    // destination. Either may be missing in a malformed visa, which the
    // visa table refuses below.
    let next_hop = visa
        .fwd_pep
        .as_ref()
        .map(|p| p.next_hop)
        .or_else(|| visa.dock_pep.as_ref().map(|d| d.dest_addr));

    if visa.visa_type == vsapi_types::VisaType::ForwardOnly && !asm.config.get().forwarding {
        warn!(target: VISA_MGMT,
            "visa {}: refusing forward-only visa to next hop {next_hop:?}: forwarding is off on this node",
            visa.issuer_id);
        return Err(visa_table::VisaTableError::ForwardingDisabled(
            visa.issuer_id,
        ));
    }

    // J11 (zl-zipline#252): a new visa with the same five-tuple as visas
    // held supersedes them, and their live streams move onto it.
    let (visa_id, superseded) = asm.visa_table.write().unwrap().insert_superseding(visa)?;

    if let Some(next_hop) = next_hop
        && asm.find_egress_link(next_hop.into()).is_none()
    {
        warn!(target: VISA_MGMT,
            "visa {visa_id}: no egress link to next hop {next_hop} yet; storing it anyway");
    }

    // The superseded visas' live streams move onto the new one, at the
    // Zode that is their ingress. That sends, so only now that the lock is
    // released (zipline#9).
    for (old, ingress) in superseded {
        crate::mgmt::node::rebind_stream(asm, old, visa_id, ingress);
    }
    Ok(visa_id)
}

/// Given a visa ID, look up the visa in our table to find the destination address
/// then use that to find an egress link.
pub fn get_egress_link_for_visa(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<NonZero<LinkId>, visa_table::VisaTableError> {
    let addr = asm
        .visa_table
        .read()
        .unwrap()
        .get_visa_next_hop_addr(visa_id)?;
    let Some(link_id) = asm.find_egress_link(addr) else {
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    Ok(link_id)
}

pub fn handle_revocation(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<(), visa_table::VisaTableError> {
    // Revoke under the write lock, then, once the lock is released, run the
    // shared tail `Assembly::withdraw_streams` as `Assembly::drop_peer` does
    // (zipline#21, zipline#85): it withdraws each stream from the actor and
    // adapters still bound to it, and unbinds a local egress DLT entry by
    // sending type 13 to this Zode's own adapter over
    // `LOCAL_ACTOR_LINK_ID` (zl-zipline#283). Zode links get neither (F5,
    // zl-zipline#251): the visa service revokes the visa on every Zode on
    // the path itself.
    asm.update_visa_table_and_withdraw(|visa_table, peer_table| {
        match visa_table.revoke(peer_table, visa_id) {
            Ok(withdrawn) => (Ok(()), withdrawn),
            Err(e) => (Err(e), Vec::new()),
        }
    })
}

/// The expiry sweep (zl-zipline#274), if it is due: at most once every
/// [config::VISA_EXPIRY_SWEEP_INTERVAL], whoever calls. The link
/// keep-alive calls it on every tick of every Zode link (operator, g184 q7:
/// no timer of its own). Every stream crosses a Zode link, so whenever
/// there is something to sweep, a keep-alive is ticking.
pub fn sweep_expired_visas_if_due(asm: &Assembly) {
    {
        let mut last = asm.last_visa_sweep.lock().unwrap();
        if last.is_some_and(|at| at.elapsed() < config::VISA_EXPIRY_SWEEP_INTERVAL) {
            return;
        }
        *last = Some(std::time::Instant::now());
    }
    sweep_expired_visas(asm, std::time::SystemTime::now());
}

/// Sweep the visas that have expired at `now` out of the visa table
/// ([visa_table::VisaTable::handle_expirations]), and withdraw their
/// streams from this Zode's own actor, so its next packet binds afresh.
/// The shared tail `Assembly::withdraw_streams` also unbinds each removed
/// binding's local egress DLT entry: type 13 to this Zode's own adapter
/// over `LOCAL_ACTOR_LINK_ID` (zl-zipline#283).
pub fn sweep_expired_visas(asm: &Assembly, now: std::time::SystemTime) {
    asm.update_visa_table_and_withdraw(|visa_table, peer_table| {
        ((), visa_table.handle_expirations(peer_table, now))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// A pushed visa whose next hop has no egress link yet (e.g. a bootstrap
    /// visa for a policy-declared peer node that has not linked up) must
    /// still be stored. Rejecting it makes the VS retry the push forever and
    /// blocks every visa queued behind it; the egress link is looked up again
    /// at forwarding time by `get_egress_link_for_visa`.
    #[test]
    fn test_insert_visa_without_egress_link_is_stored() {
        use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
        use crate::visa_table::VisaTable;
        use crate::visa_table::tests::{never_expires, new_vsapi_visa_tcp_default};

        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(VisaTable::new());
        let asm = create_assembly(builder);

        let visa_id = 4242;
        // No peers exist, so the visa's destination has no egress link.
        let visa = new_vsapi_visa_tcp_default(visa_id, never_expires());
        assert!(
            asm.find_egress_link(visa.dock_pep.as_ref().unwrap().dest_addr.into())
                .is_none()
        );

        let inserted = insert_visa(&asm, visa).expect("visa without egress link must be accepted");
        assert_eq!(inserted, visa_id as VisaId);
        assert!(
            asm.visa_table
                .read()
                .unwrap()
                .get_visa_next_hop_addr(inserted)
                .is_ok(),
            "visa must be stored in the visa table"
        );
        // Forwarding still refuses it until a link to the next hop exists.
        assert!(matches!(
            get_egress_link_for_visa(&asm, inserted),
            Err(visa_table::VisaTableError::DestNotFound(_))
        ));
    }

    /// A Node-mode assembly with an empty visa table and the given
    /// `forwarding` setting.
    fn assembly_with_forwarding(forwarding: bool) -> Arc<Assembly> {
        use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
        let mut builder = TestAssemblyBuilder::new();
        builder.visa_table = Some(visa_table::VisaTable::new());
        builder.config = Some(rcu::RcuBox::new(crate::config::Config {
            forwarding,
            ..Default::default()
        }));
        Arc::new(create_assembly(builder))
    }

    /// With `forwarding` off, a forward-only visa from the visa service is
    /// refused and the table is left unchanged; with it on, the visa is
    /// stored (zl-zipline#219; zl-zpr-dev-context docs/SECURITY_MODEL.md,
    /// Design decisions, "Non-transit has two halves").
    #[test]
    fn test_insert_forward_only_visa_obeys_forwarding_setting() {
        use crate::visa_table::tests::{never_expires, new_vsapi_visa_forward_only};
        let next_hop: IpAddr = "fd5a:5052:8::99".parse().unwrap();

        let asm = assembly_with_forwarding(false);
        let refused = insert_visa(
            &asm,
            new_vsapi_visa_forward_only(7001, never_expires(), next_hop),
        );
        assert!(matches!(
            refused,
            Err(visa_table::VisaTableError::ForwardingDisabled(7001))
        ));
        assert!(asm.visa_table.read().unwrap().is_empty());

        let asm = assembly_with_forwarding(true);
        let stored = insert_visa(
            &asm,
            new_vsapi_visa_forward_only(7002, never_expires(), next_hop),
        );
        assert_eq!(stored.unwrap(), 7002);
        assert!(asm.visa_table.read().unwrap().contains(7002));
    }
}
