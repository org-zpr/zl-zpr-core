//! Zipline: adapter-side activation of a granted actor address.
//!
//! Upstream #1410's [crate::actor_auth::ActorAuthorization] installs the
//! granted address on the TUN. Zipline adds host checks around that step,
//! all of which run here so the upstream module only calls one function:
//!
//! - zipline#83: a configured `--zpr-addr` / `zpr_addr` is a *demand*. A
//!   grant for a different address is fatal: the adapter exits non-zero.
//! - zipline#101: only one adapter per host may own the ZPR internal
//!   network route; check for another owner before and after installing ours.
//! - zipline#88: install the internal-network route so replies to peers on
//!   fabric-assigned addresses are not dropped.
//! - zipline#157: a local activation failure is fatal for this connect
//!   request ([AuthFailureReason::ActivationFailed]), not retried.
//!
//! On a *static* grant (an address was configured) the deployment
//! provisioned addressing and routes out of band, so route problems are
//! warnings. On a *dynamic* grant fabric-installed state is all the adapter
//! has, so they fail the activation (operator ruling, zipline#88).

use crate::auth_agent::AuthFailureReason;
use crate::prelude::*;

use std::net::IpAddr;
use zpr::addrs::{ZPR_INTERNAL_NETWORK, ZPRNET_PREFIX_LEN};
use zpr_utils::net_defs::IpAddress;

/// Activate `granted` on this adapter. Returns whether this call added the
/// address to the TUN (and so owns removing it at teardown).
///
/// On error nothing this call added is left behind except the internal
/// network route, and for [AuthFailureReason::GrantedAddressMismatch] the
/// process has been told to exit ([Assembly::signal_fatal_error]).
pub fn activate_granted_address(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    granted: IpAddress,
) -> Result<bool, AuthFailureReason> {
    let link = asm.formatted_link_id(link_id).to_string();

    // zipline#83: compare against the STARTUP demand, frozen in
    // `configured_zpr_addr_demand`, so an adapter started without
    // `--zpr-addr` keeps accepting fabric-assigned addresses on every
    // reconnect even when they differ from the previous grant.
    let configured = asm.configured_zpr_addr_demand.clone();
    let granted_std = IpAddr::from(granted);
    if !configured.is_empty() && configured != [granted_std] {
        let msg = format!(
            "fabric granted ZPR address {granted_std} but this adapter is configured to \
             demand {configured:?}; it cannot originate traffic from an address it was not \
             granted. Remove the --zpr-addr argument / zpr_addr config line and try again \
             to accept a fabric-assigned address."
        );
        error!(target: LINK_STATE, "{link} {msg}");
        asm.signal_fatal_error(msg);
        return Err(AuthFailureReason::GrantedAddressMismatch {
            requested: configured,
            granted: vec![granted_std],
        });
    }
    let dynamic = configured.is_empty();

    // TODO(#938): TUN subprocess I/O blocks the LocalSet.
    let owned = match asm.tun_ctl.has_address(granted_std) {
        Ok(true) => false,
        Ok(false) => {
            asm.tun_ctl
                .add_address(granted_std, ZPRNET_PREFIX_LEN)
                .map_err(|e| {
                    AuthFailureReason::ActivationFailed(format!(
                        "failed to set ZPR address {granted}: {e}"
                    ))
                })?;
            true
        }
        Err(e) => {
            return Err(AuthFailureReason::ActivationFailed(format!(
                "failed to inspect ZPR address {granted}: {e}"
            )));
        }
    };

    let result = install_internal_network_route(asm, &link, dynamic);
    if result.is_err() && owned {
        if let Err(e) = asm.tun_ctl.clear_address(granted_std, ZPRNET_PREFIX_LEN) {
            error!(target: LINK_STATE, "{link} cannot clear ZPR address {granted} after failed activation: {e}");
        }
    }
    result.map(|()| owned)
}

/// The zipline#101 / zipline#88 route steps: refuse a route another live
/// interface already owns, install ours, then re-check.
///
/// The pre-install probe cannot see a concurrent adapter whose route is not
/// yet live, so two adapters activating at once can both pass it. Each
/// re-probes only AFTER its own route is installed (and, since #1410, its
/// carrier has been up since Hello), so two overlapping activations cannot
/// both observe a clear table: at least one backs off. A probe error means
/// "unknown", never "conflict".
fn install_internal_network_route(
    asm: &Arc<Assembly>,
    link: &str,
    dynamic: bool,
) -> Result<(), AuthFailureReason> {
    let net = IpAddr::V6(ZPR_INTERNAL_NETWORK);
    let route = format!("{ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN}");

    check_route_owner(asm, link, dynamic, &route, "")?;

    // With a /32 address the kernel already installed this route; the
    // explicit install matters when the address was provisioned with a
    // longer prefix (e.g. /128).
    if let Err(e) = asm.tun_ctl.add_route(net, ZPRNET_PREFIX_LEN) {
        if dynamic {
            warn!(target: LINK_STATE, "{link} failed to install ZPR internal-network route {route}: {e}; a dynamically addressed adapter cannot function without it");
            return Err(AuthFailureReason::ActivationFailed(format!(
                "failed to install ZPR internal-network route {route}: {e}"
            )));
        }
        warn!(target: LINK_STATE, "{link} failed to install ZPR internal-network route {route}: {e}; continuing — statically provisioned deployments may already carry it");
    }

    check_route_owner(asm, link, dynamic, &route, " after carrier-up")
}

/// One route-owner probe. `when` is appended to messages to tell the pre-
/// and post-install probes apart.
fn check_route_owner(
    asm: &Arc<Assembly>,
    link: &str,
    dynamic: bool,
    route: &str,
    when: &str,
) -> Result<(), AuthFailureReason> {
    match asm
        .tun_ctl
        .route_owner_conflict(IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN)
    {
        Ok(None) => Ok(()),
        Ok(Some(owner_if)) if dynamic => {
            warn!(target: LINK_STATE, "{link} {route} routes to interface {owner_if}{when} — another ZPR adapter or tool owns ZPR traffic on this host; failing activation");
            Err(AuthFailureReason::ActivationFailed(format!(
                "{route} routes to interface {owner_if}{when} — another ZPR adapter or tool \
                 already owns ZPR traffic on this host"
            )))
        }
        Ok(Some(owner_if)) => {
            warn!(target: LINK_STATE, "{link} {route} routes to interface {owner_if}{when}; continuing — statically provisioned deployments may carry their own routes");
            Ok(())
        }
        Err(e) => {
            warn!(target: LINK_STATE, "{link} could not check the owner of {route}{when}: {e}; continuing");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{RecordingTunCtl, TestAssemblyBuilder, create_assembly};

    /// The address the fabric grants in these tests.
    fn granted() -> IpAddr {
        "fd5a:5052:adda:1::42".parse().unwrap()
    }

    /// The ZPR internal-network route activation installs (zipline#88).
    fn internal_route() -> (IpAddr, u8) {
        (IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN)
    }

    /// An adapter assembly started with `configured` as its `--zpr-addr`
    /// demand (empty: accept a fabric-assigned address) around `tun_ctl`.
    fn assembly(configured: &[IpAddr], tun_ctl: RecordingTunCtl) -> Arc<Assembly> {
        let config = crate::config::Config {
            zpr_addr: configured.to_vec(),
            ..Default::default()
        };
        Arc::new(create_assembly(TestAssemblyBuilder {
            config: Some(rcu::RcuBox::new(config)),
            tun_ctl: Some(Box::new(tun_ctl)),
            ..TestAssemblyBuilder::new()
        }))
    }

    /// Activate [granted] on the dock link.
    fn activate(asm: &Arc<Assembly>) -> Result<bool, AuthFailureReason> {
        activate_granted_address(asm, DOCK_LINK_ID, IpAddress::new_from_std(&granted()))
    }

    /// The `ActivationFailed` text of `result`, or a panic naming what
    /// came back instead.
    fn activation_failure(result: Result<bool, AuthFailureReason>) -> String {
        match result {
            Err(AuthFailureReason::ActivationFailed(msg)) => msg,
            other => panic!("expected ActivationFailed, got {other:?}"),
        }
    }

    /// zipline#83: a grant that differs from the non-empty configured
    /// `--zpr-addr` is refused with `GrantedAddressMismatch` carrying both
    /// address sets (ActorAuthorization records it and fails the link), the
    /// TUN is left untouched, and main's fatal-error watcher is signalled
    /// with the remedy (remove the `--zpr-addr` argument / `zpr_addr`
    /// config line) so the process exits non-zero.
    #[test]
    fn test_grant_address_mismatch_refuses_to_run() {
        let configured: IpAddr = "fd00:1:1::1".parse().unwrap();
        let (tun_ctl, routes) = RecordingTunCtl::new(false);
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[configured], tun_ctl);

        match activate(&asm) {
            Err(AuthFailureReason::GrantedAddressMismatch {
                requested,
                granted: g,
            }) => {
                assert_eq!(requested, vec![configured]);
                assert_eq!(g, vec![granted()]);
            }
            other => panic!("expected GrantedAddressMismatch, got {other:?}"),
        }
        assert!(
            addresses.lock().unwrap().is_empty() && routes.lock().unwrap().is_empty(),
            "a refused grant must not touch the TUN"
        );

        let fatal = asm
            .get_fatal_error()
            .expect("a mismatched grant must signal a fatal error so main exits non-zero");
        assert!(
            fatal.contains("--zpr-addr") && fatal.contains("zpr_addr"),
            "the fatal error must carry the remedy (remove the \
             --zpr-addr argument / zpr_addr config line); got: {fatal}"
        );
        assert!(
            fatal.contains("fd00:1:1::1") && fatal.contains("fd5a:5052:adda:1::42"),
            "the fatal error must name both addresses; got: {fatal}"
        );
    }

    /// zipline#83 companion: an adapter with NO configured address accepts
    /// the dynamic grant — the TUN gets the granted address, the call
    /// reports that it owns it, and no fatal error is signalled.
    #[test]
    fn test_grant_with_no_configured_address_is_accepted() {
        let (tun_ctl, _routes) = RecordingTunCtl::new(false);
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert_eq!(*addresses.lock().unwrap(), vec![granted()]);
        assert_eq!(asm.get_fatal_error(), None);
    }

    /// zipline#83 review fix (PR #27): an adapter started with NO
    /// `--zpr-addr` accepts its first dynamic grant — and on a later
    /// reconnect must accept a DIFFERENT dynamic grant too. The demand the
    /// mismatch check enforces is the *startup* configuration, frozen in
    /// `configured_zpr_addr_demand`, not whatever the fabric granted last
    /// time.
    #[test]
    fn test_reconnect_after_dynamic_grant_accepts_different_dynamic_address() {
        let second: IpAddr = "fd5a:5052:adda:1::99".parse().unwrap();
        let (tun_ctl, _routes) = RecordingTunCtl::new(false);
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        // Link teardown clears the owned address before the reconnect.
        asm.tun_ctl
            .clear_address(granted(), ZPRNET_PREFIX_LEN)
            .unwrap();

        assert_eq!(
            activate_granted_address(&asm, DOCK_LINK_ID, IpAddress::new_from_std(&second)),
            Ok(true),
            "the reconnect's different dynamic grant must be accepted"
        );
        assert_eq!(*addresses.lock().unwrap(), vec![second]);
        assert_eq!(
            asm.get_fatal_error(),
            None,
            "no fatal exit: the adapter was configured to accept any \
             fabric-assigned address"
        );
    }

    /// zipline#83 companion: a grant matching the configured address is the
    /// normal path and must stay unchanged — success, no fatal.
    #[test]
    fn test_grant_matching_configured_address_stays_active() {
        let (tun_ctl, _routes) = RecordingTunCtl::new(false);
        let asm = assembly(&[granted()], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert_eq!(asm.get_fatal_error(), None);
    }

    /// zipline#88: an adapter accepting a *dynamic* grant (no configured
    /// address) must install an on-link route for the whole ZPR internal
    /// network (`fd5a:5052::/32`) on its TUN at activation, so traffic to
    /// and from fabric-assigned (dynamic-pool) addresses has a route.
    #[test]
    fn test_dynamic_grant_installs_internal_net_route() {
        let (tun_ctl, routes) = RecordingTunCtl::new(false);
        let asm = assembly(&[], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert!(
            routes.lock().unwrap().contains(&internal_route()),
            "activation on a dynamic grant must install the ZPR internal-network \
             route; recorded routes: {:?}",
            routes.lock().unwrap()
        );
    }

    /// zipline#88: the statically-addressed activation path (grant matching
    /// the configured demand) must install the same internal-network route —
    /// the peer side of the return path: a static adapter with only its own
    /// deployment-provisioned routes has no route back to a
    /// dynamically-addressed peer, so its replies are dropped.
    #[test]
    fn test_static_grant_installs_internal_net_route() {
        let (tun_ctl, routes) = RecordingTunCtl::new(false);
        let asm = assembly(&[granted()], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert!(
            routes.lock().unwrap().contains(&internal_route()),
            "activation on a static grant must install the ZPR internal-network \
             route; recorded routes: {:?}",
            routes.lock().unwrap()
        );
    }

    /// zipline#88 (fail-fast leg) / zipline#157 (site 2): on a *dynamic*
    /// grant the adapter's reachability rides entirely on fabric-installed
    /// state, so a failed route install fails the activation exactly like a
    /// failed `add_address`: `ActivationFailed` naming the route install
    /// (which ActorAuthorization records for ph-cli), and the address this
    /// call added is removed again.
    #[test]
    fn test_dynamic_grant_route_install_failure_is_fatal() {
        let (tun_ctl, _routes) = RecordingTunCtl::new(true);
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);

        let msg = activation_failure(activate(&asm));
        assert!(
            msg.contains("internal-network route"),
            "the failure must name the route install; got: {msg}"
        );
        assert!(
            addresses.lock().unwrap().is_empty(),
            "a failed activation must remove the address it added"
        );
    }

    /// zipline#88 (warn-and-continue leg): on the static-address path the
    /// deployment provisioned the TUN's addressing and routes out of band,
    /// so a failed route install is a warning, not a reason to refuse a
    /// link that may work.
    #[test]
    fn test_static_grant_route_install_failure_warns_and_continues() {
        let (tun_ctl, _routes) = RecordingTunCtl::new(true);
        let asm = assembly(&[granted()], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert_eq!(asm.get_fatal_error(), None);
    }

    /// zipline#101 (fail-fast leg) / zipline#157 (site 3): on a *dynamic*
    /// grant, another live interface already owning fd5a:5052::/32 means
    /// this adapter's route would lose and it would activate into silence —
    /// the activation fails with `ActivationFailed` naming the conflicting
    /// interface, before any route is installed, and the added address is
    /// removed again.
    #[test]
    fn test_dynamic_grant_route_owner_conflict_is_fatal() {
        let (tun_ctl, routes) = RecordingTunCtl::with_conflict("tunA");
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);

        let msg = activation_failure(activate(&asm));
        assert!(
            msg.contains("tunA"),
            "the failure must name the conflicting owner; got: {msg}"
        );
        assert!(
            routes.lock().unwrap().is_empty(),
            "a conflicting route owner must stop the activation before our route is installed"
        );
        assert!(addresses.lock().unwrap().is_empty());
    }

    /// zipline#101 (warn-and-continue leg): on the static-address path a
    /// route owned elsewhere is a warning, consistent with the zipline#88
    /// ruling for a failed route install on that path.
    #[test]
    fn test_static_grant_route_owner_conflict_warns_and_continues() {
        let (tun_ctl, routes) = RecordingTunCtl::with_conflict("tunA");
        let asm = assembly(&[granted()], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert!(routes.lock().unwrap().contains(&internal_route()));
        assert_eq!(asm.get_fatal_error(), None);
    }

    /// zipline#101 (concurrent-activation race, Codex P1 on PR #35) /
    /// zipline#157 (site 3 variant): two adapters activating at once can
    /// both pass the pre-install probe, so the claim must be re-verified
    /// after our route is installed (since #1410 our carrier has been up
    /// since Hello). On a dynamic grant a conflict on that re-probe fails
    /// the activation with `ActivationFailed` naming the late conflict, and
    /// the claim is retracted: the address this call added is removed.
    /// (Carrier itself now belongs to the link and drops when
    /// ActorAuthorization fails it.)
    #[test]
    fn test_dynamic_grant_late_route_owner_conflict_backs_off() {
        let (tun_ctl, _routes) = RecordingTunCtl::with_late_conflict("tunA");
        let probes = tun_ctl.probes.clone();
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);

        let msg = activation_failure(activate(&asm));
        assert!(
            probes.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the ownership claim must be re-verified after our route is installed"
        );
        assert!(
            msg.contains("tunA") && msg.contains("carrier-up"),
            "the failure must name the late conflict; got: {msg}"
        );
        assert!(
            addresses.lock().unwrap().is_empty(),
            "the losing adapter must retract its address claim"
        );
    }

    /// zipline#101: on the static-address path a conflict surfacing on the
    /// post-install re-probe is a warning, consistent with the zipline#88
    /// ruling for the pre-install probe and the route install on that path.
    #[test]
    fn test_static_grant_late_route_owner_conflict_warns_and_continues() {
        let (tun_ctl, _routes) = RecordingTunCtl::with_late_conflict("tunA");
        let probes = tun_ctl.probes.clone();
        let asm = assembly(&[granted()], tun_ctl);

        assert_eq!(activate(&asm), Ok(true));
        assert!(probes.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        assert_eq!(asm.get_fatal_error(), None);
    }

    /// zipline#157 (site 1: address set): a failed `add_address` is a
    /// LOCAL, non-transient failure (e.g. EPERM — it will not clear on
    /// reconnect), so it is `ActivationFailed` naming the address-set step:
    /// the durable trace showLink prints and ph-cli's `connect` reports as
    /// this attempt's terminal outcome. Nothing else is attempted. (That the
    /// reconnect loop then hard-stops is a link-level test.)
    #[test]
    fn test_add_address_failure_is_fatal() {
        let (tun_ctl, routes) = RecordingTunCtl::with_failing_addresses();
        let asm = assembly(&[], tun_ctl);

        let msg = activation_failure(activate(&asm));
        assert!(
            msg.contains("failed to set ZPR address"),
            "the failure must name the address-set step; got: {msg}"
        );
        assert!(routes.lock().unwrap().is_empty());
    }

    /// Cleanup contract (#1410 merge): an address that was already on the
    /// TUN (provisioned out of band) is not ours — activation reports
    /// `owned == false`, so link teardown leaves it alone, and a failed
    /// activation does not remove it either.
    #[test]
    fn test_preexisting_address_is_not_owned_and_survives_failure() {
        let (tun_ctl, _routes) = RecordingTunCtl::new(false);
        tun_ctl.addresses.lock().unwrap().push(granted());
        let asm = assembly(&[], tun_ctl);
        assert_eq!(activate(&asm), Ok(false));

        let (tun_ctl, _routes) = RecordingTunCtl::with_conflict("tunA");
        tun_ctl.addresses.lock().unwrap().push(granted());
        let addresses = tun_ctl.addresses.clone();
        let asm = assembly(&[], tun_ctl);
        activation_failure(activate(&asm));
        assert_eq!(
            *addresses.lock().unwrap(),
            vec![granted()],
            "a failed activation must not remove an address it did not add"
        );
    }
}
