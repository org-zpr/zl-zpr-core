//! Zode links: who owns a link, and which keyed peers a Zode accepts
//! (docs/ZODE_LINKS.md rules 1-5, zl-zipline#250).
//!
//! A link between two Zodes has exactly one **owner**, the only end that
//! ever dials it (rules 1 and 2). That is what keeps a pair of Zodes at one
//! link without races or tie-breaks:
//!
//! - this Zode's configured initial link is always owned by this Zode, even
//!   when the relay also appears in the topology ("Kinds of link");
//! - a relay owns nothing and never dials (rule 4);
//! - otherwise the end with the lower ZPR address owns a topology link.
//!
//! Keyed peers are checked once their certificate CN is known, at
//! `KeyingDone` (rules 3 and 4): a dialer accepts only the CN it dialed for,
//! and an answerer accepts only a peer in its current topology that owns the
//! link. A relay's ownership rule makes every topology peer the owner, so the
//! same check covers it.

use crate::assembly::Assembly;
use crate::config::Config;
use crate::link_state::{LinkType, ZodeEnd};
use crate::prelude::*;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use thiserror::Error;

/// The end of a Zode link that owns it: the only end that dials it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    ThisZode,
    Peer,
}

/// Why the owner of a Zode link cannot be decided. Such a link is invalid:
/// it is refused and logged, never guessed at.
#[derive(Copy, Clone, Debug, Error, PartialEq, Eq)]
pub enum OwnerError {
    /// Both ends claim the same ZPR address, so neither is the lower.
    #[error("both ends have ZPR address {0}")]
    EqualAddresses(IpAddr),
    /// This Zode has no ZPR address configured (a node always has one).
    #[error("this Zode has no ZPR address")]
    NoSelfAddress,
}

/// Which end owns a link between ZPR addresses `self_addr` and `peer_addr`
/// by address order alone: the lower address. Addresses compare as 128-bit
/// unsigned integers, an IPv4 address as its IPv4-mapped IPv6 form.
pub fn owner_of(self_addr: IpAddr, peer_addr: IpAddr) -> Result<Owner, OwnerError> {
    let (ours, theirs) = (address_order_key(self_addr), address_order_key(peer_addr));
    if ours == theirs {
        return Err(OwnerError::EqualAddresses(self_addr));
    }
    Ok(if ours < theirs {
        Owner::ThisZode
    } else {
        Owner::Peer
    })
}

/// The 128-bit integer an address is ordered by (IPv4 as IPv4-mapped IPv6).
fn address_order_key(addr: IpAddr) -> u128 {
    let v6 = match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    u128::from(v6)
}

/// Who owns this Zode's link to the peer whose certificate CN is `peer_cn`
/// and whose ZPR address is `peer_addr`. The one ownership rule used
/// everywhere; see the module comment. This Zode's own address is
/// `zpr_addr[0]`, the address it authenticates with.
pub fn link_owner(config: &Config, peer_cn: &str, peer_addr: IpAddr) -> Result<Owner, OwnerError> {
    if config
        .initial_link
        .as_ref()
        .is_some_and(|link| link.cn == peer_cn)
    {
        return Ok(Owner::ThisZode);
    }
    if config.relay {
        return Ok(Owner::Peer);
    }
    let self_addr = *config.zpr_addr.first().ok_or(OwnerError::NoSelfAddress)?;
    owner_of(self_addr, peer_addr)
}

/// Why a keyed Zode link is refused. Each is logged with the link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Keying produced no verified certificate CN.
    NoVerifiedCn,
    /// This Zode dialed for one CN and the peer presented another.
    WrongCn { dialed: String },
    /// The peer's CN is not in this Zode's current topology (rule 3).
    UnknownCn,
    /// The peer is in the topology, but this Zode owns the link, so the
    /// peer should not have dialed it (rule 3).
    PeerIsNotOwner,
    /// The link's owner cannot be decided.
    Owner(OwnerError),
}

impl Display for Refusal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoVerifiedCn => write!(f, "no verified certificate CN"),
            Refusal::WrongCn { dialed } => write!(f, "dialed for CN {dialed:?}, got another"),
            Refusal::UnknownCn => write!(f, "unknown CN"),
            Refusal::PeerIsNotOwner => write!(f, "peer is not the owner"),
            Refusal::Owner(e) => write!(f, "invalid link: {e}"),
        }
    }
}

/// Decide whether to keep a keyed Zode link whose peer presented the
/// verified certificate CN `peer_cn`, with this Zode at `end` of the link
/// (rules 3 and 4). Runs at `KeyingDone`, when the CN is first known.
pub fn check_keyed_peer(
    asm: &Assembly,
    end: &ZodeEnd,
    peer_cn: Option<&str>,
) -> Result<(), Refusal> {
    let peer_cn = peer_cn
        .filter(|cn| !cn.is_empty())
        .ok_or(Refusal::NoVerifiedCn)?;
    match end {
        ZodeEnd::Dialer { peer_cn: dialed } if dialed == peer_cn => Ok(()),
        ZodeEnd::Dialer { peer_cn: dialed } => Err(Refusal::WrongCn {
            dialed: dialed.clone(),
        }),
        ZodeEnd::Answerer => {
            let peer_addr = asm
                .topology
                .read()
                .unwrap()
                .iter()
                .find(|link| link.peer_cn == peer_cn)
                .map(|link| link.zpr_addr)
                .ok_or(Refusal::UnknownCn)?;
            match link_owner(&asm.config.get(), peer_cn, peer_addr) {
                Ok(Owner::Peer) => Ok(()),
                Ok(Owner::ThisZode) => Err(Refusal::PeerIsNotOwner),
                Err(e) => Err(Refusal::Owner(e)),
            }
        }
    }
}

/// Rule 5: the inbound link `link_id`, just accepted from the peer with
/// certificate CN `peer_cn`, replaces every other link to that peer. Each old
/// link is dropped with all its state, and `link_id` takes over the peer's
/// substrate address if an old link held it (a same-address redial, gate g78
/// q5). Leaves exactly one link to the peer.
pub fn replace_established_links(asm: &Arc<Assembly>, link_id: LinkId, peer_cn: &str) {
    let mut replaced = Vec::new();
    asm.peer_table.for_each(|(id, peer)| {
        if id.get() != link_id
            && peer.link_state_machine.get_link_type() == LinkType::NodeToNode
            && peer.verified_peer_cn().as_deref() == Some(peer_cn)
        {
            replaced.push(id.get());
        }
    });
    for old in replaced {
        info!(target: LINK_STATE, "{} replaces {} to peer CN {peer_cn:?}; dropping the old link",
            asm.formatted_link_id(link_id), asm.formatted_link_id(old));
        if let Some(peer) = asm.peer_table.get(old) {
            peer.link_state_machine.drop_replaced(asm);
        }
    }
    asm.peer_table.map_substrate_addr(link_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::config::InitialLink;
    use crate::peer_table::test::topology_link_at;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The lower address owns: IPv6 against IPv6, IPv4 against IPv4, and
    /// IPv4 (as IPv4-mapped IPv6, `::ffff:a.b.c.d`) against IPv6. Equal
    /// addresses decide nothing.
    #[test]
    fn test_owner_of() {
        assert_eq!(owner_of(ip("fd5a::1"), ip("fd5a::2")), Ok(Owner::ThisZode));
        assert_eq!(owner_of(ip("fd5a::2"), ip("fd5a::1")), Ok(Owner::Peer));
        assert_eq!(
            owner_of(ip("10.0.0.1"), ip("10.0.0.2")),
            Ok(Owner::ThisZode)
        );
        assert_eq!(owner_of(ip("10.0.0.2"), ip("10.0.0.1")), Ok(Owner::Peer));
        // ::ffff:10.0.0.1 is below fd5a::1 and above ::1.
        assert_eq!(owner_of(ip("10.0.0.1"), ip("fd5a::1")), Ok(Owner::ThisZode));
        assert_eq!(owner_of(ip("10.0.0.1"), ip("::1")), Ok(Owner::Peer));
        assert_eq!(
            owner_of(ip("10.0.0.1"), ip("::ffff:10.0.0.1")),
            Err(OwnerError::EqualAddresses(ip("10.0.0.1")))
        );
        assert_eq!(
            owner_of(ip("fd5a::1"), ip("fd5a::1")),
            Err(OwnerError::EqualAddresses(ip("fd5a::1")))
        );
    }

    /// A Zode config with ZPR address `self_addr`.
    fn zode_config(self_addr: &str) -> Config {
        Config {
            zpr_addr: vec![ip(self_addr)],
            ..Config::default()
        }
    }

    /// The ownership matrix: the initial link wins over address order, a
    /// relay owns nothing, and otherwise the lower address owns.
    #[test]
    fn test_link_owner() {
        let config = zode_config("fd5a::5");
        assert_eq!(link_owner(&config, "b", ip("fd5a::9")), Ok(Owner::ThisZode));
        assert_eq!(link_owner(&config, "b", ip("fd5a::1")), Ok(Owner::Peer));
        assert_eq!(
            link_owner(&config, "b", ip("fd5a::5")),
            Err(OwnerError::EqualAddresses(ip("fd5a::5")))
        );

        // The initial link's relay sits at a lower address, and is in the
        // topology too: this Zode still owns the link to it.
        let mut config = zode_config("fd5a::5");
        config.initial_link = Some(InitialLink::parse_cli("relay@10.0.0.9:5000").unwrap());
        assert_eq!(
            link_owner(&config, "relay", ip("fd5a::1")),
            Ok(Owner::ThisZode)
        );
        assert_eq!(link_owner(&config, "b", ip("fd5a::1")), Ok(Owner::Peer));

        // A relay owns nothing, whatever the address order.
        let mut config = zode_config("fd5a::1");
        config.relay = true;
        assert_eq!(link_owner(&config, "b", ip("fd5a::9")), Ok(Owner::Peer));

        assert_eq!(
            link_owner(&Config::default(), "b", ip("fd5a::9")),
            Err(OwnerError::NoSelfAddress)
        );
    }

    /// A Zode assembly with `config` and a topology of (CN, ZPR address)
    /// links.
    fn zode(config: Config, topology: &[(&str, &str)]) -> Assembly {
        let asm = create_assembly(TestAssemblyBuilder {
            ph_mode: Some(crate::assembly::PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            ..TestAssemblyBuilder::new()
        });
        *asm.topology.write().unwrap() = topology
            .iter()
            .map(|(cn, addr)| topology_link_at(cn, ip(addr)))
            .collect();
        asm
    }

    /// The KeyingDone matrix for an answering Zode at fd5a::5 (rule 3).
    #[test]
    fn test_check_keyed_peer_answerer() {
        let asm = zode(
            zode_config("fd5a::5"),
            &[
                ("lower", "fd5a::1"),
                ("higher", "fd5a::9"),
                ("same", "fd5a::5"),
            ],
        );
        let answer = |cn| check_keyed_peer(&asm, &ZodeEnd::Answerer, cn);
        assert_eq!(answer(Some("lower")), Ok(()), "the peer owns the link");
        assert_eq!(answer(Some("higher")), Err(Refusal::PeerIsNotOwner));
        assert_eq!(answer(Some("stranger")), Err(Refusal::UnknownCn));
        assert_eq!(
            answer(Some("same")),
            Err(Refusal::Owner(OwnerError::EqualAddresses(ip("fd5a::5"))))
        );
        assert_eq!(answer(None), Err(Refusal::NoVerifiedCn));
        assert_eq!(answer(Some("")), Err(Refusal::NoVerifiedCn));
    }

    /// A relay accepts any peer in its topology, whatever the address
    /// order, and nothing else (rule 4).
    #[test]
    fn test_check_keyed_peer_relay() {
        let mut config = zode_config("fd5a::1");
        config.relay = true;
        let asm = zode(config, &[("b", "fd5a::9")]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("b")),
            Ok(())
        );
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("c")),
            Err(Refusal::UnknownCn)
        );
    }

    /// An endpoint owns its initial link, so a dial from its relay is
    /// refused, whether or not the relay is also in its topology.
    #[test]
    fn test_check_keyed_peer_endpoint_refuses_its_relay() {
        let mut config = zode_config("fd5a::9");
        config.initial_link = Some(InitialLink::parse_cli("relay@10.0.0.9:5000").unwrap());
        let asm = zode(config.clone(), &[("relay", "fd5a::1")]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("relay")),
            Err(Refusal::PeerIsNotOwner)
        );
        let asm = zode(config, &[]);
        assert_eq!(
            check_keyed_peer(&asm, &ZodeEnd::Answerer, Some("relay")),
            Err(Refusal::UnknownCn)
        );
    }

    /// A dialer accepts exactly the CN it dialed for, topology or not.
    #[test]
    fn test_check_keyed_peer_dialer() {
        let asm = zode(zode_config("fd5a::5"), &[]);
        let dialer = ZodeEnd::Dialer {
            peer_cn: "relay".to_owned(),
        };
        assert_eq!(check_keyed_peer(&asm, &dialer, Some("relay")), Ok(()));
        assert_eq!(
            check_keyed_peer(&asm, &dialer, Some("other")),
            Err(Refusal::WrongCn {
                dialed: "relay".to_owned()
            })
        );
        assert_eq!(
            check_keyed_peer(&asm, &dialer, None),
            Err(Refusal::NoVerifiedCn)
        );
    }
}
