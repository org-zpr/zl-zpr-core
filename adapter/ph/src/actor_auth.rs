//! The actor addresses a link's peer may use as a source.
//!
//! A Zode's own actor runs over the `Internal` link pair: its local-actor
//! peer holds the Zode's own addresses ([ActorAuthorization::add_internal_address]),
//! and a bind or stream request from it is accepted only for a source
//! address it owns. The Zode authenticates itself over its VS-API session
//! and a user logs in with [crate::zode_login], so no actor is authorized
//! over a link.

use crate::link_state::LinkType;
use std::fmt;
use zpr_utils::net_defs::IpAddress;

pub struct ActorAuthorization {
    link_type: LinkType,
    addresses: rcu::RcuBox<Vec<IpAddress>>,
}

impl ActorAuthorization {
    pub fn new(link_type: LinkType) -> Self {
        Self {
            link_type,
            addresses: rcu::RcuBox::new(Vec::new()),
        }
    }

    pub fn owns_address(&self, addr: &IpAddress) -> bool {
        self.addresses.get().contains(addr)
    }

    /// Add one of the Zode's own addresses to its `Internal` local-actor
    /// peer. Panics on any other link type: no other link owns addresses.
    pub fn add_internal_address(&self, addr: IpAddress) {
        assert_eq!(self.link_type, LinkType::Internal);
        self.addresses
            .update(|old| {
                let mut addresses = old.clone();
                addresses.push(addr);
                Some(addresses)
            })
            .unwrap();
    }

    /// Test-only: pretend this peer owns `addresses`.
    #[cfg(test)]
    pub fn test_set_addresses(&self, addresses: Vec<IpAddress>) {
        self.addresses.update(|_| Some(addresses.clone())).unwrap();
    }
}

impl fmt::Display for ActorAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Actor addresses: {:?}", *self.addresses.get())
    }
}
