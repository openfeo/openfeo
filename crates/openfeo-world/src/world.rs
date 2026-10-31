// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The snapshot every reconciler reads (SPEC §6.2): config, the live port map and link facts,
//! behind `Arc`s so a new generation is cheap to make and share.

use std::collections::BTreeMap;
use std::sync::Arc;

use openfeo_config::{Config, PortMap};

use crate::{Dhcp4Fact, LeaseFact, MacAddr};

/// What the netlink monitor knows about one interface (SPEC §7.1: link state is a fact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFact {
    /// Kernel interface index.
    pub index: u32,
    /// Kernel interface name.
    pub name: String,
    /// Administratively up (`IFF_UP`).
    pub up: bool,
    /// Carrier present (`IFF_LOWER_UP`).
    pub carrier: bool,
    /// Hardware address, when the link has one.
    pub mac: Option<MacAddr>,
    /// MTU in bytes.
    pub mtu: u32,
}

/// One immutable snapshot. Reconcilers are `fn(&World) -> Desired`.
#[derive(Debug, Clone, PartialEq)]
pub struct World {
    /// Monotonic; bumped on every change.
    pub generation: u64,
    /// The running configuration.
    pub config: Arc<Config>,
    /// The live port map (identity to `pN`).
    pub ports: Arc<PortMap>,
    /// Link facts keyed by interface name.
    pub links: Arc<BTreeMap<String, LinkFact>>,
    /// DHCPv4 leases keyed by WAN name (SPEC §7.2).
    pub dhcp4: Arc<BTreeMap<String, Dhcp4Fact>>,
    /// The leases each LAN's DHCPv4 server has granted, keyed by LAN name, ascending by
    /// address (SPEC §7.6).
    pub leases: Arc<BTreeMap<String, Vec<LeaseFact>>>,
}

impl World {
    /// Generation 0 with no facts yet.
    #[must_use]
    pub fn new(config: Config, ports: PortMap) -> Self {
        World {
            generation: 0,
            config: Arc::new(config),
            ports: Arc::new(ports),
            links: Arc::new(BTreeMap::new()),
            dhcp4: Arc::new(BTreeMap::new()),
            leases: Arc::new(BTreeMap::new()),
        }
    }

    /// The MAC of the named link, if the monitor has reported one.
    #[must_use]
    pub fn mac_of(&self, name: &str) -> Option<MacAddr> {
        self.links.get(name).and_then(|link| link.mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{Config, PortMap};

    #[test]
    fn world_new_starts_at_generation_zero_with_no_links() {
        let w = World::new(Config::default(), PortMap::default());
        assert_eq!(w.generation, 0);
        assert!(w.links.is_empty());
        assert_eq!(w.config.config_version, 0);
    }
}
