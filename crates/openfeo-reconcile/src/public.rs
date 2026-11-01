// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Public IPv4 blocks and public LANs (SPEC §7.4, §7.5): what the routing, firewall and DNS
//! reconcilers share about `[[public_ipv4]]` and the LANs numbered from it. Validation has
//! already refused blocks and LANs that do not fit, so nothing here reports anything: a block
//! that does not parse is simply not a block.

use ipnet::Ipv4Net;
use openfeo_config::{Config, Lan};

/// The metric of a declared block's blackhole route: a LAN's connected route inside the block
/// (metric 0) wins while its bridge is up; the blackhole catches the rest (SPEC §7.4).
pub const BLOCK_METRIC: u32 = 1000;

/// The declared public blocks that parse, as network prefixes.
#[must_use]
pub fn blocks(config: &Config) -> Vec<Ipv4Net> {
    config
        .public_ipv4
        .iter()
        .filter_map(|block| block.prefix.parse::<Ipv4Net>().ok())
        .map(|net| net.trunc())
        .collect()
}

/// A LAN's subnet (`ipv4` with its host bits cleared), when it parses.
#[must_use]
pub fn lan_subnet(lan: &Lan) -> Option<Ipv4Net> {
    lan.ipv4.parse::<Ipv4Net>().ok().map(|net| net.trunc())
}

/// Whether the LAN is numbered from one of the declared blocks: a public LAN, never translated,
/// reached from the WAN only through rules (SPEC §7.5).
#[must_use]
pub fn lan_is_public(lan: &Lan, blocks: &[Ipv4Net]) -> bool {
    lan_subnet(lan).is_some_and(|net| blocks.iter().any(|block| block.contains(&net)))
}

/// The private LANs' subnets: the sources that are masqueraded and the rebinding guard
/// (SPEC §7.5, §7.7).
#[must_use]
pub fn private_subnets(config: &Config) -> Vec<Ipv4Net> {
    let blocks = blocks(config);
    config
        .lans
        .iter()
        .filter(|lan| !lan_is_public(lan, &blocks))
        .filter_map(lan_subnet)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn public_helpers_tell_a_dmz_from_a_private_lan() {
        let world = fixtures::public_world();
        let blocks = blocks(&world.config);
        assert_eq!(
            blocks.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["192.0.2.232/29", "192.0.2.248/29"]
        );
        assert!(lan_is_public(&world.config.lans[1], &blocks));
        assert!(!lan_is_public(&world.config.lans[0], &blocks));
        assert_eq!(
            lan_subnet(&world.config.lans[1]).map(|n| n.to_string()),
            Some("192.0.2.232/29".to_owned())
        );
        assert_eq!(
            private_subnets(&world.config)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.168.1.0/24"]
        );
        assert_eq!(BLOCK_METRIC, 1000);
    }
}
