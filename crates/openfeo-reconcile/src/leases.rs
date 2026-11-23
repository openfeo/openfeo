// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lease table (SPEC §7.6, §8.3): every LAN's DHCPv4 leases as the API serves them, a pure
//! function of the World, built where `State` is. `State` itself carries only a count per LAN.

use openfeo_config::state::{Lease, Leases};
use openfeo_world::World;

/// The most leases one table holds: it fits a frame with room to spare. A router for a home
/// does not reach it.
pub const MAX_LEASES: usize = 4096;

/// Every LAN's leases that have not run out at `now_unix_ms`, by LAN in config order and then
/// by address. With more than [`MAX_LEASES`], the newest by joined time are kept and the table
/// says that it was cut. A lease has run out by the rule the state's count per LAN uses, so
/// the two agree.
#[must_use]
pub fn leases(world: &World, now_unix_ms: u64) -> Leases {
    let mut found: Vec<Lease> = world
        .config
        .lans
        .iter()
        .flat_map(|lan| {
            let mut facts: Vec<_> = world
                .leases
                .get(&lan.name)
                .into_iter()
                .flatten()
                .filter(|fact| fact.expires_unix.saturating_mul(1000) > now_unix_ms)
                .collect();
            facts.sort_by_key(|fact| fact.address);
            facts.into_iter().map(|fact| Lease {
                lan: lan.name.clone(),
                address: fact.address.to_string(),
                mac: fact.mac.to_string(),
                hostname: fact.hostname.clone().unwrap_or_default(),
                joined_unix: fact.joined_unix,
                expires_unix: fact.expires_unix,
            })
        })
        .collect();
    let truncated = found.len() > MAX_LEASES;
    if truncated {
        // The cut is at the joined time of the last one kept; leases that share it are kept
        // in the table's own order until it is full.
        let mut joined: Vec<u64> = found.iter().map(|lease| lease.joined_unix).collect();
        joined.sort_unstable_by(|a, b| b.cmp(a));
        let cut = joined[MAX_LEASES - 1];
        let mut at_cut = joined[..MAX_LEASES]
            .iter()
            .filter(|joined| **joined == cut)
            .count();
        found.retain(|lease| {
            if lease.joined_unix > cut {
                true
            } else if lease.joined_unix == cut && at_cut > 0 {
                at_cut -= 1;
                true
            } else {
                false
            }
        });
    }
    Leases {
        time_unix: now_unix_ms / 1000,
        leases: found,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use openfeo_world::{LeaseFact, MacAddr, World};

    use super::*;
    use crate::fixtures;
    use crate::state::{SystemFacts, state};

    /// A moment at which the fixture's leases still run.
    const NOW_MS: u64 = 1_799_999_000_000;

    fn fact(last: u8, joined_unix: u64) -> LeaseFact {
        LeaseFact {
            address: Ipv4Addr::new(192, 168, 1, last),
            mac: MacAddr([2, 0, 0, 0, 0, last]),
            hostname: None,
            expires_unix: 1_800_000_000,
            joined_unix,
        }
    }

    /// The fixture's world with a second LAN after `lan0` in the config, named so that it
    /// sorts before it.
    fn two_lans() -> World {
        let mut world = fixtures::static_world_with_leases();
        let config = Arc::make_mut(&mut world.config);
        let mut second = config.lans[0].clone();
        second.name = "aaa".to_owned();
        config.lans.push(second);
        Arc::make_mut(&mut world.leases).insert("aaa".to_owned(), vec![fact(50, 1_799_995_000)]);
        world
    }

    #[test]
    fn the_table_is_by_lan_in_config_order_then_by_address() {
        let table = leases(&two_lans(), NOW_MS);
        assert_eq!(table.time_unix, 1_799_999_000);
        assert!(!table.truncated);
        let rows: Vec<(&str, &str)> = table
            .leases
            .iter()
            .map(|lease| (lease.lan.as_str(), lease.address.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("lan0", "192.168.1.10"),
                ("lan0", "192.168.1.120"),
                ("aaa", "192.168.1.50")
            ],
            "the config's order of LANs, not the names'"
        );
        let nas = &table.leases[0];
        assert_eq!(
            (nas.mac.as_str(), nas.hostname.as_str()),
            ("52:54:00:fe:10:10", "nas")
        );
        assert_eq!(
            (nas.joined_unix, nas.expires_unix),
            (1_799_900_000, 1_800_000_000)
        );
        assert_eq!(table.leases[2].hostname, "", "no name is an empty one");
    }

    #[test]
    fn a_lease_that_has_run_out_is_left_out_as_the_count_leaves_it_out() {
        let mut world = fixtures::static_world_with_leases();
        Arc::make_mut(&mut world.leases)
            .entry("lan0".to_owned())
            .or_default()
            .push(LeaseFact {
                expires_unix: 1_800_000_500,
                ..fact(130, 1_799_999_500)
            });
        let system = |now_unix_ms| SystemFacts {
            version: String::new(),
            uptime_secs: 0,
            boot_ms: 0,
            now_unix_ms,
            health: openfeo_world::health::HealthView::default(),
            tls_fingerprint: String::new(),
            config_problem: None,
        };
        for (now_unix_ms, left) in [(NOW_MS, 3), (1_800_000_000_000, 1), (1_800_000_500_000, 0)] {
            let table = leases(&world, now_unix_ms);
            assert_eq!(table.leases.len(), left, "at {now_unix_ms}");
            assert_eq!(
                state(&world, &system(now_unix_ms)).lans[0].leases as usize,
                left,
                "the dashboard's count and the table agree at {now_unix_ms}"
            );
        }
    }

    #[test]
    fn a_lan_the_config_no_longer_has_is_not_listed() {
        let mut world = fixtures::static_world_with_leases();
        Arc::make_mut(&mut world.leases).insert("gone".to_owned(), vec![fact(60, 1_799_995_000)]);
        let table = leases(&world, NOW_MS);
        assert!(table.leases.iter().all(|lease| lease.lan == "lan0"));
        assert_eq!(table.leases.len(), 2);
    }

    #[test]
    fn beyond_the_most_the_newest_by_joined_time_are_kept_and_it_says_so() {
        let many = |count: u32| {
            let mut world = fixtures::static_world();
            let facts: Vec<LeaseFact> = (0..count)
                .map(|n| LeaseFact {
                    address: Ipv4Addr::from(0x0a00_0000 + n),
                    mac: MacAddr([2, 0, 0, 0, 0, 1]),
                    hostname: None,
                    expires_unix: 1_800_000_000,
                    // The higher the address, the longer ago it joined.
                    joined_unix: 1_799_000_000 - u64::from(n),
                })
                .collect();
            world.leases = Arc::new(BTreeMap::from([("lan0".to_owned(), facts)]));
            world
        };
        let exactly = leases(&many(4096), NOW_MS);
        assert_eq!(
            (exactly.leases.len(), exactly.truncated),
            (MAX_LEASES, false)
        );
        let over = leases(&many(4100), NOW_MS);
        assert_eq!((over.leases.len(), over.truncated), (MAX_LEASES, true));
        assert_eq!(over.leases[0].address, "10.0.0.0");
        assert_eq!(
            over.leases.last().map(|lease| lease.address.as_str()),
            Some("10.0.15.255"),
            "the four that joined longest ago are the ones left out, and the order is still by address"
        );
    }
}
