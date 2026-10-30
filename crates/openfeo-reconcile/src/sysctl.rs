// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired sysctls (SPEC §5.6, §7.9): forwarding is on only while a ruleset with a WAN and a LAN
//! is applied, and no managed interface sends ICMP redirects. Keys are paths under `/proc/sys`.

use std::collections::BTreeMap;

use openfeo_world::World;
use serde::Serialize;

use crate::bridge_name;

/// IPv4 forwarding.
pub const IP_FORWARD: &str = "net/ipv4/ip_forward";
/// IPv6 forwarding (the `inet` table filters both families, so both levers move together).
pub const IP6_FORWARDING: &str = "net/ipv6/conf/all/forwarding";

/// Everything the sysctl applier makes true: key under `/proc/sys` to value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredSysctl {
    /// `net/ipv4/ip_forward` → `"1"`, `net/ipv4/conf/p0/send_redirects` → `"0"`, …
    pub entries: BTreeMap<String, String>,
}

/// Forwarding levers set from `forwarding` (true only with a ruleset that has a WAN and a LAN,
/// [`crate::nft::DesiredNft::forwarding`]); `send_redirects = 0` on every WAN port with a role and
/// every LAN bridge.
#[must_use]
pub fn sysctl(world: &World, forwarding: bool) -> DesiredSysctl {
    let on_off = if forwarding { "1" } else { "0" };
    let mut entries = BTreeMap::new();
    entries.insert(IP_FORWARD.to_owned(), on_off.to_owned());
    entries.insert(IP6_FORWARDING.to_owned(), on_off.to_owned());
    for wan in &world.config.wans {
        if world.ports.id_of(&wan.port).is_some() {
            entries.insert(send_redirects(&wan.port), "0".to_owned());
        }
    }
    for lan in &world.config.lans {
        entries.insert(send_redirects(&bridge_name(&lan.name)), "0".to_owned());
    }
    DesiredSysctl { entries }
}

/// `net/ipv4/conf/<ifname>/send_redirects`.
#[must_use]
pub fn send_redirects(ifname: &str) -> String {
    format!("net/ipv4/conf/{ifname}/send_redirects")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn sysctl_follows_forwarding() {
        let on = sysctl(&fixtures::static_world(), true);
        assert_eq!(on.entries[IP_FORWARD], "1");
        assert_eq!(on.entries[IP6_FORWARDING], "1");
        assert_eq!(on.entries["net/ipv4/conf/p0/send_redirects"], "0");
        assert_eq!(on.entries["net/ipv4/conf/br-lan0/send_redirects"], "0");
        assert!(
            !on.entries.contains_key("net/ipv4/conf/p1/send_redirects"),
            "p1 has no role: {:?}",
            on.entries
        );
        assert_eq!(on.entries.len(), 4);
        let off = sysctl(&fixtures::static_world(), false);
        assert_eq!(off.entries[IP_FORWARD], "0");
        assert_eq!(off.entries[IP6_FORWARDING], "0");
        insta::assert_yaml_snapshot!(on);
    }

    #[test]
    fn first_boot_sysctl_keeps_forwarding_off() {
        let desired = sysctl(&fixtures::first_boot_world(), false);
        assert_eq!(desired.entries[IP_FORWARD], "0");
        assert_eq!(desired.entries["net/ipv4/conf/br-lan0/send_redirects"], "0");
        assert_eq!(desired.entries.len(), 3);
    }
}
