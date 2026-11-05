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
        if world.ports.id_of(&wan.port).is_none() {
            continue;
        }
        let ifname = crate::wan_ifname(wan);
        entries.insert(send_redirects(&ifname), "0".to_owned());
        if let Some(ipv6) = &wan.ipv6
            && ipv6.mode != "disabled"
        {
            for key in ["accept_ra", "autoconf", "accept_redirects"] {
                entries.insert(ipv6_conf(&ifname, key), "0".to_owned());
            }
            if let Some(mtu) = world.ipv6.get(&wan.name).and_then(|fact| fact.mtu) {
                let link_mtu = world.links.get(&ifname).map_or(mtu, |link| link.mtu);
                entries.insert(ipv6_conf(&ifname, "mtu"), mtu.min(link_mtu).to_string());
            }
        }
    }
    for lan in &world.config.lans {
        let bridge = bridge_name(&lan.name);
        entries.insert(send_redirects(&bridge), "0".to_owned());
        if !lan.ipv6.is_empty() {
            for key in ["accept_ra", "accept_redirects"] {
                entries.insert(ipv6_conf(&bridge, key), "0".to_owned());
            }
        }
    }
    DesiredSysctl { entries }
}

/// `net/ipv6/conf/<ifname>/<key>`.
fn ipv6_conf(ifname: &str, key: &str) -> String {
    format!("net/ipv6/conf/{ifname}/{key}")
}

/// `net/ipv4/conf/<ifname>/send_redirects`.
#[must_use]
pub fn send_redirects(ifname: &str) -> String {
    format!("net/ipv4/conf/{ifname}/send_redirects")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ipv6_wan_gets_its_knobs_and_the_advertised_mtu_capped_at_the_link() {
        let entries = sysctl(&crate::fixtures::ipv6_world(), true).entries;
        for key in ["accept_ra", "autoconf", "accept_redirects"] {
            assert_eq!(
                entries
                    .get(&format!("net/ipv6/conf/p0/{key}"))
                    .map(String::as_str),
                Some("0"),
                "{key}"
            );
        }
        assert_eq!(
            entries.get("net/ipv6/conf/p0/mtu").map(String::as_str),
            Some("1500")
        );
        let mut world = crate::fixtures::ipv6_world();
        let mut fact = crate::fixtures::ipv6_fact();
        fact.mtu = Some(9000);
        world.ipv6 = std::sync::Arc::new(BTreeMap::from([("wan0".to_owned(), fact.clone())]));
        assert_eq!(
            sysctl(&world, true)
                .entries
                .get("net/ipv6/conf/p0/mtu")
                .map(String::as_str),
            Some("1500"),
            "capped at the link"
        );
        fact.mtu = Some(1280);
        world.ipv6 = std::sync::Arc::new(BTreeMap::from([("wan0".to_owned(), fact.clone())]));
        assert_eq!(
            sysctl(&world, true)
                .entries
                .get("net/ipv6/conf/p0/mtu")
                .map(String::as_str),
            Some("1280")
        );
        fact.mtu = None;
        world.ipv6 = std::sync::Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        assert!(
            !sysctl(&world, true)
                .entries
                .contains_key("net/ipv6/conf/p0/mtu"),
            "no option, no key"
        );
        let static_entries = sysctl(&crate::fixtures::static_world(), true).entries;
        assert!(
            static_entries
                .keys()
                .all(|k| !k.starts_with("net/ipv6/conf/p0")),
            "{static_entries:?}"
        );
    }

    #[test]
    fn lans_with_ipv6_refuse_advertisements() {
        let entries = sysctl(&crate::fixtures::ipv6_world(), true).entries;
        for bridge in ["br-lan0", "br-dmz"] {
            assert_eq!(
                entries
                    .get(&format!("net/ipv6/conf/{bridge}/accept_ra"))
                    .map(String::as_str),
                Some("0")
            );
            assert_eq!(
                entries
                    .get(&format!("net/ipv6/conf/{bridge}/accept_redirects"))
                    .map(String::as_str),
                Some("0")
            );
        }
        let static_entries = sysctl(&crate::fixtures::static_world(), true).entries;
        assert!(!static_entries.contains_key("net/ipv6/conf/br-lan0/accept_ra"));
    }
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
