// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What a change from one config to another does (SPEC §5.5, §8.3): which WANs reconnect,
//! which LANs move or have their DHCP server restarted, what is added and removed. It is
//! worked out from the same slices the task managers compare ([`crate::slices`],
//! [`crate::dhcp::servers_of`]), so what the router says a change will interrupt is what it
//! then interrupts. A change that touches no slice (a priority, a firewall rule, a DNS
//! record) has no effects: it takes hold without restarting anything.

use std::collections::BTreeSet;

use openfeo_config::load::{DEFAULT_DOMAIN, DEFAULT_HOSTNAME};
use openfeo_config::{Config, Lan, Wan};
use openfeo_world::{Effect, EffectKind};

use crate::dhcp::servers_of;
use crate::slices;

fn effect(subject: &str, kind: EffectKind) -> Effect {
    Effect {
        subject: subject.to_owned(),
        kind,
    }
}

/// Whether every slice of the WAN `name` is the same in both configs.
fn wan_unchanged(old: &Config, new: &Config, name: &str) -> bool {
    slices::dhcp4_clients(old).get(name) == slices::dhcp4_clients(new).get(name)
        && slices::pppoe_clients(old).get(name) == slices::pppoe_clients(new).get(name)
        && slices::ra_clients(old).get(name) == slices::ra_clients(new).get(name)
        && slices::dhcp6_clients(old).get(name) == slices::dhcp6_clients(new).get(name)
}

fn wan_named<'a>(config: &'a Config, name: &str) -> Option<&'a Wan> {
    config.wans.iter().find(|wan| wan.name == name)
}

fn lan_named<'a>(config: &'a Config, name: &str) -> Option<&'a Lan> {
    config.lans.iter().find(|lan| lan.name == name)
}

/// `<hostname>.<domain>`, each with its default.
fn fqdn(config: &Config) -> String {
    let or_default = |value: Option<&str>, default: &'static str| -> String {
        value
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_owned()
    };
    let system = config.system.as_ref();
    format!(
        "{}.{}",
        or_default(system.map(|s| s.hostname.as_str()), DEFAULT_HOSTNAME),
        or_default(system.map(|s| s.domain.as_str()), DEFAULT_DOMAIN)
    )
}

/// What applying `new` over `old` does: WANs in `new`'s order and then those only in `old`,
/// LANs likewise, then the router itself.
#[must_use]
pub fn effects(old: &Config, new: &Config) -> Vec<Effect> {
    let mut found = Vec::new();
    for wan in &new.wans {
        if wan_named(old, &wan.name).is_none() {
            found.push(effect(&wan.name, EffectKind::WanAdded));
        } else if !wan_unchanged(old, new, &wan.name) {
            found.push(effect(&wan.name, EffectKind::WanReconnects));
        }
    }
    for wan in &old.wans {
        if wan_named(new, &wan.name).is_none() {
            found.push(effect(&wan.name, EffectKind::WanRemoved));
        }
    }
    let (servers_old, servers_new) = (servers_of(old), servers_of(new));
    for lan in &new.lans {
        let Some(before) = lan_named(old, &lan.name) else {
            found.push(effect(&lan.name, EffectKind::LanAdded));
            continue;
        };
        if before.ipv4 != lan.ipv4 {
            // The server restarts with the move; saying so twice helps nobody.
            found.push(effect(&lan.name, EffectKind::LanAddressMoves));
            continue;
        }
        match (servers_old.get(&lan.name), servers_new.get(&lan.name)) {
            (None, Some(_)) => found.push(effect(&lan.name, EffectKind::LanDhcpStarts)),
            (Some(_), None) => found.push(effect(&lan.name, EffectKind::LanDhcpStops)),
            (Some(before), Some(after)) if before != after => {
                found.push(effect(&lan.name, EffectKind::LanDhcpRestarts));
            }
            _ => {}
        }
    }
    for lan in &old.lans {
        if lan_named(new, &lan.name).is_none() {
            found.push(effect(&lan.name, EffectKind::LanRemoved));
        }
    }
    let renamed = fqdn(new);
    if fqdn(old) != renamed {
        found.push(effect(&renamed, EffectKind::RouterRenamed));
    }
    found
}

/// The LANs a change touches: in only one of the configs, or with another IPv4 address or
/// another DHCPv4 server in the two. While the change is pending their leases are short
/// (SPEC §5.5).
#[must_use]
pub fn touched_lans(old: &Config, new: &Config) -> BTreeSet<String> {
    let (servers_old, servers_new) = (servers_of(old), servers_of(new));
    let mut touched = BTreeSet::new();
    for lan in old.lans.iter().chain(&new.lans) {
        let (before, after) = (lan_named(old, &lan.name), lan_named(new, &lan.name));
        let same = match (before, after) {
            (Some(before), Some(after)) => {
                before.ipv4 == after.ipv4
                    && servers_old.get(&lan.name) == servers_new.get(&lan.name)
            }
            _ => false,
        };
        if !same {
            touched.insert(lan.name.clone());
        }
    }
    touched
}

#[cfg(test)]
mod tests {
    use openfeo_config::{Config, Lan, PppoeWan, StaticLease, System, Wan, wan};

    use super::*;
    use crate::fixtures;

    fn configs() -> Vec<Config> {
        [
            fixtures::first_boot_world(),
            fixtures::static_world(),
            fixtures::dhcp_world(),
            fixtures::vlans_world(),
            fixtures::public_world(),
            fixtures::ipv6_world(),
            fixtures::pd_world(),
            fixtures::pppoe_world(),
        ]
        .into_iter()
        .map(|world| (*world.config).clone())
        .collect()
    }

    fn dhcp() -> Config {
        (*fixtures::dhcp_world().config).clone()
    }

    fn pppoe() -> Config {
        (*fixtures::pppoe_world().config).clone()
    }

    fn vlans() -> Config {
        (*fixtures::vlans_world().config).clone()
    }

    fn effect(subject: &str, kind: EffectKind) -> Effect {
        Effect {
            subject: subject.to_owned(),
            kind,
        }
    }

    fn reservation() -> StaticLease {
        StaticLease {
            mac: "02:00:00:00:00:10".to_owned(),
            ip: "192.168.1.10".to_owned(),
            hostname: "nas".to_owned(),
            client_id: String::new(),
        }
    }

    fn account(config: &mut Config) -> &mut PppoeWan {
        let Some(wan::Kind::Pppoe(account)) = &mut config.wans[0].kind else {
            panic!("the fixture's WAN is PPPoE");
        };
        account
    }

    /// `lan0` moved to `192.168.2.1/24`, its pool with it.
    fn moved(mut config: Config) -> Config {
        let lan = &mut config.lans[0];
        lan.ipv4 = "192.168.2.1/24".to_owned();
        let dhcp = lan.dhcp.as_mut().unwrap();
        dhcp.range = vec!["192.168.2.100".to_owned(), "192.168.2.200".to_owned()];
        dhcp.r#static.clear();
        config
    }

    #[test]
    fn the_same_config_has_no_effects() {
        for config in configs() {
            assert_eq!(effects(&config, &config), Vec::new());
            assert_eq!(touched_lans(&config, &config), BTreeSet::new());
        }
    }

    #[test]
    fn a_change_outside_every_slice_has_no_effects() {
        for old in configs() {
            let mut new = old.clone();
            if let Some(wan) = new.wans.first_mut() {
                wan.priority += 5;
            }
            new.firewall
                .get_or_insert_with(Default::default)
                .port_forwards
                .push(openfeo_config::PortForward::default());
            new.dns
                .get_or_insert_with(Default::default)
                .records
                .push(openfeo_config::Record::default());
            new.lans[0].reaches = vec!["none".to_owned()];
            assert_eq!(effects(&old, &new), Vec::new());
            assert_eq!(touched_lans(&old, &new), BTreeSet::new());
        }
    }

    #[test]
    fn a_change_to_a_wan_names_its_effect() {
        // A PPPoE account's name.
        let mut new = pppoe();
        account(&mut new).username = "other@isp.example".to_owned();
        assert_eq!(
            effects(&pppoe(), &new),
            [effect("wan0", EffectKind::WanReconnects)]
        );
        // Its password alone.
        let mut new = pppoe();
        account(&mut new).password = "another-secret".to_owned();
        assert_eq!(
            effects(&pppoe(), &new),
            [effect("wan0", EffectKind::WanReconnects)]
        );
        // DHCP to PPPoE under the same name.
        let mut new = dhcp();
        new.wans[0].kind = Some(wan::Kind::Pppoe(PppoeWan {
            username: "openfeo@isp.example".to_owned(),
            password: "example-secret".to_owned(),
            ..PppoeWan::default()
        }));
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("wan0", EffectKind::WanReconnects)]
        );
        // A VLAN tag.
        let mut new = dhcp();
        new.wans[0].vlan = 101;
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("wan0", EffectKind::WanReconnects)]
        );
        // IPv6 switched on: the WAN gains its IPv6 clients.
        let mut new = dhcp();
        new.wans[0].ipv6 = Some(openfeo_config::Ipv6Wan::default());
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("wan0", EffectKind::WanReconnects)]
        );
        // A second WAN, and the first one gone.
        let mut new = dhcp();
        new.wans.push(Wan {
            name: "wan1".to_owned(),
            port: "p1".to_owned(),
            priority: 20,
            kind: Some(wan::Kind::Dhcp(openfeo_config::DhcpWan::default())),
            ..Wan::default()
        });
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("wan1", EffectKind::WanAdded)]
        );
        assert_eq!(
            effects(&new, &dhcp()),
            [effect("wan1", EffectKind::WanRemoved)]
        );
    }

    #[test]
    fn a_change_to_a_lan_names_its_effect() {
        // A LAN's address: the move says it all, the DHCP server's restart is part of it.
        assert_eq!(
            effects(&dhcp(), &moved(dhcp())),
            [effect("lan0", EffectKind::LanAddressMoves)]
        );
        // A reservation.
        let mut new = dhcp();
        new.lans[0]
            .dhcp
            .as_mut()
            .unwrap()
            .r#static
            .push(reservation());
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("lan0", EffectKind::LanDhcpRestarts)]
        );
        // The DHCP server switched off, and on.
        let mut new = dhcp();
        new.lans[0].dhcp = None;
        assert_eq!(
            effects(&dhcp(), &new),
            [effect("lan0", EffectKind::LanDhcpStops)]
        );
        assert_eq!(
            effects(&new, &dhcp()),
            [effect("lan0", EffectKind::LanDhcpStarts)]
        );
        // A LAN removed, and added.
        let mut new = vlans();
        new.lans.retain(|lan| lan.name != "guest");
        assert_eq!(
            effects(&vlans(), &new),
            [effect("guest", EffectKind::LanRemoved)]
        );
        assert_eq!(
            effects(&new, &vlans()),
            [effect("guest", EffectKind::LanAdded)]
        );
    }

    #[test]
    fn a_change_of_name_names_the_router() {
        // The router's name.
        let mut old = dhcp();
        old.system = Some(System {
            hostname: "openfeo".to_owned(),
            domain: String::new(),
            ..System::default()
        });
        let mut new = old.clone();
        new.system.as_mut().unwrap().hostname = "edge".to_owned();
        assert_eq!(
            effects(&old, &new),
            [effect("edge.home.arpa", EffectKind::RouterRenamed)]
        );
        let mut new = old.clone();
        new.system.as_mut().unwrap().domain = "lan.example".to_owned();
        // The domain is also what the DHCP server hands out, so that restarts too.
        assert_eq!(
            effects(&old, &new),
            [
                effect("lan0", EffectKind::LanDhcpRestarts),
                effect("openfeo.lan.example", EffectKind::RouterRenamed),
            ]
        );
        // The defaults spelt out are no change.
        let mut new = old.clone();
        new.system.as_mut().unwrap().domain = "home.arpa".to_owned();
        assert_eq!(effects(&old, &new), Vec::new());
    }

    #[test]
    fn effects_come_wans_then_lans_then_the_router() {
        let old = vlans();
        let mut new = old.clone();
        new.wans[0].vlan = 7;
        new.wans.push(Wan {
            name: "wan1".to_owned(),
            port: "p1".to_owned(),
            kind: Some(wan::Kind::Dhcp(openfeo_config::DhcpWan::default())),
            ..Wan::default()
        });
        new.lans.retain(|lan| lan.name != "guest");
        new.lans.push(Lan {
            name: "lab".to_owned(),
            ports: vec!["p3".to_owned()],
            ipv4: "192.168.9.1/24".to_owned(),
            ..Lan::default()
        });
        new.lans[0].ipv4 = "192.168.3.1/24".to_owned();
        new.system.get_or_insert_with(System::default).hostname = "edge".to_owned();
        let found = effects(&old, &new);
        let kinds: Vec<(&str, EffectKind)> = found
            .iter()
            .map(|effect| (effect.subject.as_str(), effect.kind))
            .collect();
        let domain = old
            .system
            .as_ref()
            .map(|system| system.domain.clone())
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| "home.arpa".to_owned());
        let renamed = format!("edge.{domain}");
        assert_eq!(kinds[0], ("wan0", EffectKind::WanReconnects));
        assert_eq!(kinds[1], ("wan1", EffectKind::WanAdded));
        assert_eq!(
            kinds[2],
            (new.lans[0].name.as_str(), EffectKind::LanAddressMoves)
        );
        assert!(kinds.contains(&("lab", EffectKind::LanAdded)));
        assert_eq!(kinds[kinds.len() - 2], ("guest", EffectKind::LanRemoved));
        assert_eq!(
            kinds[kinds.len() - 1],
            (renamed.as_str(), EffectKind::RouterRenamed)
        );
        // The other way round, what was added is removed last among its kind.
        let back = effects(&new, &old);
        let wans: Vec<&str> = back
            .iter()
            .filter(|effect| effect.kind == EffectKind::WanRemoved)
            .map(|effect| effect.subject.as_str())
            .collect();
        assert_eq!(wans, ["wan1"]);
        assert_eq!(back[0], effect("wan0", EffectKind::WanReconnects));
    }

    #[test]
    fn an_unchanged_slice_never_yields_an_effect() {
        let all = configs();
        for old in &all {
            for new in &all {
                let found = effects(old, new);
                for wan in &new.wans {
                    let name = &wan.name;
                    let same = old.wans.iter().any(|other| &other.name == name)
                        && slices::dhcp4_clients(old).get(name)
                            == slices::dhcp4_clients(new).get(name)
                        && slices::pppoe_clients(old).get(name)
                            == slices::pppoe_clients(new).get(name)
                        && slices::ra_clients(old).get(name) == slices::ra_clients(new).get(name)
                        && slices::dhcp6_clients(old).get(name)
                            == slices::dhcp6_clients(new).get(name);
                    if same {
                        assert!(
                            !found.iter().any(|effect| &effect.subject == name),
                            "{name} is untouched and yet: {found:?}"
                        );
                    }
                }
                for lan in &new.lans {
                    let name = &lan.name;
                    let same = old
                        .lans
                        .iter()
                        .any(|other| &other.name == name && other.ipv4 == lan.ipv4)
                        && servers_of(old).get(name) == servers_of(new).get(name);
                    if same {
                        assert!(
                            !found.iter().any(|effect| &effect.subject == name),
                            "{name} is untouched and yet: {found:?}"
                        );
                        assert!(!touched_lans(old, new).contains(name));
                    }
                }
            }
        }
    }

    #[test]
    fn the_touched_lans_are_those_whose_address_or_dhcp_changed() {
        let lans = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(touched_lans(&dhcp(), &moved(dhcp())), lans(&["lan0"]));
        let mut new = dhcp();
        new.lans[0]
            .dhcp
            .as_mut()
            .unwrap()
            .r#static
            .push(reservation());
        assert_eq!(touched_lans(&dhcp(), &new), lans(&["lan0"]));
        // Added or removed counts, either way round; the others are left out.
        let mut new = vlans();
        new.lans.retain(|lan| lan.name != "guest");
        assert_eq!(touched_lans(&vlans(), &new), lans(&["guest"]));
        assert_eq!(touched_lans(&new, &vlans()), lans(&["guest"]));
        // A change to a WAN touches no LAN.
        let mut new = dhcp();
        new.wans[0].vlan = 101;
        assert_eq!(touched_lans(&dhcp(), &new), lans(&[]));
    }
}
