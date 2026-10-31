// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired DNS forwarder settings (SPEC §7.7, §6.2's `reconcile::dhcp_dns`): the pure
//! translation of `[dns]`, `[system]`, the LANs with their reservations and leases, and the
//! active WAN's learned servers into what the forwarder runs with.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use openfeo_config::load::{DEFAULT_DOMAIN, DEFAULT_HOSTNAME};
use openfeo_config::{Wan, wan};
use openfeo_proto_dns::cache::DEFAULT_CAPACITY;
use openfeo_proto_dns::forwarder::{Config, LocalRecord};
use openfeo_proto_dns::name::Name;
use openfeo_world::World;
use serde::Serialize;

use crate::bridge_name;

/// One LAN the forwarder listens on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredListener {
    /// `br-<lan>`.
    pub ifname: String,
    pub address: Ipv4Addr,
}

/// A name the forwarder answers itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredLocalName {
    /// `<hostname>.<domain>`, lowercase.
    pub name: String,
    pub addr: Ipv4Addr,
}

/// What the forwarder runs with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredDns {
    /// One per LAN.
    pub listeners: Vec<DesiredListener>,
    /// The typed ones, then the active WAN's learned or static ones when `use_wan_dns`,
    /// deduplicated in order.
    pub upstreams: Vec<Ipv4Addr>,
    /// The WAN whose servers were appended.
    pub learned_from: Option<String>,
    /// The servers that WAN learned or was given, before deduplication: an upstream outside
    /// this list was typed into `[dns]`.
    pub wan_upstreams: Vec<Ipv4Addr>,
    /// `[system] domain`, else `home.arpa`.
    pub domain: String,
    /// `<hostname>.<domain>`.
    pub router_name: String,
    /// The LAN addresses.
    pub router_addrs: Vec<Ipv4Addr>,
    pub lan_subnets: Vec<Ipv4Net>,
    /// Every LAN's reservations with a hostname, then lease facts with a hostname not already
    /// named.
    pub local: Vec<DesiredLocalName>,
    pub rebind_allow: Vec<String>,
}

/// The forwarder settings the World calls for. A LAN whose address does not parse contributes
/// nothing, and so does an upstream or a reservation address that does not parse (validation
/// already refused them).
#[must_use]
pub fn desired(world: &World) -> DesiredDns {
    let system = world.config.system.as_ref();
    let domain = system
        .map(|system| system.domain.as_str())
        .filter(|domain| !domain.is_empty())
        .unwrap_or(DEFAULT_DOMAIN)
        .to_ascii_lowercase();
    let hostname = system
        .map(|system| system.hostname.as_str())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or(DEFAULT_HOSTNAME)
        .to_ascii_lowercase();
    let dns = world.config.dns.clone().unwrap_or_default();

    let mut listeners = Vec::new();
    let mut lan_subnets = Vec::new();
    let mut local: Vec<DesiredLocalName> = Vec::new();
    for lan in &world.config.lans {
        let Ok(net) = lan.ipv4.parse::<Ipv4Net>() else {
            continue;
        };
        listeners.push(DesiredListener {
            ifname: bridge_name(&lan.name),
            address: net.addr(),
        });
        lan_subnets.push(net.trunc());
        for reservation in lan.dhcp.iter().flat_map(|dhcp| &dhcp.r#static) {
            if let Ok(addr) = reservation.ip.parse::<Ipv4Addr>()
                && !reservation.hostname.is_empty()
            {
                push_local(&mut local, &reservation.hostname, &domain, addr);
            }
        }
    }
    for lan in &world.config.lans {
        for lease in world.leases.get(&lan.name).into_iter().flatten() {
            if let Some(hostname) = &lease.hostname {
                push_local(&mut local, hostname, &domain, lease.address);
            }
        }
    }

    let mut upstreams: Vec<Ipv4Addr> = Vec::new();
    for upstream in dns.upstreams.iter().filter_map(|text| text.parse().ok()) {
        push_unique(&mut upstreams, upstream);
    }
    let mut learned_from = None;
    let mut wan_upstreams = Vec::new();
    if dns.use_wan_dns.unwrap_or(true)
        && let Some(active) = active_wan(world)
    {
        wan_upstreams = wan_dns(world, active);
        if !wan_upstreams.is_empty() {
            learned_from = Some(active.name.clone());
            for upstream in &wan_upstreams {
                push_unique(&mut upstreams, *upstream);
            }
        }
    }

    DesiredDns {
        router_addrs: listeners.iter().map(|listener| listener.address).collect(),
        listeners,
        upstreams,
        learned_from,
        wan_upstreams,
        router_name: format!("{hostname}.{domain}"),
        domain,
        lan_subnets,
        local,
        rebind_allow: dns.rebind_allow,
    }
}

/// The forwarder's configuration for `desired`. Validation refuses names that do not parse,
/// but the forwarder must come up whatever reaches it: a local name or allow-list entry that
/// does not parse is left out, a domain that does not parse (or is the root, which would make
/// every name local) falls back to `home.arpa`, and a router name that does not parse falls back
/// to `openfeo.<domain>`.
#[must_use]
pub fn forwarder_config(desired: &DesiredDns) -> Config {
    let domain = desired
        .domain
        .parse::<Name>()
        .ok()
        .filter(|name| !name.is_root())
        .or_else(|| DEFAULT_DOMAIN.parse().ok())
        .unwrap_or_else(Name::root);
    let router_name = desired
        .router_name
        .parse::<Name>()
        .ok()
        .filter(|name| !name.is_root())
        .or_else(|| format!("{DEFAULT_HOSTNAME}.{domain}").parse().ok());
    Config {
        upstreams: desired.upstreams.clone(),
        domain,
        router_name,
        router_addrs: desired.router_addrs.clone(),
        lan_subnets: desired.lan_subnets.clone(),
        local: desired
            .local
            .iter()
            .filter_map(|entry| {
                Some(LocalRecord {
                    name: entry.name.parse().ok()?,
                    addr: entry.addr,
                })
            })
            .collect(),
        rebind_allow: desired
            .rebind_allow
            .iter()
            .filter_map(|name| name.parse().ok())
            .collect(),
        cache_capacity: DEFAULT_CAPACITY,
    }
}

/// The configured WAN with the lowest priority whose port the map knows.
pub(crate) fn active_wan(world: &World) -> Option<&Wan> {
    world
        .config
        .wans
        .iter()
        .filter(|wan| world.ports.id_of(&wan.port).is_some())
        .min_by_key(|wan| wan.priority)
}

/// The servers `wan` learned (a DHCP WAN's lease) or was given (a static WAN's `dns`).
fn wan_dns(world: &World, wan: &Wan) -> Vec<Ipv4Addr> {
    match &wan.kind {
        Some(wan::Kind::Dhcp(_)) => world
            .dhcp4
            .get(&wan.name)
            .map(|lease| lease.dns.clone())
            .unwrap_or_default(),
        Some(wan::Kind::Static(static_wan)) => static_wan
            .dns
            .iter()
            .filter_map(|text| text.parse().ok())
            .collect(),
        None => Vec::new(),
    }
}

/// `<hostname>.<domain>` at `addr`, unless the name is already taken.
fn push_local(local: &mut Vec<DesiredLocalName>, hostname: &str, domain: &str, addr: Ipv4Addr) {
    let name = format!("{}.{domain}", hostname.to_ascii_lowercase());
    if !local.iter().any(|entry| entry.name == name) {
        local.push(DesiredLocalName { name, addr });
    }
}

fn push_unique(upstreams: &mut Vec<Ipv4Addr>, upstream: Ipv4Addr) {
    if !upstreams.contains(&upstream) {
        upstreams.push(upstream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use openfeo_config::Dns;
    use openfeo_proto_dns::cache::DEFAULT_CAPACITY;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    #[test]
    fn static_world_lists_the_lan_the_static_wan_dns_and_the_local_names() {
        let d = desired(&fixtures::static_world());
        insta::assert_yaml_snapshot!(d);
        assert_eq!(
            d.listeners,
            vec![DesiredListener {
                ifname: "br-lan0".into(),
                address: Ipv4Addr::new(192, 168, 1, 1),
            }]
        );
        assert_eq!(
            (d.upstreams.clone(), d.learned_from.as_deref()),
            (vec![Ipv4Addr::new(203, 0, 113, 1)], Some("wan0"))
        );
        assert_eq!(
            (d.domain.as_str(), d.router_name.as_str()),
            ("home.arpa", "openfeo.home.arpa")
        );
        assert_eq!(
            d.local,
            vec![DesiredLocalName {
                name: "nas.home.arpa".into(),
                addr: Ipv4Addr::new(192, 168, 1, 10),
            }]
        );
        let cfg = forwarder_config(&d);
        assert_eq!(
            (cfg.upstreams, cfg.local.len(), cfg.cache_capacity),
            (vec![Ipv4Addr::new(203, 0, 113, 1)], 1, DEFAULT_CAPACITY)
        );
    }

    /// Review finding: a name that does not parse must not take the forwarder down; what does
    /// not parse is skipped, and the domain and router name fall back on the defaults.
    #[test]
    fn forwarder_config_skips_what_does_not_parse_and_falls_back_on_the_defaults() {
        let mut d = desired(&fixtures::static_world());
        d.domain = ".".into();
        d.router_name = "bad..name".into();
        d.local.push(DesiredLocalName {
            name: format!("{}.home.arpa", "x".repeat(64)),
            addr: Ipv4Addr::new(192, 168, 1, 77),
        });
        d.rebind_allow = vec!["ok.example".into(), "bad..name".into()];
        let cfg = forwarder_config(&d);
        assert_eq!(cfg.domain, "home.arpa".parse().unwrap());
        assert_eq!(cfg.router_name, Some("openfeo.home.arpa".parse().unwrap()));
        assert_eq!(
            cfg.local
                .iter()
                .map(|record| record.name.to_string())
                .collect::<Vec<_>>(),
            vec!["nas.home.arpa."]
        );
        assert_eq!(cfg.rebind_allow, vec!["ok.example".parse().unwrap()]);
        let mut d = desired(&fixtures::static_world());
        d.domain = "lan.example".into();
        d.router_name = "bad..name".into();
        assert_eq!(
            forwarder_config(&d).router_name,
            Some("openfeo.lan.example".parse().unwrap()),
            "the router's fallback name follows the domain"
        );
    }

    #[test]
    fn dhcp_world_learns_from_the_lease_and_has_nothing_before_it() {
        let with = desired(&fixtures::dhcp_world());
        insta::assert_yaml_snapshot!(with);
        assert_eq!(with.upstreams, vec![Ipv4Addr::new(203, 0, 113, 1)]);
        let without = desired(&fixtures::dhcp_world_without_lease());
        assert_eq!((without.upstreams.len(), without.learned_from), (0, None));
    }

    #[test]
    fn typed_upstreams_come_first_and_use_wan_dns_false_leaves_the_wan_out() {
        let mut world = fixtures::static_world();
        Arc::make_mut(&mut world.config).dns = Some(Dns {
            upstreams: vec!["9.9.9.9".into(), "203.0.113.1".into()],
            ..Default::default()
        });
        let d = desired(&world);
        assert_eq!(
            (d.upstreams, d.learned_from.as_deref()),
            (
                vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(203, 0, 113, 1)],
                Some("wan0")
            ),
            "deduplicated"
        );
        let dns = Arc::make_mut(&mut world.config).dns.as_mut().unwrap();
        dns.upstreams = vec!["9.9.9.9".into()];
        let d = desired(&world);
        assert_eq!(
            (d.upstreams, d.learned_from.as_deref()),
            (
                vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(203, 0, 113, 1)],
                Some("wan0")
            ),
            "typed first, then the WAN's"
        );
        Arc::make_mut(&mut world.config)
            .dns
            .as_mut()
            .unwrap()
            .use_wan_dns = Some(false);
        assert_eq!(
            (desired(&world).upstreams, desired(&world).learned_from),
            (vec![Ipv4Addr::new(9, 9, 9, 9)], None)
        );
    }

    #[test]
    fn lease_facts_add_local_names_without_shadowing_reservations() {
        let d = desired(&fixtures::static_world_with_leases());
        assert_eq!(
            d.local,
            vec![
                DesiredLocalName {
                    name: "nas.home.arpa".into(),
                    addr: Ipv4Addr::new(192, 168, 1, 10),
                },
                DesiredLocalName {
                    name: "pc.home.arpa".into(),
                    addr: Ipv4Addr::new(192, 168, 1, 120),
                },
            ]
        );
    }
}
