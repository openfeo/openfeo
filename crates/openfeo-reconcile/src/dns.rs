// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired DNS forwarder settings (SPEC §7.7, §6.2's `reconcile::dhcp_dns`): the pure
//! translation of `[dns]`, `[system]`, the LANs with their reservations and leases, and the
//! active WAN's learned servers into what the forwarder runs with.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
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
    /// The LAN's IPv6 address, when it has one: a second listener on the same bridge.
    pub address6: Option<Ipv6Addr>,
}

/// A name the forwarder answers itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredLocalName {
    /// `<hostname>.<domain>`, lowercase.
    pub name: String,
    pub addr: IpAddr,
}

/// What the forwarder runs with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredDns {
    /// One per LAN.
    pub listeners: Vec<DesiredListener>,
    /// The typed ones, then the active WAN's learned or static ones when `use_wan_dns`,
    /// deduplicated in order. A learned server joins only while the kernel has a default route
    /// of its family through that WAN (ADR-0019); typed and static ones are never gated.
    pub upstreams: Vec<IpAddr>,
    /// The WAN whose servers were appended.
    pub learned_from: Option<String>,
    /// The servers that WAN learned or was given, before deduplication: an upstream outside
    /// this list was typed into `[dns]`.
    pub wan_upstreams: Vec<IpAddr>,
    /// `[system] domain`, else `home.arpa`.
    pub domain: String,
    /// `<hostname>.<domain>`.
    pub router_name: String,
    /// The LAN addresses of both families and the IPv6 loopback address: the router's A and
    /// AAAA records, and never a valid upstream answer.
    pub router_addrs: Vec<IpAddr>,
    /// The active WAN's addresses: never a valid upstream answer, and not a record of the
    /// router's name.
    pub wan_addrs: Vec<IpAddr>,
    /// The reverse zones: the private LANs, and public LANs that run the DHCP server (SPEC §7.7).
    pub lan_subnets: Vec<Ipv4Net>,
    /// The rebinding guard: the private LANs' subnets.
    pub guard_subnets: Vec<Ipv4Net>,
    /// Every LAN's reservations with a hostname, then lease facts with a hostname not already
    /// named, then `[[dns.records]]` (one per name and family) not already named.
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

    let blocks = crate::public::blocks(&world.config);
    let mut listeners = Vec::new();
    let mut lan_subnets = Vec::new();
    let mut guard_subnets = Vec::new();
    let mut local: Vec<DesiredLocalName> = Vec::new();
    for lan in &world.config.lans {
        let Ok(net) = lan.ipv4.parse::<Ipv4Net>() else {
            continue;
        };
        listeners.push(DesiredListener {
            ifname: bridge_name(&lan.name),
            address: net.addr(),
            address6: lan.ipv6.parse::<Ipv6Net>().ok().map(|net| net.addr()),
        });
        let public = crate::public::lan_is_public(lan, &blocks);
        if !public || lan.dhcp.is_some() {
            lan_subnets.push(net.trunc());
        }
        if !public {
            guard_subnets.push(net.trunc());
        }
        for reservation in lan.dhcp.iter().flat_map(|dhcp| &dhcp.r#static) {
            if let Ok(addr) = reservation.ip.parse::<Ipv4Addr>()
                && !reservation.hostname.is_empty()
            {
                push_local(&mut local, &reservation.hostname, &domain, IpAddr::V4(addr));
            }
        }
    }
    for lan in &world.config.lans {
        for lease in world.leases.get(&lan.name).into_iter().flatten() {
            if let Some(hostname) = &lease.hostname {
                push_local(&mut local, hostname, &domain, IpAddr::V4(lease.address));
            }
        }
    }
    push_records(&mut local, &dns.records, &domain);

    let mut upstreams: Vec<IpAddr> = Vec::new();
    for upstream in dns.upstreams.iter().filter_map(|text| text.parse().ok()) {
        push_unique(&mut upstreams, upstream);
    }
    let mut learned_from = None;
    let mut wan_upstreams = Vec::new();
    let router_addrs = router_addrs(&listeners, world);
    let mut wan_addrs: Vec<IpAddr> = Vec::new();
    if let Some(active) = active_wan(world) {
        if dns.use_wan_dns.unwrap_or(true) {
            wan_upstreams = wan_dns(world, active);
            if !wan_upstreams.is_empty() {
                learned_from = Some(active.name.clone());
                for upstream in &wan_upstreams {
                    push_unique(&mut upstreams, *upstream);
                }
            }
        }
        // The WAN addresses are the router's too: a public name resolving to one is rebinding,
        // but they are not records of the router's name, so they are kept apart from the LAN
        // addresses.
        for addr in wan_addresses(world, active) {
            push_unique(&mut wan_addrs, addr);
        }
    }

    DesiredDns {
        router_addrs,
        wan_addrs,
        listeners,
        upstreams,
        learned_from,
        wan_upstreams,
        router_name: format!("{hostname}.{domain}"),
        domain,
        lan_subnets,
        guard_subnets,
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
        wan_addrs: desired.wan_addrs.clone(),
        lan_subnets: desired.lan_subnets.clone(),
        guard_subnets: desired.guard_subnets.clone(),
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

/// The servers `wan` was given (a static WAN's `dns`, never gated) or learned (a DHCP WAN's
/// lease over IPv4, the advertisements' RDNSS over IPv6), each learned family only while the
/// kernel has a default route of that family through the WAN (ADR-0019).
fn wan_dns(world: &World, wan: &Wan) -> Vec<IpAddr> {
    let ifname = crate::wan_ifname(wan);
    let mut servers: Vec<IpAddr> = match &wan.kind {
        Some(wan::Kind::Dhcp(_)) if world.has_default(false, &ifname) => world
            .dhcp4
            .get(&wan.name)
            .map(|lease| lease.dns.iter().copied().map(IpAddr::V4).collect())
            .unwrap_or_default(),
        Some(wan::Kind::Dhcp(_)) | None => Vec::new(),
        Some(wan::Kind::Static(static_wan)) => static_wan
            .dns
            .iter()
            .filter_map(|text| text.parse().ok())
            .collect(),
    };
    if wan
        .ipv6
        .as_ref()
        .is_some_and(|ipv6| ipv6.mode != "disabled")
        && world.has_default(true, &ifname)
        && let Some(fact) = world.ipv6.get(&wan.name)
    {
        servers.extend(fact.dns.iter().copied().map(IpAddr::V6));
    }
    servers
}

/// The addresses `wan` has now: its lease's or a static WAN's own, and the ones its
/// advertisement client made.
fn wan_addresses(world: &World, wan: &Wan) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = match &wan.kind {
        Some(wan::Kind::Dhcp(_)) => world
            .dhcp4
            .get(&wan.name)
            .map(|lease| IpAddr::V4(lease.address.addr()))
            .into_iter()
            .collect(),
        Some(wan::Kind::Static(static_wan)) => static_wan
            .address
            .parse::<Ipv4Net>()
            .ok()
            .map(|net| IpAddr::V4(net.addr()))
            .into_iter()
            .collect(),
        None => Vec::new(),
    };
    if let Some(fact) = world.ipv6.get(&wan.name) {
        addrs.extend(fact.addresses.iter().map(|net| IpAddr::V6(net.addr())));
    }
    addrs
}

/// The router's IPv6 loopback address, `::1` of the routed prefix's first /64 (SPEC §7.3),
/// when a WAN declares a prefix.
fn loopback6(world: &World) -> Option<Ipv6Addr> {
    world
        .config
        .wans
        .iter()
        .filter(|wan| world.ports.id_of(&wan.port).is_some())
        .filter_map(|wan| wan.ipv6.as_ref())
        .filter(|ipv6| ipv6.mode != "disabled")
        .find_map(|ipv6| ipv6.prefix.parse::<Ipv6Net>().ok())
        .map(|prefix| crate::routing::router_address(prefix.trunc()))
}

/// `[[dns.records]]` as local names: a label is put under the domain, a dotted name stands;
/// a name already answered for in the same family (a reservation, a lease) keeps its answer.
fn push_records(
    local: &mut Vec<DesiredLocalName>,
    records: &[openfeo_config::Record],
    domain: &str,
) {
    for record in records {
        let Ok(addr) = record.address.parse::<IpAddr>() else {
            continue;
        };
        let name = record.name.trim_end_matches('.').to_ascii_lowercase();
        let name = if name.contains('.') {
            name
        } else {
            format!("{name}.{domain}")
        };
        if !local
            .iter()
            .any(|entry| entry.name == name && entry.addr.is_ipv4() == addr.is_ipv4())
        {
            local.push(DesiredLocalName { name, addr });
        }
    }
}

/// The router's own addresses: every LAN's, both families, and the IPv6 loopback address.
fn router_addrs(listeners: &[DesiredListener], world: &World) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = listeners
        .iter()
        .map(|listener| IpAddr::V4(listener.address))
        .collect();
    addrs.extend(
        listeners
            .iter()
            .filter_map(|listener| listener.address6.map(IpAddr::V6)),
    );
    addrs.extend(loopback6(world).map(IpAddr::V6));
    addrs
}

/// `<hostname>.<domain>` at `addr`, unless the name is already taken.
fn push_local(local: &mut Vec<DesiredLocalName>, hostname: &str, domain: &str, addr: IpAddr) {
    let name = format!("{}.{domain}", hostname.to_ascii_lowercase());
    if !local.iter().any(|entry| entry.name == name) {
        local.push(DesiredLocalName { name, addr });
    }
}

fn push_unique<T: PartialEq>(upstreams: &mut Vec<T>, upstream: T) {
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn learned_resolvers_join_only_once_their_familys_default_route_exists() {
        let with = desired(&fixtures::ipv6_world());
        assert_eq!(
            with.upstreams,
            vec![ip("203.0.113.1"), ip("2001:db8:ffff::1")]
        );
        assert_eq!(
            with.wan_upstreams,
            vec![ip("203.0.113.1"), ip("2001:db8:ffff::1")]
        );
        assert_eq!(with.learned_from.as_deref(), Some("wan0"));
        let without = desired(&fixtures::ipv6_world_without_route());
        assert_eq!(
            without.wan_upstreams,
            vec![ip("203.0.113.1")],
            "the RDNSS server waits for the route"
        );
        assert_eq!(
            without.upstreams,
            vec![ip("203.0.113.1"), ip("2001:db8:ffff::1")],
            "typed ones never wait"
        );
        let mut lease_without_route = fixtures::dhcp_world();
        lease_without_route.routes = std::sync::Arc::new(std::collections::BTreeSet::new());
        let d = desired(&lease_without_route);
        assert_eq!(
            d.wan_upstreams,
            Vec::<IpAddr>::new(),
            "a lease's servers wait for the IPv4 route"
        );
        assert_eq!(d.learned_from, None);
        let d = desired(&fixtures::dhcp_world());
        assert!(
            !d.wan_upstreams.is_empty(),
            "with the route, the lease's servers are used"
        );
    }

    #[test]
    fn typed_upstreams_and_static_wan_dns_are_never_gated() {
        let mut world = fixtures::static_world();
        world.routes = std::sync::Arc::new(std::collections::BTreeSet::new());
        let d = desired(&world);
        assert_eq!(d.upstreams, vec![ip("203.0.113.1")]);
        assert_eq!(d.learned_from.as_deref(), Some("wan0"));
    }

    #[test]
    fn records_become_local_names_after_reservations_and_leases() {
        let d = desired(&fixtures::ipv6_world());
        let names: Vec<(String, IpAddr)> =
            d.local.iter().map(|l| (l.name.clone(), l.addr)).collect();
        assert_eq!(
            names,
            vec![
                ("nas.home.arpa".to_owned(), ip("192.168.1.10")),
                ("www.home.arpa".to_owned(), ip("2001:db8:1:232::10")),
            ]
        );
        assert!(d.router_addrs.contains(&ip("2001:db8:1:222::1")));
        assert!(
            d.router_addrs.contains(&ip("2001:db8:1::1")),
            "the loopback address: {:?}",
            d.router_addrs
        );
        assert!(d.router_addrs.contains(&ip("192.168.1.1")));
        assert_eq!(
            d.listeners[0].address6,
            Some("2001:db8:1:222::1".parse().unwrap())
        );
        let config = forwarder_config(&d);
        assert_eq!(config.local.len(), 2);
        assert_eq!(config.upstreams, d.upstreams);
    }

    #[test]
    fn ipv6_world_dns_snapshot() {
        insta::assert_yaml_snapshot!(desired(&fixtures::ipv6_world()));
    }

    #[test]
    fn static_world_lists_the_lan_the_static_wan_dns_and_the_local_names() {
        let d = desired(&fixtures::static_world());
        insta::assert_yaml_snapshot!(d);
        assert_eq!(
            d.listeners,
            vec![DesiredListener {
                ifname: "br-lan0".into(),
                address: Ipv4Addr::new(192, 168, 1, 1),
                address6: None,
            }]
        );
        assert_eq!(
            (d.upstreams.clone(), d.learned_from.as_deref()),
            (
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))],
                Some("wan0")
            )
        );
        assert_eq!(
            (d.domain.as_str(), d.router_name.as_str()),
            ("home.arpa", "openfeo.home.arpa")
        );
        assert_eq!(
            d.local,
            vec![DesiredLocalName {
                name: "nas.home.arpa".into(),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            }]
        );
        let cfg = forwarder_config(&d);
        assert_eq!(
            (cfg.upstreams, cfg.local.len(), cfg.cache_capacity),
            (
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))],
                1,
                DEFAULT_CAPACITY
            )
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
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77)),
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
        assert_eq!(
            with.upstreams,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]
        );
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
                vec![
                    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
                ],
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
                vec![
                    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
                ],
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
            (vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))], None)
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
                    addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                },
                DesiredLocalName {
                    name: "pc.home.arpa".into(),
                    addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 120)),
                },
            ]
        );
    }

    #[test]
    fn public_lans_leave_the_guard_and_the_reverse_zones_unless_they_run_dhcp() {
        let d = desired(&fixtures::public_world()); // the DMZ runs no DHCP
        let private: Vec<Ipv4Net> = vec!["192.168.1.0/24".parse().unwrap()];
        assert_eq!(d.guard_subnets, private);
        assert_eq!(
            d.lan_subnets, private,
            "the ISP owns the DMZ's reverse zone"
        );
        let mut world = fixtures::public_world();
        let mut config = (*world.config).clone();
        config.lans[1].dhcp = Some(openfeo_config::LanDhcp {
            range: vec!["192.0.2.234".into(), "192.0.2.238".into()],
            ..Default::default()
        });
        world.config = Arc::new(config);
        let d = desired(&world);
        assert_eq!(
            d.lan_subnets.len(),
            2,
            "a DHCP-served public LAN names its hosts, so its reverse zone is local"
        );
        assert_eq!(
            d.guard_subnets, private,
            "but its addresses stay valid answers"
        );
        let config = forwarder_config(&d);
        assert_eq!(config.guard_subnets, private);
        assert_eq!(config.lan_subnets.len(), 2);
        insta::assert_yaml_snapshot!(d);
    }

    #[test]
    fn the_wan_address_is_never_a_valid_answer() {
        let d = desired(&fixtures::static_world());
        assert_eq!(
            d.wan_addrs,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
        assert_eq!(
            d.router_addrs,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            "the router's A records stay the LAN's"
        );
        let d = desired(&fixtures::dhcp_world());
        assert_eq!(
            d.wan_addrs,
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100))]
        );
        assert_eq!(
            desired(&fixtures::dhcp_world_without_lease()).wan_addrs,
            Vec::<Ipv4Addr>::new()
        );
    }
}
