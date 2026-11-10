// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Who may connect, and by what name (SPEC §9). The firewall admits the API's ports from
//! private LANs only; the listener asks the same of every connection itself, so a firewall
//! mistake does not expose the panel. And a request must call the router by one of its own
//! names or addresses: a page on another site, pointed here by a rebinding DNS answer, sends
//! that site's name and is refused.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use openfeo_config::System;
use openfeo_reconcile::{bridge_name, public};
use openfeo_world::World;

/// The router's two names, lower-case: the hostname and `<hostname>.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// `openfeo`.
    pub hostname: String,
    /// `openfeo.home.arpa`.
    pub fqdn: String,
}

impl Names {
    /// The names the config gives, or the defaults.
    #[must_use]
    pub fn of(system: Option<&System>) -> Self {
        let mut names = crate::cert::names(system).into_iter();
        Names {
            hostname: names.next().unwrap_or_default(),
            fqdn: names.next().unwrap_or_default(),
        }
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

/// An IPv4-mapped IPv6 address (how a dual-stack listener reports an IPv4 client) as IPv4.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Whether `peer` is a client on a private LAN: inside the LAN's IPv4 subnet, inside a /64
/// (or any prefix) its bridge holds an address in, or link-local on its bridge.
#[must_use]
pub fn client_admitted(world: &World, peer: SocketAddr) -> bool {
    let ip = unmapped(peer.ip());
    let scope = match peer {
        SocketAddr::V6(v6) => v6.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    let blocks = public::blocks(&world.config);
    world
        .config
        .lans
        .iter()
        .filter(|lan| !public::lan_is_public(lan, &blocks))
        .any(|lan| {
            let bridge = bridge_name(&lan.name);
            if is_link_local(ip) {
                return world
                    .links
                    .get(&bridge)
                    .is_some_and(|link| scope != 0 && link.index == scope);
            }
            match ip {
                IpAddr::V4(v4) => public::lan_subnet(lan).is_some_and(|net| net.contains(&v4)),
                IpAddr::V6(_) => world.addresses.iter().any(|addr| {
                    addr.ifname == bridge
                        && matches!(addr.net, IpNet::V6(_))
                        && !is_link_local(addr.net.addr())
                        && addr.net.trunc().contains(&ip)
                }),
            }
        })
}

/// The host of a `Host` header or an origin's authority, without its port: `name`,
/// `name:port`, `a.b.c.d:port`, `[v6]`, `[v6]:port`.
fn host_only(text: &str) -> Option<&str> {
    if let Some(rest) = text.strip_prefix('[') {
        let (address, after) = rest.split_once(']')?;
        return (after.is_empty() || after.strip_prefix(':').is_some_and(is_port))
            .then_some(address);
    }
    match text.rsplit_once(':') {
        Some((host, port)) if is_port(port) => Some(host),
        Some(_) => None,
        None => Some(text),
    }
}

/// Where port 80 sends a request for `host`: the same host over HTTPS on its default port
/// (an IPv6 literal keeps its brackets). `None` for a host that does not parse.
#[must_use]
pub fn https_authority(host: &str) -> Option<String> {
    let bare = host_only(host)?;
    Some(if host.starts_with('[') {
        format!("[{bare}]")
    } else {
        bare.to_owned()
    })
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.len() <= 5 && text.bytes().all(|b| b.is_ascii_digit())
}

/// Whether a request's `Host` (or `:authority`) is the router: one of its two names, or an
/// address literal the kernel holds on any interface; any port.
#[must_use]
pub fn host_allowed(host: &str, names: &Names, world: &World) -> bool {
    let Some(host) = host_only(host) else {
        return false;
    };
    // A name may carry the root's trailing dot; an address literal may not.
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    if name == names.hostname || name == names.fqdn {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|ip| world.addresses.iter().any(|addr| addr.net.addr() == ip))
}

/// Whether a WebSocket upgrade's `Origin` is the router's own panel: `https://` and a host
/// that passes [`host_allowed`]. No `Origin` at all is not a browser, and goes on to the token
/// check.
#[must_use]
pub fn origin_allowed(origin: Option<&str>, names: &Names, world: &World) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    origin
        .strip_prefix("https://")
        .is_some_and(|authority| !authority.contains('/') && host_allowed(authority, names, world))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV6;
    use std::sync::Arc;

    use openfeo_reconcile::fixtures;
    use openfeo_world::{AddrFact, LinkFact};

    use super::*;

    /// `vm-public.toml` (private `lan0`, public `dmz`) with its bridges and addresses up.
    fn world() -> World {
        let mut world = fixtures::public_world();
        let links = Arc::make_mut(&mut world.links);
        for (name, index) in [("br-lan0", 10), ("br-dmz", 11)] {
            links.insert(
                name.to_owned(),
                LinkFact {
                    index,
                    name: name.to_owned(),
                    up: true,
                    carrier: true,
                    mac: None,
                    mtu: 1500,
                    link_local6: None,
                    speed_mbps: None,
                },
            );
        }
        world.addresses = Arc::new(
            [
                ("br-lan0", "192.168.1.1/24"),
                ("br-lan0", "2001:db8:1:1::1/64"),
                ("br-lan0", "fd12:3456:789a:1::1/64"),
                ("br-lan0", "fe80::1/64"),
                ("br-dmz", "192.0.2.233/29"),
                ("br-dmz", "2001:db8:1:2::1/64"),
                ("lo", "fd12:3456:789a::1/128"),
                ("p0", "203.0.113.2/24"),
            ]
            .into_iter()
            .map(|(ifname, net)| AddrFact {
                ifname: ifname.to_owned(),
                net: net.parse().unwrap(),
                peer: None,
                deprecated: false,
            })
            .collect(),
        );
        world
    }

    fn names() -> Names {
        Names::of(None)
    }

    fn scoped(ip: &str, scope: u32) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 50_000, 0, scope))
    }

    #[test]
    fn a_client_on_a_private_lan_is_admitted_by_any_of_its_addresses() {
        let world = world();
        for peer in [
            "192.168.1.23:50000",
            "[2001:db8:1:1::23]:50000",
            "[fd12:3456:789a:1::23]:50000",
        ] {
            assert!(client_admitted(&world, peer.parse().unwrap()), "{peer}");
        }
        assert!(client_admitted(&world, scoped("fe80::23", 10)));
    }

    #[test]
    fn nobody_else_is() {
        let world = world();
        for peer in [
            "203.0.113.9:50000",
            "[2001:db8:ffff::9]:50000",
            "192.0.2.234:50000",         // on the public LAN
            "[2001:db8:1:2::9]:50000",   // on the public LAN
            "[fd12:3456:789a::9]:50000", // in the ULA /48 but on no LAN
            "127.0.0.1:50000",
        ] {
            assert!(!client_admitted(&world, peer.parse().unwrap()), "{peer}");
        }
        assert!(
            !client_admitted(&world, scoped("fe80::1", 2)),
            "link-local on the WAN port"
        );
        assert!(
            !client_admitted(&world, scoped("fe80::1", 11)),
            "link-local on the public LAN"
        );
        assert!(
            !client_admitted(&world, scoped("fe80::1", 0)),
            "link-local with no scope"
        );
    }

    #[test]
    fn an_ipv4_mapped_peer_is_its_ipv4_self() {
        assert!(client_admitted(
            &world(),
            "[::ffff:192.168.1.23]:50000".parse().unwrap()
        ));
        assert!(!client_admitted(
            &world(),
            "[::ffff:203.0.113.9]:50000".parse().unwrap()
        ));
    }

    #[test]
    fn only_the_routers_names_and_its_own_addresses_pass_as_host() {
        let (world, names) = (world(), names());
        for host in [
            "openfeo",
            "OpenFeO.home.arpa.",
            "openfeo.home.arpa:443",
            "192.168.1.1",
            "192.168.1.1:8443",
            "[2001:db8:1:1::1]",
            "[2001:db8:1:1::1]:443",
            "[fd12:3456:789a::1]",
            "203.0.113.2",
        ] {
            assert!(host_allowed(host, &names, &world), "{host}");
        }
        for host in [
            "evil.example",
            "openfeo.evil.example",
            "openfeo.home.arpa.evil.example",
            "192.168.1.2",
            "[2001:db8:1:1::2]",
            "2001:db8:1:1::1",
            "[2001:db8:1:1::1",
            "[2001:db8:1:1::1]x",
            "[2001:db8:1:1::1.]",
            "[2001:db8:1:1::1.]:443",
            "192.168.1.1.",
            "openfeo:port",
            "openfeo:",
            "",
            ".",
        ] {
            assert!(!host_allowed(host, &names, &world), "{host}");
        }
    }

    #[test]
    fn an_origin_must_be_https_and_ours_and_none_at_all_is_a_script() {
        let (world, names) = (world(), names());
        assert!(origin_allowed(None, &names, &world));
        assert!(origin_allowed(
            Some("https://openfeo.home.arpa"),
            &names,
            &world
        ));
        assert!(origin_allowed(
            Some("https://openfeo.home.arpa:8443"),
            &names,
            &world
        ));
        assert!(origin_allowed(Some("https://192.168.1.1"), &names, &world));
        assert!(origin_allowed(
            Some("https://[2001:db8:1:1::1]"),
            &names,
            &world
        ));
        for origin in [
            "http://openfeo.home.arpa",
            "https://evil.example",
            "https://openfeo.home.arpa/",
            "https://openfeo.home.arpa.evil.example",
            "null",
            "",
        ] {
            assert!(!origin_allowed(Some(origin), &names, &world), "{origin}");
        }
    }

    #[test]
    fn port_80_sends_a_host_to_itself_over_https() {
        assert_eq!(
            https_authority("openfeo.home.arpa:80").as_deref(),
            Some("openfeo.home.arpa")
        );
        assert_eq!(
            https_authority("192.168.1.1").as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(
            https_authority("[2001:db8:1:1::1]:80").as_deref(),
            Some("[2001:db8:1:1::1]")
        );
        assert_eq!(https_authority("[2001:db8:1:1::1"), None);
    }

    #[test]
    fn the_names_follow_the_config() {
        assert_eq!(
            names(),
            Names {
                hostname: "openfeo".into(),
                fqdn: "openfeo.home.arpa".into()
            }
        );
    }
}
