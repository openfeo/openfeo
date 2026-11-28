// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The kernel's routes as the API answers them (SPEC §8.3, M4 part 3c): the netlink monitor's
//! cache, whole, each route with its table and its interface by name and who installed it.

use std::sync::Arc;

use openfeo_api::RouteSource;
use openfeo_config::api::{Route, RouteKind};
use openfeo_netlink::{Cache, RTPROT_OPENFEO, TABLE_MAIN};
use openfeo_reconcile::routing::wan_table;
use openfeo_runtime::WorldRx;
use tokio::sync::watch;

/// The kernel's `local` table: its own entries for the addresses it holds.
const TABLE_LOCAL: u32 = 255;
/// `RTPROT_KERNEL`: a route the kernel made for an address or a link.
const RTPROT_KERNEL: u8 = 2;
/// `RTPROT_RA`: a route the kernel learned from a router advertisement.
const RTPROT_RA: u8 = 9;

/// The cache's routes as the wire says them, in the cache's order. `wans` are the WANs' names
/// in config order: the table `100 + n` is the nth one's own (SPEC §7.4).
///
/// A route through a link the cache does not have is left out. It cannot be named, and it is
/// either one whose link is about to be announced or one the kernel has dropped with its link
/// (ADR-0027).
#[must_use]
pub fn routes_of(cache: &Cache, wans: &[String]) -> Vec<Route> {
    cache
        .routes
        .iter()
        .filter_map(|route| {
            let interface = match route.oif {
                Some(index) => cache.links.get(&index)?.name.clone(),
                None => String::new(),
            };
            let kind = match route.kind {
                openfeo_netlink::RouteKind::Unicast => RouteKind::Unicast,
                openfeo_netlink::RouteKind::Unreachable => RouteKind::Unreachable,
                openfeo_netlink::RouteKind::Blackhole => RouteKind::Blackhole,
                openfeo_netlink::RouteKind::Prohibit => RouteKind::Prohibit,
                openfeo_netlink::RouteKind::Local => RouteKind::Local,
            };
            Some(Route {
                v6: route.v6,
                table: table_name(route.table, wans),
                destination: route.dst.map_or_else(String::new, |dst| dst.to_string()),
                gateway: route
                    .gateway
                    .map_or_else(String::new, |gateway| gateway.to_string()),
                interface,
                protocol: match route.protocol {
                    RTPROT_KERNEL => "kernel".to_owned(),
                    RTPROT_OPENFEO => "openfeo".to_owned(),
                    RTPROT_RA => "ra".to_owned(),
                    other => other.to_string(),
                },
                metric: route.priority,
                kind: kind.into(),
            })
        })
        .collect()
}

/// `main`, `local`, the name of the WAN whose own table it is, or the number.
fn table_name(table: u32, wans: &[String]) -> String {
    match table {
        TABLE_MAIN => "main".to_owned(),
        TABLE_LOCAL => "local".to_owned(),
        other => wans
            .iter()
            .enumerate()
            .find(|(index, _)| wan_table(*index) == other)
            .map_or_else(|| other.to_string(), |(_, name)| name.clone()),
    }
}

/// The routes the netlink monitor follows, with the WANs' names from the running config.
pub struct RouterRoutes {
    cache: watch::Receiver<Arc<Cache>>,
    world: WorldRx,
}

impl RouterRoutes {
    /// Routes read from `cache`, tables named by `world`'s config.
    #[must_use]
    pub fn new(cache: watch::Receiver<Arc<Cache>>, world: WorldRx) -> Self {
        RouterRoutes { cache, world }
    }
}

impl RouteSource for RouterRoutes {
    fn routes(&self) -> Vec<Route> {
        let wans: Vec<String> = self
            .world
            .borrow()
            .config
            .wans
            .iter()
            .map(|wan| wan.name.clone())
            .collect();
        routes_of(&self.cache.borrow(), &wans)
    }
}

#[cfg(test)]
mod tests {
    use openfeo_netlink::{Link, Route as Kernel, RouteKind as KernelKind};

    use super::*;

    fn link(index: u32, name: &str) -> Link {
        Link {
            index,
            name: name.to_owned(),
            kind: None,
            master: None,
            parent: None,
            vlan_id: None,
            up: true,
            carrier: true,
            mac: None,
            mtu: 1500,
        }
    }

    /// The IPv4 default route of the main table through link 2, as the router installs it.
    fn default4() -> Kernel {
        Kernel {
            v6: false,
            table: TABLE_MAIN,
            dst: None,
            gateway: Some("203.0.113.1".parse().unwrap()),
            oif: Some(2),
            protocol: RTPROT_OPENFEO,
            priority: 10,
            kind: KernelKind::Unicast,
            pref_src: None,
        }
    }

    fn cache(routes: impl IntoIterator<Item = Kernel>) -> Cache {
        let mut cache = Cache::default();
        cache.links.insert(2, link(2, "p0"));
        cache.links.insert(5, link(5, "br-lan0"));
        cache.routes.extend(routes);
        cache
    }

    fn wans() -> Vec<String> {
        vec!["wan0".to_owned(), "wan1".to_owned()]
    }

    fn one(route: Kernel) -> Route {
        let said = routes_of(&cache([route]), &wans());
        assert_eq!(said.len(), 1, "{said:?}");
        said.into_iter().next().unwrap()
    }

    #[test]
    fn a_table_is_said_by_name() {
        let in_table = |table: u32| {
            one(Kernel {
                table,
                ..default4()
            })
            .table
        };
        assert_eq!(in_table(254), "main");
        assert_eq!(in_table(255), "local");
        assert_eq!(in_table(100), "wan0");
        assert_eq!(in_table(101), "wan1");
        assert_eq!(in_table(102), "102", "no third WAN: the number");
        assert_eq!(in_table(53), "53");
    }

    #[test]
    fn the_default_route_has_no_destination() {
        assert_eq!(one(default4()).destination, "");
        let prefix = one(Kernel {
            v6: true,
            dst: Some("2001:db8:1::/48".parse().unwrap()),
            gateway: None,
            oif: None,
            kind: KernelKind::Blackhole,
            ..default4()
        });
        assert!(prefix.v6);
        assert_eq!(prefix.destination, "2001:db8:1::/48");
    }

    #[test]
    fn a_route_says_its_gateway_and_its_interface_by_name() {
        let through = one(default4());
        assert_eq!(
            (through.gateway.as_str(), through.interface.as_str()),
            ("203.0.113.1", "p0")
        );
        let on_the_link = one(Kernel {
            dst: Some("192.168.1.0/24".parse().unwrap()),
            gateway: None,
            oif: Some(5),
            ..default4()
        });
        assert_eq!(
            (on_the_link.gateway.as_str(), on_the_link.interface.as_str()),
            ("", "br-lan0")
        );
        let refused = one(Kernel {
            gateway: None,
            oif: None,
            kind: KernelKind::Unreachable,
            ..default4()
        });
        assert_eq!(
            (refused.gateway.as_str(), refused.interface.as_str()),
            ("", "")
        );
    }

    /// A PPPoE session that came back is a new interface; what was routed through the old one
    /// is not listed (ADR-0027).
    #[test]
    fn a_route_through_a_link_the_cache_does_not_have_is_left_out() {
        let gone = Kernel {
            oif: Some(9),
            ..default4()
        };
        let said = routes_of(&cache([gone, default4()]), &wans());
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].interface, "p0");
    }

    #[test]
    fn who_installed_it_is_a_word_or_the_number() {
        let by = |protocol: u8| {
            one(Kernel {
                protocol,
                ..default4()
            })
            .protocol
        };
        assert_eq!(by(2), "kernel");
        assert_eq!(by(200), "openfeo");
        assert_eq!(by(9), "ra");
        assert_eq!(by(16), "16");
    }

    #[test]
    fn each_kind_is_said() {
        for (kernel, said) in [
            (KernelKind::Unicast, RouteKind::Unicast),
            (KernelKind::Unreachable, RouteKind::Unreachable),
            (KernelKind::Blackhole, RouteKind::Blackhole),
            (KernelKind::Prohibit, RouteKind::Prohibit),
            (KernelKind::Local, RouteKind::Local),
        ] {
            let route = one(Kernel {
                kind: kernel,
                ..default4()
            });
            assert_eq!(route.kind(), said);
            assert_eq!(route.metric, 10, "the metric is the kernel's priority");
        }
    }
}
