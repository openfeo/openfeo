// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel-backed tests for `openfeo-netlink` (and, from Task 11, `openfeo-apply`) against veth
//! pairs inside the rootless sandbox: no QEMU, a few milliseconds each. `harness = false`: this
//! binary is its own runner; an optional first argument filters scenarios by substring. Every
//! scenario uses interface names of its own and deletes them on the way out, because the sandbox's
//! network namespace outlives the scenarios.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use ipnet::IpNet;
use openfeo_apply::ApplyError;
use openfeo_apply::links::LinksApplier;
use openfeo_apply::nft::NftApplier;
use openfeo_apply::routing::RoutingApplier;
use openfeo_apply::sysctl::SysctlApplier;
use openfeo_config::{Config, PortMap, PortMapEntry};
use openfeo_harness::lab::Lab;
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_harness::{daemons, lanclient, netns, nftlist, nftprobe, sandbox, vlanprobe};
use openfeo_netlink::{
    Cache, LinkKind, Netlink, RTPROT_OPENFEO, RULE_PRIORITY_MAIN_SUPPRESS, RULE_PRIORITY_SOURCE,
    Route, RouteKind, Rule, RuleAction, TABLE_MAIN,
};
use openfeo_nft::Nft;
use openfeo_platform::sysctl;
use openfeo_reconcile::links::{DesiredLinks, DesiredPort, DesiredPpp, PPPOE_PORT_MTU, PortKind};
use openfeo_reconcile::nft::nft;
use openfeo_reconcile::routing::{DesiredAddr, DesiredRouting};
use openfeo_reconcile::sysctl::DesiredSysctl;
use openfeo_world::{Dhcp4Fact, LinkFact, MacAddr, TimeFact, WanIpv6Fact, World};
use tokio::sync::watch;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "a_suppress_main_rule_and_a_source_rule_are_added_dumped_and_removed",
        run: a_suppress_main_rule_and_a_source_rule_are_added_dumped_and_removed,
    },
    Scenario {
        name: "an_unreachable_rule_answers_with_no_route",
        run: an_unreachable_rule_answers_with_no_route,
    },
    Scenario {
        name: "an_unreachable_default_in_table_100_is_added_and_dumped",
        run: an_unreachable_default_in_table_100_is_added_and_dumped,
    },
    Scenario {
        name: "a_rule_added_behind_the_monitors_back_is_cached",
        run: a_rule_added_behind_the_monitors_back_is_cached,
    },
    Scenario {
        name: "ipv6_addresses_default_with_preferred_source_and_blackhole_are_applied_and_removed",
        run: ipv6_addresses_default_with_preferred_source_and_blackhole_are_applied_and_removed,
    },
    Scenario {
        name: "an_ipv6_blackhole_route_round_trips_through_the_cache",
        run: an_ipv6_blackhole_route_round_trips_through_the_cache,
    },
    Scenario {
        name: "a_stable_privacy_link_local_is_the_same_across_two_bounces",
        run: a_stable_privacy_link_local_is_the_same_across_two_bounces,
    },
    Scenario {
        name: "monitor_sees_veth_addr_and_route",
        run: monitor_sees_veth_addr_and_route,
    },
    Scenario {
        name: "bridge_with_vlan_filtering_enslave_rename",
        run: bridge_with_vlan_filtering_enslave_rename,
    },
    Scenario {
        name: "addr_and_route_primitives",
        run: addr_and_route_primitives,
    },
    Scenario {
        name: "apply_builds_bridge_addrs_routes",
        run: apply_builds_bridge_addrs_routes,
    },
    Scenario {
        name: "reapply_is_a_noop",
        run: reapply_is_a_noop,
    },
    Scenario {
        name: "config_change_moves_the_lan_address",
        run: config_change_moves_the_lan_address,
    },
    Scenario {
        name: "foreign_state_is_untouched",
        run: foreign_state_is_untouched,
    },
    Scenario {
        name: "global_ipv6_address_is_untouched",
        run: global_ipv6_address_is_untouched,
    },
    Scenario {
        name: "partial_failure_still_applies_the_rest",
        run: partial_failure_still_applies_the_rest,
    },
    Scenario {
        name: "nft_applier_applies_once_then_noops",
        run: nft_applier_applies_once_then_noops,
    },
    Scenario {
        name: "sysctl_applier_turns_forwarding_on_and_off",
        run: sysctl_applier_turns_forwarding_on_and_off,
    },
    Scenario {
        name: "sysctl_for_a_missing_interface_is_reported_last",
        run: sysctl_for_a_missing_interface_is_reported_last,
    },
    Scenario {
        name: "http_get_reaches_a_server_in_the_sandbox",
        run: http_get_reaches_a_server_in_the_sandbox,
    },
    Scenario {
        name: "link_set_mtu_shows_in_the_cache",
        run: link_set_mtu_shows_in_the_cache,
    },
    Scenario {
        name: "links_applier_sets_a_dhcp_wan_mtu",
        run: links_applier_sets_a_dhcp_wan_mtu,
    },
    Scenario {
        name: "routing_applier_adds_a_host_route_before_an_off_link_default",
        run: routing_applier_adds_a_host_route_before_an_off_link_default,
    },
    Scenario {
        name: "vlan_link_primitive_and_facts",
        run: vlan_link_primitive_and_facts,
    },
    Scenario {
        name: "blackhole_route_primitive_and_facts",
        run: blackhole_route_primitive_and_facts,
    },
    Scenario {
        name: "stray_vlan_sub_interfaces_are_removed",
        run: stray_vlan_sub_interfaces_are_removed,
    },
    Scenario {
        name: "routing_applier_owns_block_blackholes",
        run: routing_applier_owns_block_blackholes,
    },
    Scenario {
        name: "a_point_to_point_address_is_added_with_its_peer_and_removed",
        run: a_point_to_point_address_is_added_with_its_peer_and_removed,
    },
    Scenario {
        name: "the_links_applier_renames_and_sizes_a_unit_netdev",
        run: the_links_applier_renames_and_sizes_a_unit_netdev,
    },
    Scenario {
        name: "a_refused_port_mtu_is_tolerated",
        run: a_refused_port_mtu_is_tolerated,
    },
];

/// The routing applier adds a declared block's blackhole once, keeps it on a second pass, and
/// removes it when the block leaves the config (SPEC §7.4).
fn routing_applier_owns_block_blackholes(_lab: &mut Lab) -> anyhow::Result<()> {
    fn has_blackhole(cache: &Cache) -> bool {
        cache.routes.iter().any(|r| {
            r.kind == RouteKind::Blackhole
                && r.dst.map(|d| d.to_string()) == Some("192.0.2.248/29".to_owned())
                && r.protocol == RTPROT_OPENFEO
                && r.priority == 1000
        })
    }
    let _ports = FakePorts::create()?;
    block_on(async {
        let (mut rig, mut config) = build_static().await?;
        config.public_ipv4.push(openfeo_config::PublicIpv4 {
            prefix: "192.0.2.248/29".into(),
        });
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 1), "one blackhole added: {ops:?}");
        wait_until(&mut rig.rx, "blackhole cached", has_blackhole).await?;
        ensure!(
            netns::ip(&["route", "show", "type", "blackhole"])?.contains("192.0.2.248/29"),
            "the kernel has the blackhole"
        );
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 0), "second pass is a no-op: {ops:?}");
        config.public_ipv4.clear();
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 1), "blackhole removed: {ops:?}");
        wait_until(&mut rig.rx, "blackhole gone", |c| !has_blackhole(c)).await?;
        anyhow::Ok(())
    })?
}

/// A `p1.223` nobody wants is deleted by the links applier; a VLAN that is not ours (`vlan7` on
/// a foreign link) is left alone.
fn stray_vlan_sub_interfaces_are_removed(_lab: &mut Lab) -> anyhow::Result<()> {
    vlanprobe::require_vlan_links()?;
    let _ports = FakePorts::create()?;
    let _ = netns::ip(&["link", "del", "vlan7"]);
    block_on(async {
        let (mut rig, config) = build_static().await?;
        netns::ip(&[
            "link", "add", "link", "p1", "name", "p1.223", "type", "vlan", "id", "223",
        ])?;
        netns::ip(&[
            "link", "add", "link", "h0", "name", "vlan7", "type", "vlan", "id", "7",
        ])?;
        wait_until(&mut rig.rx, "both VLANs in the cache", |c| {
            c.link_by_name("p1.223").is_some() && c.link_by_name("vlan7").is_some()
        })
        .await?;
        let ops = rig.apply(&config).await?;
        ensure!(
            ops == (1, 0),
            "expected only the stray p1.223 to go: {ops:?}"
        );
        wait_until(&mut rig.rx, "p1.223 gone", |c| {
            c.link_by_name("p1.223").is_none()
        })
        .await?;
        ensure!(
            rig.rx.borrow().link_by_name("vlan7").is_some(),
            "vlan7 is not ours"
        );
        let _ = netns::ip(&["link", "del", "vlan7"]);
        anyhow::Ok(())
    })?
}

/// A VLAN sub-interface is created on a fake port, seen by the monitor with its kind, parent and
/// id, enslaved to a bridge, and deleted (ADR-0017).
fn vlan_link_primitive_and_facts(_lab: &mut Lab) -> anyhow::Result<()> {
    vlanprobe::require_vlan_links()?;
    let _ports = FakePorts::create()?;
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let p1 = nl.link_index("p1").await?.context("p1")?;
        nl.link_add_vlan(p1, 223, "p1.223").await?;
        wait_until(&mut rx, "p1.223 appears", |c| {
            c.link_by_name("p1.223").is_some()
        })
        .await?;
        let link = rx
            .borrow()
            .link_by_name("p1.223")
            .context("p1.223")?
            .clone();
        ensure!(
            link.kind == Some(LinkKind::Vlan)
                && link.parent == Some(p1)
                && link.vlan_id == Some(223),
            "the monitor's account of p1.223: {link:?}"
        );
        nl.link_add_bridge("br-lan0", true).await?;
        let br = nl.link_index("br-lan0").await?.context("br-lan0")?;
        nl.link_set_master(link.index, Some(br)).await?;
        wait_until(&mut rx, "p1.223 enslaved", |c| {
            c.link_by_name("p1.223")
                .is_some_and(|l| l.master == Some(br))
        })
        .await?;
        nl.link_del(link.index).await?;
        wait_until(&mut rx, "p1.223 gone", |c| {
            c.link_by_name("p1.223").is_none()
        })
        .await?;
        anyhow::Ok(())
    })?
}

/// A blackhole route is added with its kind, cached with its kind, described, and deleted.
fn blackhole_route_primitive_and_facts(_lab: &mut Lab) -> anyhow::Result<()> {
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let route = Route {
            v6: false,
            table: TABLE_MAIN,
            dst: Some("192.0.2.248/29".parse()?),
            gateway: None,
            oif: None,
            protocol: RTPROT_OPENFEO,
            priority: 1000,
            kind: RouteKind::Blackhole,
            pref_src: None,
        };
        let _ = nl.route_del(&route).await; // left by an interrupted run
        nl.route_add(&route).await?;
        wait_until(&mut rx, "blackhole cached", |c| c.routes.contains(&route)).await?;
        ensure!(
            openfeo_netlink::describe(&route)
                == "blackhole 192.0.2.248/29 proto 200 metric 1000 table 254",
            "describe: {}",
            openfeo_netlink::describe(&route)
        );
        nl.route_del(&route).await?;
        wait_until(&mut rx, "blackhole gone", |c| !c.routes.contains(&route)).await?;
        anyhow::Ok(())
    })?
}

/// The IPv6 lab configuration (`harness/fixtures/vm-ipv6.toml`) on the three fake ports: the
/// DMZ on p3 and the public block are dropped.
fn ipv6_config() -> anyhow::Result<Config> {
    let mut config = openfeo_config::file::parse(include_str!("../fixtures/vm-ipv6.toml"))?;
    config.lans.retain(|lan| lan.name == "lan0");
    config.public_ipv4.clear(); // its blackhole has no device and would outlive the fake ports
    if let Some(firewall) = &mut config.firewall {
        firewall.rules.clear();
    }
    Ok(config)
}

/// What the ISP's advertisements would have taught wan0: a router at `fe80::1` and an MTU.
fn ipv6_fact() -> WanIpv6Fact {
    WanIpv6Fact {
        router: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        addresses: Vec::new(),
        on_link: Vec::new(),
        routes: Vec::new(),
        dns: vec![Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1)],
        search: Vec::new(),
        mtu: Some(1500),
    }
}

/// The IPv6 default the routing applier installs for the IPv6 lab: via the advertised router
/// on p0, metric 10, the router's loopback address as preferred source.
fn ipv6_default_via_router(p0: u32) -> Route {
    Route {
        v6: true,
        table: TABLE_MAIN,
        dst: None,
        gateway: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into()),
        oif: Some(p0),
        protocol: RTPROT_OPENFEO,
        priority: 10,
        kind: RouteKind::Unicast,
        pref_src: Some(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1).into()),
    }
}

/// The blackhole for the IPv6 lab's routed prefix.
fn ipv6_blackhole() -> Route {
    Route {
        v6: true,
        table: TABLE_MAIN,
        dst: Some(IpNet::V6(ipnet::Ipv6Net::new_assert(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
            48,
        ))),
        gateway: None,
        oif: None,
        protocol: RTPROT_OPENFEO,
        priority: 1000,
        kind: RouteKind::Blackhole,
        pref_src: None,
    }
}

/// The link-local address of the named link in the cache, if the kernel has made one.
fn link_local_of(cache: &Cache, name: &str) -> Option<Ipv6Addr> {
    let link = cache.link_by_name(name)?;
    cache.addrs.iter().find_map(|a| match a.net {
        IpNet::V6(net)
            if a.ifindex == link.index && net.addr().segments()[0] & 0xffc0 == 0xfe80 =>
        {
            Some(net.addr())
        }
        _ => None,
    })
}

/// The IPv6 side of the routing applier (SPEC §7.3, §7.4) on fake ports: the LAN's /64 on its
/// bridge, the router's /128 on lo, the default via the advertised router with the loopback
/// address as preferred source, the blackhole for the routed prefix; a second pass does nothing
/// (the IPv6 blackhole compares equal through the cache, ADR-0020); a LAN that loses its `ipv6`
/// loses the bridge address, while lo and the default stay.
fn ipv6_addresses_default_with_preferred_source_and_blackhole_are_applied_and_removed(
    _lab: &mut Lab,
) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    netns::ip(&["link", "set", "h0", "up"])?; // carrier for p0, so it gets a link-local address
    block_on(async {
        let mut config = ipv6_config()?;
        let mut rig = Rig::connect().await?;
        let links_pass = async |rig: &mut Rig, config: &Config| -> anyhow::Result<usize> {
            let cache = rig.rx.borrow_and_update().clone();
            let world = world_from(&cache, config);
            Ok(rig
                .links
                .apply(&openfeo_reconcile::links::links(&world), &cache, &rig.nl)
                .await?
                .ops)
        };
        let routing_pass = async |rig: &mut Rig, config: &Config| -> anyhow::Result<usize> {
            let cache = rig.rx.borrow_and_update().clone();
            let mut world = world_from(&cache, config);
            world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), ipv6_fact())]));
            Ok(rig
                .routing
                .apply(
                    &openfeo_reconcile::routing::routing(&world),
                    &cache,
                    &rig.nl,
                )
                .await?
                .ops)
        };
        links_pass(&mut rig, &config).await?;
        wait_until(&mut rig.rx, "p0 up with a link-local address", |c| {
            c.link_by_name("p0").is_some_and(|l| l.up && l.carrier)
                && link_local_of(c, "p0").is_some()
        })
        .await?;
        let ops = routing_pass(&mut rig, &config).await?;
        ensure!(ops >= 4, "the first routing pass did {ops} things");
        let lan6: IpNet = "2001:db8:1:222::1/64".parse()?;
        let lo6: IpNet = "2001:db8:1::1/128".parse()?;
        wait_until(&mut rig.rx, "lan and loopback IPv6 addresses", |c| {
            let on = |name: &str, net: IpNet| {
                c.link_by_name(name)
                    .is_some_and(|l| c.addrs.iter().any(|a| a.ifindex == l.index && a.net == net))
            };
            on("br-lan0", lan6) && on("lo", lo6)
        })
        .await?;
        let p0 = rig.rx.borrow().link_by_name("p0").context("p0")?.index;
        let default6 = ipv6_default_via_router(p0);
        let blackhole6 = ipv6_blackhole();
        wait_until(
            &mut rig.rx,
            "the IPv6 default with its source and the blackhole",
            |c| c.routes.contains(&default6) && c.routes.contains(&blackhole6),
        )
        .await?;
        let again = routing_pass(&mut rig, &config).await?;
        ensure!(again == 0, "second routing pass changed {again} things");
        config.lans[0].ipv6 = String::new();
        let ops = routing_pass(&mut rig, &config).await?;
        ensure!(
            ops == 1,
            "dropping the LAN's ipv6 removed {ops} things, not one"
        );
        wait_until(
            &mut rig.rx,
            "the bridge address gone, lo and the default kept",
            |c| {
                let gone = c.link_by_name("br-lan0").is_some_and(|l| {
                    !c.addrs
                        .iter()
                        .any(|a| a.ifindex == l.index && a.net == lan6)
                });
                gone && c.routes.contains(&default6) && c.addrs.iter().any(|a| a.net == lo6)
            },
        )
        .await?;
        // A box that drops [wans.ipv6] loses the default in `main` and in the WAN's table, the
        // blackhole, its loopback address and the suppress-main rule (SPEC §7.4): nothing of
        // this scenario outlives it in the shared namespace.
        config.wans[0].ipv6 = None;
        let ops = routing_pass(&mut rig, &config).await?;
        ensure!(
            ops == 5,
            "dropping [wans.ipv6] removed {ops} things, not five"
        );
        wait_until(&mut rig.rx, "no IPv6 of ours left", |c| {
            !c.routes
                .iter()
                .any(|r| r.v6 && r.protocol == RTPROT_OPENFEO)
                && !c.addrs.iter().any(|a| a.net == lo6)
                && !c.rules.iter().any(|r| r.protocol == RTPROT_OPENFEO)
        })
        .await?;
        anyhow::Ok(())
    })?
}

/// An IPv6 blackhole route comes back from the kernel with `lo` as its device (ADR-0020); the
/// monitor drops it, so the cache holds the route exactly as added.
fn an_ipv6_blackhole_route_round_trips_through_the_cache(_lab: &mut Lab) -> anyhow::Result<()> {
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let route = ipv6_blackhole();
        let _ = nl.route_del(&route).await; // left by an interrupted run
        nl.route_add(&route).await?;
        wait_until(&mut rx, "IPv6 blackhole cached as added", |c| {
            c.routes.contains(&route)
        })
        .await?;
        ensure!(
            netns::ip(&["-6", "route", "show", "type", "blackhole"])?.contains("2001:db8:1::/48"),
            "the kernel shows the blackhole"
        );
        nl.route_del(&route).await?;
        wait_until(&mut rx, "IPv6 blackhole gone", |c| {
            !c.routes.contains(&route)
        })
        .await?;
        anyhow::Ok(())
    })?
}

/// The links applier writes the stable-privacy secret to the IPv6 WAN's port before bringing
/// it up (SPEC §7.3): the link-local address is not the EUI-64 of the port's MAC, a second pass
/// does nothing, and the address is the same after the port is bounced.
fn a_stable_privacy_link_local_is_the_same_across_two_bounces(
    _lab: &mut Lab,
) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    netns::ip(&["link", "set", "h0", "up"])?;
    block_on(async {
        let config = ipv6_config()?;
        let mut rig = Rig::connect().await?;
        rig.links = LinksApplier::with_ipv6_secret([7; 16]);
        let pass = async |rig: &mut Rig| -> anyhow::Result<usize> {
            let cache = rig.rx.borrow_and_update().clone();
            let world = world_from(&cache, &config);
            Ok(rig
                .links
                .apply(&openfeo_reconcile::links::links(&world), &cache, &rig.nl)
                .await?
                .ops)
        };
        pass(&mut rig).await?;
        wait_until(&mut rig.rx, "p0 up with a link-local address", |c| {
            c.link_by_name("p0").is_some_and(|l| l.up) && link_local_of(c, "p0").is_some()
        })
        .await?;
        let first = link_local_of(&rig.rx.borrow(), "p0").context("link-local")?;
        let mac = rig
            .rx
            .borrow()
            .link_by_name("p0")
            .and_then(|l| l.mac)
            .context("mac")?;
        let eui64 = Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
            u16::from_be_bytes([mac[2], 0xff]),
            u16::from_be_bytes([0xfe, mac[3]]),
            u16::from_be_bytes([mac[4], mac[5]]),
        );
        ensure!(
            first != eui64,
            "{first} is the EUI-64 address, not a stable-privacy one"
        );
        ensure!(
            sysctl::read("net/ipv6/conf/p0/addr_gen_mode")?.trim() == "2",
            "addr_gen_mode is stable-privacy"
        );
        let again = pass(&mut rig).await?;
        ensure!(again == 0, "second links pass changed {again} things");
        let p0 = rig.rx.borrow().link_by_name("p0").context("p0")?.index;
        rig.nl.link_set_up(p0, false).await?;
        wait_until(&mut rig.rx, "p0 down without its link-local", |c| {
            c.link_by_name("p0").is_some_and(|l| !l.up) && link_local_of(c, "p0").is_none()
        })
        .await?;
        rig.nl.link_set_up(p0, true).await?;
        wait_until(&mut rig.rx, "p0 up again with a link-local", |c| {
            c.link_by_name("p0").is_some_and(|l| l.up) && link_local_of(c, "p0").is_some()
        })
        .await?;
        let second = link_local_of(&rig.rx.borrow(), "p0").context("link-local")?;
        ensure!(second == first, "{second} after the bounce, {first} before");
        anyhow::Ok(())
    })?
}

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// How long a kernel notification may take to reach the cache.
const SETTLE: Duration = Duration::from_secs(2);

fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    Ok(runtime.block_on(future))
}

/// Wait until `pred` holds for the cache, or fail after [`SETTLE`].
async fn wait_until(
    rx: &mut watch::Receiver<Arc<Cache>>,
    what: &str,
    pred: impl Fn(&Cache) -> bool,
) -> anyhow::Result<()> {
    loop {
        if pred(&rx.borrow_and_update()) {
            return Ok(());
        }
        tokio::time::timeout(SETTLE, rx.changed())
            .await
            .with_context(|| {
                let cache = rx.borrow();
                format!(
                    "timed out waiting for {what}; cache has {} links, addrs {:?}, {} routes",
                    cache.links.len(),
                    cache.addrs,
                    cache.routes.len()
                )
            })?
            .context("monitor stopped")?;
    }
}

/// The monitor's initial dump and its notifications for a link, an address and a route.
fn monitor_sees_veth_addr_and_route(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ = netns::ip(&["link", "del", "nv0"]);
    netns::ip(&["link", "add", "nv0", "type", "veth", "peer", "name", "nv1"])?;
    let result = block_on(async {
        let (_nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let nv0 = {
            let cache = rx.borrow().clone();
            let link = cache
                .link_by_name("nv0")
                .context("nv0 in the initial dump")?;
            ensure!(link.kind == Some(LinkKind::Veth), "kind {:?}", link.kind);
            ensure!(!link.up, "nv0 should start down");
            link.index
        };
        netns::ip(&["link", "set", "nv1", "up"])?;
        netns::ip(&["link", "set", "nv0", "up"])?;
        wait_until(&mut rx, "nv0 up", |c| {
            c.link_by_name("nv0").is_some_and(|l| l.up)
        })
        .await?;
        netns::ip(&["addr", "add", "10.0.0.1/24", "dev", "nv0"])?;
        wait_until(&mut rx, "10.0.0.1/24 on nv0", |c| {
            c.addrs
                .iter()
                .any(|a| a.ifindex == nv0 && a.net.to_string() == "10.0.0.1/24")
        })
        .await?;
        netns::ip(&[
            "route",
            "add",
            "10.9.0.0/24",
            "via",
            "10.0.0.2",
            "proto",
            "200",
        ])?;
        wait_until(&mut rx, "route 10.9.0.0/24 via 10.0.0.2 proto 200", |c| {
            c.routes.iter().any(|r| {
                r.dst.map(|d| d.to_string()) == Some("10.9.0.0/24".to_owned())
                    && r.gateway.map(|g| g.to_string()) == Some("10.0.0.2".to_owned())
                    && r.protocol == RTPROT_OPENFEO
                    && r.table == TABLE_MAIN
                    && r.oif == Some(nv0)
                    && !r.v6
            })
        })
        .await?;
        netns::ip(&["route", "del", "10.9.0.0/24"])?;
        wait_until(&mut rx, "route gone", |c| {
            !c.routes.iter().any(|r| r.protocol == RTPROT_OPENFEO)
        })
        .await?;
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "nv0"]);
    result?
}

/// Bridge creation with VLAN filtering, enslaving and releasing, renaming, setting a MAC,
/// up/down, deletion: every link primitive the links applier uses.
fn bridge_with_vlan_filtering_enslave_rename(_lab: &mut Lab) -> anyhow::Result<()> {
    for name in ["bv0", "br-t0", "bt1"] {
        let _ = netns::ip(&["link", "del", name]);
    }
    netns::ip(&["link", "add", "bv0", "type", "veth", "peer", "name", "bv1"])?;
    let result = block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        nl.link_add_bridge("br-t0", true).await?;
        wait_until(&mut rx, "br-t0 in the cache", |c| {
            c.link_by_name("br-t0")
                .is_some_and(|l| l.kind == Some(LinkKind::Bridge))
        })
        .await?;
        let details = netns::ip(&["-d", "link", "show", "br-t0"])?;
        ensure!(details.contains("vlan_filtering 1"), "{details}");
        // Born down: the applier sets the MAC before it brings the bridge up, so the kernel
        // derives the link-local from the MAC the LAN will know, not from the random one.
        let born_up = rx.borrow().link_by_name("br-t0").context("br-t0")?.up;
        ensure!(!born_up, "a new bridge came up by itself");
        let br = rx.borrow().link_by_name("br-t0").context("br-t0")?.index;
        let bv0 = rx.borrow().link_by_name("bv0").context("bv0")?.index;
        nl.link_set_master(bv0, Some(br)).await?;
        wait_until(&mut rx, "bv0 enslaved", |c| {
            c.links.get(&bv0).is_some_and(|l| l.master == Some(br))
        })
        .await?;
        nl.link_set_master(bv0, None).await?;
        wait_until(&mut rx, "bv0 released", |c| {
            c.links.get(&bv0).is_some_and(|l| l.master.is_none())
        })
        .await?;
        let bv1 = rx.borrow().link_by_name("bv1").context("bv1")?.index;
        nl.link_set_name(bv1, "bt1").await?;
        wait_until(&mut rx, "bv1 renamed to bt1", |c| {
            c.link_by_name("bt1").is_some_and(|l| l.index == bv1)
        })
        .await?;
        let mac = [0x02, 0x00, 0x00, 0xfe, 0x00, 0x01];
        nl.link_set_mac(br, mac).await?;
        wait_until(&mut rx, "bridge mac", |c| {
            c.links.get(&br).is_some_and(|l| l.mac == Some(mac))
        })
        .await?;
        nl.link_set_up(bv0, true).await?;
        wait_until(&mut rx, "bv0 up", |c| {
            c.links.get(&bv0).is_some_and(|l| l.up)
        })
        .await?;
        nl.link_set_up(bv0, false).await?;
        wait_until(&mut rx, "bv0 down", |c| {
            c.links.get(&bv0).is_some_and(|l| !l.up)
        })
        .await?;
        nl.link_del(br).await?;
        wait_until(&mut rx, "br-t0 gone", |c| c.link_by_name("br-t0").is_none()).await?;
        anyhow::Ok(())
    });
    for name in ["bv0", "br-t0", "bt1"] {
        let _ = netns::ip(&["link", "del", name]);
    }
    result?
}

/// Address and route primitives, including the `EEXIST` a duplicate route add reports.
fn addr_and_route_primitives(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ = netns::ip(&["link", "del", "rv0"]);
    netns::ip(&["link", "add", "rv0", "type", "veth", "peer", "name", "rv1"])?;
    netns::ip(&["link", "set", "rv1", "up"])?;
    netns::ip(&["link", "set", "rv0", "up"])?;
    let result = block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let rv0 = rx.borrow().link_by_name("rv0").context("rv0")?.index;
        let net: IpNet = "10.0.1.1/24".parse()?;
        nl.addr_add(rv0, net).await?;
        wait_until(&mut rx, "10.0.1.1/24 on rv0", |c| {
            c.addrs.iter().any(|a| a.ifindex == rv0 && a.net == net)
        })
        .await?;
        ensure!(netns::ip(&["-4", "addr", "show", "rv0"])?.contains("10.0.1.1/24"));
        let route = Route {
            v6: false,
            table: TABLE_MAIN,
            dst: None,
            gateway: Some("10.0.1.2".parse()?),
            oif: Some(rv0),
            protocol: RTPROT_OPENFEO,
            priority: 10,
            kind: RouteKind::Unicast,
            pref_src: None,
        };
        nl.route_add(&route).await?;
        wait_until(&mut rx, "default route", |c| c.routes.contains(&route)).await?;
        let shown = netns::ip(&["route", "show", "default"])?;
        ensure!(
            shown.contains("default via 10.0.1.2 dev rv0 proto 200 metric 10"),
            "{shown}"
        );
        match nl.route_add(&route).await {
            Err(err) if err.is_exist() => {}
            other => anyhow::bail!("duplicate route add should be EEXIST, got {other:?}"),
        }
        nl.route_del(&route).await?;
        wait_until(&mut rx, "route gone", |c| !c.routes.contains(&route)).await?;
        nl.addr_del(rv0, net).await?;
        wait_until(&mut rx, "address gone", |c| {
            !c.addrs.iter().any(|a| a.ifindex == rv0 && a.net == net)
        })
        .await?;
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "rv0"]);
    result?
}

// ---- openfeo-apply against the lab's port names -------------------------------------------

/// The lab's configuration (`harness/fixtures/vm-static.toml`), parsed.
fn static_config() -> anyhow::Result<Config> {
    Ok(openfeo_config::file::parse(include_str!(
        "../fixtures/vm-static.toml"
    ))?)
}

/// Three veth pairs named like the lab's ports (`p0..p2`, peers `h0..h2`); everything the
/// appliers may have created is removed when the guard drops.
struct FakePorts;

impl FakePorts {
    fn create() -> anyhow::Result<Self> {
        let guard = FakePorts;
        Self::cleanup();
        for i in 0..3 {
            netns::ip(&[
                "link",
                "add",
                &format!("p{i}"),
                "type",
                "veth",
                "peer",
                "name",
                &format!("h{i}"),
            ])?;
        }
        Ok(guard)
    }

    fn cleanup() {
        for name in ["p1.223", "p0", "p1", "p2", "br-lan0", "br-zz"] {
            let _ = netns::ip(&["link", "del", name]);
        }
    }
}

impl Drop for FakePorts {
    fn drop(&mut self) {
        Self::cleanup();
    }
}

/// A World over the cache's link facts, a `p0..p2` port map and `config`.
/// The lab's three ports, as the QEMU VM sees them.
fn lab_portmap() -> PortMap {
    PortMap {
        ports: (0..3)
            .map(|i| PortMapEntry {
                id: format!("pci-0000:00:0{}.0", 3 + i),
                name: format!("p{i}"),
            })
            .collect(),
    }
}

fn world_from(cache: &Cache, config: &Config) -> World {
    let ports = lab_portmap();
    let links = cache
        .links
        .values()
        .map(|l| {
            (
                l.name.clone(),
                LinkFact {
                    index: l.index,
                    name: l.name.clone(),
                    up: l.up,
                    carrier: l.carrier,
                    mac: l.mac.map(MacAddr),
                    mtu: l.mtu,
                    link_local6: None,
                },
            )
        })
        .collect();
    World {
        generation: 1,
        config: Arc::new(config.clone()),
        ports: Arc::new(ports),
        links: Arc::new(links),
        dhcp4: Arc::new(BTreeMap::new()),
        leases: Arc::new(BTreeMap::new()),
        time: TimeFact::default(),
        ipv6: Arc::new(BTreeMap::new()),
        routes: Arc::new(std::collections::BTreeSet::new()),
        dhcp6: Arc::new(BTreeMap::new()),
        pppoe: Arc::new(BTreeMap::new()),
        ula: None,
    }
}

/// Everything a scenario needs to apply configs repeatedly.
struct Rig {
    nl: Netlink,
    rx: watch::Receiver<Arc<Cache>>,
    links: LinksApplier,
    routing: RoutingApplier,
}

impl Rig {
    async fn connect() -> anyhow::Result<Self> {
        let (nl, monitor) = Netlink::connect().await?;
        let rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        Ok(Rig {
            nl,
            rx,
            links: LinksApplier::new(),
            routing: RoutingApplier::new(),
        })
    }

    /// One pass of both appliers over `config`; returns `(links ops, routing ops)`.
    async fn apply(&mut self, config: &Config) -> anyhow::Result<(usize, usize)> {
        let cache = self.rx.borrow_and_update().clone();
        let world = world_from(&cache, config);
        let links = self
            .links
            .apply(&openfeo_reconcile::links::links(&world), &cache, &self.nl)
            .await?;
        let cache = self.rx.borrow_and_update().clone();
        let world = world_from(&cache, config);
        let routing = self
            .routing
            .apply(
                &openfeo_reconcile::routing::routing(&world),
                &cache,
                &self.nl,
            )
            .await?;
        Ok((links.ops, routing.ops))
    }

    /// Wait until the cache shows the static config fully applied.
    async fn settled(&mut self, lan: &str) -> anyhow::Result<()> {
        let lan_net: IpNet = lan.parse()?;
        wait_until(&mut self.rx, "static config applied", |c| {
            let Some(br) = c.link_by_name("br-lan0") else {
                return false;
            };
            br.up
                && br.mac.is_some()
                && br.mac == c.link_by_name("p2").and_then(|p| p.mac)
                && c.link_by_name("p2")
                    .is_some_and(|p| p.master == Some(br.index))
                && c.link_by_name("p0").is_some_and(|p| p.up)
                && c.addrs
                    .iter()
                    .any(|a| a.ifindex == br.index && a.net == lan_net)
                && c.routes.iter().any(|r| {
                    r.protocol == RTPROT_OPENFEO
                        && r.dst.is_none()
                        && r.gateway.map(|g| g.to_string()) == Some("203.0.113.1".to_owned())
                })
        })
        .await
    }
}

/// Apply the static config onto fresh fake ports and wait for the cache to reflect it.
async fn build_static() -> anyhow::Result<(Rig, Config)> {
    let config = static_config()?;
    let mut rig = Rig::connect().await?;
    let (links, routing) = rig.apply(&config).await?;
    ensure!(
        links > 0 && routing > 0,
        "first pass did work: {links}/{routing}"
    );
    rig.settled("192.168.1.1/24").await?;
    Ok((rig, config))
}

/// The static config: bridge with VLAN filtering, p2 enslaved, p0 up, p1 down, bridge MAC from
/// p2, both addresses and the default route.
fn apply_builds_bridge_addrs_routes(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (rig, _config) = build_static().await?;
        let cache = rig.rx.borrow().clone();
        let details = netns::ip(&["-d", "link", "show", "br-lan0"])?;
        ensure!(details.contains("vlan_filtering 1"), "{details}");
        let br = cache.link_by_name("br-lan0").context("br-lan0")?;
        let p2 = cache.link_by_name("p2").context("p2")?;
        ensure!(p2.master == Some(br.index), "p2 master {:?}", p2.master);
        ensure!(
            br.mac == p2.mac,
            "bridge mac {:?} vs p2 {:?}",
            br.mac,
            p2.mac
        );
        ensure!(cache.link_by_name("p0").is_some_and(|p| p.up), "p0 up");
        ensure!(
            cache.link_by_name("p1").is_some_and(|p| !p.up),
            "p1 stays down"
        );
        ensure!(netns::ip(&["-4", "addr", "show", "br-lan0"])?.contains("192.168.1.1/24"));
        ensure!(netns::ip(&["-4", "addr", "show", "p0"])?.contains("203.0.113.10/24"));
        let route = netns::ip(&["route", "show", "default"])?;
        ensure!(
            route.contains("default via 203.0.113.1 dev p0 proto 200 metric 10"),
            "{route}"
        );
        anyhow::Ok(())
    })?
}

/// A second pass over the same config issues no operations (a restarted child adopts state).
fn reapply_is_a_noop(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (mut rig, config) = build_static().await?;
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 0), "second pass issued {ops:?}");
        anyhow::Ok(())
    })?
}

/// Changing the LAN address removes the old one and adds the new one, nothing else.
fn config_change_moves_the_lan_address(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (mut rig, mut config) = build_static().await?;
        config.lans[0].ipv4 = "192.168.5.1/24".into();
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 2), "address move issued {ops:?}");
        rig.settled("192.168.5.1/24").await?;
        let shown = netns::ip(&["-4", "addr", "show", "br-lan0"])?;
        ensure!(
            !shown.contains("192.168.1.1/24"),
            "old address left: {shown}"
        );
        ensure!(shown.contains("192.168.5.1/24"), "{shown}");
        anyhow::Ok(())
    })?
}

/// A link-local address and a route with another protocol survive a pass; a stray `br-*`
/// bridge does not.
fn foreign_state_is_untouched(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (mut rig, config) = build_static().await?;
        netns::ip(&["addr", "add", "fe80::1/64", "dev", "br-lan0"])?;
        netns::ip(&[
            "route",
            "add",
            "10.77.0.0/16",
            "via",
            "203.0.113.1",
            "dev",
            "p0",
            "proto",
            "static",
        ])?;
        netns::ip(&["link", "add", "br-zz", "type", "bridge"])?;
        wait_until(&mut rig.rx, "foreign state in the cache", |c| {
            c.link_by_name("br-zz").is_some()
                && c.addrs.iter().any(|a| a.net.to_string() == "fe80::1/64")
                && c.routes
                    .iter()
                    .any(|r| r.dst.map(|d| d.to_string()) == Some("10.77.0.0/16".to_owned()))
        })
        .await?;
        let ops = rig.apply(&config).await?;
        ensure!(
            ops == (1, 0),
            "expected only the stray bridge to go: {ops:?}"
        );
        wait_until(&mut rig.rx, "br-zz gone", |c| {
            c.link_by_name("br-zz").is_none()
        })
        .await?;
        ensure!(netns::ip(&["-6", "addr", "show", "br-lan0"])?.contains("fe80::1/64"));
        ensure!(netns::ip(&["route", "show", "10.77.0.0/16"])?.contains("proto static"));
        anyhow::Ok(())
    })?
}

/// A global IPv6 address the kernel (SLAAC) or an operator put on a managed interface is not
/// ours to delete: IPv6 ownership is M2's; until then the appliers own IPv4 only.
fn global_ipv6_address_is_untouched(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (mut rig, config) = build_static().await?;
        netns::ip(&["addr", "add", "2001:db8::1/64", "dev", "br-lan0"])?;
        wait_until(&mut rig.rx, "2001:db8::1/64 in the cache", |c| {
            c.addrs
                .iter()
                .any(|a| a.net.to_string() == "2001:db8::1/64")
        })
        .await?;
        let ops = rig.apply(&config).await?;
        ensure!(ops == (0, 0), "the pass touched the IPv6 address: {ops:?}");
        ensure!(netns::ip(&["-6", "addr", "show", "br-lan0"])?.contains("2001:db8::1/64"));
        anyhow::Ok(())
    })?
}

/// One refused operation (a bridge name the kernel rejects as too long) does not stop the rest of
/// the pass: the other LAN still gets its bridge and its address, and the failure is reported.
fn partial_failure_still_applies_the_rest(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let mut config = static_config()?;
        config.lans.push(openfeo_config::Lan {
            name: "guest-network".into(), // br-guest-network is 16 bytes: EINVAL from the kernel
            ports: vec!["p1".into()],
            ipv4: "192.168.9.1/24".into(),
            dhcp: None,
            reaches: Vec::new(),
            ipv6: String::new(),
            ra: None,
            ipv6_index: 0,
        });
        let mut rig = Rig::connect().await?;
        let cache = rig.rx.borrow_and_update().clone();
        let world = world_from(&cache, &config);
        let links = rig
            .links
            .apply(&openfeo_reconcile::links::links(&world), &cache, &rig.nl)
            .await;
        ensure!(links.is_err(), "the invalid bridge name must be reported");
        wait_until(&mut rig.rx, "br-lan0 created despite the failure", |c| {
            c.link_by_name("br-lan0").is_some()
        })
        .await?;
        let cache = rig.rx.borrow_and_update().clone();
        let world = world_from(&cache, &config);
        let routing = rig
            .routing
            .apply(
                &openfeo_reconcile::routing::routing(&world),
                &cache,
                &rig.nl,
            )
            .await;
        ensure!(
            routing.is_err(),
            "the missing guest bridge must be reported by routing"
        );
        wait_until(
            &mut rig.rx,
            "lan0 address applied despite the failure",
            |c| {
                c.addrs
                    .iter()
                    .any(|a| a.net.to_string() == "192.168.1.1/24")
            },
        )
        .await?;
        ensure!(netns::ip(&["-4", "addr", "show", "br-lan0"])?.contains("192.168.1.1/24"));
        anyhow::Ok(())
    })?
}

fn desired_sysctl(entries: &[(&str, &str)]) -> DesiredSysctl {
    DesiredSysctl {
        entries: entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// The nft applier applies a ruleset once, is a no-op while it is unchanged, and applies again
/// when the World changes it (here: `wan_ping` toggles the echo-request rule).
fn nft_applier_applies_once_then_noops(_lab: &mut Lab) -> anyhow::Result<()> {
    nftprobe::require_expressions()?;
    let mut config = static_config()?;
    let mut applier = NftApplier::new(Nft::new()?);
    let mut lister = Nft::new()?;
    let result = (|| {
        let world = World::new(config.clone(), lab_portmap());
        let first = applier.apply(&nft(&world))?;
        ensure!(first.ops == 1, "first apply: {first:?}");
        let again = applier.apply(&nft(&world))?;
        ensure!(again.ops == 0, "unchanged ruleset re-applied: {again:?}");
        let icmp_type = serde_json::json!({"payload": {"protocol": "icmp", "field": "type"}});
        ensure!(
            nftlist::chain_matches(&lister.list_ruleset()?, "input", &icmp_type),
            "input should match icmp type while wan_ping is on"
        );
        config
            .firewall
            .as_mut()
            .context("fixture has [firewall]")?
            .wan_ping = false;
        let world = World::new(config.clone(), lab_portmap());
        let changed = applier.apply(&nft(&world))?;
        ensure!(changed.ops == 1, "changed ruleset: {changed:?}");
        ensure!(
            !nftlist::chain_matches(&lister.list_ruleset()?, "input", &icmp_type),
            "the icmp type rule should be gone with wan_ping off"
        );
        anyhow::Ok(())
    })();
    let _ = lister
        .apply(&[serde_json::json!({"delete": {"table": {"family": "inet", "name": "openfeo"}}})]);
    result
}

/// Forwarding and per-interface `send_redirects` follow the desired set; unchanged keys cost
/// nothing; turning forwarding off is one write.
fn sysctl_applier_turns_forwarding_on_and_off(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (_rig, _config) = build_static().await?;
        let mut applier = SysctlApplier::new();
        // A new network namespace inherits the host's values (this host forwards): baseline.
        applier.apply(&desired_sysctl(&[
            ("net/ipv4/ip_forward", "0"),
            ("net/ipv4/conf/br-lan0/send_redirects", "1"),
        ]))?;
        ensure!(sysctl::read("net/ipv4/ip_forward")? == "0");
        let on = desired_sysctl(&[
            ("net/ipv4/ip_forward", "1"),
            ("net/ipv4/conf/br-lan0/send_redirects", "0"),
        ]);
        let report = applier.apply(&on)?;
        ensure!(report.ops == 2, "two writes expected: {report:?}");
        ensure!(sysctl::read("net/ipv4/ip_forward")? == "1");
        ensure!(sysctl::read("net/ipv4/conf/br-lan0/send_redirects")? == "0");
        let report = applier.apply(&on)?;
        ensure!(report.ops == 0, "nothing to write: {report:?}");
        let report = applier.apply(&desired_sysctl(&[("net/ipv4/ip_forward", "0")]))?;
        ensure!(report.ops == 1, "one write expected: {report:?}");
        ensure!(sysctl::read("net/ipv4/ip_forward")? == "0");
        anyhow::Ok(())
    })?
}

/// A key that cannot be written (an interface that does not exist) is reported after every other
/// key was written.
fn sysctl_for_a_missing_interface_is_reported_last(_lab: &mut Lab) -> anyhow::Result<()> {
    let mut applier = SysctlApplier::new();
    applier.apply(&desired_sysctl(&[("net/ipv4/ip_forward", "0")]))?;
    let desired = desired_sysctl(&[
        ("net/ipv4/conf/nosuchif/send_redirects", "0"),
        ("net/ipv4/ip_forward", "1"),
    ]);
    let result = applier.apply(&desired);
    let forwarding = sysctl::read("net/ipv4/ip_forward");
    let _ = applier.apply(&desired_sysctl(&[("net/ipv4/ip_forward", "0")]));
    match result {
        Err(ApplyError::Io { path, .. }) => {
            ensure!(path.contains("nosuchif"), "wrong key reported: {path}");
        }
        other => anyhow::bail!("expected Io error, got {other:?}"),
    }
    ensure!(
        forwarding? == "1",
        "ip_forward must still have been written"
    );
    Ok(())
}

/// The in-namespace HTTP client reaches a server started in the same namespace (here the lab's
/// ISP namespace on its own address), returns the body, and the server logged the request.
fn http_get_reaches_a_server_in_the_sandbox(lab: &mut Lab) -> anyhow::Result<()> {
    let dir = lab.run_dir.join("http-sandbox");
    std::fs::create_dir_all(&dir)?;
    let server = daemons::http_server(&lab.isp0, "203.0.113.1", 8081, &dir, "hello from isp0")?;
    server.log.wait_for(
        &mut Cursor::default(),
        &Regex::new(r"Serving HTTP on")?,
        Duration::from_secs(5),
    )?;
    let body = lanclient::http_get(
        &lab.isp0,
        "203.0.113.1:8081".parse()?,
        "/",
        Duration::from_secs(5),
    )?;
    ensure!(body.trim() == "hello from isp0", "unexpected body {body:?}");
    ensure!(
        server.log.count(&Regex::new(
            r#"203\.0\.113\.1 - - .*"GET / HTTP/1\.0" 200"#
        )?) == 1,
        "server log lacks the request: {:?}",
        server.log.tail(5)
    );
    let refused = lanclient::http_get(
        &lab.isp0,
        "203.0.113.1:8082".parse()?,
        "/",
        Duration::from_secs(2),
    );
    ensure!(refused.is_err(), "a closed port must be an error");
    Ok(())
}

/// `link_set_mtu` and the cache's view of it.
fn link_set_mtu_shows_in_the_cache(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ = netns::ip(&["link", "del", "mv0"]);
    netns::ip(&["link", "add", "mv0", "type", "veth", "peer", "name", "mv1"])?;
    let result = block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let (index, mtu) = {
            let cache = rx.borrow().clone();
            let link = cache.link_by_name("mv0").context("mv0 in the dump")?;
            (link.index, link.mtu)
        };
        ensure!(mtu == 1500, "a veth starts at 1500, not {mtu}");
        nl.link_set_mtu(index, 1400).await?;
        wait_until(&mut rx, "mv0 mtu 1400", |c| {
            c.link_by_name("mv0").is_some_and(|l| l.mtu == 1400)
        })
        .await?;
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "mv0"]);
    result?
}

/// A DHCP WAN's lease MTU reaches the port through the links applier, and a second pass with
/// the same World changes nothing.
fn links_applier_sets_a_dhcp_wan_mtu(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let config = openfeo_config::file::parse(include_str!("../fixtures/vm-dhcp.toml"))?;
        let fact = Dhcp4Fact {
            address: "203.0.113.100/24".parse()?,
            server: Ipv4Addr::new(203, 0, 113, 1),
            gateway: None,
            routes: Vec::new(),
            dns: Vec::new(),
            domain: None,
            ntp: vec![],
            mtu: Some(1400),
        };
        let mut rig = Rig::connect().await?;
        let pass = async |rig: &mut Rig| -> anyhow::Result<usize> {
            let cache = rig.rx.borrow_and_update().clone();
            let mut world = world_from(&cache, &config);
            world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact.clone())]));
            let report = rig
                .links
                .apply(&openfeo_reconcile::links::links(&world), &cache, &rig.nl)
                .await?;
            Ok(report.ops)
        };
        let first = pass(&mut rig).await?;
        ensure!(first >= 1, "first pass did nothing");
        wait_until(&mut rig.rx, "p0 mtu 1400", |c| {
            c.link_by_name("p0").is_some_and(|l| l.mtu == 1400 && l.up)
        })
        .await?;
        let again = pass(&mut rig).await?;
        ensure!(again == 0, "second pass changed {again} things");
        anyhow::Ok(())
    })?
}

/// A lease whose gateway lies outside the leased /32 (cloud and some ISP DHCP): the host route to
/// the gateway goes in before the default route, so the kernel accepts both in one pass.
fn routing_applier_adds_a_host_route_before_an_off_link_default(
    _lab: &mut Lab,
) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let config = openfeo_config::file::parse(include_str!("../fixtures/vm-dhcp.toml"))?;
        let gateway = Ipv4Addr::new(203, 0, 113, 1);
        let fact = Dhcp4Fact {
            address: "203.0.113.100/32".parse()?,
            server: gateway,
            gateway: Some(gateway),
            routes: Vec::new(),
            dns: Vec::new(),
            domain: None,
            ntp: vec![],
            mtu: None,
        };
        let mut rig = Rig::connect().await?;
        let cache = rig.rx.borrow_and_update().clone();
        let mut world = world_from(&cache, &config);
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact.clone())]));
        rig.links
            .apply(&openfeo_reconcile::links::links(&world), &cache, &rig.nl)
            .await?;
        wait_until(&mut rig.rx, "p0 up", |c| {
            c.link_by_name("p0").is_some_and(|l| l.up)
        })
        .await?;
        let cache = rig.rx.borrow_and_update().clone();
        let mut world = world_from(&cache, &config);
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let report = rig
            .routing
            .apply(
                &openfeo_reconcile::routing::routing(&world),
                &cache,
                &rig.nl,
            )
            .await
            .context("routing pass with an off-link gateway")?;
        ensure!(
            report.ops == 4,
            "LAN address, WAN address, host route and default: {}",
            report.ops
        );
        wait_until(
            &mut rig.rx,
            "default via 203.0.113.1 and 203.0.113.1/32",
            |c| {
                let p0 = c.link_by_name("p0").map(|l| l.index);
                c.routes.iter().any(|r| {
                    r.dst.is_none()
                        && r.gateway.map(|g| g.to_string()) == Some("203.0.113.1".to_owned())
                        && r.oif == p0
                }) && c.routes.iter().any(|r| {
                    r.dst.map(|d| d.to_string()) == Some("203.0.113.1/32".to_owned())
                        && r.gateway.is_none()
                        && r.protocol == RTPROT_OPENFEO
                })
            },
        )
        .await?;
        anyhow::Ok(())
    })?
}

/// Policy rules (SPEC §7.4): the 1500 `from all lookup main suppress_prefixlength 0` rule and a
/// 2000 source rule into a WAN's table, both protocol 200, added, seen in the cache with every
/// field, shown by `ip`, and removed.
fn a_suppress_main_rule_and_a_source_rule_are_added_dumped_and_removed(
    _lab: &mut Lab,
) -> anyhow::Result<()> {
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let suppress = Rule {
            v6: true,
            priority: RULE_PRIORITY_MAIN_SUPPRESS,
            src: None,
            action: RuleAction::ToTable(TABLE_MAIN),
            suppress_prefixlen: Some(0),
            protocol: RTPROT_OPENFEO,
        };
        let source = Rule {
            v6: true,
            priority: RULE_PRIORITY_SOURCE,
            src: Some("2001:db8:100::/56".parse()?),
            action: RuleAction::ToTable(100),
            suppress_prefixlen: None,
            protocol: RTPROT_OPENFEO,
        };
        for rule in [&suppress, &source] {
            let _ = nl.rule_del(rule).await; // left by an interrupted run
        }
        nl.rule_add(&suppress).await?;
        nl.rule_add(&source).await?;
        wait_until(&mut rx, "both rules cached", |c| {
            c.rules.contains(&suppress) && c.rules.contains(&source)
        })
        .await?;
        let shown = netns::ip(&["-6", "rule", "show"])?;
        ensure!(
            shown.contains("suppress_prefixlength 0"),
            "ip rule: {shown}"
        );
        ensure!(
            shown.contains("from 2001:db8:100::/56 lookup 100"),
            "ip rule: {shown}"
        );
        ensure!(
            openfeo_netlink::describe_rule(&source)
                == "rule 2000 from 2001:db8:100::/56 lookup 100 proto 200",
            "describe: {}",
            openfeo_netlink::describe_rule(&source)
        );
        ensure!(
            openfeo_netlink::describe_rule(&suppress)
                == "rule 1500 from all lookup main suppress_prefixlength 0 proto 200",
            "describe: {}",
            openfeo_netlink::describe_rule(&suppress)
        );
        ensure!(
            nl.rule_add(&source).await.is_err_and(|e| e.is_exist()),
            "adding the same rule twice is EEXIST"
        );
        nl.rule_del(&suppress).await?;
        nl.rule_del(&source).await?;
        wait_until(&mut rx, "rules gone", |c| {
            !c.rules.iter().any(|r| r.protocol == RTPROT_OPENFEO)
        })
        .await?;
        ensure!(
            rx.borrow()
                .rules
                .iter()
                .any(|r| r.v6 && r.protocol != RTPROT_OPENFEO),
            "the kernel's own IPv6 rules stay cached: {:?}",
            rx.borrow().rules
        );
        anyhow::Ok(())
    })?
}

/// A `from <prefix> unreachable` rule (the deprecation rule of SPEC §7.3): a lookup from a
/// source in the prefix fails where the same lookup from another source finds the default.
fn an_unreachable_rule_answers_with_no_route(_lab: &mut Lab) -> anyhow::Result<()> {
    block_on(async {
        let _ = netns::ip(&["link", "del", "r0"]);
        netns::ip(&["link", "add", "r0", "type", "veth", "peer", "name", "r1"])?;
        netns::ip(&["link", "set", "r0", "up"])?;
        netns::ip(&["link", "set", "r1", "up"])?;
        netns::ip(&["-6", "route", "replace", "default", "dev", "r0"])?;
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let rule = Rule {
            v6: true,
            priority: RULE_PRIORITY_SOURCE,
            src: Some("2001:db8:200::/56".parse()?),
            action: RuleAction::Unreachable,
            suppress_prefixlen: None,
            protocol: RTPROT_OPENFEO,
        };
        let _ = nl.rule_del(&rule).await;
        let lookup = || {
            netns::ip(&[
                "-6",
                "route",
                "get",
                "2001:db8:ffff::1",
                "from",
                "2001:db8:200::1",
                "iif",
                "r0",
            ])
        };
        let before = lookup();
        ensure!(
            before.as_ref().is_ok_and(|text| text.contains("dev r0")),
            "without the rule the default answers: {before:?}"
        );
        nl.rule_add(&rule).await?;
        wait_until(&mut rx, "unreachable rule cached", |c| {
            c.rules.contains(&rule)
        })
        .await?;
        let Err(after) = lookup() else {
            anyhow::bail!("with the rule the lookup should fail");
        };
        let text = format!("{after:#}");
        ensure!(
            text.contains("unreachable") || text.contains("Unreachable"),
            "the kernel says unreachable: {text}"
        );
        let other = netns::ip(&[
            "-6",
            "route",
            "get",
            "2001:db8:ffff::1",
            "from",
            "2001:db8:100::1",
            "iif",
            "r0",
        ]);
        ensure!(
            other.as_ref().is_ok_and(|text| text.contains("dev r0")),
            "another source still finds the default: {other:?}"
        );
        ensure!(
            openfeo_netlink::describe_rule(&rule)
                == "rule 2000 from 2001:db8:200::/56 unreachable proto 200",
            "describe: {}",
            openfeo_netlink::describe_rule(&rule)
        );
        nl.rule_del(&rule).await?;
        wait_until(&mut rx, "unreachable rule gone", |c| {
            !c.rules.contains(&rule)
        })
        .await?;
        netns::ip(&["link", "del", "r0"])?;
        anyhow::Ok(())
    })?
}

/// An `unreachable default` in a WAN's table (SPEC §7.3, §7.4): added, cached with its kind
/// and no device (the kernel reports `lo`, as for a blackhole: ADR-0020), shown by `ip`,
/// removed.
fn an_unreachable_default_in_table_100_is_added_and_dumped(_lab: &mut Lab) -> anyhow::Result<()> {
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let route = Route {
            v6: true,
            table: 100,
            dst: None,
            gateway: None,
            oif: None,
            protocol: RTPROT_OPENFEO,
            priority: 1000,
            kind: RouteKind::Unreachable,
            pref_src: None,
        };
        let _ = nl.route_del(&route).await;
        nl.route_add(&route).await?;
        wait_until(&mut rx, "unreachable default cached", |c| {
            c.routes.contains(&route)
        })
        .await?;
        let shown = netns::ip(&["-6", "route", "show", "table", "100"])?;
        ensure!(shown.contains("unreachable default"), "ip route: {shown}");
        ensure!(
            openfeo_netlink::describe(&route)
                == "unreachable default proto 200 metric 1000 table 100",
            "describe: {}",
            openfeo_netlink::describe(&route)
        );
        nl.route_del(&route).await?;
        wait_until(&mut rx, "unreachable default gone", |c| {
            !c.routes.contains(&route)
        })
        .await?;
        anyhow::Ok(())
    })?
}

/// A rule added with `ip` while the monitor runs lands in the cache, and the applier can
/// remove a protocol-200 rule it did not add itself.
fn a_rule_added_behind_the_monitors_back_is_cached(_lab: &mut Lab) -> anyhow::Result<()> {
    block_on(async {
        let (nl, monitor) = Netlink::connect().await?;
        let mut rx = monitor.subscribe();
        tokio::spawn(monitor.run());
        let expected = Rule {
            v6: true,
            priority: 2001,
            src: Some("2001:db8:300::/56".parse()?),
            action: RuleAction::ToTable(101),
            suppress_prefixlen: None,
            protocol: RTPROT_OPENFEO,
        };
        let _ = nl.rule_del(&expected).await;
        netns::ip(&[
            "-6",
            "rule",
            "add",
            "priority",
            "2001",
            "from",
            "2001:db8:300::/56",
            "lookup",
            "101",
            "protocol",
            "200",
        ])?;
        wait_until(&mut rx, "foreign rule cached", |c| {
            c.rules.contains(&expected)
        })
        .await?;
        nl.rule_del(&expected).await?;
        wait_until(&mut rx, "foreign rule gone", |c| {
            !c.rules.contains(&expected)
        })
        .await?;
        anyhow::Ok(())
    })?
}

/// A PPP netdev's address is point-to-point: ours as `IFA_LOCAL`, the peer as `IFA_ADDRESS`.
/// The primitive adds and removes one, the cache shows it under our address with the peer, and
/// the routing applier adds it from a `DesiredAddr` with a peer on a managed `ppp-*` link and
/// removes it when the desire goes. (A veth stands in for the PPP unit: the sandbox has no
/// `/dev/ppp`, and the kernel treats a point-to-point address the same on any link.)
fn a_point_to_point_address_is_added_with_its_peer_and_removed(
    _lab: &mut Lab,
) -> anyhow::Result<()> {
    let _ = netns::ip(&["link", "del", "ppp-wan9"]);
    netns::ip(&[
        "link",
        "add",
        "ppp-wan9",
        "type",
        "veth",
        "peer",
        "name",
        "ppp-wan9p",
    ])?;
    netns::ip(&["link", "set", "ppp-wan9", "up"])?;
    let result = block_on(async {
        let mut rig = Rig::connect().await?;
        let index = rig
            .rx
            .borrow()
            .link_by_name("ppp-wan9")
            .context("ppp-wan9")?
            .index;
        let net: IpNet = "203.0.113.100/32".parse()?;
        let peer: IpAddr = "203.0.113.1".parse()?;
        rig.nl.addr_add_peer(index, net, peer).await?;
        wait_until(
            &mut rig.rx,
            "the point-to-point address in the cache",
            |c| {
                c.addrs
                    .iter()
                    .any(|a| a.ifindex == index && a.net == net && a.peer == Some(peer))
            },
        )
        .await?;
        let shown = netns::ip(&["-4", "addr", "show", "ppp-wan9"])?;
        ensure!(
            shown.contains("203.0.113.100 peer 203.0.113.1/32"),
            "ip shows {shown}"
        );
        rig.nl.addr_del_peer(index, net, peer).await?;
        wait_until(&mut rig.rx, "the address gone", |c| {
            !c.addrs.iter().any(|a| a.ifindex == index && a.net == net)
        })
        .await?;
        // Through the applier: desired with the peer, then desired without it.
        let desired = DesiredRouting {
            addrs: BTreeSet::from([DesiredAddr {
                ifname: "ppp-wan9".to_owned(),
                net,
                peer: Some(peer),
            }]),
            ..DesiredRouting::default()
        };
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig.routing.apply(&desired, &cache, &rig.nl).await?;
        ensure!(report.ops == 1, "one add, got {}", report.ops);
        wait_until(&mut rig.rx, "the applier's address", |c| {
            c.addrs
                .iter()
                .any(|a| a.ifindex == index && a.net == net && a.peer == Some(peer))
        })
        .await?;
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig.routing.apply(&desired, &cache, &rig.nl).await?;
        ensure!(
            report.ops == 0,
            "a second pass changed {} things",
            report.ops
        );
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig
            .routing
            .apply(&DesiredRouting::default(), &cache, &rig.nl)
            .await?;
        ensure!(report.ops == 1, "one removal, got {}", report.ops);
        wait_until(&mut rig.rx, "the applier's address gone", |c| {
            !c.addrs.iter().any(|a| a.ifindex == index && a.net == net)
        })
        .await?;
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "ppp-wan9"]);
    result?
}

/// The kernel names a PPP unit `ppp<N>`; the links applier renames it to the WAN's `ppp-<wan>`,
/// sets the negotiated MTU and brings it up, once, and leaves it alone afterwards (ADR-0023).
/// A veth created under the kernel's unit name stands in for the unit.
fn the_links_applier_renames_and_sizes_a_unit_netdev(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ = netns::ip(&["link", "del", "ppp7"]);
    let _ = netns::ip(&["link", "del", "ppp-wan0"]);
    netns::ip(&[
        "link", "add", "ppp7", "type", "veth", "peer", "name", "ppp7p",
    ])?;
    let result = block_on(async {
        let mut rig = Rig::connect().await?;
        wait_until(&mut rig.rx, "ppp7 in the cache", |c| {
            c.link_by_name("ppp7").is_some()
        })
        .await?;
        let desired = DesiredLinks {
            ppp: BTreeMap::from([("ppp-wan0".to_owned(), DesiredPpp { unit: 7, mtu: 1492 })]),
            ..DesiredLinks::default()
        };
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig.links.apply(&desired, &cache, &rig.nl).await?;
        ensure!(report.ops >= 2, "rename, MTU and up: got {}", report.ops);
        wait_until(&mut rig.rx, "ppp-wan0 up at 1492", |c| {
            c.link_by_name("ppp7").is_none()
                && c.link_by_name("ppp-wan0")
                    .is_some_and(|l| l.mtu == 1492 && l.up)
        })
        .await?;
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig.links.apply(&desired, &cache, &rig.nl).await?;
        ensure!(
            report.ops == 0,
            "a second pass changed {} things",
            report.ops
        );
        // A unit the World no longer desires is left alone: the task's drop removes it.
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig
            .links
            .apply(&DesiredLinks::default(), &cache, &rig.nl)
            .await?;
        ensure!(
            report.ops == 0,
            "an undesired ppp-* is not touched: {}",
            report.ops
        );
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "ppp-wan0"]);
    let _ = netns::ip(&["link", "del", "ppp7"]);
    result?
}

/// A port that cannot carry 1508-byte frames (here a VLAN sub-interface whose parent stays at
/// 1500) keeps its MTU and the pass goes on without failing: the offer of a 1500-byte payload
/// is simply withheld (SPEC §7.2).
fn a_refused_port_mtu_is_tolerated(_lab: &mut Lab) -> anyhow::Result<()> {
    vlanprobe::require_vlan_links()?;
    let _ = netns::ip(&["link", "del", "mv0"]);
    netns::ip(&["link", "add", "mv0", "type", "veth", "peer", "name", "mv1"])?;
    netns::ip(&[
        "link", "add", "link", "mv0", "name", "mv0.7", "type", "vlan", "id", "7",
    ])?;
    netns::ip(&["link", "set", "mv0", "up"])?;
    let result = block_on(async {
        let mut rig = Rig::connect().await?;
        wait_until(&mut rig.rx, "mv0.7 in the cache", |c| {
            c.link_by_name("mv0.7").is_some()
        })
        .await?;
        let desired = DesiredLinks {
            ports: BTreeMap::from([(
                "mv0.7".to_owned(),
                DesiredPort {
                    name: "mv0.7".to_owned(),
                    kind: PortKind::Vlan {
                        parent: "mv0".to_owned(),
                        id: 7,
                    },
                    up: true,
                    master: None,
                    mtu: Some(PPPOE_PORT_MTU),
                    ipv6_stable_privacy: false,
                },
            )]),
            ..DesiredLinks::default()
        };
        let cache = rig.rx.borrow_and_update().clone();
        let report = rig.links.apply(&desired, &cache, &rig.nl).await;
        // A tolerated answer is neither announced nor counted, so the report says nothing of
        // the attempt; the MTU below and the pass not failing are the proof.
        report.context("the pass must not fail on the refused MTU")?;
        let mtu = rig
            .rx
            .borrow()
            .link_by_name("mv0.7")
            .map(|l| l.mtu)
            .context("mv0.7")?;
        ensure!(
            mtu == 1500,
            "the sub-interface stays at its parent's MTU, not {mtu}"
        );
        anyhow::Ok(())
    });
    let _ = netns::ip(&["link", "del", "mv0"]);
    result?
}
