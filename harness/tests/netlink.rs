// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel-backed tests for `openfeo-netlink` (and, from Task 11, `openfeo-apply`) against veth
//! pairs inside the rootless sandbox: no QEMU, a few milliseconds each. `harness = false`: this
//! binary is its own runner; an optional first argument filters scenarios by substring. Every
//! scenario uses interface names of its own and deletes them on the way out, because the sandbox's
//! network namespace outlives the scenarios.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
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
use openfeo_harness::{daemons, lanclient, netns, nftlist, nftprobe, sandbox};
use openfeo_netlink::{Cache, LinkKind, Netlink, RTPROT_OPENFEO, Route, TABLE_MAIN};
use openfeo_nft::Nft;
use openfeo_platform::sysctl;
use openfeo_reconcile::nft::nft;
use openfeo_reconcile::sysctl::DesiredSysctl;
use openfeo_world::{Dhcp4Fact, LinkFact, MacAddr, TimeFact, World};
use tokio::sync::watch;

const SCENARIOS: &[Scenario] = &[
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
];

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
        for name in ["p0", "p1", "p2", "br-lan0", "br-zz"] {
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
