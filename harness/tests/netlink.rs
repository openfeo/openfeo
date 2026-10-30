// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel-backed tests for `openfeo-netlink` (and, from Task 11, `openfeo-apply`) against veth
//! pairs inside the rootless sandbox: no QEMU, a few milliseconds each. `harness = false`: this
//! binary is its own runner; an optional first argument filters scenarios by substring. Every
//! scenario uses interface names of its own and deletes them on the way out, because the sandbox's
//! network namespace outlives the scenarios.

use std::future::Future;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use ipnet::IpNet;
use openfeo_harness::lab::Lab;
use openfeo_harness::netns;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_netlink::{Cache, LinkKind, Netlink, RTPROT_OPENFEO, Route, TABLE_MAIN};
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
