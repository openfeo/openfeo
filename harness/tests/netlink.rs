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
use openfeo_harness::lab::Lab;
use openfeo_harness::netns;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_netlink::{Cache, LinkKind, Netlink, RTPROT_OPENFEO, TABLE_MAIN};
use tokio::sync::watch;

const SCENARIOS: &[Scenario] = &[Scenario {
    name: "monitor_sees_veth_addr_and_route",
    run: monitor_sees_veth_addr_and_route,
}];

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
            .with_context(|| format!("timed out waiting for {what}"))?
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
