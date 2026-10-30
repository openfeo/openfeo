// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M1 part 1 acceptance scenarios (SPEC §12 row M1, the foundations): first-boot defaults, a
//! static WAN and a LAN from `config.toml` on the state disk, a router-child restart that changes
//! nothing, a WAN link flap, and a port map that survives a reset. Run inside the rootless sandbox;
//! `harness = false`: this binary is its own runner and an optional first argument filters
//! scenarios by substring.

use std::process::ExitCode;
use std::time::Duration;

use openfeo_harness::lab::{BOOT_TIMEOUT, Lab};
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "first_boot_defaults_bridge_all_ports",
        run: first_boot_defaults_bridge_all_ports,
    },
    Scenario {
        name: "static_wan_and_lan_from_config",
        run: static_wan_and_lan_from_config,
    },
    Scenario {
        name: "child_restart_converges_without_changes",
        run: child_restart_converges_without_changes,
    },
    Scenario {
        name: "wan_link_flap_recovers",
        run: wan_link_flap_recovers,
    },
    Scenario {
        name: "portmap_persists_across_reset",
        run: portmap_persists_across_reset,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The lab's static configuration: WAN A on p0, LAN on p2, p1 idle.
const VM_STATIC: &str = include_str!("../fixtures/vm-static.toml");
const SOON: Duration = Duration::from_secs(10);
const READY: &str = r"openfeo: ready generation=\d+";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

/// `ping -c 1` from `ns`, retried a few times so ARP and a freshly-up link get a chance.
fn ping(ns: &NetNs, target: &str) -> anyhow::Result<()> {
    let mut last: Option<anyhow::Error> = None;
    for _ in 0..6 {
        let mut cmd = ns.command("ping")?;
        cmd.args(["-c", "1", "-W", "2", target]);
        match netns::run(&mut cmd) {
            Ok(_) => return Ok(()),
            Err(err) => {
                last = Some(err);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    Err(last
        .unwrap_or_else(|| anyhow::anyhow!("no attempts"))
        .context(format!("ping {target}")))
}

/// Give the LAN namespace's end of the LAN tap an address on the router's first-boot subnet.
fn address_lan_side(lab: &Lab) -> anyhow::Result<()> {
    lab.lan0.ip(&["link", "set", "lan0", "up"])?;
    lab.lan0
        .ip(&["addr", "replace", "192.168.1.2/24", "dev", "lan0"])?;
    Ok(())
}

/// No state disk: every port joins `br-lan0` at 192.168.1.1/24 and the LAN side can ping it.
fn first_boot_defaults_bridge_all_ports(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(
        &mut cur,
        &re(r"openfeo: config: none at /state/config\.toml; first-boot defaults \(all ports in lan0 192\.168\.1\.1/24\)"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(&mut cur, &re(r"openfeo: add bridge br-lan0"), SOON)?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    let enslaved = c.count(&re(r"openfeo: enslave p[0-2] -> br-lan0"));
    anyhow::ensure!(enslaved == 3, "expected 3 enslave lines, saw {enslaved}");
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    address_lan_side(lab)?;
    ping(&lab.lan0, "192.168.1.1")
}

/// `vm-static.toml` on the state disk: kernel check, port map, both addresses, the default route,
/// p1 left down; the LAN side and the ISP side both reach the router.
fn static_wan_and_lan_from_config(lab: &mut Lab) -> anyhow::Result<()> {
    lab.with_config(VM_STATIC)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(
        &mut cur,
        &re(r"openfeo-init: state: ext4 /dev/vda"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: kernel: all \d+ required options present"),
        SOON,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: portmap: recorded 3 new ports in /state/identity/portmap"),
        SOON,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: config: loaded /state/config\.toml version=1"),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    for (port, mac) in [("p0", "00"), ("p1", "01"), ("p2", "02")] {
        let line = format!(
            r"openfeo: port {port} eth\d id=pci-0000:00:[0-9a-f]{{2}}\.0 mac=52:54:00:fe:00:{mac} \(new\)"
        );
        anyhow::ensure!(c.count(&re(&line)) == 1, "missing {line}");
    }
    for expected in [
        r"openfeo: add addr 203\.0\.113\.10/24 dev p0",
        r"openfeo: add addr 192\.168\.1\.1/24 dev br-lan0",
        r"openfeo: add route default via 203\.0\.113\.1 dev p0 proto 200 metric 10",
        r"openfeo: enslave p2 -> br-lan0",
        r"openfeo: set p0 up",
    ] {
        anyhow::ensure!(c.count(&re(expected)) == 1, "missing /{expected}/");
    }
    anyhow::ensure!(
        c.count(&re(r"openfeo: set p1 up")) == 0,
        "p1 has no role and must stay down"
    );
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    address_lan_side(lab)?;
    ping(&lab.lan0, "192.168.1.1")?;
    ping(&lab.isp0, "203.0.113.10")
}

/// A router-child restart on a configured kernel adopts everything: no add, del, enslave,
/// release or set line between the second start and the second `ready`.
fn child_restart_converges_without_changes(lab: &mut Lab) -> anyhow::Result<()> {
    lab.with_config(VM_STATIC)?;
    lab.boot("openfeo.chaos=child-exit:20")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: chaos child-exit: exiting with status 3"),
        Duration::from_secs(30),
    )?;
    c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=\d+"), SOON)?;
    let restarted = cur;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: portmap: unchanged \(3 ports\)"),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    let changes = c.count_since(
        &restarted,
        &re(r"openfeo: (add|del|enslave|release|renamed|set \S+ (up|down|mac)) "),
    );
    anyhow::ensure!(
        changes == 0,
        "the restarted child changed the kernel ({changes} operations)"
    );
    address_lan_side(lab)?;
    ping(&lab.lan0, "192.168.1.1")
}

/// Carrier loss and return on the WAN port are seen as facts and the WAN address answers again.
fn wan_link_flap_recovers(lab: &mut Lab) -> anyhow::Result<()> {
    lab.with_config(VM_STATIC)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    ping(&lab.isp0, "203.0.113.10")?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    c.wait_for(&mut cur, &re(r"openfeo: link p0 down"), SOON)?;
    qmp.set_link("p0", true)?;
    c.wait_for(&mut cur, &re(r"openfeo: link p0 up"), SOON)?;
    ping(&lab.isp0, "203.0.113.10")?;
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    Ok(())
}

/// The port map written on the first boot is found unchanged after a reset of the machine.
fn portmap_persists_across_reset(lab: &mut Lab) -> anyhow::Result<()> {
    lab.with_config(VM_STATIC)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(
        &mut cur,
        &re(r"openfeo: portmap: recorded 3 new ports in /state/identity/portmap"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    lab.qmp()?.system_reset()?;
    c.wait_for(
        &mut cur,
        &re(r"Linux version 6\.18\.59-openfeo"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: port p0 eth\d id=pci-\S+ mac=52:54:00:fe:00:00 \(known\)"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: portmap: unchanged \(3 ports\)"),
        SOON,
    )?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: config: loaded /state/config\.toml version=1"),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    Ok(())
}
