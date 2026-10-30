// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M1 acceptance scenarios (SPEC §12 row M1). Part 1, the foundations: first-boot defaults, a
//! static WAN and a LAN from `config.toml` on the state disk, a router-child restart that changes
//! nothing, a WAN link flap, and a port map that survives a reset. Part 2a, firewall and NAT: a
//! LAN host fetching HTTP through NAT, a port forward reached from the WAN and by hairpin, a WAN
//! that is blocked by default, a router-child crash that does not interrupt forwarding, and a
//! first boot that forwards nothing. Run inside the rootless sandbox; `harness = false`: this
//! binary is its own runner and an optional first argument filters scenarios by substring.

use std::process::ExitCode;
use std::time::Duration;

use openfeo_harness::daemons::{self, Daemon};
use openfeo_harness::lab::{BOOT_TIMEOUT, ISP_HTTP_BODY, LAN_HTTP_BODY, Lab};
use openfeo_harness::lanclient;
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
    Scenario {
        name: "lan_fetches_isp_http_through_nat",
        run: lan_fetches_isp_http_through_nat,
    },
    Scenario {
        name: "port_forward_from_wan_and_hairpin",
        run: port_forward_from_wan_and_hairpin,
    },
    Scenario {
        name: "wan_is_blocked_by_default",
        run: wan_is_blocked_by_default,
    },
    Scenario {
        name: "child_crash_does_not_interrupt_forwarding",
        run: child_crash_does_not_interrupt_forwarding,
    },
    Scenario {
        name: "first_boot_forwards_nothing",
        run: first_boot_forwards_nothing,
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
/// How long an HTTP fetch that is supposed to work may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// The ISP-side HTTP target.
const ISP_HTTP: &str = "203.0.113.1:8080";
/// The LAN-side HTTP target, where the fixture's port forward points.
const LAN_HTTP: &str = "192.168.1.2:8080";
/// The fixture's port forward as seen from outside: the WAN address, port 2222.
const WAN_FORWARD: &str = "203.0.113.10:2222";
/// Operations a converged restart must not log.
const KERNEL_CHANGES: &str = r"openfeo: (add|del|enslave|release|renamed|set \S+ (up|down|mac)) ";

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

/// An HTTP target in `ns` on `bind:8080` serving `body`, up before this returns.
fn http_target(lab: &Lab, ns: &NetNs, bind: &str, body: &str) -> anyhow::Result<Daemon> {
    let server = daemons::http_server(
        ns,
        bind,
        8080,
        &lab.run_dir.join(format!("http-{bind}")),
        body,
    )?;
    server
        .log
        .wait_for(&mut Cursor::default(), &re(r"Serving HTTP on"), SOON)?;
    Ok(server)
}

/// Boot the static fixture, wait for `ready`, make the LAN namespace a LAN host.
fn boot_static_with_lan_host(lab: &mut Lab, extra_cmdline: &str) -> anyhow::Result<Cursor> {
    lab.with_config(VM_STATIC)?;
    lab.boot(extra_cmdline)?;
    let mut cur = Cursor::default();
    lab.console()?
        .wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    lab.lan_side_host()?;
    Ok(cur)
}

/// A LAN host fetches a page from the ISP side through the router: the ISP server sees the WAN
/// address (masquerade), never the LAN host's.
fn lan_fetches_isp_http_through_nat(lab: &mut Lab) -> anyhow::Result<()> {
    boot_static_with_lan_host(lab, "")?;
    let server = http_target(lab, &lab.isp0, "203.0.113.1", ISP_HTTP_BODY)?;
    let body = lanclient::http_get(&lab.lan0, ISP_HTTP.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(body == ISP_HTTP_BODY, "unexpected body {body:?}");
    anyhow::ensure!(
        server.log.count(&re(r"^203\.0\.113\.10 - - ")) == 1,
        "the ISP server did not see the WAN address: {:?}",
        server.log.tail(5)
    );
    anyhow::ensure!(
        server.log.count(&re(r"192\.168\.1\.2")) == 0,
        "the LAN address leaked to the ISP side: {:?}",
        server.log.tail(5)
    );
    Ok(())
}

/// The fixture forwards 2222/tcp to the LAN host's port 8080: reached from the ISP side (the
/// server sees the ISP host) and from the LAN itself through the WAN address (hairpin: the
/// server sees the router's LAN address).
fn port_forward_from_wan_and_hairpin(lab: &mut Lab) -> anyhow::Result<()> {
    boot_static_with_lan_host(lab, "")?;
    let server = http_target(lab, &lab.lan0, "192.168.1.2", LAN_HTTP_BODY)?;
    let body = lanclient::http_get(&lab.isp0, WAN_FORWARD.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(
        body == LAN_HTTP_BODY,
        "from the WAN: unexpected body {body:?}"
    );
    anyhow::ensure!(
        server.log.count(&re(r"^203\.0\.113\.1 - - ")) == 1,
        "the LAN server did not see the ISP host: {:?}",
        server.log.tail(5)
    );
    let body = lanclient::http_get(&lab.lan0, WAN_FORWARD.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(body == LAN_HTTP_BODY, "hairpin: unexpected body {body:?}");
    anyhow::ensure!(
        server.log.count(&re(r"^192\.168\.1\.1 - - ")) == 1,
        "the hairpinned request was not SNATed to the router's LAN address: {:?}",
        server.log.tail(5)
    );
    Ok(())
}

/// Without `wan_ping` the WAN answers nothing it was not asked to: no forwarding into the LAN
/// even with a route, no ping of the router, while the explicit port forward still works.
fn wan_is_blocked_by_default(lab: &mut Lab) -> anyhow::Result<()> {
    let config = VM_STATIC.replace("wan_ping = true", "wan_ping = false");
    anyhow::ensure!(config != VM_STATIC, "fixture lost its wan_ping line");
    lab.with_config(&config)?;
    lab.boot("")?;
    let mut cur = Cursor::default();
    lab.console()?
        .wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    lab.lan_side_host()?;
    lab.isp_route_to_lan()?;
    let server = http_target(lab, &lab.lan0, "192.168.1.2", LAN_HTTP_BODY)?;
    let direct = lanclient::http_get(&lab.isp0, LAN_HTTP.parse()?, "/", Duration::from_secs(3));
    anyhow::ensure!(
        direct.is_err(),
        "the ISP side reached a LAN host directly: {direct:?}"
    );
    let pings = lanclient::ping_loop(&lab.isp0, "203.0.113.10", 3, Duration::from_millis(200))?;
    anyhow::ensure!(
        pings.received == 0,
        "the WAN answered {} of {} pings with wan_ping off",
        pings.received,
        pings.sent
    );
    let body = lanclient::http_get(&lab.isp0, WAN_FORWARD.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(
        body == LAN_HTTP_BODY,
        "the explicit forward failed: {body:?}"
    );
    anyhow::ensure!(
        server.log.count(&re(r"^203\.0\.113\.1 - - ")) == 1,
        "server log: {:?}",
        server.log.tail(5)
    );
    Ok(())
}

/// The kernel forwards while the router child is dead and restarting: a LAN host pinging the ISP
/// side across the crash loses at most two of 125 echoes, HTTP through NAT works afterwards, and
/// the restarted child re-applied the ruleset once without touching links or routes.
fn child_crash_does_not_interrupt_forwarding(lab: &mut Lab) -> anyhow::Result<()> {
    let mut cur = boot_static_with_lan_host(lab, "openfeo.chaos=child-exit:20")?;
    let _server = http_target(lab, &lab.isp0, "203.0.113.1", ISP_HTTP_BODY)?;
    let c = lab.console()?;
    let (stats, restarted) = std::thread::scope(|scope| -> anyhow::Result<_> {
        let pinger = scope.spawn(|| {
            lanclient::ping_loop(&lab.lan0, "203.0.113.1", 125, Duration::from_millis(200))
        });
        c.wait_for(
            &mut cur,
            &re(r"openfeo: chaos child-exit: exiting with status 3"),
            Duration::from_secs(30),
        )?;
        c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=\d+"), SOON)?;
        let restarted = cur;
        c.wait_for(&mut cur, &re(READY), SOON)?;
        let stats = pinger
            .join()
            .map_err(|_| anyhow::anyhow!("ping thread panicked"))??;
        Ok((stats, restarted))
    })?;
    anyhow::ensure!(stats.sent == 125, "ping sent {} of 125", stats.sent);
    anyhow::ensure!(
        stats.received + 2 >= stats.sent,
        "forwarding was interrupted: {} of {} pings answered",
        stats.received,
        stats.sent
    );
    let body = lanclient::http_get(&lab.lan0, ISP_HTTP.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(body == ISP_HTTP_BODY, "after the restart: {body:?}");
    anyhow::ensure!(
        c.count_since(&restarted, &re(r"openfeo: ruleset applied: ")) == 1,
        "the restarted child must apply the ruleset exactly once"
    );
    let changes = c.count_since(&restarted, &re(KERNEL_CHANGES));
    anyhow::ensure!(
        changes == 0,
        "the restarted child changed links or routes ({changes} operations)"
    );
    Ok(())
}

/// No state disk: the ruleset exists (LAN services stay reachable) but forwarding is never
/// switched on, because there is no WAN.
fn first_boot_forwards_nothing(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    anyhow::ensure!(
        c.count(&re(r"openfeo: sysctl net/ipv4/ip_forward=1")) == 0,
        "first boot switched forwarding on"
    );
    anyhow::ensure!(
        c.count(&re(r"openfeo: ruleset applied: ")) == 1,
        "the ruleset was not applied exactly once"
    );
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    address_lan_side(lab)?;
    ping(&lab.lan0, "192.168.1.1")
}
