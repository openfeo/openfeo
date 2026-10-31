// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M1 acceptance scenarios (SPEC §12 row M1). Part 1, the foundations: first-boot defaults, a
//! static WAN and a LAN from `config.toml` on the state disk, a router-child restart that changes
//! nothing, a WAN link flap, and a port map that survives a reset. Part 2a, firewall and NAT: a
//! LAN host fetching HTTP through NAT, a port forward reached from the WAN and by hairpin, a WAN
//! that is blocked by default, a router-child crash that does not interrupt forwarding, and a
//! first boot that forwards nothing. Part 2b, the DHCPv4 client: a lease from the ISP's Kea
//! with NAT on it, a renewal at T1, a link flap that re-acquires, a reset that keeps the
//! address through INIT-REBOOT, and a WAN without a server that leaves the LAN working. Run
//! inside the rootless sandbox; `harness = false`: this
//! binary is its own runner and an optional first argument filters scenarios by substring.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;

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
    Scenario {
        name: "dhcp_wan_gets_a_lease_and_nats",
        run: dhcp_wan_gets_a_lease_and_nats,
    },
    Scenario {
        name: "dhcp_lease_renews_at_t1",
        run: dhcp_lease_renews_at_t1,
    },
    Scenario {
        name: "dhcp_wan_link_flap_reacquires",
        run: dhcp_wan_link_flap_reacquires,
    },
    Scenario {
        name: "dhcp_lease_survives_reset",
        run: dhcp_lease_survives_reset,
    },
    Scenario {
        name: "dhcp_without_a_server_keeps_the_lan_working",
        run: dhcp_without_a_server_keeps_the_lan_working,
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
/// The lab's DHCP configuration: WAN A on p0 takes its address from isp0's Kea, LAN on p2.
const VM_DHCP: &str = include_str!("../fixtures/vm-dhcp.toml");
/// An address in Kea's pool, 203.0.113.100-200.
const DHCP_POOL: &str = r"203\.0\.113\.(?:1\d\d|200)";
/// The box's DUID: DUID-LL of p0's MAC.
const DUID_LINE: &str = r"openfeo: identity: duid 00030001525400fe0000";
/// Kea renews at 20 s; the client's retransmission jitter adds up to a second.
const RENEW_TIMEOUT: Duration = Duration::from_secs(35);

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

/// Boot `VM_DHCP` with Kea on the ISP side and wait for the lease: the console cursor just past
/// the `bound` line, and the leased address.
fn boot_dhcp(lab: &mut Lab) -> anyhow::Result<(Cursor, String)> {
    lab.start_kea()?;
    lab.with_config(VM_DHCP)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    let bound = c.wait_for(
        &mut cur,
        &re(&format!(
            r"openfeo: wan wan0 dhcp bound ({DHCP_POOL})/24 via 203\.0\.113\.1 lease=60s t1=20s t2=40s server=203\.0\.113\.1"
        )),
        BOOT_TIMEOUT,
    )?;
    let address = bound
        .groups
        .first()
        .cloned()
        .flatten()
        .context("no address in the bound line")?;
    Ok((cur, address))
}

/// How many lines of Kea's log match `pattern`.
fn kea_log_count(lab: &Lab, pattern: &str) -> usize {
    lab.daemons
        .iter()
        .filter(|daemon| daemon.name == "kea-dhcp4")
        .map(|daemon| daemon.log.count(&re(pattern)))
        .sum()
}

/// `203.0.113.100` as a regex.
fn escaped(address: &str) -> String {
    address.replace('.', r"\.")
}

/// The box takes its WAN address from Kea: DISCOVER, OFFER, REQUEST, bound; the lease's address,
/// routes and MTU reach the kernel; a LAN host fetches through NAT on the leased address.
fn dhcp_wan_gets_a_lease_and_nats(lab: &mut Lab) -> anyhow::Result<()> {
    let (mut cur, address) = boot_dhcp(lab)?;
    let server = http_target(lab, &lab.isp0, "203.0.113.1", ISP_HTTP_BODY)?;
    let c = lab.console()?;
    let addr = escaped(&address);
    for expected in [
        format!(r"{DUID_LINE} \(new\)"),
        r"openfeo: wan wan0 dhcp discover".to_owned(),
        format!(r"openfeo: wan wan0 dhcp offer {addr} from 203\.0\.113\.1"),
        format!(r"openfeo: wan wan0 dhcp request {addr}"),
        r"openfeo: wan wan0 dhcp options dns=203\.0\.113\.1 domain=isp\.example mtu=1400 routes=2"
            .to_owned(),
    ] {
        anyhow::ensure!(c.count(&re(&expected)) == 1, "missing /{expected}/");
    }
    c.wait_for(&mut cur, &re(READY), SOON)?;
    for expected in [
        format!(r"openfeo: add addr {addr}/24 dev p0"),
        r"openfeo: add route default via 203\.0\.113\.1 dev p0 proto 200 metric 10".to_owned(),
        r"openfeo: add route 198\.51\.100\.0/24 via 203\.0\.113\.1 dev p0 proto 200 metric 10"
            .to_owned(),
        r"openfeo: set p0 mtu 1400".to_owned(),
    ] {
        anyhow::ensure!(c.count(&re(&expected)) == 1, "missing /{expected}/");
    }
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    lab.lan_side_host()?;
    let body = lanclient::http_get(&lab.lan0, ISP_HTTP.parse()?, "/", HTTP_TIMEOUT)?;
    anyhow::ensure!(body == ISP_HTTP_BODY, "unexpected body {body:?}");
    anyhow::ensure!(
        server.log.count(&re(&format!(r"^{addr} - - "))) == 1,
        "the ISP server did not see the leased address {address}: {:?}",
        server.log.tail(5)
    );
    anyhow::ensure!(
        server.log.count(&re(r"192\.168\.1\.2")) == 0,
        "the LAN address leaked to the ISP side: {:?}",
        server.log.tail(5)
    );
    anyhow::ensure!(
        kea_log_count(lab, "DHCP4_LEASE_ALLOC") >= 1,
        "Kea did not log the allocation"
    );
    Ok(())
}

/// At T1 (20 s) the client renews by unicast and Kea extends the lease; no second DISCOVER.
fn dhcp_lease_renews_at_t1(lab: &mut Lab) -> anyhow::Result<()> {
    let (mut cur, address) = boot_dhcp(lab)?;
    let after_bound = cur;
    let c = lab.console()?;
    c.wait_for(
        &mut cur,
        &re(&format!(
            r"openfeo: wan wan0 dhcp renewed {}/24 lease=60s",
            escaped(&address)
        )),
        RENEW_TIMEOUT,
    )?;
    anyhow::ensure!(
        c.count_since(&after_bound, &re(r"openfeo: wan wan0 dhcp discover")) == 0,
        "a renewal must not discover"
    );
    anyhow::ensure!(
        kea_log_count(lab, "DHCP4_LEASE_ALLOC") >= 2,
        "Kea logged {} allocations, expected the renewal too",
        kea_log_count(lab, "DHCP4_LEASE_ALLOC")
    );
    Ok(())
}

/// Carrier lost and regained on the WAN port: the client confirms its address with INIT-REBOOT
/// and is bound to the same address again.
fn dhcp_wan_link_flap_reacquires(lab: &mut Lab) -> anyhow::Result<()> {
    let (mut cur, address) = boot_dhcp(lab)?;
    let c = lab.console()?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    ping(&lab.isp0, &address)?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    c.wait_for(&mut cur, &re(r"openfeo: link p0 down"), SOON)?;
    qmp.set_link("p0", true)?;
    c.wait_for(&mut cur, &re(r"openfeo: link p0 up"), SOON)?;
    let addr = escaped(&address);
    c.wait_for(
        &mut cur,
        &re(&format!(r"openfeo: wan wan0 dhcp init-reboot {addr}")),
        SOON,
    )?;
    c.wait_for(
        &mut cur,
        &re(&format!(r"openfeo: wan wan0 dhcp bound {addr}/24")),
        Duration::from_secs(15),
    )?;
    ping(&lab.isp0, &address)?;
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    Ok(())
}

/// A reset of the machine: the DUID is read back and the lease file is confirmed with
/// INIT-REBOOT, so the box comes back with the same address and no DISCOVER.
fn dhcp_lease_survives_reset(lab: &mut Lab) -> anyhow::Result<()> {
    let (mut cur, address) = boot_dhcp(lab)?;
    let c = lab.console()?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    anyhow::ensure!(c.count(&re(&format!(r"{DUID_LINE} \(new\)"))) == 1);
    lab.qmp()?.system_reset()?;
    c.wait_for(
        &mut cur,
        &re(r"Linux version 6\.18\.59-openfeo"),
        BOOT_TIMEOUT,
    )?;
    let after_reset = cur;
    c.wait_for(
        &mut cur,
        &re(&format!(r"{DUID_LINE} \(known\)")),
        BOOT_TIMEOUT,
    )?;
    let addr = escaped(&address);
    c.wait_for(
        &mut cur,
        &re(&format!(r"openfeo: wan wan0 dhcp init-reboot {addr}")),
        SOON,
    )?;
    c.wait_for(
        &mut cur,
        &re(&format!(r"openfeo: wan wan0 dhcp bound {addr}/24")),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(READY), SOON)?;
    anyhow::ensure!(
        c.count_since(&after_reset, &re(r"openfeo: wan wan0 dhcp discover")) == 0,
        "the reboot must reuse the lease, not discover"
    );
    Ok(())
}

/// No DHCP server: the LAN is served and `ready` is announced while the WAN keeps discovering
/// with backoff; nothing binds.
fn dhcp_without_a_server_keeps_the_lan_working(lab: &mut Lab) -> anyhow::Result<()> {
    lab.with_config(VM_DHCP)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    let mut discovers = Cursor::default();
    let discover = re(r"openfeo: wan wan0 dhcp discover");
    c.wait_for(&mut discovers, &discover, SOON)?;
    c.wait_for(&mut discovers, &discover, Duration::from_secs(12))?;
    lab.lan_side_host()?;
    ping(&lab.lan0, "192.168.1.1")?;
    anyhow::ensure!(
        c.count(&re(r"openfeo: wan wan0 dhcp bound")) == 0,
        "bound without a server"
    );
    anyhow::ensure!(
        c.count(&re(r"openfeo: apply \S+ failed")) == 0,
        "an apply failed"
    );
    Ok(())
}
