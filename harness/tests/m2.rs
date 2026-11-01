// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M2 part 1 acceptance (SPEC §12): LAN VLANs, the tagged WAN, the per-LAN policy and its rules,
//! and public IPv4 blocks, in the rootless QEMU lab. Like `m1`, `harness = false`: this binary is
//! its own runner and an optional first argument filters scenarios by substring.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;

use openfeo_harness::daemons::{self, Daemon};
use openfeo_harness::lab::{BOOT_TIMEOUT, ISP_HTTP_BODY, LAN_HTTP_BODY, Lab};
use openfeo_harness::lanclient;
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_harness::{sandbox, vlanprobe};

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "tagged_wan_leases_and_nats",
        run: tagged_wan_leases_and_nats,
    },
    Scenario {
        name: "tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet",
        run: tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet,
    },
    Scenario {
        name: "trusted_reaches_main_and_nothing_initiates_into_trusted_except_a_rule",
        run: trusted_reaches_main_and_nothing_initiates_into_trusted_except_a_rule,
    },
    Scenario {
        name: "a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge",
        run: a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge,
    },
    Scenario {
        name: "dmz_host_is_reached_from_the_isp_only_through_a_rule",
        run: dmz_host_is_reached_from_the_isp_only_through_a_rule,
    },
    Scenario {
        name: "dmz_host_leaves_without_translation",
        run: dmz_host_leaves_without_translation,
    },
    Scenario {
        name: "a_public_address_forwards_to_a_lan_host",
        run: a_public_address_forwards_to_a_lan_host,
    },
    Scenario {
        name: "an_unused_public_address_is_blackholed",
        run: an_unused_public_address_is_blackholed,
    },
];

/// The lab's public-block configuration: the static WAN and lan0 of `vm-static.toml`, a DMZ on
/// p3 (lan1) from 192.0.2.232/29, a second block 192.0.2.248/29 whose .249 fronts a forward to
/// the main host, and a rule opening tcp 80 to the DMZ hosts.
const VM_PUBLIC: &str = include_str!("../fixtures/vm-public.toml");
/// The DMZ host (lan1) and its gateway, the router's DMZ address.
const DMZ_HOST: &str = "192.0.2.234";
const DMZ_GATEWAY: &str = "192.0.2.233";
/// The ISP host as the DMZ and LAN servers log it: untranslated.
const ISP_HOST_LINE: &str = r"^203\.0\.113\.1 - - ";
/// The fixture's forward on a public address: the second block's .249, port 443.
const PUBLIC_FORWARD: &str = "192.0.2.249:443";

/// Boot `VM_PUBLIC`: lan0 the main host, lan1 the DMZ host 192.0.2.234/29 via .233, and isp0
/// routing both blocks to the router's WAN address, as the ISP of a routed block does.
fn boot_public(lab: &mut Lab) -> anyhow::Result<Cursor> {
    lab.add_lan1()?;
    lab.with_config(VM_PUBLIC)?;
    lab.boot("")?;
    let mut cur = Cursor::default();
    lab.console()?
        .wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    Lab::host(lan1, "lan1", &format!("{DMZ_HOST}/29"), DMZ_GATEWAY)?;
    lab.isp_route_block("192.0.2.232/29")?;
    lab.isp_route_block("192.0.2.248/29")?;
    Ok(cur)
}

/// From the ISP side, the DMZ host answers on tcp 80, which the fixture's rule opens, and on
/// nothing else: another port and ICMP get no reply. The DMZ server sees the ISP host's own
/// address: a rule opens, it does not translate (SPEC §7.5).
fn dmz_host_is_reached_from_the_isp_only_through_a_rule(lab: &mut Lab) -> anyhow::Result<()> {
    boot_public(lab)?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    let web = http_target(lab, lan1, DMZ_HOST, 80, "dmz web")?;
    let _other = http_target(lab, lan1, DMZ_HOST, 8080, "dmz other")?;
    anyhow::ensure!(
        fetch(&lab.isp0, &format!("{DMZ_HOST}:80"))? == "dmz web",
        "the rule opens tcp 80"
    );
    anyhow::ensure!(
        web.log.count(&re(ISP_HOST_LINE)) == 1,
        "the DMZ server did not see the ISP host untranslated: {:?}",
        web.log.tail(5)
    );
    dropped(&lab.isp0, &format!("{DMZ_HOST}:8080")).context("no rule opens 8080")?;
    anyhow::ensure!(
        !ping_once(&lab.isp0, DMZ_HOST)?,
        "no rule opens ICMP to the DMZ"
    );
    Ok(())
}

/// The DMZ host fetches from the ISP side and the ISP server sees the host's own public address:
/// a public LAN is never masqueraded (SPEC §7.5).
fn dmz_host_leaves_without_translation(lab: &mut Lab) -> anyhow::Result<()> {
    boot_public(lab)?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    let isp = http_target(lab, &lab.isp0, "203.0.113.1", 8080, ISP_HTTP_BODY)?;
    anyhow::ensure!(fetch(lan1, ISP_HTTP)? == ISP_HTTP_BODY);
    anyhow::ensure!(
        isp.log.count(&re(r"^192\.0\.2\.234 - - ")) == 1,
        "the DMZ host was translated: {:?}",
        isp.log.tail(5)
    );
    Ok(())
}

/// The fixture forwards 192.0.2.249:443 to the main host's 8080: reached from the ISP side
/// (the server sees the ISP host) and from the main LAN by the public address (hairpin: the
/// server sees the router's LAN address). The WAN-address forward on 2222 does not answer on
/// the public address (SPEC §7.5).
fn a_public_address_forwards_to_a_lan_host(lab: &mut Lab) -> anyhow::Result<()> {
    boot_public(lab)?;
    let server = http_target(lab, &lab.lan0, "192.168.1.2", 8080, LAN_HTTP_BODY)?;
    anyhow::ensure!(
        fetch(&lab.isp0, PUBLIC_FORWARD)? == LAN_HTTP_BODY,
        "from the ISP side"
    );
    anyhow::ensure!(
        server.log.count(&re(ISP_HOST_LINE)) == 1,
        "the LAN server did not see the ISP host: {:?}",
        server.log.tail(5)
    );
    anyhow::ensure!(
        fetch(&lab.lan0, PUBLIC_FORWARD)? == LAN_HTTP_BODY,
        "hairpin by the public address"
    );
    anyhow::ensure!(
        server.log.count(&re(r"^192\.168\.1\.1 - - ")) == 1,
        "the hairpinned request was not SNATed to the router's LAN address: {:?}",
        server.log.tail(5)
    );
    dropped(&lab.isp0, "192.0.2.249:2222")
        .context("the WAN-address forward does not answer on a public address")?;
    Ok(())
}

/// The console shows the second block's blackhole, and a probe from the ISP side to an address
/// of it that nobody uses gets no reply and no ICMP error (SPEC §7.4).
fn an_unused_public_address_is_blackholed(lab: &mut Lab) -> anyhow::Result<()> {
    boot_public(lab)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: add route blackhole 192\.0\.2\.248/29 proto 200 metric 1000"),
        SOON,
    )?;
    let mut cmd = lab.isp0.command("ping")?;
    cmd.args(["-c", "2", "-W", "1", "192.0.2.250"]);
    let output = cmd.output().context("ping")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        text.contains(" 0 received") || text.contains(" 0 packets received"),
        "a reply from a blackholed address: {text}"
    );
    anyhow::ensure!(
        !text.to_lowercase().contains("unreachable"),
        "a blackhole answers nothing, not an ICMP error: {text}"
    );
    Ok(())
}

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The lab's VLAN configuration: a tagged DHCP WAN on p0.101, lan0 untagged on p2, guest tagged
/// 223 and trusted tagged 224 on p2, trusted untagged on p3 (lan1).
const VM_VLANS: &str = include_str!("../fixtures/vm-vlans.toml");
const SOON: Duration = Duration::from_secs(10);
const READY: &str = r"openfeo: ready generation=\d+";
/// How long an HTTP fetch that is supposed to work may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a fetch the firewall must drop is given before "nothing came back" counts.
const DROPPED: Duration = Duration::from_secs(3);
/// The ISP-side HTTP target.
const ISP_HTTP: &str = "203.0.113.1:8080";
/// The main LAN host's HTTP target, where the fixture's port forward points.
const LAN_HTTP: &str = "192.168.1.2:8080";
/// The trusted host (lan1) and the port the fixture's rule opens to it from lan0.
const TRUSTED_HOST: &str = "192.168.3.2";
/// An address in Kea's pool, 203.0.113.100-200.
const DHCP_POOL: &str = r"203\.0\.113\.(?:1\d\d|200)";
/// udhcpc's four tries of three seconds, with margin.
const UDHCPC_TIMEOUT: Duration = Duration::from_secs(20);

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

fn sock(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.parse()
        .with_context(|| format!("socket address {addr}"))
}

/// An HTTP target in `ns` on `bind:port` serving `body`, up before this returns.
fn http_target(lab: &Lab, ns: &NetNs, bind: &str, port: u16, body: &str) -> anyhow::Result<Daemon> {
    let server = daemons::http_server(
        ns,
        bind,
        port,
        &lab.run_dir.join(format!("http-{bind}-{port}")),
        body,
    )?;
    server
        .log
        .wait_for(&mut Cursor::default(), &re(r"Serving HTTP on"), SOON)?;
    Ok(server)
}

/// A fetch that must work.
fn fetch(ns: &NetNs, addr: &str) -> anyhow::Result<String> {
    lanclient::http_get(ns, sock(addr)?, "/", HTTP_TIMEOUT)
        .with_context(|| format!("GET http://{addr}/ from {}", ns.name))
}

/// A fetch the firewall must drop: nothing comes back within [`DROPPED`].
fn dropped(ns: &NetNs, addr: &str) -> anyhow::Result<()> {
    match lanclient::http_get(ns, sock(addr)?, "/", DROPPED) {
        Ok(body) => anyhow::bail!("GET http://{addr}/ from {} was answered: {body:?}", ns.name),
        Err(_) => Ok(()),
    }
}

/// One `ping -c 1 -W 2` from `ns`, true when answered.
fn ping_once(ns: &NetNs, target: &str) -> anyhow::Result<bool> {
    let mut cmd = ns.command("ping")?;
    cmd.args(["-c", "1", "-W", "2", target]);
    Ok(netns::run(&mut cmd).is_ok())
}

/// One variable udhcpc set for its `bound` event.
fn udhcpc_env<'a>(events: &'a [lanclient::UdhcpcEvent], key: &str) -> anyhow::Result<&'a str> {
    let bound = events
        .iter()
        .find(|event| event.kind == "bound")
        .with_context(|| format!("udhcpc never bound: {events:?}"))?;
    bound
        .env
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("udhcpc bound without {key}: {:?}", bound.env))
}

/// Boot `VM_VLANS`: isp0 serves Kea on `wan0.101`, lan0 is the main host 192.168.1.2 and lan1 the
/// trusted host 192.168.3.2. Returns the console cursor past `ready` and the leased WAN address.
fn boot_vlans(lab: &mut Lab) -> anyhow::Result<(Cursor, String)> {
    // The ISP and LAN sides tag with the host kernel's 8021q: without it the scenario skips.
    vlanprobe::require_vlan_links()?;
    lab.add_lan1()?;
    let tagged = lab.isp0_tagged(101)?;
    lab.start_kea_on(&tagged)?;
    lab.with_config(VM_VLANS)?;
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
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    Lab::host(lan1, "lan1", "192.168.3.2/24", "192.168.3.1")?;
    Ok((cur, address))
}

/// A guest client: a VLAN 223 sub-interface of the lan0 tap in its own namespace, leased from
/// the guest LAN, with the router as its default gateway.
fn guest_client(lab: &Lab, ns: &str) -> anyhow::Result<NetNs> {
    let guest = lab.vlan_host(&lab.lan0, "lan0", 223, ns)?;
    let events = lanclient::udhcpc(&guest, "lan0.223", &lab.run_dir, &[], UDHCPC_TIMEOUT)?;
    let ip = udhcpc_env(&events, "ip")?;
    anyhow::ensure!(
        ip.starts_with("192.168.2."),
        "the guest leased from the wrong LAN: {ip} ({events:?})"
    );
    guest.ip(&["route", "replace", "default", "via", "192.168.2.1"])?;
    Ok(guest)
}

/// The WAN with `vlan = 101` runs on `p0.101`: it leases from a Kea that only listens on
/// `wan0.101`, and the LAN fetches through NAT on the leased address (SPEC §7.2).
fn tagged_wan_leases_and_nats(lab: &mut Lab) -> anyhow::Result<()> {
    let (_, address) = boot_vlans(lab)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: add vlan p0\.101"),
        SOON,
    )?;
    let server = http_target(lab, &lab.isp0, "203.0.113.1", 8080, ISP_HTTP_BODY)?;
    let body = fetch(&lab.lan0, ISP_HTTP)?;
    anyhow::ensure!(body == ISP_HTTP_BODY, "unexpected body {body:?}");
    anyhow::ensure!(
        server
            .log
            .count(&re(&format!("^{} - - ", address.replace('.', r"\."))))
            == 1,
        "the ISP server did not see the leased address {address}: {:?}",
        server.log.tail(5)
    );
    Ok(())
}

/// A client tagged 223 leases from `guest`, reaches the internet through NAT, and cannot reach
/// the main host, nor the main host's forwarded port by the WAN address: hairpin follows the
/// policy (SPEC §7.1, §7.5).
fn tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let (_, address) = boot_vlans(lab)?;
    let guest = guest_client(lab, "guest")?;
    let isp = http_target(lab, &lab.isp0, "203.0.113.1", 8080, ISP_HTTP_BODY)?;
    let main_server = http_target(lab, &lab.lan0, "192.168.1.2", 8080, LAN_HTTP_BODY)?;
    anyhow::ensure!(
        fetch(&guest, ISP_HTTP)? == ISP_HTTP_BODY,
        "guest reaches the internet"
    );
    anyhow::ensure!(
        isp.log.count(&re(r"192\.168\.2\.")) == 0,
        "the guest address leaked to the ISP side: {:?}",
        isp.log.tail(5)
    );
    dropped(&guest, LAN_HTTP).context("guest must not reach the main host")?;
    dropped(&guest, &format!("{address}:2222"))
        .context("hairpin to the main host's forwarded port follows the policy")?;
    anyhow::ensure!(
        main_server.log.count(&re(r"^192\.168\.2\.")) == 0
            && main_server.log.count(&re(r"^192\.168\.1\.1 - - ")) == 0,
        "the main server heard from the guest: {:?}",
        main_server.log.tail(5)
    );
    Ok(())
}

/// Trusted (lan1) fetches from the main host; the main host reaches trusted only on the port
/// the fixture's rule opens; a guest client does not reach trusted at all (SPEC §7.5).
fn trusted_reaches_main_and_nothing_initiates_into_trusted_except_a_rule(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    boot_vlans(lab)?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    let _main_server = http_target(lab, &lab.lan0, "192.168.1.2", 8080, LAN_HTTP_BODY)?;
    let opened = http_target(lab, lan1, TRUSTED_HOST, 8080, "trusted 8080")?;
    let _other = http_target(lab, lan1, TRUSTED_HOST, 8081, "trusted 8081")?;
    anyhow::ensure!(
        fetch(lan1, LAN_HTTP)? == LAN_HTTP_BODY,
        "trusted reaches main"
    );
    anyhow::ensure!(
        fetch(&lab.lan0, &format!("{TRUSTED_HOST}:8080"))? == "trusted 8080",
        "the rule opens 8080 from lan0"
    );
    anyhow::ensure!(
        opened.log.count(&re(r"^192\.168\.1\.2 - - ")) == 1,
        "the rule opens, it does not translate: {:?}",
        opened.log.tail(5)
    );
    dropped(&lab.lan0, &format!("{TRUSTED_HOST}:8081"))
        .context("nothing else initiates into trusted")?;
    let guest = guest_client(lab, "guest2")?;
    dropped(&guest, &format!("{TRUSTED_HOST}:8080")).context("the rule is from lan0 only")?;
    Ok(())
}

/// A client tagged with a VLAN no LAN carries cannot reach the main LAN's router address: the
/// frame reaches p2's filtering bridge and is dropped there (ADR-0017); the untagged client
/// still can.
fn a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge(lab: &mut Lab) -> anyhow::Result<()> {
    boot_vlans(lab)?;
    let stray = lab.vlan_host(&lab.lan0, "lan0", 999, "stray")?;
    Lab::host(&stray, "lan0.999", "192.168.1.77/24", "192.168.1.1")?;
    anyhow::ensure!(
        !ping_once(&stray, "192.168.1.1")?,
        "a frame tagged 999 reached br-lan0"
    );
    anyhow::ensure!(
        ping_once(&lab.lan0, "192.168.1.1")?,
        "the untagged client lost the router"
    );
    Ok(())
}
