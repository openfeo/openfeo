// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M2 part 3 acceptance (SPEC §12) in the rootless QEMU lab: the WAN's prefix delegated by the
//! ISP's DHCPv6 server, the LANs numbered from it and from the router's ULA, renumbering when
//! the ISP changes its mind, deprecation on WAN loss, the ULA that never leaves, the stateless
//! responder, a reboot that keeps the delegation, and the resolver learned over DHCPv6. Like
//! `m2`, `harness = false`: this binary is its own runner and an optional first argument
//! filters scenarios by substring.

use std::net::{Ipv6Addr, SocketAddr};
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use ipnet::Ipv6Net;
use openfeo_harness::daemons::{self, Daemon, ISP_WWW_ADDR6, Kea6Config, RadvdConfig};
use openfeo_harness::lab::{BOOT_TIMEOUT, ISP_HTTP_BODY, Lab, PD_POOL_A, PD_POOL_B};
use openfeo_harness::lanclient::{self, DigAnswer};
use openfeo_harness::lines::{Cursor, Lines, Match, Regex};
use openfeo_harness::netns::NetNs;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_reconcile::lan6::subnet;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "a_lan_client_gets_a_gua_from_the_delegation_and_reaches_the_isp",
        run: a_lan_client_gets_a_gua_from_the_delegation_and_reaches_the_isp,
    },
    Scenario {
        name: "the_isp_changes_the_prefix_and_the_lan_is_renumbered_within_ten_seconds",
        run: the_isp_changes_the_prefix_and_the_lan_is_renumbered_within_ten_seconds,
    },
    Scenario {
        name: "wan_ipv6_loss_deprecates_the_delegated_prefix_and_carrier_back_rebinds_it",
        run: wan_ipv6_loss_deprecates_the_delegated_prefix_and_carrier_back_rebinds_it,
    },
    Scenario {
        name: "ula_addresses_reach_the_other_lan_and_never_leave_the_wan",
        run: ula_addresses_reach_the_other_lan_and_never_leave_the_wan,
    },
    Scenario {
        name: "stateless_dhcpv6_hands_out_the_resolver_and_the_search_list",
        run: stateless_dhcpv6_hands_out_the_resolver_and_the_search_list,
    },
    Scenario {
        name: "a_rebooted_router_keeps_its_delegation",
        run: a_rebooted_router_keeps_its_delegation,
    },
    Scenario {
        name: "isp_resolvers_learned_over_dhcpv6_join_after_the_route",
        run: isp_resolvers_learned_over_dhcpv6_join_after_the_route,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The lab's delegated-prefix configuration: the DHCPv4 WAN with `[wans.ipv6] pd_hint = 56`,
/// lan0 at index 1 and lan1 at index 2 of every prefix, reaching each other, no typed upstreams.
const VM_PD: &str = include_str!("../fixtures/vm-pd.toml");
const READY: &str = r"openfeo: ready generation=\d+";
const KERNEL_BANNER: &str = r"Linux version 6\.18\.59-openfeo";
const WAN_LINK_LOCAL: &str = r"openfeo: wan wan0 ipv6 link-local (fe80:[0-9a-f:]+)";
const ROUTER_LEARNED: &str = r"openfeo: wan wan0 ipv6 router fe80::1 \(learned\)";
/// The delegation and the WAN's address as the console reports them, from either pool.
const BOUND: &str = r"openfeo: dhcp6 wan0 bound prefix (2001:db8:[0-9a-f:]+/56) \(preferred \d+ s, valid \d+ s\) address (2001:db8:ffff:[0-9a-f:]+) t1=10s t2=16s from [0-9a-f]+";
/// The same, from pool B only.
const BOUND_B: &str = r"openfeo: dhcp6 wan0 bound prefix (2001:db8:200:[0-9a-f:]+/56) ";
/// The ISP host on the WAN link and its HTTP target.
const ISP_HOST6: &str = "2001:db8:ffff::1";
const ISP_HTTP6: &str = "[2001:db8:ffff::1]:8080";
/// A ULA source the ISP side tries: inside the documentation ULA, which no router draws its own
/// /48 from.
const ISP_ULA_SOURCE: &str = "fd12:3456:789a:ffff::1";
/// The fixture's LAN indexes.
const LAN0_INDEX: u32 = 1;
const SOON: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const DIG_TIMEOUT: Duration = Duration::from_secs(6);
/// How long `rdisc6` waits where an advertisement is due.
const RDISC6_TIMEOUT: Duration = Duration::from_secs(4);
/// SPEC §12: the LAN is renumbered within ten seconds of the ISP's answer.
const RENUMBER: Duration = Duration::from_secs(10);
/// Kea's valid lifetime is 60 s: the old prefix's deprecation can last no longer.
const DEPRECATION_MAX: Duration = Duration::from_secs(75);

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

/// `text` as a regex matching itself (addresses and prefixes only carry `.` as a metacharacter).
fn escaped(text: &str) -> String {
    text.replace('.', r"\.")
}

fn pool(text: &str) -> anyhow::Result<Ipv6Net> {
    text.parse().with_context(|| format!("pool {text}"))
}

/// Capture group `index` of a console match.
fn group(found: &Match, index: usize) -> anyhow::Result<String> {
    found
        .groups
        .get(index)
        .cloned()
        .flatten()
        .with_context(|| format!("no group {index} in {:?}", found.line))
}

/// Poll `done` every 200 ms until it says so, or `what` has not happened within `timeout`.
fn wait_until(
    timeout: Duration,
    what: &str,
    mut done: impl FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if done()? {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "{what} did not happen within {timeout:?}"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for `pattern` anywhere after `since`, which stays where it is: for lines that come in
/// no fixed order relative to each other.
fn wait_since(
    c: &Lines,
    since: Cursor,
    pattern: &Regex,
    timeout: Duration,
) -> anyhow::Result<Match> {
    let mut cur = since;
    c.wait_for(&mut cur, pattern, timeout)
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

/// Is `rdisc6` (package ndisc6) on this host? Without it the assertions that read
/// advertisements on the LAN side are skipped with a note; CI has it.
fn rdisc6_installed() -> bool {
    let found = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("rdisc6").is_file()));
    if !found {
        eprintln!("  rdisc6 is not installed: its assertions are skipped");
    }
    found
}

/// `answer` must be `NOERROR` with exactly one AAAA record, `addr`.
fn expect_aaaa(answer: &DigAnswer, name: &str, addr: &str) -> anyhow::Result<()> {
    ensure!(
        answer.status == "NOERROR",
        "{name}: status {} in {answer:?}",
        answer.status
    );
    let addrs: Vec<&str> = answer
        .answers
        .iter()
        .filter(|row| row.2 == "AAAA")
        .map(|row| row.3.as_str())
        .collect();
    ensure!(addrs == [addr], "{name}: answers {:?}", answer.answers);
    Ok(())
}

/// One global address of a LAN host as `ip -6 addr` shows it.
#[derive(Debug, Clone, Copy)]
struct HostAddr {
    addr: Ipv6Addr,
    tentative: bool,
    deprecated: bool,
}

/// The host's global addresses on `ifname`.
fn host_addrs(ns: &NetNs, ifname: &str) -> anyhow::Result<Vec<HostAddr>> {
    let text = ns.ip(&["-6", "addr", "show", "dev", ifname, "scope", "global"])?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            if words.next()? != "inet6" {
                return None;
            }
            let addr = words.next()?.split('/').next()?.parse().ok()?;
            let flags: Vec<&str> = words.collect();
            Some(HostAddr {
                addr,
                tentative: flags.contains(&"tentative"),
                deprecated: flags.contains(&"deprecated"),
            })
        })
        .collect())
}

/// The host's address inside `net`, if any.
fn host_addr_in(ns: &NetNs, ifname: &str, net: Ipv6Net) -> anyhow::Result<Option<HostAddr>> {
    Ok(host_addrs(ns, ifname)?
        .into_iter()
        .find(|host| net.contains(&host.addr)))
}

fn is_ula(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xfe00 == 0xfc00
}

/// The host's ULA address, if any.
fn host_ula(ns: &NetNs, ifname: &str) -> anyhow::Result<Option<HostAddr>> {
    Ok(host_addrs(ns, ifname)?
        .into_iter()
        .find(|host| is_ula(host.addr)))
}

/// The /64 `addr` sits in.
fn net_of(addr: Ipv6Addr) -> Ipv6Net {
    Ipv6Net::new_assert(addr, 64).trunc()
}

/// The router's address in `net`: `::1`.
fn router_in(net: Ipv6Net) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(net.network()) | 1)
}

/// The host has a default route via a link-local on `ifname`: the router advertises itself.
fn has_default6(ns: &NetNs, ifname: &str) -> anyhow::Result<bool> {
    Ok(ns
        .ip(&["-6", "route", "show", "default", "dev", ifname])?
        .contains("via fe80:"))
}

/// The host configured itself from the router's advertisement: an address in `net` past
/// duplicate address detection, and the default route.
fn lan_ready(ns: &NetNs, ifname: &str, net: Ipv6Net) -> anyhow::Result<bool> {
    Ok(
        host_addr_in(ns, ifname, net)?.is_some_and(|host| !host.tentative)
            && has_default6(ns, ifname)?,
    )
}

/// `ping -6 -c 1 -W 2 [-I source] target` from `ns`: whether it was answered, and what ping
/// printed (an ICMPv6 error names itself there).
fn ping6(ns: &NetNs, source: Option<&str>, target: &str) -> anyhow::Result<(bool, String)> {
    let mut cmd = ns.command("ping")?;
    cmd.args(["-6", "-c", "1", "-W", "2"]);
    if let Some(source) = source {
        cmd.args(["-I", source]);
    }
    cmd.arg(target);
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("ping {target} from {}", ns.name))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.success(), text))
}

/// A few pings at `target`, so neighbour discovery and a fresh address get a chance; true when
/// one was answered.
fn pingable6(ns: &NetNs, source: Option<&str>, target: &str) -> anyhow::Result<bool> {
    for _ in 0..5 {
        if ping6(ns, source, target)?.0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The ISP's advertisements for a delegating ISP: M and O on (the router starts DHCPv6 without
/// waiting for either, SPEC §7.3), the lab's resolver and search domain.
fn isp_radvd() -> RadvdConfig {
    RadvdConfig {
        managed: true,
        other: true,
        ..RadvdConfig::isp("wan0")
    }
}

/// What a boot established: the console cursor past `ready`, the delegation and the WAN's
/// address from the console.
struct Booted {
    cur: Cursor,
    prefix: Ipv6Net,
    address: Ipv6Addr,
}

impl Booted {
    /// lan0's /64 inside the delegation.
    fn lan0_net(&self) -> anyhow::Result<Ipv6Net> {
        subnet(self.prefix, LAN0_INDEX).context("lan0's /64 inside the delegation")
    }
}

/// Boot `VM_PD` with radvd, Kea's DHCPv6 server and dnsmasq on ISP A, Kea's DHCPv4 server for
/// the WAN, lan0 the main host and lan1 the second LAN's host (IPv4 by hand, IPv6 from the
/// router's advertisements); ISP A routes both delegation pools to the router's wan0 link-local
/// read from the console.
fn boot_pd(lab: &mut Lab, kea: &Kea6Config, radvd: &RadvdConfig) -> anyhow::Result<Booted> {
    lab.add_lan1()?;
    // radvd first: it gives isp0 its IPv6 addresses, and Kea and dnsmasq bind what exists.
    lab.start_radvd(radvd)?;
    lab.start_kea6(kea)?;
    lab.start_dnsmasq()?;
    lab.start_kea()?;
    lab.with_config(VM_PD)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    let link_local = group(
        &c.wait_for(&mut Cursor::default(), &re(WAN_LINK_LOCAL), SOON)?,
        0,
    )?;
    lab.isp_route_block6(PD_POOL_A, &link_local)?;
    lab.isp_route_block6(PD_POOL_B, &link_local)?;
    let bound = c.wait_for(&mut Cursor::default(), &re(BOUND), SOON)?;
    let prefix: Ipv6Net = group(&bound, 0)?.parse()?;
    let address: Ipv6Addr = group(&bound, 1)?.parse()?;
    // A link that comes up now solicits and the router answers; one up since the lab was made
    // solicited before the router existed and would wait for an unsolicited advertisement.
    lab.lan0.ip(&["link", "set", "lan0", "down"])?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    lan1.ip(&["link", "set", "lan1", "down"])?;
    Lab::host(lan1, "lan1", "192.168.2.2/24", "192.168.2.1")?;
    Ok(Booted {
        cur,
        prefix,
        address,
    })
}

/// The LAN host's kernel takes a GUA from lan0's /64 of the delegation and an address from the
/// ULA /64, the router as its default, O = 1 and the router's ULA address first among the
/// resolvers, and fetches from the ISP side through the delegation; the ISP pings the WAN's
/// own address (SPEC §7.3, §12).
fn a_lan_client_gets_a_gua_from_the_delegation_and_reaches_the_isp(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &isp_radvd())?;
    let lan_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        Ok(lan_ready(&lab.lan0, "lan0", lan_net)?
            && host_ula(&lab.lan0, "lan0")?.is_some_and(|host| !host.tentative))
    })?;
    let ula = host_ula(&lab.lan0, "lan0")?.context("the LAN host's ULA address")?;
    let router_ula = router_in(net_of(ula.addr));
    let _isp = http_target(lab, &lab.isp0, ISP_HOST6, 8080, ISP_HTTP_BODY)?;
    ensure!(
        fetch(&lab.lan0, ISP_HTTP6)? == ISP_HTTP_BODY,
        "the LAN host reaches the ISP over IPv6 through the delegation"
    );
    if rdisc6_installed() {
        let report = lanclient::rdisc6(&lab.lan0, "lan0", RDISC6_TIMEOUT)?;
        ensure!(
            report.other == Some(true) && report.managed == Some(false),
            "M and O in {report:?}"
        );
        ensure!(
            report.rdnss.first() == Some(&router_ula),
            "RDNSS must name the router's ULA address {router_ula} first in {report:?}"
        );
        ensure!(
            report.prefixes.contains(&lan_net.to_string())
                && report.prefixes.contains(&net_of(ula.addr).to_string()),
            "prefixes in {report:?}"
        );
        ensure!(
            report.dnssl == vec!["home.arpa".to_owned()],
            "DNSSL in {report:?}"
        );
    }
    ensure!(
        pingable6(&lab.isp0, None, &booted.address.to_string())?,
        "the ISP cannot ping the WAN's address {}",
        booted.address
    );
    Ok(())
}

/// Kea restarted with another delegation pool has forgotten the binding: the router's Renew
/// gets a prefix from the new pool and the old one gone; within ten seconds the LAN host holds
/// an address in the new /64 and its old one is deprecated, traffic from the old one is
/// answered unreachable, and when the old prefix's remaining valid lifetime runs out it leaves
/// the advertisements, the host and the router (SPEC §7.3, §12).
fn the_isp_changes_the_prefix_and_the_lan_is_renumbered_within_ten_seconds(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &isp_radvd())?;
    let old_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_ready(&lab.lan0, "lan0", old_net)
    })?;
    let old = host_addr_in(&lab.lan0, "lan0", old_net)?.context("the old address")?;
    lab.restart_kea6(&Kea6Config::isp(Some(pool(PD_POOL_B)?)))?;
    let c = lab.console()?;
    let bound = c.wait_for(&mut booted.cur, &re(BOUND_B), Duration::from_secs(30))?;
    let new_prefix: Ipv6Net = group(&bound, 0)?.parse()?;
    let new_net = subnet(new_prefix, LAN0_INDEX).context("lan0's new /64")?;
    wait_until(RENUMBER, "the LAN host's renumbering", || {
        Ok(lan_ready(&lab.lan0, "lan0", new_net)?
            && host_addr_in(&lab.lan0, "lan0", old_net)?.is_some_and(|host| host.deprecated))
    })?;
    let gone = re(&format!(
        r"openfeo: dhcp6 wan0 prefix {} gone: deprecated for \d+ s",
        escaped(&booted.prefix.to_string())
    ));
    ensure!(
        c.count(&gone) == 1,
        "the console must report the old prefix gone once: {:?}",
        c.tail(20)
    );
    ensure!(
        c.count(&re(&format!(
            r"openfeo: ra br-lan0 deprecating {}",
            escaped(&old_net.to_string())
        ))) == 1,
        "the advertisements must deprecate the old /64 once: {:?}",
        c.tail(20)
    );
    let (answered, text) = ping6(&lab.lan0, Some(&old.addr.to_string()), ISP_HOST6)?;
    ensure!(
        !answered && text.contains("Destination unreachable"),
        "traffic from the deprecated prefix must be answered unreachable, got: {text}"
    );
    let dropped = re(&format!(
        r"openfeo: dhcp6 wan0 prefix {} dropped",
        escaped(&booted.prefix.to_string())
    ));
    c.wait_for(&mut booted.cur, &dropped, DEPRECATION_MAX)?;
    wait_until(SOON, "the old address leaving the LAN host", || {
        Ok(host_addr_in(&lab.lan0, "lan0", old_net)?.is_none())
    })?;
    if rdisc6_installed() {
        let report = lanclient::rdisc6(&lab.lan0, "lan0", RDISC6_TIMEOUT)?;
        ensure!(
            !report.prefixes.contains(&old_net.to_string())
                && report.prefixes.contains(&new_net.to_string()),
            "after the drop the advertisement must carry the new /64 and not the old: {report:?}"
        );
    }
    Ok(())
}

/// Carrier lost on the WAN: within one advertisement the LAN host has no IPv6 default and its
/// delegated address is deprecated while the ULA one is not; carrier back: the router Rebinds
/// and the binding continues, and the host's delegated address is preferred again (SPEC §7.3).
fn wan_ipv6_loss_deprecates_the_delegated_prefix_and_carrier_back_rebinds_it(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &isp_radvd())?;
    let lan_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        Ok(lan_ready(&lab.lan0, "lan0", lan_net)?
            && host_ula(&lab.lan0, "lan0")?.is_some_and(|host| !host.tentative))
    })?;
    let ula_net = net_of(
        host_ula(&lab.lan0, "lan0")?
            .context("the ULA address")?
            .addr,
    );
    let c = lab.console()?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    c.wait_for(&mut booted.cur, &re(r"openfeo: link p0 down"), SOON)?;
    let down = booted.cur;
    wait_until(
        Duration::from_secs(8),
        "the LAN host deprecating the delegated address",
        || {
            Ok(!has_default6(&lab.lan0, "lan0")?
                && host_addr_in(&lab.lan0, "lan0", lan_net)?.is_some_and(|host| host.deprecated)
                && host_addr_in(&lab.lan0, "lan0", ula_net)?.is_some_and(|host| !host.deprecated))
        },
    )?;
    qmp.set_link("p0", true)?;
    c.wait_for(&mut booted.cur, &re(r"openfeo: dhcp6 wan0 rebinding"), SOON)?;
    c.wait_for(&mut booted.cur, &re(r"openfeo: dhcp6 wan0 renewed"), SOON)?;
    ensure!(
        c.count_since(&down, &re(BOUND)) == 0
            && c.count_since(&down, &re(r"openfeo: dhcp6 wan0 soliciting")) == 0,
        "the binding must continue across the flap, not be made again: {:?}",
        c.tail(20)
    );
    wait_until(
        SOON,
        "the LAN host's delegated address preferred again",
        || {
            Ok(
                host_addr_in(&lab.lan0, "lan0", lan_net)?.is_some_and(|host| !host.deprecated)
                    && has_default6(&lab.lan0, "lan0")?,
            )
        },
    )?;
    Ok(())
}

/// The lan1 host reaches the lan0 host's ULA address through the router; a ULA source toward
/// the ISP is answered unreachable by the router; a ULA source from the ISP side is dropped
/// (SPEC §7.3, §7.5).
fn ula_addresses_reach_the_other_lan_and_never_leave_the_wan(lab: &mut Lab) -> anyhow::Result<()> {
    let booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &isp_radvd())?;
    let lan_net = booted.lan0_net()?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    wait_until(SOON, "both LAN hosts' ULA addresses", || {
        Ok(lan_ready(&lab.lan0, "lan0", lan_net)?
            && host_ula(&lab.lan0, "lan0")?.is_some_and(|host| !host.tentative)
            && host_ula(lan1, "lan1")?.is_some_and(|host| !host.tentative))
    })?;
    let lan0_ula = host_ula(&lab.lan0, "lan0")?.context("the lan0 host's ULA address")?;
    let lan1_ula = host_ula(lan1, "lan1")?.context("the lan1 host's ULA address")?;
    ensure!(
        net_of(lan0_ula.addr) != net_of(lan1_ula.addr)
            && lan0_ula.addr.segments()[..3] == lan1_ula.addr.segments()[..3],
        "the LANs take different /64s of one ULA /48: {} and {}",
        lan0_ula.addr,
        lan1_ula.addr
    );
    ensure!(
        pingable6(lan1, None, &lan0_ula.addr.to_string())?,
        "the lan1 host cannot reach the lan0 host's ULA address {}",
        lan0_ula.addr
    );
    let (answered, text) = ping6(&lab.lan0, Some(&lan0_ula.addr.to_string()), ISP_HOST6)?;
    ensure!(
        !answered && text.contains("Destination unreachable"),
        "a ULA source toward the ISP must be answered unreachable, got: {text}"
    );
    lab.isp0.ip(&[
        "-6",
        "addr",
        "replace",
        &format!("{ISP_ULA_SOURCE}/64"),
        "dev",
        "wan0",
        "nodad",
    ])?;
    let router = booted.address.to_string();
    let (answered, text) = ping6(&lab.isp0, Some(ISP_ULA_SOURCE), &router)?;
    ensure!(
        !answered,
        "the router answered a ULA source from the WAN: {text}"
    );
    ensure!(
        pingable6(&lab.isp0, None, &router)?,
        "the WAN's address must still answer the ISP's own source"
    );
    Ok(())
}

/// busybox `udhcpc6 -l` on the LAN host, the stateless reference client, gets the router's
/// addresses in that LAN (ULA first) as resolvers and the system domain as the search list
/// (SPEC §7.3).
fn stateless_dhcpv6_hands_out_the_resolver_and_the_search_list(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &isp_radvd())?;
    let lan_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        Ok(lan_ready(&lab.lan0, "lan0", lan_net)?
            && host_ula(&lab.lan0, "lan0")?.is_some_and(|host| !host.tentative))
    })?;
    let ula = host_ula(&lab.lan0, "lan0")?.context("the ULA address")?;
    let (router_ula, router_gua) = (router_in(net_of(ula.addr)), router_in(lan_net));
    let info = lanclient::udhcpc6_info(&lab.lan0, "lan0", &lab.run_dir, Duration::from_secs(15))?;
    ensure!(
        info.dns == vec![router_ula, router_gua],
        "udhcpc6 got the resolvers {:?}, expected {router_ula} then {router_gua}",
        info.dns
    );
    ensure!(
        info.search == vec!["home.arpa".to_owned()],
        "search {:?}",
        info.search
    );
    let serving = re(&format!(
        r"openfeo: dhcp6-server br-lan0 serving {router_ula},{router_gua} home\.arpa"
    ));
    ensure!(
        lab.console()?.count(&serving) >= 1,
        "no responder line for both addresses: {:?}",
        lab.console()?.tail(20)
    );
    Ok(())
}

/// A reset of the machine with a long-lived binding: the console shows the binding restored
/// from disk and Rebound, the prefix is the same, and the LAN host's delegated address is
/// neither lost nor deprecated meanwhile (SPEC §7.3).
fn a_rebooted_router_keeps_its_delegation(lab: &mut Lab) -> anyhow::Result<()> {
    let kea = Kea6Config {
        long_lived: true,
        ..Kea6Config::isp(Some(pool(PD_POOL_A)?))
    };
    let mut booted = boot_pd(lab, &kea, &isp_radvd())?;
    let lan_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_ready(&lab.lan0, "lan0", lan_net)
    })?;
    let c = lab.console()?;
    let stop = AtomicBool::new(false);
    let restored = re(&format!(
        r"openfeo: dhcp6 wan0 binding restored from disk: prefix {} \(preferred \d+ s, valid \d+ s\) address {}",
        escaped(&booted.prefix.to_string()),
        escaped(&booted.address.to_string())
    ));
    let lan0 = &lab.lan0;
    let (deprecated, lost) = thread::scope(|scope| -> anyhow::Result<(bool, bool)> {
        let poller = scope.spawn(|| -> anyhow::Result<(bool, bool)> {
            let (mut deprecated, mut lost) = (false, false);
            while !stop.load(Ordering::Relaxed) {
                match host_addr_in(lan0, "lan0", lan_net)? {
                    Some(host) => deprecated |= host.deprecated,
                    None => lost = true,
                }
                thread::sleep(Duration::from_millis(200));
            }
            Ok((deprecated, lost))
        });
        let rebooted = (|| -> anyhow::Result<Cursor> {
            lab.qmp()?.system_reset()?;
            c.wait_for(&mut booted.cur, &re(KERNEL_BANNER), BOOT_TIMEOUT)?;
            let reset = booted.cur;
            // `ready` and the Rebind's answer come in either order after the reset.
            wait_since(c, reset, &restored, BOOT_TIMEOUT)?;
            wait_since(
                c,
                reset,
                &re(r"openfeo: dhcp6 wan0 rebinding"),
                BOOT_TIMEOUT,
            )?;
            wait_since(c, reset, &re(READY), BOOT_TIMEOUT)?;
            wait_since(c, reset, &re(r"openfeo: dhcp6 wan0 renewed"), BOOT_TIMEOUT)?;
            // The advertisements that follow the reboot reach the host within a moment.
            thread::sleep(Duration::from_secs(3));
            Ok(reset)
        })();
        stop.store(true, Ordering::Relaxed);
        let watched = poller
            .join()
            .map_err(|_| anyhow::anyhow!("the address poller panicked"))??;
        let reset = rebooted?;
        ensure!(
            c.count_since(&reset, &re(r"openfeo: dhcp6 wan0 soliciting")) == 0
                && c.count_since(&reset, &re(BOUND)) == 0,
            "the rebooted router must rebind the persisted binding, not solicit: {:?}",
            c.tail(30)
        );
        Ok(watched)
    })?;
    ensure!(
        !lost,
        "the LAN host lost its delegated address across the reboot"
    );
    ensure!(
        !deprecated,
        "the LAN host's delegated address was deprecated during the reboot"
    );
    Ok(())
}

/// With no typed upstreams and an ISP that names its resolver only over DHCPv6, the resolver
/// is announced only after the routing pass that installed the IPv6 default (ADR-0019), and
/// names resolve to AAAA through it at the router's ULA address (SPEC §7.3, §7.7).
fn isp_resolvers_learned_over_dhcpv6_join_after_the_route(lab: &mut Lab) -> anyhow::Result<()> {
    let radvd = RadvdConfig {
        rdnss: Vec::new(),
        dnssl: Vec::new(),
        ..isp_radvd()
    };
    let booted = boot_pd(lab, &Kea6Config::isp(Some(pool(PD_POOL_A)?)), &radvd)?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(ROUTER_LEARNED), SOON)?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: apply routing generation=\d+ ops=\d+"),
        SOON,
    )?;
    let routed = cur;
    let announced =
        re(r"openfeo: dns upstreams 203\.0\.113\.1 2001:db8:ffff::1 \(learned from wan0\)");
    c.wait_for(&mut cur, &announced, SOON)?;
    ensure!(
        c.count(&announced) == c.count_since(&routed, &announced),
        "the DHCPv6 upstream was announced before its route was applied"
    );
    let lan_net = booted.lan0_net()?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        Ok(lan_ready(&lab.lan0, "lan0", lan_net)?
            && host_ula(&lab.lan0, "lan0")?.is_some_and(|host| !host.tentative))
    })?;
    let ula = host_ula(&lab.lan0, "lan0")?.context("the ULA address")?;
    let router_ula = router_in(net_of(ula.addr));
    let answer = lanclient::dig(
        &lab.lan0,
        router_ula.into(),
        "www.isp.example",
        "AAAA",
        &[],
        DIG_TIMEOUT,
    )?;
    expect_aaaa(&answer, "www.isp.example", ISP_WWW_ADDR6)
}
