// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M2 acceptance (SPEC §12) in the rootless QEMU lab: part 1, LAN VLANs, the tagged WAN, the
//! per-LAN policy and its rules, and public IPv4 blocks; part 2, IPv6 with a statically routed
//! prefix. Like `m1`, `harness = false`: this binary is its own runner and an optional first
//! argument filters scenarios by substring.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use openfeo_harness::daemons::{self, Daemon, ISP_WWW_ADDR6, RadvdConfig};
use openfeo_harness::lab::{BOOT_TIMEOUT, ISP_HTTP_BODY, LAN_HTTP_BODY, Lab, ROUTED_PREFIX6};
use openfeo_harness::lanclient::{self, DigAnswer};
use openfeo_harness::lines::{Cursor, Match, Regex};
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
    Scenario {
        name: "lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6",
        run: lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6,
    },
    Scenario {
        name: "the_router_learns_its_default_from_the_isp_and_sources_from_its_loopback_address",
        run: the_router_learns_its_default_from_the_isp_and_sources_from_its_loopback_address,
    },
    Scenario {
        name: "a_typed_gateway_replaces_the_learned_default",
        run: a_typed_gateway_replaces_the_learned_default,
    },
    Scenario {
        name: "a_link_prefix_from_the_isp_gives_the_wan_a_stable_address",
        run: a_link_prefix_from_the_isp_gives_the_wan_a_stable_address,
    },
    Scenario {
        name: "dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule",
        run: dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule,
    },
    Scenario {
        name: "wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval",
        run: wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval,
    },
    Scenario {
        name: "an_unused_ipv6_subnet_is_blackholed",
        run: an_unused_ipv6_subnet_is_blackholed,
    },
    Scenario {
        name: "isp_names_resolve_to_aaaa_through_a_learned_ipv6_upstream",
        run: isp_names_resolve_to_aaaa_through_a_learned_ipv6_upstream,
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
    blackholed(&lab.isp0, "192.0.2.250")
}

/// `ping -c 2 -W 1 <target>` from `ns` gets no reply and no ICMP error: a blackhole answers
/// nothing.
fn blackholed(ns: &NetNs, target: &str) -> anyhow::Result<()> {
    let mut cmd = ns.command("ping")?;
    cmd.args(["-c", "2", "-W", "1", target]);
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

// ---- M2 part 2: IPv6 with a statically routed prefix (SPEC §7.3) ----

/// The lab's IPv6 configuration: the static WAN and lan0 of `vm-static.toml`, the ISP's routed
/// `2001:db8:1::/48` with no typed gateway, lan0 advertising `2001:db8:1:222::/64`, a DMZ on p3
/// (lan1) at `2001:db8:1:232::/64` with advertisements off, a rule opening tcp 80 to the DMZ
/// host over IPv6, an AAAA record for it, and a typed IPv6 upstream beside the IPv4 one.
const VM_IPV6: &str = include_str!("../fixtures/vm-ipv6.toml");
/// The router's lan0 address: the LAN's gateway and resolver over IPv6, its RDNSS.
const ROUTER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0x222, 0, 0, 0, 1);
/// The router's lan0 address over IPv4, where the LAN host asks for names by hand.
const ROUTER_DNS4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
/// The DMZ host (lan1) and its gateway, the router's DMZ address.
const DMZ_HOST6: &str = "2001:db8:1:232::10";
const DMZ_GATEWAY6: &str = "2001:db8:1:232::1";
/// ISP A's address on the WAN link, where the ISP-side IPv6 targets listen.
const ISP_HOST6: &str = "2001:db8:ffff::1";
/// The ISP-side IPv6 HTTP target.
const ISP_HTTP6: &str = "[2001:db8:ffff::1]:8080";
/// The ISP's link prefix, when a scenario has radvd advertise one.
const ISP_LINK_PREFIX6: &str = "2001:db8:ffff::/64";
/// The router's wan0 link-local as its console line shows it: where the ISP routes the prefix.
const WAN_LINK_LOCAL: &str = r"openfeo: wan wan0 ipv6 link-local (fe80:[0-9a-f:]+)";
/// The WAN's stable address from the ISP's link prefix, as its console line shows it.
const WAN_ADDRESS6: &str = r"openfeo: wan wan0 ipv6 address (2001:db8:ffff:[0-9a-f:]+)/64";
/// The router learned ISP A, at its link-local, as its default router from radvd.
const ROUTER_LEARNED: &str = r"openfeo: wan wan0 ipv6 router fe80::1 \(learned\)";
/// The ISP's resolver logging a query the router sent over IPv6: from its loopback address.
const FROM_ROUTER_LOOPBACK6: &str = r"from 2001:db8:1::1\s*$";
/// How long one `dig` from the LAN host may take in all.
const DIG_TIMEOUT: Duration = Duration::from_secs(6);
/// How long `rdisc6` waits where an advertisement is due: the router answers a solicitation
/// within half a second, or after the three-second floor between advertisements.
const RDISC6_TIMEOUT: Duration = Duration::from_secs(4);

/// Boot `config` (a `VM_IPV6` text) with radvd as ISP A's advertiser, dnsmasq on ISP A's
/// addresses of both families, lan0 the main host (IPv4 by hand, IPv6 from the router's
/// advertisements) and lan1 the DMZ host placed by hand; ISP A routes the prefix to the router's
/// wan0 link-local read from the console. Returns the console cursor past `ready`.
fn boot_ipv6(lab: &mut Lab, radvd: &RadvdConfig, config: &str) -> anyhow::Result<Cursor> {
    lab.add_lan1()?;
    // radvd first: it gives isp0 its IPv6 addresses, and dnsmasq binds what exists when it starts.
    lab.start_radvd(radvd)?;
    lab.start_dnsmasq()?;
    lab.with_config(config)?;
    lab.boot("")?;
    let mut cur = Cursor::default();
    lab.console()?
        .wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    let link_local = group(
        &lab.console()?
            .wait_for(&mut Cursor::default(), &re(WAN_LINK_LOCAL), SOON)?,
        0,
    )?;
    lab.isp_route_block6(ROUTED_PREFIX6, &link_local)?;
    // A link that comes up now solicits and the router answers; one up since the lab was made
    // solicited before the router existed and would wait for an unsolicited advertisement.
    lab.lan0.ip(&["link", "set", "lan0", "down"])?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    Lab::host(lan1, "lan1", &format!("{DMZ_HOST}/29"), DMZ_GATEWAY)?;
    Lab::host6(lan1, "lan1", &format!("{DMZ_HOST6}/64"), DMZ_GATEWAY6)?;
    Ok(cur)
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
        anyhow::ensure!(
            Instant::now() < deadline,
            "{what} did not happen within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The LAN host's kernel has a default route via a link-local on `lan0`: the router advertises
/// itself as one.
fn lan_has_default6(ns: &NetNs) -> anyhow::Result<bool> {
    Ok(ns
        .ip(&["-6", "route", "show", "default", "dev", "lan0"])?
        .contains("via fe80:"))
}

/// The LAN host's kernel configured itself from the router's advertisement: a global address in
/// lan0's prefix past duplicate address detection, and the default route.
fn lan_configured6(ns: &NetNs) -> anyhow::Result<bool> {
    let addrs = ns.ip(&["-6", "addr", "show", "dev", "lan0", "scope", "global"])?;
    Ok(addrs.contains("inet6 2001:db8:1:222:")
        && !addrs.contains("tentative")
        && lan_has_default6(ns)?)
}

/// `dig <name> <qtype>` at the router's lan0 address over IPv6, from the LAN host.
fn dig6(lab: &Lab, name: &str, qtype: &str) -> anyhow::Result<DigAnswer> {
    lanclient::dig(&lab.lan0, ROUTER6.into(), name, qtype, &[], DIG_TIMEOUT)
}

/// `answer` must be `NOERROR` with exactly one AAAA record, `addr`.
fn expect_aaaa(answer: &DigAnswer, name: &str, addr: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
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
    anyhow::ensure!(addrs == [addr], "{name}: answers {:?}", answer.answers);
    Ok(())
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

/// A few `ping -c 1` tries at `target` from `ns`, so neighbour discovery and a fresh address get
/// a chance; true when one was answered.
fn pingable(ns: &NetNs, target: &str) -> anyhow::Result<bool> {
    for _ in 0..5 {
        if ping_once(ns, target)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The LAN host's kernel takes lan0's prefix, the router as its default and the router's RDNSS
/// and DNSSL from the router's advertisements, and fetches from the ISP side over IPv6 (SPEC
/// §7.3).
fn lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    boot_ipv6(lab, &RadvdConfig::isp("wan0"), VM_IPV6)?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_configured6(&lab.lan0)
    })?;
    let _isp = http_target(lab, &lab.isp0, ISP_HOST6, 8080, ISP_HTTP_BODY)?;
    anyhow::ensure!(
        fetch(&lab.lan0, ISP_HTTP6)? == ISP_HTTP_BODY,
        "the LAN host reaches the ISP over IPv6"
    );
    if rdisc6_installed() {
        let report = lanclient::rdisc6(&lab.lan0, "lan0", RDISC6_TIMEOUT)?;
        anyhow::ensure!(report.rdnss == vec![ROUTER6], "RDNSS in {report:?}");
        anyhow::ensure!(
            report.dnssl == vec!["home.arpa".to_owned()],
            "DNSSL in {report:?}"
        );
    }
    Ok(())
}

/// The router learns ISP A as its default router from radvd and sends from its loopback address
/// out of the prefix: the ISP's resolver, asked over IPv6, logs a query from `2001:db8:1::1`
/// (SPEC §7.3).
fn the_router_learns_its_default_from_the_isp_and_sources_from_its_loopback_address(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    boot_ipv6(lab, &RadvdConfig::isp("wan0"), VM_IPV6)?;
    lab.console()?
        .wait_for(&mut Cursor::default(), &re(ROUTER_LEARNED), SOON)?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_configured6(&lab.lan0)
    })?;
    // The forwarder takes its upstreams in turn: two names reach both of them.
    expect_aaaa(
        &dig6(lab, "www.isp.example", "AAAA")?,
        "www.isp.example",
        ISP_WWW_ADDR6,
    )?;
    let ns = dig6(lab, "ns.isp.example", "A")?;
    anyhow::ensure!(ns.status == "NOERROR", "ns.isp.example: {ns:?}");
    let dnsmasq = lab
        .daemons
        .iter()
        .find(|daemon| daemon.name == "dnsmasq")
        .context("dnsmasq is running")?;
    anyhow::ensure!(
        dnsmasq.log.count(&re(FROM_ROUTER_LOOPBACK6)) >= 1,
        "the ISP's resolver never heard from the router's loopback address: {:?}",
        dnsmasq.log.tail(8)
    );
    Ok(())
}

/// A typed `gateway` is the default whatever the ISP advertises: radvd offering no default
/// router (lifetime 0) leaves the LAN host reaching the ISP over IPv6 (SPEC §7.3).
fn a_typed_gateway_replaces_the_learned_default(lab: &mut Lab) -> anyhow::Result<()> {
    let config = VM_IPV6.replace(
        "prefix = \"2001:db8:1::/48\"\n",
        "prefix = \"2001:db8:1::/48\"\ngateway = \"fe80::1\"\n",
    );
    anyhow::ensure!(config != VM_IPV6, "fixture lost its prefix line");
    let radvd = RadvdConfig {
        lifetime: 0,
        ..RadvdConfig::isp("wan0")
    };
    boot_ipv6(lab, &radvd, &config)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: wan wan0 ipv6 gateway fe80::1 \(configured\)"),
        SOON,
    )?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_configured6(&lab.lan0)
    })?;
    let _isp = http_target(lab, &lab.isp0, ISP_HOST6, 8080, ISP_HTTP_BODY)?;
    anyhow::ensure!(
        fetch(&lab.lan0, ISP_HTTP6)? == ISP_HTTP_BODY,
        "the LAN host reaches the ISP through the typed gateway"
    );
    anyhow::ensure!(
        lab.console()?.count(&re(ROUTER_LEARNED)) == 0,
        "radvd with lifetime 0 was learned as a default router"
    );
    Ok(())
}

/// With a link prefix in the ISP's advertisements the WAN gets a stable address in it (RFC
/// 7217): the ISP pings it, and the same address comes back after a reset of the machine (SPEC
/// §7.3).
fn a_link_prefix_from_the_isp_gives_the_wan_a_stable_address(lab: &mut Lab) -> anyhow::Result<()> {
    let radvd = RadvdConfig {
        prefix: Some(ISP_LINK_PREFIX6.to_owned()),
        ..RadvdConfig::isp("wan0")
    };
    boot_ipv6(lab, &radvd, VM_IPV6)?;
    let mut cur = Cursor::default();
    let address = group(
        &lab.console()?.wait_for(&mut cur, &re(WAN_ADDRESS6), SOON)?,
        0,
    )?;
    anyhow::ensure!(
        pingable(&lab.isp0, &address)?,
        "the ISP cannot ping the WAN's address {address}"
    );
    lab.qmp()?.system_reset()?;
    let c = lab.console()?;
    c.wait_for(
        &mut cur,
        &re(r"Linux version 6\.18\.59-openfeo"),
        BOOT_TIMEOUT,
    )?;
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    let again = group(&c.wait_for(&mut cur, &re(WAN_ADDRESS6), SOON)?, 0)?;
    anyhow::ensure!(
        again == address,
        "the WAN's address changed across a reset: {address} then {again}"
    );
    Ok(())
}

/// From the ISP side, the DMZ host answers over IPv6 on tcp 80, which the fixture's rule opens,
/// and on nothing else: another port and ICMPv6 echo get no reply. The DMZ server sees the ISP
/// host's own address, the router answers the host's typed AAAA, and the DMZ, with `ra = false`,
/// advertises nothing (SPEC §7.3, §7.5).
fn dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule(lab: &mut Lab) -> anyhow::Result<()> {
    boot_ipv6(lab, &RadvdConfig::isp("wan0"), VM_IPV6)?;
    let lan1 = lab.lan1.as_ref().context("lan1 was added")?;
    let web = http_target(lab, lan1, DMZ_HOST6, 80, "dmz web6")?;
    let _other = http_target(lab, lan1, DMZ_HOST6, 81, "dmz other6")?;
    anyhow::ensure!(
        fetch(&lab.isp0, &format!("[{DMZ_HOST6}]:80"))? == "dmz web6",
        "the rule opens tcp 80"
    );
    anyhow::ensure!(
        web.log.count(&re(r"^2001:db8:ffff::1 - - ")) == 1,
        "the DMZ server did not see the ISP host untranslated: {:?}",
        web.log.tail(5)
    );
    dropped(&lab.isp0, &format!("[{DMZ_HOST6}]:81")).context("no rule opens 81")?;
    anyhow::ensure!(
        !ping_once(&lab.isp0, DMZ_HOST6)?,
        "no rule opens ICMPv6 echo to the DMZ"
    );
    expect_aaaa(
        &lanclient::dig(
            &lab.lan0,
            ROUTER_DNS4.into(),
            "www.home.arpa",
            "AAAA",
            &[],
            DIG_TIMEOUT,
        )?,
        "www.home.arpa",
        DMZ_HOST6,
    )?;
    if rdisc6_installed() {
        anyhow::ensure!(
            lanclient::rdisc6(lan1, "lan1", RDISC6_TIMEOUT).is_err(),
            "the DMZ advertises with ra = false"
        );
    }
    Ok(())
}

/// When the ISP's advertisements stop, the router's own go out with lifetime 0 at once and the
/// LAN host drops its IPv6 default within the interval, keeping IPv4; when they return, so does
/// the lifetime and the host's default (SPEC §7.3).
fn wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut cur = boot_ipv6(lab, &RadvdConfig::isp("wan0"), VM_IPV6)?;
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_configured6(&lab.lan0)
    })?;
    let _isp = http_target(lab, &lab.isp0, "203.0.113.1", 8080, ISP_HTTP_BODY)?;
    anyhow::ensure!(lab.stop_radvd(), "radvd was running");
    lab.console()?.wait_for(
        &mut cur,
        &re(r"openfeo: ra br-lan0 lifetime 0 \(wan0 has no ipv6 route\)"),
        SOON,
    )?;
    wait_until(
        Duration::from_secs(5),
        "the LAN host's IPv6 default going",
        || Ok(!lan_has_default6(&lab.lan0)?),
    )?;
    anyhow::ensure!(
        fetch(&lab.lan0, ISP_HTTP)? == ISP_HTTP_BODY,
        "IPv4 outlives the IPv6 loss"
    );
    lab.start_radvd(&RadvdConfig::isp("wan0"))?;
    lab.console()?
        .wait_for(&mut cur, &re(r"openfeo: ra br-lan0 lifetime 1800"), SOON)?;
    wait_until(SOON, "the LAN host's IPv6 default returning", || {
        lan_has_default6(&lab.lan0)
    })?;
    Ok(())
}

/// The console shows the prefix's blackhole, and a probe from the ISP side to a subnet of it
/// that no LAN uses gets no reply and no ICMPv6 error (SPEC §7.3, §7.4).
fn an_unused_ipv6_subnet_is_blackholed(lab: &mut Lab) -> anyhow::Result<()> {
    boot_ipv6(lab, &RadvdConfig::isp("wan0"), VM_IPV6)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: add route blackhole 2001:db8:1::/48 proto 200 metric 1000"),
        SOON,
    )?;
    blackholed(&lab.isp0, "2001:db8:1:5::1")
}

/// With no typed upstreams the resolver learned from the ISP's RDNSS is announced only after the
/// routing pass that installed the IPv6 default (ADR-0019), and names resolve to AAAA through it
/// (SPEC §7.3, §7.7).
fn isp_names_resolve_to_aaaa_through_a_learned_ipv6_upstream(lab: &mut Lab) -> anyhow::Result<()> {
    let config = VM_IPV6.replace(
        "upstreams = [\"203.0.113.1\", \"2001:db8:ffff::1\"]",
        "upstreams = []",
    );
    anyhow::ensure!(config != VM_IPV6, "fixture lost its upstreams line");
    boot_ipv6(lab, &RadvdConfig::isp("wan0"), &config)?;
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
    anyhow::ensure!(
        c.count(&announced) == c.count_since(&routed, &announced),
        "the IPv6 upstream was announced before its route was applied"
    );
    wait_until(SOON, "the LAN host's autoconfiguration", || {
        lan_configured6(&lab.lan0)
    })?;
    expect_aaaa(
        &dig6(lab, "www.isp.example", "AAAA")?,
        "www.isp.example",
        ISP_WWW_ADDR6,
    )
}
