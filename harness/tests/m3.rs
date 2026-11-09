// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M3 in QEMU: the router's PPPoE WAN (`harness/fixtures/vm-pppoe.toml`) against the lab's
//! access concentrator, rp-pppoe's `pppoe-server` with `pppd` on isp0's `wan0` (SPEC §7.2, §12).
//! The console's PPPoE lines (the design's contract) are what the scenarios wait on; the LAN
//! host proves NAT and the MSS clamp over the PPP link; no scenario may find the password on the
//! console. `harness = false`: this binary is its own runner; an optional first argument filters
//! scenarios by substring.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use ipnet::Ipv6Net;
use openfeo_harness::daemons::{self, Auth, Daemon, Kea6Config, PppoeServerConfig, RadvdConfig};
use openfeo_harness::lab::{BOOT_TIMEOUT, Lab, PD_POOL_A, ROUTED_PREFIX6};
use openfeo_harness::lanclient;
use openfeo_harness::lines::{Cursor, Match, Regex};
use openfeo_harness::netns::NetNs;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, Skip, run_all};
use openfeo_harness::vlanprobe;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "lan_fetches_isp_http_through_nat_over_ppp",
        run: lan_fetches_isp_http_through_nat_over_ppp,
    },
    Scenario {
        name: "the_lan_resolves_a_name_through_the_ipcp_resolver_over_ppp",
        run: the_lan_resolves_a_name_through_the_ipcp_resolver_over_ppp,
    },
    Scenario {
        name: "the_mss_clamp_makes_the_server_send_segments_that_fit",
        run: the_mss_clamp_makes_the_server_send_segments_that_fit,
    },
    Scenario {
        name: "the_console_never_shows_the_password",
        run: the_console_never_shows_the_password,
    },
    Scenario {
        name: "pppoe_server_killed_is_keepalive_lost_and_the_session_returns",
        run: pppoe_server_killed_is_keepalive_lost_and_the_session_returns,
    },
    Scenario {
        name: "the_access_concentrator_ending_the_session_is_reported_and_retried",
        run: the_access_concentrator_ending_the_session_is_reported_and_retried,
    },
    Scenario {
        name: "carrier_loss_is_reported_and_the_session_returns_within_ten_seconds",
        run: carrier_loss_is_reported_and_the_session_returns_within_ten_seconds,
    },
    Scenario {
        name: "carrier_loss_during_discovery_restarts_discovery",
        run: carrier_loss_during_discovery_restarts_discovery,
    },
    Scenario {
        name: "pap_authenticates_too",
        run: pap_authenticates_too,
    },
    Scenario {
        name: "the_tagged_wan_runs_pppoe_over_a_vlan",
        run: the_tagged_wan_runs_pppoe_over_a_vlan,
    },
    Scenario {
        name: "ipv6_over_ppp_gives_the_lan_a_gua_and_reaches_the_isp",
        run: ipv6_over_ppp_gives_the_lan_a_gua_and_reaches_the_isp,
    },
    Scenario {
        name: "pd_over_ppp_binds_a_prefix_and_the_lan_takes_a_gua_from_it",
        run: pd_over_ppp_binds_a_prefix_and_the_lan_takes_a_gua_from_it,
    },
    Scenario {
        name: "a_reboot_comes_back_with_a_fresh_session_and_the_same_prefix",
        run: a_reboot_comes_back_with_a_fresh_session_and_the_same_prefix,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

const VM_PPPOE: &str = include_str!("../fixtures/vm-pppoe.toml");
const VM_PPPOE_VLAN: &str = include_str!("../fixtures/vm-pppoe-vlan.toml");
const VM_PPPOE_PD: &str = include_str!("../fixtures/vm-pppoe-pd.toml");
const READY: &str = r"openfeo: ready generation=\d+";
const DOWN: &str = r"openfeo: pppoe wan0 down: (.*?) after \d+ s(; retry in (\d+) s)?$";
const SESSION: &str = r#"openfeo: pppoe wan0 session 0x([0-9a-f]{4}) with ([0-9a-f:]{17}) ac "isp" max payload 1492 \(no RFC 4638\)"#;
const LCP_UP: &str = r"openfeo: pppoe wan0 lcp up mru 1492 auth (chap|pap|none)";
const AUTH_OK: &str = r"openfeo: pppoe wan0 auth (chap|pap) ok as openfeo@isp\.example";
const IPCP_UP: &str =
    r"openfeo: pppoe wan0 ipcp up (203\.0\.113\.\d+) peer 203\.0\.113\.1 dns 203\.0\.113\.1$";
const IPV6CP_UP: &str = r"openfeo: pppoe wan0 ipv6cp up local ([0-9a-f:]{19}) peer ([0-9a-f:]{19})";
const ISP_HTTP: &str = "203.0.113.1:8080";
const SOON: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// `discovering on <port>` asking for `payload`: the router's port is `p0`, or `p0.<vid>` when the
/// ISP's interface is `wan0.<vid>`. The port goes to 1508 (virtio-net takes it), so the session
/// is always discovered asking for 1500: a discovery begun at 1492 before the links applier got
/// there starts again once it has.
fn discovering(isp_iface: &str, payload: &str) -> String {
    let port = isp_iface.replacen("wan0", "p0", 1);
    format!(
        r"openfeo: pppoe wan0 discovering on {} \(service any, max payload {payload}\)",
        port.replace('.', r"\.")
    )
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
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

/// The lab's access concentrator can run here, or the scenario skips with what is missing:
/// `/dev/ppp` openable (from the sandbox, where `ppp_generic`'s `CAP_NET_ADMIN` check passes)
/// and `pppd` and `pppoe-server` installed. CI sets `OPENFEO_NO_SKIP`, so a skip fails there.
fn require_access_concentrator() -> anyhow::Result<()> {
    if let Err(err) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ppp")
    {
        return Err(Skip(format!(
            "/dev/ppp: {err}: load ppp_generic and make it group-accessible \
             (udev: KERNEL==\"ppp\", GROUP=\"<your group>\", MODE=\"0660\")"
        ))
        .into());
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for tool in ["pppd", "pppoe-server"] {
        if !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()) {
            return Err(Skip(format!(
                "{tool} is not installed (packages ppp and pppoe, or rp-pppoe)"
            ))
            .into());
        }
    }
    Ok(())
}

/// What a PPPoE boot established.
struct Booted {
    /// The console after the last PPP line waited for.
    cur: Cursor,
    session_id: u16,
    address: Ipv4Addr,
    /// The router's IPV6CP identifier, as the console prints it (`0000:0000:0000:0002`).
    local_iid: u64,
}

impl Booted {
    /// The router's link-local on `ppp-wan0`: `fe80::<identifier>`.
    fn link_local(&self) -> String {
        let iid = self.local_iid;
        format!(
            "fe80::{:x}:{:x}:{:x}:{:x}",
            (iid >> 48) & 0xffff,
            (iid >> 32) & 0xffff,
            (iid >> 16) & 0xffff,
            iid & 0xffff
        )
    }
}

/// `0000:0000:0000:0002` as the console prints an identifier.
fn parse_iid(text: &str) -> anyhow::Result<u64> {
    let hex: String = text.split(':').collect();
    u64::from_str_radix(&hex, 16).with_context(|| format!("identifier {text}"))
}

/// The access concentrator on isp0's `wan0` with `server`, the router booted on `config`, and
/// every PPPoE line of the contract waited for in order: discovery, the session, LCP,
/// authentication (unless none was asked), IPCP and IPV6CP. The LAN host is placed last.
fn boot_pppoe(lab: &mut Lab, server: &PppoeServerConfig, config: &str) -> anyhow::Result<Booted> {
    require_access_concentrator()?;
    lab.start_pppoe_server(server)?;
    lab.with_config(config)?;
    lab.boot("")?;
    let c = lab.console()?;
    // The session can be up before the router says ready: the PPP lines are waited for in
    // their own order from the boot, and ready on its own.
    c.wait_for(&mut Cursor::default(), &re(READY), BOOT_TIMEOUT)?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(&discovering(&server.iface, "1500")), SOON)?;
    let session = c.wait_for(&mut cur, &re(SESSION), SOON)?;
    let session_id = u16::from_str_radix(&group(&session, 0)?, 16)?;
    c.wait_for(&mut cur, &re(LCP_UP), SOON)?;
    if server.auth != Auth::None {
        c.wait_for(&mut cur, &re(AUTH_OK), SOON)?;
    }
    let mut after_auth = cur;
    let ipcp = c.wait_for(&mut cur, &re(IPCP_UP), SOON)?;
    let address: Ipv4Addr = group(&ipcp, 0)?.parse()?;
    let ipv6cp = c.wait_for(&mut after_auth, &re(IPV6CP_UP), SOON)?;
    let local_iid = parse_iid(&group(&ipv6cp, 0)?)?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    Ok(Booted {
        cur,
        session_id,
        address,
        local_iid,
    })
}

/// Neither the console nor the ISP's `pppd` log carries the lab's password.
fn no_password_on_the_console(lab: &Lab, iface: &str) -> anyhow::Result<()> {
    let c = lab.console()?;
    let seen = c.count(&re(daemons::PPP_PASSWORD));
    ensure!(seen == 0, "the password is on the console {seen} times");
    let log = std::fs::read_to_string(lab.pppd_log(iface)).unwrap_or_default();
    ensure!(
        !log.contains(daemons::PPP_PASSWORD),
        "the password is in pppd's log"
    );
    Ok(())
}

/// The IPCP resolver carries a real query (#55): the LAN host asks the router, the forwarder
/// asks the ISP's resolver over the PPP session, and `www.isp.example` comes back.
fn the_lan_resolves_a_name_through_the_ipcp_resolver_over_ppp(lab: &mut Lab) -> anyhow::Result<()> {
    lab.start_dnsmasq()?;
    let booted = boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    let mut cur = booted.cur;
    let c = lab.console()?;
    // m1's UPSTREAMS_LEARNED: the resolver joins once the route exists (ADR-0019).
    c.wait_for(
        &mut cur,
        &re(r"openfeo: dns upstreams 203\.0\.113\.1 \(learned from wan0\)"),
        SOON,
    )?;
    let answer = lanclient::dig(
        &lab.lan0,
        "192.168.1.1".parse()?,
        "www.isp.example",
        "A",
        &[],
        Duration::from_secs(6),
    )?;
    ensure!(answer.status == "NOERROR", "{answer:?}");
    ensure!(
        answer
            .answers
            .iter()
            .any(|(_, _, rtype, value)| rtype == "A" && value == "198.51.100.10"),
        "{answer:?}"
    );
    let dnsmasq = lab
        .daemons
        .iter()
        .find(|d| d.name == "dnsmasq")
        .context("dnsmasq")?;
    ensure!(
        dnsmasq
            .log
            .count(&re(r"auth\[A\] www\.isp\.example from 203\.0\.113\.100"))
            >= 1,
        "the query reached the ISP over PPP: {:?}",
        dnsmasq.log.tail(8)
    );
    Ok(())
}

/// The LAN host fetches from the ISP over the PPP link; the ISP sees the request from the
/// address IPCP gave the router, never the LAN's.
fn lan_fetches_isp_http_through_nat_over_ppp(lab: &mut Lab) -> anyhow::Result<()> {
    let booted = boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    ensure!(booted.session_id != 0, "a session id");
    let body = "openfeo isp target over ppp";
    let server = http_target(lab, &lab.isp0, "203.0.113.1", 8080, body)?;
    let got = fetch(&lab.lan0, ISP_HTTP)?;
    ensure!(got == body, "unexpected body {got:?}");
    let from = format!("{} - - ", booted.address);
    ensure!(
        server.log.count(&re(&regex_escape(&from))) == 1,
        "the ISP did not see {}: {:?}",
        booted.address,
        server.log.tail(5)
    );
    ensure!(
        server.log.count(&re(r"192\.168\.1\.2")) == 0,
        "the LAN address leaked to the ISP side: {:?}",
        server.log.tail(5)
    );
    no_password_on_the_console(lab, "wan0")
}

fn regex_escape(text: &str) -> String {
    text.replace('.', r"\.")
}

/// What the router's MSS clamp is for: a server whose own path is 1500 bytes (one beyond the
/// ISP's 1500-byte links, here the ISP's own unit raised to 1500) would send 1460-byte segments
/// that cannot cross the 1492-byte PPP link. The router rewrites the LAN host's SYN to the PPP
/// path's MSS, so the server's socket settles on 1452; without the clamp it would say 1460.
fn the_mss_clamp_makes_the_server_send_segments_that_fit(lab: &mut Lab) -> anyhow::Result<()> {
    boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    let ppp = lab.isp_ppp_ifname("wan0", SOON)?;
    lab.isp0.ip(&["link", "set", &ppp, "mtu", "1500"])?;
    let server = mss_server(&lab.isp0, "203.0.113.1", 8081)?;
    let got = fetch(&lab.lan0, "203.0.113.1:8081")?;
    let mss: u32 = got
        .trim()
        .parse()
        .with_context(|| format!("an MSS, not {got:?}"))?;
    // TCP_MAXSEG counts the payload left after the options in use: 12 bytes go to timestamps
    // when both ends use them, so the clamp's 1452 reads 1440 and an unclamped 1460 would read
    // 1448.
    ensure!(
        mss == 1452 || mss == 1440,
        "the server's segments carry {mss} bytes (1452, or 1440 with timestamps, fit 1492; 1460 or 1448 mean no clamp): {:?}",
        server.log.tail(3)
    );
    let body = "x".repeat(65536);
    let _www = http_target(lab, &lab.isp0, "203.0.113.1", 8080, &body)?;
    let got = fetch(&lab.lan0, ISP_HTTP)?;
    ensure!(
        got.len() == body.len(),
        "{} of {} bytes arrived",
        got.len(),
        body.len()
    );
    no_password_on_the_console(lab, "wan0")
}

/// The MSS server's program (`python3 -c`), arguments bind and port.
const MSS_SERVER: &str = r"import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(4)
print('mss server listening', flush=True)
while True:
    c, a = s.accept()
    c.recv(4096)
    m = c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    print('mss', a[0], m, flush=True)
    b = str(m).encode()
    c.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(b)).encode() + b'\r\n\r\n' + b)
    c.close()
";

/// A one-shot HTTP server on `bind:port` in `ns` that answers each request with the MSS its
/// accepted socket settled on (`TCP_MAXSEG`): the lesser of its own path's and the one the
/// client's SYN advertised, after anything in between rewrote it.
fn mss_server(ns: &NetNs, bind: &str, port: u16) -> anyhow::Result<Daemon> {
    let mut cmd = ns.command("python3")?;
    cmd.args(["-u", "-c", MSS_SERVER, bind, &port.to_string()]);
    let server = Daemon::spawn(&format!("mss-{port}"), cmd)?;
    server
        .log
        .wait_for(&mut Cursor::default(), &re("mss server listening"), SOON)?;
    Ok(server)
}

/// The named proof of what every scenario checks at its end: after a whole CHAP session, the
/// password is nowhere on the console.
fn the_console_never_shows_the_password(lab: &mut Lab) -> anyhow::Result<()> {
    boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    no_password_on_the_console(lab, "wan0")
}

/// The ISP's server and its `pppd` killed outright: the router's echoes go unanswered and the
/// console says `keepalive lost` within the three echo intervals plus one, with the ladder's
/// first wait; the server back, a new session and IPCP follow.
fn pppoe_server_killed_is_keepalive_lost_and_the_session_returns(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let server = PppoeServerConfig::isp("wan0", Auth::Chap);
    let booted = boot_pppoe(lab, &server, VM_PPPOE)?;
    lab.kill_pppoe_server();
    let c = lab.console()?;
    let mut cur = booted.cur;
    let down = c.wait_for(&mut cur, &re(DOWN), Duration::from_secs(45))?;
    ensure!(
        group(&down, 0)? == "keepalive lost (3 echoes)",
        "{:?}",
        down.line
    );
    ensure!(
        group(&down, 2)? == "1",
        "the first retry waits 1 s: {:?}",
        down.line
    );
    lab.start_pppoe_server(&server)?;
    let c = lab.console()?;
    let session = c.wait_for(&mut cur, &re(SESSION), Duration::from_secs(70))?;
    let id = u16::from_str_radix(&group(&session, 0)?, 16)?;
    ensure!(id != 0, "a new session");
    c.wait_for(&mut cur, &re(IPCP_UP), SOON)?;
    no_password_on_the_console(lab, "wan0")
}

/// The WAN port's carrier goes: `carrier lost`, no retry wait (carrier's return is the retry);
/// it comes back, and a session is up again within ten seconds.
fn carrier_loss_is_reported_and_the_session_returns_within_ten_seconds(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let booted = boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    let c = lab.console()?;
    let mut cur = booted.cur;
    let down = c.wait_for(&mut cur, &re(DOWN), SOON)?;
    ensure!(group(&down, 0)? == "carrier lost", "{:?}", down.line);
    ensure!(
        group(&down, 1).is_err(),
        "no retry wait after carrier loss: {:?}",
        down.line
    );
    qmp.set_link("p0", true)?;
    c.wait_for(&mut cur, &re(SESSION), SOON)?;
    c.wait_for(&mut cur, &re(IPCP_UP), SOON)?;
    Ok(())
}

/// Carrier lost while discovering (no access concentrator yet): discovery starts again when the
/// link returns, with a fresh attempt, and the session comes up once the server does.
fn carrier_loss_during_discovery_restarts_discovery(lab: &mut Lab) -> anyhow::Result<()> {
    require_access_concentrator()?;
    lab.with_config(VM_PPPOE)?;
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(
        &mut cur,
        &re(&discovering("wan0", "(1492|1500)")),
        BOOT_TIMEOUT,
    )?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    std::thread::sleep(Duration::from_secs(1));
    qmp.set_link("p0", true)?;
    c.wait_for(&mut cur, &re(&discovering("wan0", "(1492|1500)")), SOON)?;
    lab.start_pppoe_server(&PppoeServerConfig::isp("wan0", Auth::Chap))?;
    let c = lab.console()?;
    c.wait_for(&mut cur, &re(SESSION), Duration::from_secs(40))?;
    c.wait_for(&mut cur, &re(IPCP_UP), SOON)?;
    Ok(())
}

/// The concentrator asks for PAP: `auth pap ok`, and the LAN reaches the ISP.
fn pap_authenticates_too(lab: &mut Lab) -> anyhow::Result<()> {
    boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Pap), VM_PPPOE)?;
    let c = lab.console()?;
    let auth = c.wait_for(&mut Cursor::default(), &re(AUTH_OK), SOON)?;
    ensure!(group(&auth, 0)? == "pap", "{:?}", auth.line);
    let body = "openfeo isp target over pap";
    let _server = http_target(lab, &lab.isp0, "203.0.113.1", 8080, body)?;
    ensure!(fetch(&lab.lan0, ISP_HTTP)? == body);
    no_password_on_the_console(lab, "wan0")
}

/// PPPoE on VLAN 101 of the WAN port (`vm-pppoe-vlan.toml`): discovery on `p0.101` against the
/// ISP's tagged interface, and the LAN reaches the ISP through it.
fn the_tagged_wan_runs_pppoe_over_a_vlan(lab: &mut Lab) -> anyhow::Result<()> {
    vlanprobe::require_vlan_links()?;
    let tagged = lab.isp0_tagged(101)?;
    boot_pppoe(
        lab,
        &PppoeServerConfig::isp(&tagged, Auth::Chap),
        VM_PPPOE_VLAN,
    )?;
    let body = "openfeo isp target over a tagged ppp";
    let _server = http_target(lab, &lab.isp0, "203.0.113.1", 8080, body)?;
    ensure!(fetch(&lab.lan0, ISP_HTTP)? == body);
    no_password_on_the_console(lab, &tagged)
}

const ROUTER_LEARNED: &str = r"openfeo: wan wan0 ipv6 router fe80::1 \(learned\)";
/// The routing applier's IPv6 default through the PPP netdev, in the main table.
const DEFAULT6_OVER_PPP: &str =
    r"openfeo: add route default via fe80::1 dev ppp-wan0( src [0-9a-f:]+)? proto 200 metric 10$";
/// The LAN host's own address in lan0's /64 of the routed /48.
const LAN0_NET6: &str = "2001:db8:1:222:";

/// Poll `done` every 200 ms until it says so, or `what` has not happened within `timeout`.
fn wait_until(
    timeout: Duration,
    what: &str,
    mut done: impl FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if done()? {
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "{what} did not happen within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The routed /48 over PPP (SPEC §7.3 part 2's shape, `vm-pppoe.toml`): radvd on the ISP's
/// `ppp<N>` gives the router its IPv6 default through `ppp-wan0`; the ISP routes the /48 to the
/// router's IPV6CP link-local; the LAN host configures itself from lan0's /64 and fetches the
/// ISP's target over IPv6.
fn ipv6_over_ppp_gives_the_lan_a_gua_and_reaches_the_isp(lab: &mut Lab) -> anyhow::Result<()> {
    let booted = boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    let ppp = lab.isp_ppp_ifname("wan0", SOON)?;
    lab.start_radvd_on(&RadvdConfig::isp(&ppp))?;
    lab.isp_route_block6_on(ROUTED_PREFIX6, &booted.link_local(), &ppp)?;
    let c = lab.console()?;
    c.wait_for(&mut Cursor::default(), &re(ROUTER_LEARNED), SOON)?;
    c.wait_for(&mut Cursor::default(), &re(DEFAULT6_OVER_PPP), SOON)?;
    // A link that comes up now solicits and the router answers at once.
    lab.lan0.ip(&["link", "set", "lan0", "down"])?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    wait_until(SOON, "the LAN host's address in lan0's /64", || {
        Ok(lab
            .lan0
            .ip(&["-6", "addr", "show", "dev", "lan0", "scope", "global"])?
            .lines()
            .any(|line| line.contains(LAN0_NET6) && !line.contains("tentative")))
    })?;
    let body = "openfeo isp target over ipv6 over ppp";
    let _server = http_target(lab, &lab.isp0, "2001:db8:ffff::1", 8080, body)?;
    let got = fetch(&lab.lan0, "[2001:db8:ffff::1]:8080")?;
    ensure!(got == body, "unexpected body {got:?}");
    no_password_on_the_console(lab, "wan0")
}

/// The router's delegation over PPP: `dhcp6 wan0 bound prefix <the /56>`.
const BOUND: &str =
    r"openfeo: dhcp6 wan0 (?:bound|renewed|restored) prefix (2001:db8:[0-9a-f:]+/56) ";

/// The ISP's IPv6 on the session's `ppp<N>`: radvd with M and O set (the delegation's shape) and
/// Kea's DHCPv6 server delegating from `PD_POOL_A`, and the pool routed to the router's IPV6CP
/// link-local through `ppp<N>`. Returns the interface.
fn isp_delegates_over(lab: &mut Lab, booted: &Booted) -> anyhow::Result<String> {
    let ppp = lab.isp_ppp_ifname("wan0", SOON)?;
    lab.start_radvd_on(&RadvdConfig {
        managed: true,
        other: true,
        ..RadvdConfig::isp(&ppp)
    })?;
    // Kea takes the far end of pppd's point-to-point link-local (`fe80::1 peer fe80::2`) for its
    // own and cannot bind it: the ISP's unit gets a plain fe80::1/64 instead.
    lab.isp0.ip(&[
        "-6", "addr", "del", "fe80::1", "peer", "fe80::2", "dev", &ppp,
    ])?;
    lab.isp0
        .ip(&["-6", "addr", "add", "fe80::1/64", "dev", &ppp, "nodad"])?;
    lab.start_kea6(&Kea6Config {
        iface: ppp.clone(),
        ..Kea6Config::isp(Some(PD_POOL_A.parse()?))
    })?;
    lab.isp_route_block6_on(PD_POOL_A, &booted.link_local(), &ppp)?;
    Ok(ppp)
}

/// The LAN host's global address in `net`, once it has one that is not tentative.
fn lan_host_takes(lab: &Lab, net: Ipv6Net) -> anyhow::Result<()> {
    let wanted = net.to_string();
    let head = wanted.trim_end_matches("/64").trim_end_matches("::");
    lab.lan0.ip(&["link", "set", "lan0", "down"])?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    wait_until(SOON, &format!("the LAN host's address in {net}"), || {
        Ok(lab
            .lan0
            .ip(&["-6", "addr", "show", "dev", "lan0", "scope", "global"])?
            .lines()
            .any(|line| line.contains(&format!("inet6 {head}:")) && !line.contains("tentative")))
    })
}

/// Prefix delegation over PPP (`vm-pppoe-pd.toml`): Kea's DHCPv6 server on the ISP's `ppp<N>`
/// delegates a /56, the router binds it on `ppp-wan0`, the LAN host takes an address from
/// lan0's /64 of it, and fetches the ISP's target over IPv6.
fn pd_over_ppp_binds_a_prefix_and_the_lan_takes_a_gua_from_it(lab: &mut Lab) -> anyhow::Result<()> {
    let booted = boot_pppoe(
        lab,
        &PppoeServerConfig::isp("wan0", Auth::Chap),
        VM_PPPOE_PD,
    )?;
    isp_delegates_over(lab, &booted)?;
    let c = lab.console()?;
    let bound = c.wait_for(&mut Cursor::default(), &re(BOUND), Duration::from_secs(20))?;
    let prefix: Ipv6Net = group(&bound, 0)?.parse()?;
    ensure!(
        PD_POOL_A.parse::<Ipv6Net>()?.contains(&prefix),
        "{prefix} from the ISP's pool"
    );
    let lan0 = openfeo_reconcile::lan6::subnet(prefix, 1).context("lan0's /64")?;
    lan_host_takes(lab, lan0)?;
    let body = "openfeo isp target over a delegation over ppp";
    let _server = http_target(lab, &lab.isp0, "2001:db8:ffff::1", 8080, body)?;
    ensure!(fetch(&lab.lan0, "[2001:db8:ffff::1]:8080")? == body);
    no_password_on_the_console(lab, "wan0")
}

/// A reboot over PPP: a fresh session (the old one lingers at the ISP until its echoes fail, so
/// the new one is another unit there), the ISP's IPv6 moved to the new unit, and the same prefix
/// delegated again.
fn a_reboot_comes_back_with_a_fresh_session_and_the_same_prefix(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let booted = boot_pppoe(
        lab,
        &PppoeServerConfig::isp("wan0", Auth::Chap),
        VM_PPPOE_PD,
    )?;
    let old_ppp = isp_delegates_over(lab, &booted)?;
    let c = lab.console()?;
    let mut reset_at = Cursor::default();
    let bound = c.wait_for(&mut reset_at, &re(BOUND), Duration::from_secs(20))?;
    let before: Ipv6Net = group(&bound, 0)?.parse()?;
    lab.qmp()?.system_reset()?;
    let c = lab.console()?;
    // `ready` and the new session come in either order after the reset.
    c.wait_for(&mut { reset_at }, &re(READY), BOOT_TIMEOUT)?;
    let mut after_reset = reset_at;
    let session = c.wait_for(&mut after_reset, &re(SESSION), BOOT_TIMEOUT)?;
    let id = u16::from_str_radix(&group(&session, 0)?, 16)?;
    ensure!(
        id != booted.session_id,
        "a fresh session, not {id:#06x} again"
    );
    let mut ppp = lab.isp_ppp_ifname("wan0", SOON)?;
    let deadline = std::time::Instant::now() + SOON;
    while ppp == old_ppp {
        ensure!(
            std::time::Instant::now() < deadline,
            "no new unit at the ISP"
        );
        std::thread::sleep(Duration::from_millis(200));
        ppp = lab.isp_ppp_ifname("wan0", SOON)?;
    }
    lab.daemons
        .retain(|daemon| daemon.name != format!("radvd-{old_ppp}"));
    lab.stop_kea6();
    let c = lab.console()?;
    let ipv6cp = c.wait_for(&mut reset_at, &re(IPV6CP_UP), SOON)?;
    let rebooted = Booted {
        cur: after_reset,
        session_id: id,
        address: booted.address,
        local_iid: parse_iid(&group(&ipv6cp, 0)?)?,
    };
    isp_delegates_over(lab, &rebooted)?;
    let c = lab.console()?;
    let mut since_reset = reset_at;
    let bound = c.wait_for(&mut since_reset, &re(BOUND), Duration::from_secs(30))?;
    let after: Ipv6Net = group(&bound, 0)?.parse()?;
    ensure!(
        after == before,
        "the same prefix after the reboot: {before} then {after}"
    );
    no_password_on_the_console(lab, "wan0")
}

/// The access concentrator ends the session itself (SIGTERM: `pppd` sends Terminate-Request and
/// the server a PADT): the console says so with the ladder's first wait, never as a task
/// failure, and a new session follows once the server is back (SPEC §12's M3 row).
fn the_access_concentrator_ending_the_session_is_reported_and_retried(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let server = PppoeServerConfig::isp("wan0", Auth::Chap);
    let booted = boot_pppoe(lab, &server, VM_PPPOE)?;
    ensure!(lab.stop_pppoe_server(), "a server was running");
    let c = lab.console()?;
    let mut cur = booted.cur;
    let down = c.wait_for(&mut cur, &re(DOWN), SOON)?;
    let cause = group(&down, 0)?;
    ensure!(
        cause == "terminated by peer"
            || cause == "padt from ac"
            || cause.starts_with("session lost"),
        "the concentrator's end, not a keepalive or a failure: {:?}",
        down.line
    );
    ensure!(
        group(&down, 2)? == "1",
        "the first retry waits 1 s: {:?}",
        down.line
    );
    lab.start_pppoe_server(&server)?;
    let c = lab.console()?;
    c.wait_for(&mut cur, &re(SESSION), Duration::from_secs(30))?;
    c.wait_for(&mut cur, &re(IPCP_UP), SOON)?;
    ensure!(
        c.count(&re(r"task pppoe-wan0 (failed|panicked|restart)")) == 0,
        "the supervisor saw no failure"
    );
    no_password_on_the_console(lab, "wan0")
}
