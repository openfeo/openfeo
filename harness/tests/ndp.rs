// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The neighbour-discovery drivers (`openfeo-net`) against real peers inside the rootless
//! sandbox, no QEMU: the WAN client on `w0` learns from radvd on the far end `w1` of one veth
//! pair, and the LAN server on `l0` configures the far end `l1` of another, whose namespace's
//! own kernel is the SLAAC reference client and where `rdisc6` reads the advertised options.
//! `harness = false`: this binary is its own runner; an optional first argument filters
//! scenarios by substring.

use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use ipnet::Ipv6Net;
use openfeo_harness::daemons::{self, Daemon, RadvdConfig};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::{self, Rdisc6Report};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, Skip, run_all};
use openfeo_net::ndp::{ALL_NODES, ALL_ROUTERS, NdpSocket, Role};
use openfeo_proto_ndp::client::{self, Client, Learned};
use openfeo_proto_ndp::server::{self, Server};
use tokio::runtime::Runtime;
use tokio::sync::watch;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "the_client_learns_router_prefix_mtu_rdnss_and_dnssl_from_radvd",
        run: the_client_learns_router_prefix_mtu_rdnss_and_dnssl_from_radvd,
    },
    Scenario {
        name: "the_client_drops_the_router_when_radvd_stops_and_on_lifetime_expiry",
        run: the_client_drops_the_router_when_radvd_stops_and_on_lifetime_expiry,
    },
    Scenario {
        name: "the_server_configures_a_kernel_host_and_rdisc6_reads_its_options",
        run: the_server_configures_a_kernel_host_and_rdisc6_reads_its_options,
    },
    Scenario {
        name: "a_solicitation_is_answered_within_the_delay_or_the_floor",
        run: a_solicitation_is_answered_within_the_delay_or_the_floor,
    },
    Scenario {
        name: "a_lifetime_change_goes_out_at_once",
        run: a_lifetime_change_goes_out_at_once,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

const WAN_IF: &str = "w0";
const WAN_PEER_IF: &str = "w1";
const LAN_IF: &str = "l0";
const LAN_PEER_IF: &str = "l1";
/// The LAN the server advertises and the router's address in it.
const LAN_PREFIX: &str = "2001:db8:1:222::/64";
/// [`LAN_PREFIX`] as the server takes it.
const LAN_NET: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0xdb8, 1, 0x222, 0, 0, 0, 0), 64);
const ROUTER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0x222, 0, 0, 0, 1);
/// How long a scenario waits for the kernel or the far end.
const SOON: Duration = Duration::from_secs(10);

/// Two veth pairs: radvd's namespace on the far end of the WAN pair, the SLAAC host's on the
/// far end of the LAN pair. Fields drop in order: the daemon, the namespaces, then the pairs.
struct Rig {
    radvd: Option<Daemon>,
    isp: NetNs,
    host: NetNs,
}

impl Rig {
    fn create(lab: &Lab) -> anyhow::Result<Self> {
        for ifname in [WAN_IF, LAN_IF] {
            let _ = netns::ip(&["link", "del", ifname]);
        }
        for (near, far) in [(WAN_IF, WAN_PEER_IF), (LAN_IF, LAN_PEER_IF)] {
            netns::ip(&["link", "add", near, "type", "veth", "peer", "name", far])?;
        }
        let isp = NetNs::create(&format!("{}-isp", lab.name()))?;
        let host = NetNs::create(&format!("{}-host", lab.name()))?;
        netns::ip(&["link", "set", WAN_PEER_IF, "netns", &isp.name])?;
        netns::ip(&["link", "set", LAN_PEER_IF, "netns", &host.name])?;
        netns::ip(&[
            "-6",
            "addr",
            "add",
            &format!("{ROUTER6}/64"),
            "dev",
            LAN_IF,
            "nodad",
        ])?;
        netns::ip(&["link", "set", WAN_IF, "up"])?;
        netns::ip(&["link", "set", LAN_IF, "up"])?;
        isp.ip(&[
            "-6",
            "addr",
            "add",
            &format!("{}/64", daemons::ISP_RESOLVER6),
            "dev",
            WAN_PEER_IF,
            "nodad",
        ])?;
        isp.ip(&["link", "set", WAN_PEER_IF, "up"])?;
        let mut forwarding = isp.command("sh")?;
        forwarding.args(["-c", "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"]);
        let _ = netns::run(&mut forwarding);
        host.ip(&["link", "set", LAN_PEER_IF, "up"])?;
        Ok(Rig {
            radvd: None,
            isp,
            host,
        })
    }

    fn start_radvd(&mut self, lab: &Lab, config: &RadvdConfig) -> anyhow::Result<()> {
        let radvd = daemons::radvd(&self.isp, config, &lab.run_dir)?;
        radvd.log.wait_for(
            &mut openfeo_harness::lines::Cursor::default(),
            &openfeo_harness::lines::Regex::new("version .* started")?,
            SOON,
        )?;
        self.radvd = Some(radvd);
        Ok(())
    }

    /// The link-local address of the far end of the WAN pair: what the client should learn as
    /// its router.
    fn isp_link_local(&self) -> anyhow::Result<Ipv6Addr> {
        let text = self
            .isp
            .ip(&["-6", "addr", "show", "dev", WAN_PEER_IF, "scope", "link"])?;
        text.split_whitespace()
            .skip_while(|word| *word != "inet6")
            .nth(1)
            .and_then(|addr| addr.split('/').next())
            .and_then(|addr| addr.parse().ok())
            .context("the ISP end's link-local address")
    }

    /// Until the host end's link-local address is past duplicate address detection, which
    /// `rdisc6` needs as its source.
    fn wait_for_host_link_local(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + SOON;
        loop {
            let text =
                self.host
                    .ip(&["-6", "addr", "show", "dev", LAN_PEER_IF, "scope", "link"])?;
            if text.contains("fe80:") && !text.contains("tentative") {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "no link-local on {LAN_PEER_IF}: {text}"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// `rdisc6` on the host's end of the LAN pair.
    fn rdisc6(&self) -> anyhow::Result<Rdisc6Report> {
        lanclient::rdisc6(&self.host, LAN_PEER_IF, Duration::from_secs(2))
    }

    /// The host end's global addresses and default route, as `ip` shows them.
    fn host_ipv6(&self) -> anyhow::Result<(String, String)> {
        Ok((
            self.host
                .ip(&["-6", "addr", "show", "dev", LAN_PEER_IF, "scope", "global"])?,
            self.host.ip(&["-6", "route", "show", "default"])?,
        ))
    }
}

/// The `ndisc6` package, or a skip.
fn require_rdisc6() -> anyhow::Result<()> {
    let found = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("rdisc6").is_file()));
    if found {
        Ok(())
    } else {
        Err(Skip("rdisc6 (package ndisc6) is not installed".to_owned()).into())
    }
}

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The WAN client on `w0`, driven until `done` holds for what it learned or `timeout` passes;
/// what it learned last.
fn learn(
    rt: &Runtime,
    mut done: impl FnMut(&Learned) -> bool,
    timeout: Duration,
) -> anyhow::Result<Learned> {
    let (ifindex, mac) = lanclient::link_info(WAN_IF)?;
    rt.block_on(async {
        let socket = NdpSocket::open(ifindex, WAN_IF, Role::Client)?;
        let mut client = Client::new(client::Config {
            ifname: WAN_IF.to_owned(),
            secret: [7; 16],
            mac: Some(mac),
        });
        let start = Instant::now();
        let deadline = start + timeout;
        let mut learned = Learned::default();
        let mut outputs = client.handle(client::Input::LinkUp, 0);
        let mut buf = vec![0u8; 1500];
        loop {
            for output in outputs.drain(..) {
                match output {
                    client::Output::Solicit(bytes) => {
                        let _ = socket.send(ALL_ROUTERS, &bytes);
                    }
                    client::Output::Learned(l) => learned = l,
                    client::Output::Note(_) => {}
                }
            }
            if done(&learned) {
                return Ok(learned);
            }
            ensure!(
                Instant::now() < deadline,
                "timed out; learned so far: {learned:?}"
            );
            let timer = client
                .next_timeout()
                .map_or(deadline, |at| start + Duration::from_millis(at))
                .min(deadline);
            tokio::select! {
                received = socket.recv(&mut buf) => {
                    let received = received?;
                    outputs = client.handle(
                        client::Input::Advertisement {
                            from: received.from,
                            hop_limit: received.hop_limit,
                            bytes: buf[..received.len].to_vec(),
                        },
                        millis(start),
                    );
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(timer)) => {
                    outputs = client.handle(client::Input::Timeout, millis(start));
                }
            }
        }
    })
}

fn server_config(lifetime: u16, mac: [u8; 6]) -> server::Config {
    server::Config {
        prefixes: vec![server::Pio {
            prefix: LAN_NET,
            valid: server::Lifetime::Fixed(server::PIO_VALID),
            preferred: server::Lifetime::Fixed(server::PIO_PREFERRED),
        }],
        mac,
        rdnss: vec![ROUTER6],
        mtu: Some(1500),
        domain: "home.arpa".to_owned(),
        router_lifetime: lifetime,
        other: true,
        routes: Vec::new(),
    }
}

/// The LAN server on `l0`: started, then stepped while `client` runs on another thread (and for
/// a moment after), reconfigured whenever `config` changes; the client's result.
fn serve_while<T: Send>(
    rt: &Runtime,
    config: &mut watch::Receiver<server::Config>,
    seed: u64,
    client: impl FnOnce() -> anyhow::Result<T> + Send,
) -> anyhow::Result<T> {
    let (ifindex, _mac) = lanclient::link_info(LAN_IF)?;
    thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let handle = scope.spawn(move || {
            let result = client();
            let _ = done_tx.send(());
            result
        });
        rt.block_on(async {
            let socket = NdpSocket::open(ifindex, LAN_IF, Role::Server)?;
            let mut server = Server::new(config.borrow_and_update().clone(), seed);
            let start = Instant::now();
            let mut outputs = server.handle(server::Input::Start, 0);
            let mut buf = vec![0u8; 1500];
            let mut drain_until: Option<Instant> = None;
            loop {
                for output in outputs.drain(..) {
                    if let server::Output::Advertise(bytes) = output {
                        socket.send(ALL_NODES, &bytes)?;
                    }
                }
                if drain_until.is_none() && done_rx.try_recv().is_ok() {
                    drain_until = Some(Instant::now() + Duration::from_millis(200));
                }
                if drain_until.is_some_and(|until| Instant::now() >= until) {
                    break;
                }
                let timer = server
                    .next_timeout()
                    .map_or_else(
                        || Instant::now() + Duration::from_secs(1),
                        |at| start + Duration::from_millis(at),
                    )
                    .min(Instant::now() + Duration::from_millis(50));
                tokio::select! {
                    received = socket.recv(&mut buf) => {
                        let received = received?;
                        outputs = server.handle(
                            server::Input::Solicitation {
                                from: received.from,
                                hop_limit: received.hop_limit,
                                bytes: buf[..received.len].to_vec(),
                            },
                            millis(start),
                        );
                    }
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(timer)) => {
                        if config.has_changed().unwrap_or(false) {
                            let next = config.borrow_and_update().clone();
                            outputs = server.handle(server::Input::Configure(next), millis(start));
                        } else if server.next_timeout().is_some_and(|at| at <= millis(start)) {
                            outputs = server.handle(server::Input::Timeout, millis(start));
                        }
                    }
                }
            }
            anyhow::Ok(())
        })?;
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))?
    })
}

/// SPEC §7.3: the client learns the ISP's router, the link prefix and the address it yields,
/// the MTU, the resolver and the search domain from radvd's advertisements.
fn the_client_learns_router_prefix_mtu_rdnss_and_dnssl_from_radvd(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut rig = Rig::create(lab)?;
    let mut config = RadvdConfig::isp(WAN_PEER_IF);
    config.prefix = Some("2001:db8:ffff::/64".to_owned());
    rig.start_radvd(lab, &config)?;
    let rt = runtime()?;
    let learned = learn(
        &rt,
        |l| {
            l.router.is_some()
                && !l.addresses.is_empty()
                && !l.dns.is_empty()
                && !l.search.is_empty()
                && l.mtu.is_some()
        },
        SOON,
    )?;
    ensure!(learned.router == Some(rig.isp_link_local()?), "{learned:?}");
    ensure!(
        learned
            .addresses
            .iter()
            .any(|net| net.to_string().starts_with("2001:db8:ffff:")),
        "an address in the link prefix: {learned:?}"
    );
    ensure!(
        learned
            .on_link
            .iter()
            .any(|net| net.to_string() == "2001:db8:ffff::/64"),
        "{learned:?}"
    );
    ensure!(
        learned.dns == vec![daemons::ISP_RESOLVER6.parse::<Ipv6Addr>()?],
        "{learned:?}"
    );
    ensure!(
        learned.search == vec!["isp.example".to_owned()],
        "{learned:?}"
    );
    ensure!(learned.mtu == Some(1500), "{learned:?}");
    Ok(())
}

/// The router goes when radvd stops (its goodbye carries lifetime 0) or its lifetime lapses,
/// whichever first; the link address stays.
fn the_client_drops_the_router_when_radvd_stops_and_on_lifetime_expiry(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut rig = Rig::create(lab)?;
    let mut config = RadvdConfig::isp(WAN_PEER_IF);
    config.lifetime = 4;
    config.prefix = Some("2001:db8:ffff::/64".to_owned());
    rig.start_radvd(lab, &config)?;
    let rt = runtime()?;
    // One client across the whole story: once it has the router and the link address, radvd is
    // stopped (its goodbye carries lifetime 0; the 4 s lifetime is the backstop), and the client
    // must end with no router and the address still there.
    let mut stopped_at: Option<Instant> = None;
    let learned = learn(
        &rt,
        |l| {
            if stopped_at.is_none() && l.router.is_some() && !l.addresses.is_empty() {
                rig.radvd = None;
                stopped_at = Some(Instant::now());
                return false;
            }
            stopped_at.is_some() && l.router.is_none() && !l.addresses.is_empty()
        },
        Duration::from_secs(20),
    )?;
    let since = stopped_at.context("radvd was stopped")?.elapsed();
    ensure!(
        learned.router.is_none() && !learned.addresses.is_empty(),
        "{learned:?}"
    );
    ensure!(
        since < Duration::from_secs(6),
        "the router lingered {since:?} after radvd stopped"
    );
    Ok(())
}

/// The server's advertisement configures the host end's kernel (an address in the LAN's /64,
/// a default via our link-local) and carries the resolver and the search domain `rdisc6` reads.
fn the_server_configures_a_kernel_host_and_rdisc6_reads_its_options(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    require_rdisc6()?;
    let rig = Rig::create(lab)?;
    let (_, mac) = lanclient::link_info(LAN_IF)?;
    let (_tx, mut rx) = watch::channel(server_config(1800, mac));
    let rt = runtime()?;
    let (addrs, routes, report) = serve_while(&rt, &mut rx, 1, || {
        let deadline = Instant::now() + SOON;
        loop {
            let (addrs, routes) = rig.host_ipv6()?;
            if addrs.contains("2001:db8:1:222:") && routes.contains("default via fe80::") {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "host not configured: {addrs} {routes}"
            );
            thread::sleep(Duration::from_millis(200));
        }
        let report = rig.rdisc6()?;
        let (addrs, routes) = rig.host_ipv6()?;
        anyhow::Ok((addrs, routes, report))
    })?;
    ensure!(addrs.contains("2001:db8:1:222:"), "{addrs}");
    ensure!(routes.contains("default via fe80::"), "{routes}");
    ensure!(report.lifetime == Some(1800), "{report:?}");
    ensure!(report.prefixes == vec![LAN_PREFIX.to_owned()], "{report:?}");
    ensure!(report.rdnss == vec![ROUTER6], "{report:?}");
    ensure!(report.dnssl == vec!["home.arpa".to_owned()], "{report:?}");
    ensure!(report.mtu == Some(1500), "{report:?}");
    Ok(())
}

/// A solicitation is answered within half a second (RFC 4861 §6.2.6), or, when a multicast
/// advertisement went out less than three seconds before, as soon as that floor passes:
/// `rdisc6`, which solicits, is back within the floor plus the delay.
fn a_solicitation_is_answered_within_the_delay_or_the_floor(lab: &mut Lab) -> anyhow::Result<()> {
    require_rdisc6()?;
    let rig = Rig::create(lab)?;
    let (_, mac) = lanclient::link_info(LAN_IF)?;
    let (_tx, mut rx) = watch::channel(server_config(1800, mac));
    let rt = runtime()?;
    let took = serve_while(&rt, &mut rx, 2, || {
        rig.wait_for_host_link_local()?;
        let start = Instant::now();
        let report = lanclient::rdisc6(&rig.host, LAN_PEER_IF, Duration::from_secs(4))?;
        ensure!(report.lifetime == Some(1800), "{report:?}");
        anyhow::Ok(start.elapsed())
    })?;
    ensure!(
        took < Duration::from_millis(3_600),
        "answered after {took:?}"
    );
    Ok(())
}

/// A lifetime change (the WAN lost its IPv6 route) is advertised at once: the host hears
/// lifetime 0 and drops its default route within one advertisement floor, and hears 1800 again
/// when the route is back.
fn a_lifetime_change_goes_out_at_once(lab: &mut Lab) -> anyhow::Result<()> {
    require_rdisc6()?;
    let rig = Rig::create(lab)?;
    let (_, mac) = lanclient::link_info(LAN_IF)?;
    let (tx, mut rx) = watch::channel(server_config(1800, mac));
    let rt = runtime()?;
    serve_while(&rt, &mut rx, 3, || {
        let deadline = Instant::now() + SOON;
        loop {
            let (_, routes) = rig.host_ipv6()?;
            if routes.contains("default via fe80::") {
                break;
            }
            ensure!(Instant::now() < deadline, "no default yet: {routes}");
            thread::sleep(Duration::from_millis(200));
        }
        thread::sleep(Duration::from_millis(3_200)); // past the 3 s floor after the start
        tx.send_replace(server_config(0, mac));
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let (_, routes) = rig.host_ipv6()?;
            if !routes.contains("default via fe80::") {
                break;
            }
            ensure!(Instant::now() < deadline, "the default stayed: {routes}");
            thread::sleep(Duration::from_millis(100));
        }
        let report = rig.rdisc6()?;
        ensure!(report.lifetime == Some(0), "{report:?}");
        tx.send_replace(server_config(1800, mac));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (_, routes) = rig.host_ipv6()?;
            if routes.contains("default via fe80::") {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "the default did not return: {routes}"
            );
            thread::sleep(Duration::from_millis(100));
        }
        anyhow::Ok(())
    })
}
