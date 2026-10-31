// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DNS forwarder driver (`openfeo-net`) against real peers inside the rootless sandbox, no
//! QEMU: a veth pair whose far end is the LAN host (where `dig` runs), another whose far end is
//! the ISP (where dnsmasq answers for `isp.example`), and the driver here on the near ends with
//! the lab's `[dns]` settings. `harness = false`: this binary is its own runner; an optional
//! first argument filters scenarios by substring.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use openfeo_harness::daemons::{self, Daemon, ISP_TXT_RECORDS};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::{self, DigAnswer};
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_net::dns::{DnsDriver, DnsDriverConfig};
use openfeo_proto_dns::forwarder::{Config, Event, LocalRecord};
use tokio::runtime::Runtime;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "local_names_resolve_authoritatively_and_never_leave",
        run: local_names_resolve_authoritatively_and_never_leave,
    },
    Scenario {
        name: "isp_names_resolve_through_the_upstream_once_and_then_from_the_cache",
        run: isp_names_resolve_through_the_upstream_once_and_then_from_the_cache,
    },
    Scenario {
        name: "negative_answers_are_cached",
        run: negative_answers_are_cached,
    },
    Scenario {
        name: "big_answers_truncate_over_udp_and_arrive_whole_over_tcp",
        run: big_answers_truncate_over_udp_and_arrive_whole_over_tcp,
    },
    Scenario {
        name: "rebinding_answers_are_refused_unless_allowed",
        run: rebinding_answers_are_refused_unless_allowed,
    },
    Scenario {
        name: "a_dead_upstream_is_skipped_after_one_timeout",
        run: a_dead_upstream_is_skipped_after_one_timeout,
    },
    Scenario {
        name: "reconfiguration_takes_effect_live",
        run: reconfiguration_takes_effect_live,
    },
    Scenario {
        name: "the_wan_side_is_not_served",
        run: the_wan_side_is_not_served,
    },
    Scenario {
        name: "without_upstreams_local_names_still_resolve",
        run: without_upstreams_local_names_still_resolve,
    },
    Scenario {
        name: "the_box_can_use_its_own_resolver_on_loopback",
        run: the_box_can_use_its_own_resolver_on_loopback,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    // `OPENFEO_TRACE=1` shows the driver's debug lines.
    if std::env::var_os("OPENFEO_TRACE").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
            .with_writer(std::io::stderr)
            .init();
    }
    let filter = std::env::args().nth(1);
    run_all(SCENARIOS, filter.as_deref())
}

const LAN_IF: &str = "n0";
const LAN_HOST_IF: &str = "n1";
const WAN_IF: &str = "u0";
const UPSTREAM_IF: &str = "u1";
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
const WAN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const UPSTREAM: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const DEAD_UPSTREAM: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);
/// How long one `dig` may take in all, its own retries included.
const LOOKUP: Duration = Duration::from_secs(5);
/// How long a scenario's serving loop may run.
const SCENARIO: Duration = Duration::from_secs(30);

/// Two veth pairs: the LAN host on `n1` in its own namespace, dnsmasq on `u1` in another, the
/// driver here on `n0` and `u0`. Fields drop in order: the daemon, the namespaces, then the
/// pairs.
struct Rig {
    dnsmasq: Daemon,
    lan_host: NetNs,
    upstream: NetNs,
}

impl Rig {
    fn create(lab: &Lab) -> anyhow::Result<Self> {
        for ifname in [LAN_IF, WAN_IF] {
            let _ = netns::ip(&["link", "del", ifname]);
        }
        netns::ip(&[
            "link",
            "add",
            LAN_IF,
            "type",
            "veth",
            "peer",
            "name",
            LAN_HOST_IF,
        ])?;
        netns::ip(&[
            "link",
            "add",
            WAN_IF,
            "type",
            "veth",
            "peer",
            "name",
            UPSTREAM_IF,
        ])?;
        let lan_host = NetNs::create(&format!("{}-lanhost", lab.name()))?;
        let upstream = NetNs::create(&format!("{}-upstream", lab.name()))?;
        netns::ip(&["link", "set", LAN_HOST_IF, "netns", &lan_host.name])?;
        netns::ip(&["link", "set", UPSTREAM_IF, "netns", &upstream.name])?;
        netns::ip(&["addr", "add", &format!("{ROUTER}/24"), "dev", LAN_IF])?;
        netns::ip(&["link", "set", LAN_IF, "up"])?;
        netns::ip(&["addr", "add", &format!("{WAN}/24"), "dev", WAN_IF])?;
        netns::ip(&["link", "set", WAN_IF, "up"])?;
        lan_host.ip(&["addr", "add", &format!("{LAN_HOST}/24"), "dev", LAN_HOST_IF])?;
        lan_host.ip(&["link", "set", LAN_HOST_IF, "up"])?;
        upstream.ip(&["addr", "add", &format!("{UPSTREAM}/24"), "dev", UPSTREAM_IF])?;
        upstream.ip(&["link", "set", UPSTREAM_IF, "up"])?;
        let dnsmasq = daemons::dnsmasq(&upstream, UPSTREAM_IF, &lab.run_dir)?;
        dnsmasq.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("started, version")?,
            Duration::from_secs(10),
        )?;
        Ok(Rig {
            dnsmasq,
            lan_host,
            upstream,
        })
    }

    /// The lab's `[dns]` settings, as the router would run them with the `nas` reservation and
    /// a `pc` lease.
    fn config() -> anyhow::Result<Config> {
        Ok(Config {
            upstreams: vec![UPSTREAM],
            domain: "home.arpa".parse().context("a name")?,
            router_name: Some("openfeo.home.arpa".parse().context("a name")?),
            router_addrs: vec![ROUTER],
            lan_subnets: vec!["192.168.1.0/24".parse().context("a subnet")?],
            local: vec![
                LocalRecord {
                    name: "nas.home.arpa".parse().context("a name")?,
                    addr: Ipv4Addr::new(192, 168, 1, 10),
                },
                LocalRecord {
                    name: "pc.home.arpa".parse().context("a name")?,
                    addr: Ipv4Addr::new(192, 168, 1, 120),
                },
            ],
            rebind_allow: vec!["allowed.isp.example".parse().context("a name")?],
            cache_capacity: 64,
        })
    }

    fn driver(rt: &Runtime, config: Config) -> anyhow::Result<DnsDriver> {
        rt.block_on(async {
            DnsDriver::new(DnsDriverConfig {
                listeners: vec![LAN_IF.to_owned()],
                loopback: true,
                forwarder: config,
                seed: 0x5eed,
            })
            .context("start the DNS driver")
        })
    }

    /// `dig <name> <qtype>` at the router from the LAN host.
    fn dig(&self, name: &str, qtype: &str, extra: &[&str]) -> anyhow::Result<DigAnswer> {
        lanclient::dig(&self.lan_host, ROUTER, name, qtype, extra, LOOKUP)
    }

    /// How many queries dnsmasq has logged matching `pattern`.
    fn upstream_queries(&self, pattern: &str) -> anyhow::Result<usize> {
        Ok(self.dnsmasq.log.count(&Regex::new(pattern)?))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for ifname in [LAN_IF, WAN_IF] {
            let _ = netns::ip(&["link", "del", ifname]);
        }
    }
}

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Step the driver while `client` runs on another thread; once the client is done, drain the
/// driver for a moment (late events trail the client's exit) and return both.
fn serve_while<'a, T: Send + 'a>(
    rt: &Runtime,
    driver: &mut DnsDriver,
    client: impl FnOnce() -> anyhow::Result<T> + Send + 'a,
) -> anyhow::Result<(Vec<Event>, T)> {
    thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let handle = scope.spawn(move || {
            let result = client();
            let _ = done_tx.send(());
            result
        });
        let mut events = Vec::new();
        let deadline = Instant::now() + SCENARIO;
        let mut drain_until: Option<Instant> = None;
        loop {
            let step = rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(50), driver.step()).await
            });
            match step {
                Ok(Ok(new)) => events.extend(new),
                Ok(Err(err)) => return Err(err.into()),
                Err(_elapsed) => {}
            }
            if drain_until.is_none() && done_rx.try_recv().is_ok() {
                drain_until = Some(Instant::now() + Duration::from_millis(200));
            }
            if drain_until.is_some_and(|until| Instant::now() >= until) {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "the serving loop timed out; events so far: {events:?}"
            );
        }
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))??;
        Ok((events, result))
    })
}

/// One lookup from the LAN host while the driver serves; the answer and the events.
fn lookup(
    rt: &Runtime,
    driver: &mut DnsDriver,
    rig: &Rig,
    name: &str,
    qtype: &str,
    extra: &[&str],
) -> anyhow::Result<(Vec<Event>, DigAnswer)> {
    serve_while(rt, driver, || rig.dig(name, qtype, extra))
}

/// A lookup that must come back `NOERROR` with exactly one A record of `addr`.
fn expect_a(answer: &DigAnswer, name: &str, addr: &str) -> anyhow::Result<()> {
    ensure!(
        answer.status == "NOERROR",
        "{name}: status {} in {answer:?}",
        answer.status
    );
    let addrs: Vec<&str> = answer
        .answers
        .iter()
        .filter(|row| row.2 == "A")
        .map(|row| row.3.as_str())
        .collect();
    ensure!(addrs == [addr], "{name}: answers {:?}", answer.answers);
    Ok(())
}

fn has_flag(answer: &DigAnswer, flag: &str) -> bool {
    answer.flags.iter().any(|f| f == flag)
}

fn local_names_resolve_authoritatively_and_never_leave(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let (_, nas) = lookup(&rt, &mut driver, &rig, "nas.home.arpa", "A", &[])?;
    expect_a(&nas, "nas.home.arpa", "192.168.1.10")?;
    ensure!(
        has_flag(&nas, "aa"),
        "nas.home.arpa is not authoritative: {nas:?}"
    );
    ensure!(
        nas.answers[0].1 == 60,
        "nas.home.arpa TTL {}",
        nas.answers[0].1
    );
    let (_, ptr) = lookup(
        &rt,
        &mut driver,
        &rig,
        "10.1.168.192.in-addr.arpa",
        "PTR",
        &[],
    )?;
    ensure!(
        ptr.answers
            .iter()
            .any(|row| row.2 == "PTR" && row.3 == "nas.home.arpa."),
        "reverse lookup: {ptr:?}"
    );
    let (_, router) = lookup(&rt, &mut driver, &rig, "openfeo.home.arpa", "A", &[])?;
    expect_a(&router, "openfeo.home.arpa", "192.168.1.1")?;
    let (_, missing) = lookup(&rt, &mut driver, &rig, "printer.home.arpa", "A", &[])?;
    ensure!(
        missing.status == "NXDOMAIN" && has_flag(&missing, "aa"),
        "printer.home.arpa: {missing:?}"
    );
    ensure!(
        rig.upstream_queries(r"auth\[")? == 0,
        "a local name reached the upstream: {:?}",
        rig.dnsmasq.log.tail(5)
    );
    Ok(())
}

fn isp_names_resolve_through_the_upstream_once_and_then_from_the_cache(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let (_, first) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &[])?;
    expect_a(&first, "www.isp.example", "198.51.100.10")?;
    ensure!(
        has_flag(&first, "ra") && !has_flag(&first, "aa"),
        "a forwarded answer's flags: {first:?}"
    );
    let upstream = r"auth\[A\] www\.isp\.example";
    ensure!(
        rig.upstream_queries(upstream)? == 1,
        "upstream queries: {:?}",
        rig.dnsmasq.log.tail(5)
    );
    let (_, second) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &[])?;
    expect_a(&second, "www.isp.example", "198.51.100.10")?;
    ensure!(
        rig.upstream_queries(upstream)? == 1,
        "the second lookup went upstream: {:?}",
        rig.dnsmasq.log.tail(5)
    );
    ensure!(
        second.answers[0].1 <= first.answers[0].1,
        "the cached TTL {} exceeds the first {}",
        second.answers[0].1,
        first.answers[0].1
    );
    ensure!(
        driver.cache_stats().hits == 1,
        "cache stats: {:?}",
        driver.cache_stats()
    );
    Ok(())
}

fn negative_answers_are_cached(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    for _ in 0..2 {
        let (_, answer) = lookup(&rt, &mut driver, &rig, "nx.isp.example", "A", &[])?;
        ensure!(answer.status == "NXDOMAIN", "nx.isp.example: {answer:?}");
    }
    ensure!(
        rig.upstream_queries(r"auth\[A\] nx\.isp\.example")? == 1,
        "the negative answer was not cached: {:?}",
        rig.dnsmasq.log.tail(5)
    );
    Ok(())
}

fn big_answers_truncate_over_udp_and_arrive_whole_over_tcp(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    // dig with a 512-byte buffer sees TC from the forwarder and comes back over TCP by itself;
    // the forwarder itself saw TC from the upstream (the answer is over 1232 bytes) and came
    // back to it over TCP.
    let (_, big) = lookup(
        &rt,
        &mut driver,
        &rig,
        "big.isp.example",
        "TXT",
        &["+bufsize=512"],
    )?;
    ensure!(big.status == "NOERROR", "big.isp.example: {big:?}");
    ensure!(
        !has_flag(&big, "tc"),
        "the final answer is still truncated: {big:?}"
    );
    let txt = big.answers.iter().filter(|row| row.2 == "TXT").count();
    ensure!(
        txt == ISP_TXT_RECORDS,
        "{txt} TXT records of {ISP_TXT_RECORDS}: {big:?}"
    );
    ensure!(
        rig.upstream_queries(r"auth\[TXT\] big\.isp\.example")? >= 2,
        "the upstream saw fewer than two queries (UDP, then TCP): {:?}",
        rig.dnsmasq.log.tail(8)
    );
    let (_, tcp) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &["+tcp"])?;
    expect_a(&tcp, "www.isp.example over TCP", "198.51.100.10")?;
    Ok(())
}

fn rebinding_answers_are_refused_unless_allowed(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let (events, evil) = lookup(&rt, &mut driver, &rig, "evil.isp.example", "A", &[])?;
    ensure!(evil.status == "REFUSED", "evil.isp.example: {evil:?}");
    let dropped = events
        .iter()
        .filter(|event| {
            matches!(event, Event::RebindDropped { name, addr, client }
                if name.to_string() == "evil.isp.example."
                    && *addr == Ipv4Addr::new(192, 168, 1, 5)
                    && *client == LAN_HOST)
        })
        .count();
    ensure!(dropped == 1, "rebind events: {events:?}");
    let (_, allowed) = lookup(&rt, &mut driver, &rig, "allowed.isp.example", "A", &[])?;
    expect_a(&allowed, "allowed.isp.example", "192.168.1.6")?;
    Ok(())
}

fn a_dead_upstream_is_skipped_after_one_timeout(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(
        &rt,
        Config {
            upstreams: vec![DEAD_UPSTREAM, UPSTREAM],
            ..Rig::config()?
        },
    )?;
    let started = Instant::now();
    // dig's own timeout must outlast the forwarder's 2 s attempt on the dead server.
    let (events, first) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &["+time=4"])?;
    let took = started.elapsed();
    expect_a(&first, "www.isp.example", "198.51.100.10")?;
    ensure!(
        took < Duration::from_millis(3_500),
        "the first lookup took {took:?}"
    );
    ensure!(
        events.contains(&Event::UpstreamDown(DEAD_UPSTREAM)),
        "events: {events:?}"
    );
    let started = Instant::now();
    let (_, second) = lookup(&rt, &mut driver, &rig, "allowed.isp.example", "A", &[])?;
    let took = started.elapsed();
    expect_a(&second, "allowed.isp.example", "192.168.1.6")?;
    ensure!(
        took < Duration::from_millis(500),
        "the dead server was tried again: {took:?}"
    );
    Ok(())
}

fn reconfiguration_takes_effect_live(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(
        &rt,
        Config {
            upstreams: vec![DEAD_UPSTREAM],
            ..Rig::config()?
        },
    )?;
    let (_, failed) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &["+time=4"])?;
    ensure!(
        failed.status == "SERVFAIL",
        "with a dead upstream alone: {failed:?}"
    );
    let events = driver.configure(Rig::config()?);
    ensure!(
        events.contains(&Event::Configured {
            upstreams: 1,
            local: 2
        }),
        "configure events: {events:?}"
    );
    let (_, answered) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &[])?;
    expect_a(
        &answered,
        "www.isp.example after reconfiguration",
        "198.51.100.10",
    )?;
    Ok(())
}

fn the_wan_side_is_not_served(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let (_, from_wan) = serve_while(&rt, &mut driver, || {
        Ok(lanclient::dig(
            &rig.upstream,
            WAN,
            "www.isp.example",
            "A",
            &[],
            LOOKUP,
        ))
    })?;
    ensure!(from_wan.is_err(), "the WAN side was answered: {from_wan:?}");
    ensure!(
        driver.stats().queries == 0,
        "the driver saw the WAN-side query: {:?}",
        driver.stats()
    );
    Ok(())
}

fn without_upstreams_local_names_still_resolve(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let events = driver.configure(Config {
        upstreams: Vec::new(),
        ..Rig::config()?
    });
    ensure!(
        events.iter().filter(|e| **e == Event::NoUpstreams).count() == 1,
        "configure events: {events:?}"
    );
    let (_, nas) = lookup(&rt, &mut driver, &rig, "nas.home.arpa", "A", &[])?;
    expect_a(&nas, "nas.home.arpa", "192.168.1.10")?;
    let started = Instant::now();
    let (events, remote) = lookup(&rt, &mut driver, &rig, "www.isp.example", "A", &[])?;
    let took = started.elapsed();
    ensure!(remote.status == "SERVFAIL", "www.isp.example: {remote:?}");
    ensure!(took < Duration::from_millis(500), "SERVFAIL took {took:?}");
    ensure!(
        !events.contains(&Event::NoUpstreams),
        "no upstreams was announced again: {events:?}"
    );
    Ok(())
}

/// The forwarder also answers on loopback, for the box's own lookups (time server names, later
/// TLS and updates): `dig @127.0.0.1` from the router's own namespace, and the resolver stub the
/// time task uses.
fn the_box_can_use_its_own_resolver_on_loopback(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Rig::config()?)?;
    let (_, answer) = serve_while(&rt, &mut driver, || {
        let output = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "+time=2",
                "+tries=1",
                "+noall",
                "+comments",
                "+answer",
                "www.isp.example",
                "A",
            ])
            .output()
            .context("run dig")?;
        lanclient::parse_dig(&String::from_utf8_lossy(&output.stdout))
    })?;
    expect_a(&answer, "www.isp.example via 127.0.0.1", "198.51.100.10")?;
    let (_, addrs) = serve_while(&rt, &mut driver, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let name: openfeo_proto_dns::Name = "www.isp.example".parse()?;
        runtime
            .block_on(openfeo_net::resolve::lookup_a(
                &name,
                openfeo_net::resolve::LOCAL_RESOLVER,
                7,
            ))
            .context("lookup_a through the loopback listener")
    })?;
    ensure!(
        addrs == vec![Ipv4Addr::new(198, 51, 100, 10)],
        "lookup_a answered {addrs:?}"
    );
    ensure!(
        rig.upstream_queries(r"auth\[A\] www\.isp\.example")? == 1,
        "the second lookup went upstream: {:?}",
        rig.dnsmasq.log.tail(5)
    );
    Ok(())
}
