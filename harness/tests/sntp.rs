// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The SNTP driver (`openfeo-net`) against real peers inside the rootless sandbox, no QEMU: a
//! veth pair whose far end is the ISP (where the lab's Python SNTP server answers with a clock
//! the scenario dials), another whose far end is the LAN host (`ntpdate -q` and raw queries),
//! and the driver here on a recording clock, since the sandbox may not move the real one.
//! `harness = false`: this binary is its own runner; an optional first argument filters
//! scenarios by substring.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use openfeo_harness::daemons::{self, Daemon};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient;
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_net::clock::Recording;
use openfeo_net::sntp::{ServerSpec, SntpDriver, SntpDriverConfig};
use openfeo_proto_sntp::client::Event;
use openfeo_proto_sntp::packet::{LI_UNSYNCHRONISED, STRATUM_UNSYNCHRONISED};
use openfeo_proto_sntp::timestamp::NANOS_PER_SEC;
use tokio::runtime::Runtime;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "the_first_valid_answer_steps_the_recording_clock",
        run: the_first_valid_answer_steps_the_recording_clock,
    },
    Scenario {
        name: "small_offsets_slew_after_the_first_sync",
        run: small_offsets_slew_after_the_first_sync,
    },
    Scenario {
        name: "a_server_before_the_build_floor_is_refused",
        run: a_server_before_the_build_floor_is_refused,
    },
    Scenario {
        name: "a_silent_server_is_skipped_for_the_next",
        run: a_silent_server_is_skipped_for_the_next,
    },
    Scenario {
        name: "lan_clients_get_answers_at_stratum_plus_one",
        run: lan_clients_get_answers_at_stratum_plus_one,
    },
    Scenario {
        name: "unsynced_answers_are_marked_as_such",
        run: unsynced_answers_are_marked_as_such,
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

const WAN_IF: &str = "t0";
const SERVER_IF: &str = "t1";
const LAN_IF: &str = "c0";
const CLIENT_IF: &str = "c1";
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const WAN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const SECOND_SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const DEAD_SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);
/// The build floor of these scenarios: 2023-11-14.
const FLOOR: u64 = 1_700_000_000;
/// How long one query from the LAN host may take in all.
const LOOKUP: Duration = Duration::from_secs(6);
/// How long a scenario's serving loop may run.
const SCENARIO: Duration = Duration::from_secs(30);

/// Two veth pairs: the time server on `t1` in its own namespace, the LAN host on `c1` in
/// another, the driver here on `t0` and `c0`. Fields drop in order: the daemons, the namespaces,
/// then the pairs.
struct Rig {
    servers: Vec<Daemon>,
    timeserver: NetNs,
    client: NetNs,
}

impl Rig {
    /// The rig with the primary server at 203.0.113.1, its clock `offset_secs` from the host's.
    fn create(lab: &Lab, offset_secs: i64) -> anyhow::Result<Self> {
        for ifname in [WAN_IF, LAN_IF] {
            let _ = netns::ip(&["link", "del", ifname]);
        }
        netns::ip(&[
            "link", "add", WAN_IF, "type", "veth", "peer", "name", SERVER_IF,
        ])?;
        netns::ip(&[
            "link", "add", LAN_IF, "type", "veth", "peer", "name", CLIENT_IF,
        ])?;
        let timeserver = NetNs::create(&format!("{}-timeserver", lab.name()))?;
        let client = NetNs::create(&format!("{}-timeclient", lab.name()))?;
        netns::ip(&["link", "set", SERVER_IF, "netns", &timeserver.name])?;
        netns::ip(&["link", "set", CLIENT_IF, "netns", &client.name])?;
        netns::ip(&["addr", "add", &format!("{WAN}/24"), "dev", WAN_IF])?;
        netns::ip(&["link", "set", WAN_IF, "up"])?;
        netns::ip(&["addr", "add", &format!("{ROUTER}/24"), "dev", LAN_IF])?;
        netns::ip(&["link", "set", LAN_IF, "up"])?;
        timeserver.ip(&["addr", "add", &format!("{SERVER}/24"), "dev", SERVER_IF])?;
        timeserver.ip(&[
            "addr",
            "add",
            &format!("{SECOND_SERVER}/24"),
            "dev",
            SERVER_IF,
        ])?;
        timeserver.ip(&["link", "set", SERVER_IF, "up"])?;
        client.ip(&["addr", "add", "192.168.1.50/24", "dev", CLIENT_IF])?;
        client.ip(&["link", "set", CLIENT_IF, "up"])?;
        let mut rig = Rig {
            servers: Vec::new(),
            timeserver,
            client,
        };
        rig.start_server(SERVER, offset_secs)?;
        Ok(rig)
    }

    /// Another server on the ISP side at `addr`, its clock `offset_secs` from the host's.
    fn start_server(&mut self, addr: Ipv4Addr, offset_secs: i64) -> anyhow::Result<()> {
        let server = daemons::sntp_server(&self.timeserver, &addr.to_string(), offset_secs, 2)?;
        server.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("sntp-server listening on")?,
            Duration::from_secs(10),
        )?;
        self.servers.push(server);
        Ok(())
    }

    /// The driver on a recording clock, polling `servers`, serving `c0`.
    fn driver(rt: &Runtime, servers: Vec<Ipv4Addr>) -> anyhow::Result<SntpDriver<Recording>> {
        rt.block_on(async {
            SntpDriver::new(
                SntpDriverConfig {
                    servers: servers.into_iter().map(ServerSpec::Address).collect(),
                    learned: Vec::new(),
                    resolver: None,
                    listeners: vec![LAN_IF.to_owned()],
                    floor_unix_secs: FLOOR,
                    seed: 0x5eed,
                },
                Recording::new(),
            )
            .context("start the SNTP driver")
        })
    }

    /// How many requests the servers have logged.
    fn queries(&self) -> anyhow::Result<usize> {
        let re = Regex::new("query from")?;
        Ok(self.servers.iter().map(|s| s.log.count(&re)).sum())
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for ifname in [WAN_IF, LAN_IF] {
            let _ = netns::ip(&["link", "del", ifname]);
        }
    }
}

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Step the driver until `done` says the events so far are enough, or `timeout` passes.
fn serve_until(
    rt: &Runtime,
    driver: &mut SntpDriver<Recording>,
    done: impl Fn(&[Event]) -> bool,
    timeout: Duration,
) -> anyhow::Result<Vec<Event>> {
    let deadline = Instant::now() + timeout;
    let mut events = Vec::new();
    while !done(&events) {
        ensure!(
            Instant::now() < deadline,
            "the serving loop timed out; events so far: {events:?}"
        );
        let step = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(50), driver.step()).await
        });
        match step {
            Ok(Ok(new)) => events.extend(new),
            Ok(Err(err)) => return Err(err.into()),
            Err(_elapsed) => {}
        }
    }
    Ok(events)
}

/// Step the driver while `client` runs on another thread; once the client is done, drain the
/// driver for a moment and return both.
fn serve_while<'a, T: Send + 'a>(
    rt: &Runtime,
    driver: &mut SntpDriver<Recording>,
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

fn synced(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Synced { .. }))
}

/// Sync against the primary server once, returning the driver and the events.
fn synced_driver(
    rt: &Runtime,
    servers: Vec<Ipv4Addr>,
) -> anyhow::Result<(SntpDriver<Recording>, Vec<Event>)> {
    let mut driver = Rig::driver(rt, servers)?;
    let events = serve_until(rt, &mut driver, synced, Duration::from_secs(10))?;
    Ok((driver, events))
}

fn the_first_valid_answer_steps_the_recording_clock(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, 7_200)?;
    let rt = runtime()?;
    let (driver, events) = synced_driver(&rt, vec![SERVER])?;
    let steps = driver.clock().steps();
    ensure!(
        steps.len() == 1 && (steps[0] - 7_200 * NANOS_PER_SEC).abs() < 100_000_000,
        "steps {steps:?}; events {events:?}"
    );
    let state = driver.state();
    ensure!(
        state.synced && state.stratum == 2 && state.source == Some(SERVER),
        "{state:?}"
    );
    ensure!(
        events
            .iter()
            .any(|e| matches!(e, Event::Step { server, stratum: 2, .. } if *server == SERVER)),
        "{events:?}"
    );
    ensure!(rig.queries()? >= 1, "the server saw no query");
    Ok(())
}

fn small_offsets_slew_after_the_first_sync(lab: &mut Lab) -> anyhow::Result<()> {
    let mut rig = Rig::create(lab, 7_200)?;
    let rt = runtime()?;
    let (mut driver, _) = synced_driver(&rt, vec![SERVER])?;
    // A second server whose clock is 200 ms further on than the one we stepped to.
    rig.start_server_fraction(SECOND_SERVER, 7_200.2)?;
    rt.block_on(async {
        driver.configure(vec![ServerSpec::Address(SECOND_SERVER)], Vec::new());
    });
    let events = serve_until(
        &rt,
        &mut driver,
        |events| events.iter().any(|e| matches!(e, Event::Slewed { .. })),
        Duration::from_secs(10),
    )?;
    let slews = driver.clock().slews();
    ensure!(
        slews.len() == 1 && (slews[0] - 200_000_000).abs() < 60_000_000,
        "slews {slews:?}; events {events:?}"
    );
    ensure!(
        driver.clock().steps().len() == 1,
        "a second step: {:?}",
        driver.clock().steps()
    );
    Ok(())
}

impl Rig {
    /// As [`Rig::start_server`], with a fractional offset.
    fn start_server_fraction(&mut self, addr: Ipv4Addr, offset_secs: f64) -> anyhow::Result<()> {
        let script = openfeo_harness::lab::workspace_root().join("harness/fixtures/sntp-server.py");
        let mut cmd = self.timeserver.command("python3")?;
        cmd.args(["-I", "-u"]).arg(&script).args([
            "--bind",
            &addr.to_string(),
            "--port",
            "123",
            "--offset",
            &format!("{offset_secs}"),
            "--stratum",
            "2",
        ]);
        let server = Daemon::spawn(&format!("sntp-{addr}"), cmd)?;
        server.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("sntp-server listening on")?,
            Duration::from_secs(10),
        )?;
        self.servers.push(server);
        Ok(())
    }
}

fn a_server_before_the_build_floor_is_refused(lab: &mut Lab) -> anyhow::Result<()> {
    let _rig = Rig::create(lab, -400_000_000)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, vec![SERVER])?;
    let events = serve_until(
        &rt,
        &mut driver,
        |events| events.iter().any(|e| matches!(e, Event::Refused { .. })),
        Duration::from_secs(10),
    )?;
    ensure!(
        events.iter().any(|e| matches!(e, Event::Refused { server, floor_unix_secs: FLOOR, .. } if *server == SERVER)),
        "{events:?}"
    );
    ensure!(
        driver.clock().steps().is_empty() && !driver.state().synced,
        "the clock moved: {:?}",
        driver.clock().steps()
    );
    Ok(())
}

fn a_silent_server_is_skipped_for_the_next(lab: &mut Lab) -> anyhow::Result<()> {
    let _rig = Rig::create(lab, 0)?;
    let rt = runtime()?;
    let started = Instant::now();
    let (driver, events) = synced_driver(&rt, vec![DEAD_SERVER, SERVER])?;
    let took = started.elapsed();
    ensure!(
        events
            .iter()
            .any(|e| matches!(e, Event::Synced { server, .. } if *server == SERVER)),
        "{events:?}"
    );
    ensure!(
        took < Duration::from_secs(5),
        "the dead server held things up for {took:?}"
    );
    ensure!(
        driver.state().source == Some(SERVER),
        "{:?}",
        driver.state()
    );
    Ok(())
}

fn lan_clients_get_answers_at_stratum_plus_one(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, 7_200)?;
    let rt = runtime()?;
    let (mut driver, _) = synced_driver(&rt, vec![SERVER])?;
    let (_, reply) = serve_while(&rt, &mut driver, || {
        lanclient::ntpdate_query(&rig.client, ROUTER, LOOKUP)
    })?;
    ensure!(
        reply.stratum == 3,
        "busybox saw stratum {}: {reply:?}",
        reply.stratum
    );
    ensure!(
        (reply.offset_s - 7_200.0).abs() < 1.0,
        "ntpdate saw offset {}: {reply:?}",
        reply.offset_s
    );
    let (_, packet) = serve_while(&rt, &mut driver, || {
        lanclient::sntp_query(&rig.client, ROUTER, LOOKUP)
    })?;
    ensure!(
        packet.leap == 0 && packet.stratum == 3 && packet.reference_id == SERVER.octets(),
        "{packet:?}"
    );
    ensure!(driver.stats().served == 2, "{:?}", driver.stats());
    Ok(())
}

fn unsynced_answers_are_marked_as_such(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, 0)?;
    let rt = runtime()?;
    let mut driver = Rig::driver(&rt, Vec::new())?;
    let (_, packet) = serve_while(&rt, &mut driver, || {
        lanclient::sntp_query(&rig.client, ROUTER, LOOKUP)
    })?;
    ensure!(
        packet.leap == LI_UNSYNCHRONISED && packet.stratum == STRATUM_UNSYNCHRONISED,
        "{packet:?}"
    );
    ensure!(driver.stats().served == 1, "{:?}", driver.stats());
    ensure!(!driver.state().synced);
    Ok(())
}
