// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 server driver (`openfeo-net`) against real clients inside the rootless sandbox,
//! no QEMU: a veth pair whose far end lives in a namespace of its own, where the LAN-side
//! clients run (our own as `openfeo-harness dhcp-client`, busybox `udhcpc` as the reference),
//! and the driver on the near end with the lab's `[lans.dhcp]` settings. `harness = false`:
//! this binary is its own runner; an optional first argument filters scenarios by substring.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use openfeo_config::{PortMap, file};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::{self, UdhcpcEvent};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_net::dhcp4_server::{ServerDriver, ServerDriverConfig};
use openfeo_proto_dhcp4::{LeaseRecord, NakReason, ServerConfig, ServerEvent};
use openfeo_reconcile::dhcp::{server_config, servers};
use openfeo_world::World;
use serde_json::{Value, json};
use tokio::runtime::Runtime;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "rust_client_gets_a_pool_lease_with_options",
        run: rust_client_gets_a_pool_lease_with_options,
    },
    Scenario {
        name: "udhcpc_gets_a_lease",
        run: udhcpc_gets_a_lease,
    },
    Scenario {
        name: "reservation_gives_the_nas_its_address",
        run: reservation_gives_the_nas_its_address,
    },
    Scenario {
        name: "init_reboot_is_confirmed_from_restored_leases",
        run: init_reboot_is_confirmed_from_restored_leases,
    },
    Scenario {
        name: "a_foreign_address_is_naked_then_a_pool_address_granted",
        run: a_foreign_address_is_naked_then_a_pool_address_granted,
    },
    Scenario {
        name: "a_squatted_address_is_skipped_after_the_probe",
        run: a_squatted_address_is_skipped_after_the_probe,
    },
    Scenario {
        name: "inform_is_answered_with_options",
        run: inform_is_answered_with_options,
    },
    Scenario {
        name: "release_frees_the_address",
        run: release_frees_the_address,
    },
    Scenario {
        name: "two_clients_get_distinct_addresses",
        run: two_clients_get_distinct_addresses,
    },
    Scenario {
        name: "renewal_is_acked_at_t1",
        run: renewal_is_acked_at_t1,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    // `OPENFEO_TRACE=1` shows the driver's debug lines (bytes in and out, probes, failed sends).
    if std::env::var_os("OPENFEO_TRACE").is_some() {
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
            .with_writer(std::io::stderr)
            .init();
    }
    let filter = std::env::args().nth(1);
    run_all(SCENARIOS, filter.as_deref())
}

/// The harness binary: `dhcp-client` runs inside the client namespace.
const HARNESS_BIN: &str = env!("CARGO_BIN_EXE_openfeo-harness");
const VM_STATIC: &str = include_str!("../fixtures/vm-static.toml");
const SERVER_IF: &str = "s0";
const CLIENT_IF: &str = "s1";
const SERVER_ADDR: &str = "192.168.1.1/24";
const CLIENT_MAC: &str = "02:00:00:00:00:01";
const SECOND_MAC: &str = "02:00:00:00:00:02";
const SQUATTER_MAC: &str = "02:00:00:00:00:99";
const NAS_MAC: &str = "52:54:00:fe:10:10";
const LEASE_TIMEOUT: Duration = Duration::from_secs(15);
/// The client holds off for 10 s after a NAK before it discovers again.
const NAK_TIMEOUT: Duration = Duration::from_secs(30);

/// A veth pair: the server driver on `s0` here, the clients on `s1` in a namespace of their
/// own. Fields drop in order: the namespace first, then the pair.
struct Rig {
    ns: NetNs,
    ifindex: u32,
    mac: [u8; 6],
}

impl Rig {
    fn create(lab: &Lab) -> anyhow::Result<Self> {
        let _ = netns::ip(&["link", "del", SERVER_IF]);
        netns::ip(&[
            "link", "add", SERVER_IF, "type", "veth", "peer", "name", CLIENT_IF,
        ])?;
        let ns = NetNs::create(&format!("{}-lan", lab.name()))?;
        netns::ip(&["link", "set", CLIENT_IF, "netns", &ns.name])?;
        ns.ip(&["link", "set", CLIENT_IF, "address", CLIENT_MAC])?;
        ns.ip(&["link", "set", CLIENT_IF, "up"])?;
        netns::ip(&["addr", "add", SERVER_ADDR, "dev", SERVER_IF])?;
        netns::ip(&["link", "set", SERVER_IF, "up"])?;
        let (ifindex, mac) = lanclient::link_info(SERVER_IF)?;
        Ok(Rig { ns, ifindex, mac })
    }

    /// The lab fixture's `[lans.dhcp]`, as the router would run it.
    fn config() -> anyhow::Result<ServerConfig> {
        let world = World::new(file::parse(VM_STATIC)?, PortMap::default());
        let desired = servers(&world);
        let lan0 = desired.get("lan0").context("fixture has lan0")?;
        Ok(server_config(lan0))
    }

    fn driver(
        &self,
        rt: &Runtime,
        config: ServerConfig,
        leases: Vec<LeaseRecord>,
    ) -> anyhow::Result<ServerDriver> {
        rt.block_on(async {
            ServerDriver::new(ServerDriverConfig {
                ifname: SERVER_IF.to_owned(),
                ifindex: self.ifindex,
                mac: self.mac,
                server: config,
                leases,
            })
            .context("start the server driver")
        })
    }

    /// A second LAN host: a macvlan on the client interface with its own MAC.
    fn add_host(&self, name: &str, mac: &str) -> anyhow::Result<()> {
        self.ns.ip(&[
            "link", "add", name, "link", CLIENT_IF, "type", "macvlan", "mode", "bridge",
        ])?;
        self.ns.ip(&["link", "set", name, "address", mac])?;
        self.ns.ip(&["link", "set", name, "up"])?;
        Ok(())
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = netns::ip(&["link", "del", SERVER_IF]);
    }
}

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

/// Step the server while `client` runs on another thread; once the client is done, drain the
/// server for half a second (its last ACK's events trail the client's exit) and return both.
fn serve_while<'a, T: Send + 'a>(
    rt: &Runtime,
    driver: &mut ServerDriver,
    client: impl FnOnce() -> anyhow::Result<T> + Send + 'a,
    timeout: Duration,
) -> anyhow::Result<(Vec<ServerEvent>, T)> {
    thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let handle = scope.spawn(move || {
            let result = client();
            let _ = done_tx.send(());
            result
        });
        let mut events = Vec::new();
        let deadline = Instant::now() + timeout;
        let mut drain_until: Option<Instant> = None;
        loop {
            let step = rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(100), driver.step()).await
            });
            match step {
                Ok(Ok(new)) => events.extend(new),
                Ok(Err(err)) => return Err(err.into()),
                Err(_elapsed) => {}
            }
            if drain_until.is_none() && done_rx.try_recv().is_ok() {
                drain_until = Some(Instant::now() + Duration::from_millis(500));
            }
            if drain_until.is_some_and(|until| Instant::now() >= until) {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "the server loop timed out; events so far: {events:?}"
            );
        }
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))??;
        Ok((events, result))
    })
}

fn kinds(lines: &[Value]) -> Vec<&str> {
    lines
        .iter()
        .filter_map(|line| line["event"].as_str())
        .collect()
}

fn bound_line(lines: &[Value]) -> anyhow::Result<&Value> {
    lines
        .iter()
        .find(|line| line["event"] == "bound")
        .with_context(|| format!("no bound event in {lines:?}"))
}

/// The address, which must lie in the fixture's pool.
fn pool_address(text: &Value) -> anyhow::Result<Ipv4Addr> {
    let address: Ipv4Addr = text
        .as_str()
        .with_context(|| format!("not an address: {text}"))?
        .parse()?;
    ensure!(
        (100..=200).contains(&address.octets()[3]) && address.octets()[..3] == [192, 168, 1],
        "{address} is outside the pool 192.168.1.100-200"
    );
    Ok(address)
}

fn udhcpc_bound(events: &[UdhcpcEvent]) -> anyhow::Result<&UdhcpcEvent> {
    events
        .iter()
        .find(|event| event.kind == "bound")
        .with_context(|| format!("udhcpc never bound: {events:?}"))
}

fn granted(events: &[ServerEvent]) -> Vec<&LeaseRecord> {
    events
        .iter()
        .filter_map(|event| match event {
            ServerEvent::Granted(record) => Some(record),
            _ => None,
        })
        .collect()
}

fn count<F: Fn(&ServerEvent) -> bool>(events: &[ServerEvent], pred: F) -> usize {
    events.iter().filter(|event| pred(event)).count()
}

/// Our client does DISCOVER, OFFER, REQUEST, ACK against the driver and gets the fixture's
/// options; the server records the sanitised hostname.
fn rust_client_gets_a_pool_lease_with_options(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || {
            lanclient::dhcp_client(
                HARNESS_BIN,
                &rig.ns,
                CLIENT_IF,
                &["--hostname", "lanhost"],
                LEASE_TIMEOUT,
            )
        },
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    ensure!(
        kinds(&lines) == ["discover", "offer", "request", "bound"],
        "client events {:?}; server events {events:?}; server stats {:?}",
        kinds(&lines),
        driver.stats()
    );
    let bound = bound_line(&lines)?;
    let address = pool_address(&bound["address"])?;
    ensure!(bound["prefix"] == 24, "prefix {}", bound["prefix"]);
    ensure!(
        bound["server"] == "192.168.1.1",
        "server {}",
        bound["server"]
    );
    ensure!(
        bound["gateway"] == "192.168.1.1",
        "gateway {}",
        bound["gateway"]
    );
    ensure!(
        bound["dns"] == json!(["192.168.1.1"]),
        "dns {}",
        bound["dns"]
    );
    ensure!(bound["domain"] == "home.arpa", "domain {}", bound["domain"]);
    ensure!(
        (bound["lease_secs"] == 43_200)
            && (bound["t1_secs"] == 21_600)
            && (bound["t2_secs"] == 37_800),
        "timers {bound}"
    );
    ensure!(
        matches!(events.first(), Some(ServerEvent::Offered { .. })),
        "server events {events:?}"
    );
    let records = granted(&events);
    ensure!(records.len() == 1, "granted {records:?}");
    ensure!(records[0].address == address && records[0].hostname.as_deref() == Some("lanhost"));
    ensure!(driver.leases().len() == 1);
    Ok(())
}

/// busybox udhcpc, the independent client, gets a pool lease with the fixture's options.
fn udhcpc_gets_a_lease(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let run_dir = lab.run_dir.clone();
    let (events, udhcpc) = serve_while(
        &rt,
        &mut driver,
        || lanclient::udhcpc(&rig.ns, CLIENT_IF, &run_dir, &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let bound = udhcpc_bound(&udhcpc)?;
    let address = pool_address(&Value::String(bound.env["ip"].clone()))?;
    for (key, expected) in [
        ("subnet", "255.255.255.0"),
        ("router", "192.168.1.1"),
        ("dns", "192.168.1.1"),
        ("domain", "home.arpa"),
        ("lease", "43200"),
        ("serverid", "192.168.1.1"),
    ] {
        ensure!(
            bound.env.get(key).map(String::as_str) == Some(expected),
            "udhcpc {key}={:?}, expected {expected}",
            bound.env.get(key)
        );
    }
    let records = granted(&events);
    ensure!(
        records.len() == 1 && records[0].address == address,
        "granted {records:?}"
    );
    Ok(())
}

/// A client with the fixture's `nas` MAC gets 192.168.1.10 and its name, whatever the pool.
fn reservation_gives_the_nas_its_address(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    rig.ns.ip(&["link", "set", CLIENT_IF, "down"])?;
    rig.ns.ip(&["link", "set", CLIENT_IF, "address", NAS_MAC])?;
    rig.ns.ip(&["link", "set", CLIENT_IF, "up"])?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let run_dir = lab.run_dir.clone();
    let (events, udhcpc) = serve_while(
        &rt,
        &mut driver,
        || lanclient::udhcpc(&rig.ns, CLIENT_IF, &run_dir, &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let bound = udhcpc_bound(&udhcpc)?;
    ensure!(bound.env["ip"] == "192.168.1.10", "ip {}", bound.env["ip"]);
    ensure!(
        bound.env.get("hostname").map(String::as_str) == Some("nas"),
        "hostname {:?}",
        bound.env.get("hostname")
    );
    let records = granted(&events);
    ensure!(
        records.len() == 1 && records[0].hostname.as_deref() == Some("nas"),
        "granted {records:?}"
    );
    Ok(())
}

/// A lease outlives the server: a new driver with the exported records acknowledges the
/// client's INIT-REBOOT as a renewal, with no DISCOVER and no OFFER.
fn init_reboot_is_confirmed_from_restored_leases(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let (_, lines) = serve_while(
        &rt,
        &mut driver,
        || lanclient::dhcp_client(HARNESS_BIN, &rig.ns, CLIENT_IF, &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let address = pool_address(&bound_line(&lines)?["address"])?;
    let kept = driver.leases();
    ensure!(kept.len() == 1, "kept {kept:?}");
    drop(driver);
    let mut driver = rig.driver(&rt, Rig::config()?, kept)?;
    let request = address.to_string();
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || {
            lanclient::dhcp_client(
                HARNESS_BIN,
                &rig.ns,
                CLIENT_IF,
                &["--request", &request],
                LEASE_TIMEOUT,
            )
        },
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    ensure!(
        kinds(&lines) == ["init-reboot", "request", "bound"],
        "client events {:?}",
        kinds(&lines)
    );
    ensure!(
        bound_line(&lines)?["address"] == request,
        "rebooted to {}",
        bound_line(&lines)?["address"]
    );
    ensure!(
        count(&events, |e| matches!(e, ServerEvent::Renewed(_))) == 1
            && count(&events, |e| matches!(e, ServerEvent::Offered { .. })) == 0,
        "server events {events:?}"
    );
    Ok(())
}

/// A client rebooting a lease from another router is refused and gets a pool address.
fn a_foreign_address_is_naked_then_a_pool_address_granted(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || {
            lanclient::dhcp_client(
                HARNESS_BIN,
                &rig.ns,
                CLIENT_IF,
                &["--request", "192.168.1.77"],
                NAK_TIMEOUT,
            )
        },
        NAK_TIMEOUT + Duration::from_secs(5),
    )?;
    ensure!(
        kinds(&lines)
            == [
                "init-reboot",
                "request",
                "nak",
                "discover",
                "offer",
                "request",
                "bound"
            ],
        "client events {:?}",
        kinds(&lines)
    );
    pool_address(&bound_line(&lines)?["address"])?;
    ensure!(
        events.iter().any(|event| matches!(
            event,
            ServerEvent::Nak { address, reason: NakReason::OutsidePool, .. }
                if *address == Ipv4Addr::new(192, 168, 1, 77)
        )),
        "server events {events:?}"
    );
    Ok(())
}

/// Another host already uses the first pool address: the probe finds it and the next one is
/// offered.
fn a_squatted_address_is_skipped_after_the_probe(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    rig.add_host("squat0", SQUATTER_MAC)?;
    rig.ns
        .ip(&["addr", "add", "192.168.1.100/24", "dev", "squat0"])?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || lanclient::dhcp_client(HARNESS_BIN, &rig.ns, CLIENT_IF, &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    ensure!(
        bound_line(&lines)?["address"] == "192.168.1.101",
        "bound {}",
        bound_line(&lines)?["address"]
    );
    ensure!(
        events.iter().any(|event| matches!(
            event,
            ServerEvent::Conflict { address, mac }
                if *address == Ipv4Addr::new(192, 168, 1, 100) && *mac == [2, 0, 0, 0, 0, 0x99]
        )),
        "server events {events:?}"
    );
    Ok(())
}

/// A host with an address of its own asks for the options with DHCPINFORM and gets them, with
/// no lease recorded.
fn inform_is_answered_with_options(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    rig.ns
        .ip(&["addr", "add", "192.168.1.50/24", "dev", CLIENT_IF])?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || {
            lanclient::dhcp_client(
                HARNESS_BIN,
                &rig.ns,
                CLIENT_IF,
                &["--inform", "192.168.1.50"],
                LEASE_TIMEOUT,
            )
        },
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let ack = lines
        .iter()
        .find(|line| line["event"] == "ack")
        .with_context(|| format!("no ack in {lines:?}"))?;
    ensure!(ack["dns"] == json!(["192.168.1.1"]), "dns {}", ack["dns"]);
    ensure!(
        ack["router"] == json!(["192.168.1.1"]),
        "router {}",
        ack["router"]
    );
    ensure!(ack["domain"] == "home.arpa", "domain {}", ack["domain"]);
    ensure!(
        count(&events, |e| matches!(e, ServerEvent::Informed { .. })) == 1,
        "server events {events:?}"
    );
    ensure!(driver.leases().is_empty(), "leases {:?}", driver.leases());
    Ok(())
}

/// udhcpc releases its lease when told to leave (`-R` and SIGTERM): the address is free again.
fn release_frees_the_address(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let run_dir = lab.run_dir.clone();
    let (events, udhcpc) = serve_while(
        &rt,
        &mut driver,
        || lanclient::udhcpc_release(&rig.ns, CLIENT_IF, &run_dir, LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    udhcpc_bound(&udhcpc)?;
    if std::env::var_os("OPENFEO_TRACE").is_some() {
        eprintln!(
            "client addresses: {:?}",
            rig.ns.ip(&["-4", "-o", "addr", "show", CLIENT_IF])
        );
    }
    ensure!(
        count(&events, |e| matches!(e, ServerEvent::Granted(_))) == 1
            && count(&events, |e| matches!(e, ServerEvent::Released(_))) == 1,
        "server events {events:?}; udhcpc events {:?}",
        udhcpc.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()
    );
    ensure!(driver.leases().is_empty(), "leases {:?}", driver.leases());
    Ok(())
}

/// Two hosts, two MACs, two different pool addresses.
fn two_clients_get_distinct_addresses(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    rig.add_host("c2", SECOND_MAC)?;
    let rt = runtime()?;
    let mut driver = rig.driver(&rt, Rig::config()?, vec![])?;
    let run_dir = lab.run_dir.clone();
    let (_, udhcpc) = serve_while(
        &rt,
        &mut driver,
        || lanclient::udhcpc(&rig.ns, CLIENT_IF, &run_dir, &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let first = pool_address(&Value::String(udhcpc_bound(&udhcpc)?.env["ip"].clone()))?;
    let (_, lines) = serve_while(
        &rt,
        &mut driver,
        || lanclient::dhcp_client(HARNESS_BIN, &rig.ns, "c2", &[], LEASE_TIMEOUT),
        LEASE_TIMEOUT + Duration::from_secs(5),
    )?;
    let second = pool_address(&bound_line(&lines)?["address"])?;
    ensure!(first != second, "both clients got {first}");
    ensure!(driver.leases().len() == 2, "leases {:?}", driver.leases());
    Ok(())
}

/// With a 60 s lease the client renews at T1 (30 s) by unicast; the server answers with a
/// renewal, not a new lease.
fn renewal_is_acked_at_t1(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab)?;
    let rt = runtime()?;
    let mut config = Rig::config()?;
    config.lease_secs = 60;
    let mut driver = rig.driver(&rt, config, vec![])?;
    let (events, lines) = serve_while(
        &rt,
        &mut driver,
        || {
            lanclient::dhcp_client(
                HARNESS_BIN,
                &rig.ns,
                CLIENT_IF,
                &["--until-renewed"],
                Duration::from_secs(45),
            )
        },
        Duration::from_secs(50),
    )?;
    let bounds: Vec<&Value> = lines.iter().filter(|l| l["event"] == "bound").collect();
    ensure!(
        bounds.len() == 2 && bounds[0]["renewed"] == false && bounds[1]["renewed"] == true,
        "client events {lines:?}"
    );
    ensure!(bounds[0]["lease_secs"] == 60 && bounds[0]["t1_secs"] == 30);
    ensure!(
        count(&events, |e| matches!(e, ServerEvent::Granted(_))) == 1
            && count(&events, |e| matches!(e, ServerEvent::Renewed(_))) == 1,
        "server events {events:?}"
    );
    Ok(())
}
