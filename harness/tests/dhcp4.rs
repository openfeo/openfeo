// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 client driver (`openfeo-net`) against a real Kea inside the rootless sandbox, no
//! QEMU: a veth pair whose far end lives in a namespace of its own with Kea on it, and the
//! driver on the near end. `harness = false`: this binary is its own runner; an optional first
//! argument filters scenarios by substring.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, ensure};
use openfeo_harness::daemons::{self, Daemon};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::link_info;
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_net::dhcp4::{Driver, DriverConfig, Event};
use openfeo_proto_dhcp4::identity::{client_id, duid_ll, iaid};
use openfeo_proto_dhcp4::{ClientConfig, Lease, State};

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "client_obtains_a_lease_from_kea",
        run: client_obtains_a_lease_from_kea,
    },
    Scenario {
        name: "client_renews_at_t1",
        run: client_renews_at_t1,
    },
    Scenario {
        name: "client_reboots_with_a_stored_lease",
        run: client_reboots_with_a_stored_lease,
    },
    Scenario {
        name: "client_without_a_server_retransmits",
        run: client_without_a_server_retransmits,
    },
    Scenario {
        name: "client_survives_the_port_going_down_and_up",
        run: client_survives_the_port_going_down_and_up,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The near end of the veth pair, where the driver runs.
const CLIENT_IF: &str = "d0";
/// The far end, in the ISP namespace, where Kea listens.
const SERVER_IF: &str = "d1";
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LEASE_TIMEOUT: Duration = Duration::from_secs(10);
/// The lab's Kea renews at 20 s; a renewal must have happened by then.
const RENEW_TIMEOUT: Duration = Duration::from_secs(35);

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

/// A veth pair with Kea (unless `with_kea` is false) on the far end in its own namespace.
/// Fields drop in order: Kea before its namespace, the pair last.
struct Rig {
    kea: Option<Daemon>,
    #[allow(dead_code)]
    ns: NetNs,
    ifindex: u32,
    mac: [u8; 6],
}

impl Rig {
    fn create(lab: &Lab, with_kea: bool) -> anyhow::Result<Self> {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
        netns::ip(&[
            "link", "add", CLIENT_IF, "type", "veth", "peer", "name", SERVER_IF,
        ])?;
        let ns = NetNs::create(&format!("{}-dhcp", lab.name()))?;
        netns::ip(&["link", "set", SERVER_IF, "netns", &ns.name])?;
        ns.ip(&["addr", "add", "203.0.113.1/24", "dev", SERVER_IF])?;
        ns.ip(&["link", "set", SERVER_IF, "up"])?;
        netns::ip(&["link", "set", CLIENT_IF, "up"])?;
        let (ifindex, mac) = link_info(CLIENT_IF)?;
        let kea = if with_kea {
            let kea = daemons::kea_dhcp4(&ns, SERVER_IF, &lab.run_dir)?;
            kea.log.wait_for(
                &mut Cursor::default(),
                &re("DHCP4_STARTED"),
                Duration::from_secs(15),
            )?;
            Some(kea)
        } else {
            None
        };
        Ok(Rig {
            kea,
            ns,
            ifindex,
            mac,
        })
    }

    fn driver(&self, initial_lease: Option<Lease>) -> anyhow::Result<Driver> {
        let duid = duid_ll(self.mac);
        let client = ClientConfig::new(self.mac, client_id(iaid(self.mac), &duid));
        Ok(Driver::new(DriverConfig {
            ifname: CLIENT_IF.to_owned(),
            ifindex: self.ifindex,
            mac: self.mac,
            client,
            initial_lease,
            seed: 0x5eed,
        })?)
    }

    fn kea_log_count(&self, pattern: &str) -> usize {
        self.kea
            .as_ref()
            .map_or(0, |kea| kea.log.count(&re(pattern)))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
    }
}

/// `(ifindex, mac)` of `name` from `ip -o link show`, since the sandbox's sysfs shows the
/// host's devices rather than its own.
fn block_on<F: std::future::Future>(future: F) -> anyhow::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

/// Run the driver until `done` says so, or `timeout` passes; the events seen, in order.
async fn run_until(
    driver: &mut Driver,
    timeout: Duration,
    mut done: impl FnMut(&Event) -> bool,
) -> anyhow::Result<Vec<Event>> {
    let mut seen = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        loop {
            for event in driver.step().await? {
                let finished = done(&event);
                seen.push(event);
                if finished {
                    return anyhow::Ok(());
                }
            }
        }
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(seen),
        Ok(Err(err)) => Err(err),
        Err(_) => anyhow::bail!("timed out after {timeout:?}; events so far: {seen:?}"),
    }
}

/// Mimic the routing applier: the leased address goes on the interface so renewals can be sent.
fn configure(lease: &Lease) -> anyhow::Result<()> {
    netns::ip(&[
        "addr",
        "replace",
        &format!("{}/{}", lease.address, lease.prefix),
        "dev",
        CLIENT_IF,
    ])?;
    Ok(())
}

fn bound_lease(events: &[Event]) -> Option<&Lease> {
    events.iter().find_map(|event| match event {
        Event::Bound { lease, .. } => Some(lease),
        _ => None,
    })
}

fn check_lease(lease: &Lease) -> anyhow::Result<()> {
    ensure!(
        lease.address.octets()[..3] == [203, 0, 113]
            && (100..=200).contains(&lease.address.octets()[3]),
        "address {} outside Kea's pool",
        lease.address
    );
    ensure!(lease.prefix == 24, "prefix {}", lease.prefix);
    ensure!(lease.server == SERVER, "server {}", lease.server);
    ensure!(
        lease.gateway.is_none(),
        "option 3 must yield to classless routes"
    );
    ensure!(
        lease.default_gateway() == Some(SERVER),
        "default via {:?}",
        lease.default_gateway()
    );
    let routes: Vec<String> = lease
        .routes
        .iter()
        .map(|route| format!("{}/{} via {}", route.dst, route.prefix, route.via))
        .collect();
    ensure!(
        routes
            == [
                "0.0.0.0/0 via 203.0.113.1",
                "198.51.100.0/24 via 203.0.113.1"
            ],
        "routes {routes:?}"
    );
    ensure!(lease.dns == vec![SERVER], "dns {:?}", lease.dns);
    ensure!(
        lease.domain.as_deref() == Some("isp.example"),
        "domain {:?}",
        lease.domain
    );
    ensure!(lease.mtu == Some(1400), "mtu {:?}", lease.mtu);
    ensure!(lease.ntp == vec![SERVER], "ntp {:?}", lease.ntp);
    ensure!(
        (lease.lease_secs, lease.t1_secs, lease.t2_secs) == (60, 20, 40),
        "timers {} {} {}",
        lease.lease_secs,
        lease.t1_secs,
        lease.t2_secs
    );
    Ok(())
}

/// DISCOVER, OFFER, REQUEST, ACK against Kea: a lease with every option the template serves.
fn client_obtains_a_lease_from_kea(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, true)?;
    let (events, state, counters) = block_on(async {
        let mut driver = rig.driver(None)?;
        let events = run_until(&mut driver, LEASE_TIMEOUT, |event| {
            matches!(event, Event::Bound { .. })
        })
        .await?;
        anyhow::Ok((events, driver.state(), driver.stats()))
    })??;
    ensure!(
        matches!(events.first(), Some(Event::Discover)),
        "first event {:?}",
        events.first()
    );
    ensure!(
        events
            .iter()
            .any(|event| matches!(event, Event::Offer { server, .. } if *server == SERVER)),
        "no offer from Kea in {events:?}"
    );
    let lease = bound_lease(&events).context("no lease")?;
    check_lease(lease)?;
    ensure!(state == State::Bound, "state {state:?}");
    ensure!(
        counters.discovers == 1 && counters.requests == 1,
        "counters {counters:?}"
    );
    ensure!(
        rig.kea_log_count("DHCP4_LEASE_ALLOC") >= 1,
        "Kea did not log the allocation"
    );
    Ok(())
}

/// At T1 the client renews by unicast and Kea extends the lease; no second DISCOVER.
fn client_renews_at_t1(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, true)?;
    let (lease, renewed, stats) = block_on(async {
        let mut driver = rig.driver(None)?;
        let events = run_until(&mut driver, LEASE_TIMEOUT, |event| {
            matches!(event, Event::Bound { .. })
        })
        .await?;
        let lease = bound_lease(&events).context("no lease")?.clone();
        configure(&lease)?;
        let renewed = run_until(&mut driver, RENEW_TIMEOUT, |event| {
            matches!(event, Event::Bound { renewed: true, .. })
        })
        .await?;
        anyhow::Ok((lease, renewed, driver.stats()))
    })??;
    let again = bound_lease(&renewed).context("no renewed lease")?;
    ensure!(again.address == lease.address, "address changed on renewal");
    ensure!(
        !renewed.iter().any(|event| matches!(event, Event::Discover)),
        "a renewal must not discover: {renewed:?}"
    );
    ensure!(stats.discovers == 1, "stats {stats:?}");
    ensure!(
        rig.kea_log_count("DHCP4_LEASE_ALLOC") >= 2,
        "Kea logged {} allocations, expected the renewal too",
        rig.kea_log_count("DHCP4_LEASE_ALLOC")
    );
    Ok(())
}

/// A driver started with the previous lease confirms it with INIT-REBOOT: the same address,
/// no DISCOVER.
fn client_reboots_with_a_stored_lease(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, true)?;
    let (lease, events, stats) = block_on(async {
        let lease = {
            let mut first = rig.driver(None)?;
            let events = run_until(&mut first, LEASE_TIMEOUT, |event| {
                matches!(event, Event::Bound { .. })
            })
            .await?;
            bound_lease(&events).context("no lease")?.clone()
        };
        let mut rebooted = rig.driver(Some(lease.clone()))?;
        let events = run_until(&mut rebooted, LEASE_TIMEOUT, |event| {
            matches!(event, Event::Bound { .. })
        })
        .await?;
        anyhow::Ok((lease, events, rebooted.stats()))
    })??;
    ensure!(
        matches!(events.first(), Some(Event::Rebooting(address)) if *address == lease.address),
        "first event {:?}",
        events.first()
    );
    let again = bound_lease(&events).context("no lease after reboot")?;
    ensure!(again.address == lease.address, "address changed: {again:?}");
    ensure!(
        !events.iter().any(|event| matches!(event, Event::Discover)),
        "INIT-REBOOT must not discover: {events:?}"
    );
    ensure!(
        stats.discovers == 0 && stats.requests == 1,
        "stats {stats:?}"
    );
    Ok(())
}

/// No server: DISCOVERs keep going out with backoff and nothing binds.
fn client_without_a_server_retransmits(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, false)?;
    let (result, state, counters) = block_on(async {
        let mut driver = rig.driver(None)?;
        let result = run_until(&mut driver, Duration::from_secs(6), |event| {
            matches!(event, Event::Bound { .. })
        })
        .await;
        anyhow::Ok((result, driver.state(), driver.stats()))
    })??;
    ensure!(result.is_err(), "bound without a server: {result:?}");
    ensure!(counters.discovers >= 2, "counters {counters:?}");
    ensure!(state == State::Selecting, "state {state:?}");
    Ok(())
}

/// The port goes administratively down and up while the client is unaddressed: the packet
/// socket's error is not fatal, and a lease still arrives once the link is back.
fn client_survives_the_port_going_down_and_up(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, true)?;
    let events = block_on(async {
        let mut driver = rig.driver(None)?;
        netns::ip(&["link", "set", CLIENT_IF, "down"])?;
        driver.link(false)?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Ok(stepped) = tokio::time::timeout(Duration::from_millis(500), driver.step()).await {
            stepped.context("a step while the port is down")?;
        }
        netns::ip(&["link", "set", CLIENT_IF, "up"])?;
        driver.link(true)?;
        run_until(&mut driver, LEASE_TIMEOUT, |event| {
            matches!(event, Event::Bound { .. })
        })
        .await
    })??;
    ensure!(
        bound_lease(&events).is_some(),
        "no lease after the flap: {events:?}"
    );
    Ok(())
}
