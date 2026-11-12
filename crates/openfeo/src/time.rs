// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The time task (SPEC §7.10): one supervised task driving `openfeo_net::sntp::SntpDriver` on
//! the box's clock, following the World (the configured servers, the WAN's learned ones, the LAN
//! bridges), publishing `World.time`, and serving the LANs. Every line logged here is a contract
//! with the harness scenarios.

use std::net::Ipv4Addr;
use std::sync::Arc;

use openfeo_net::clock::SystemClock;
use openfeo_net::dhcp4::DriverError;
use openfeo_net::resolve::LOCAL_RESOLVER;
use openfeo_net::sntp::{SntpDriver, SntpDriverConfig};
use openfeo_proto_sntp::client::{Event, SyncState};
use openfeo_proto_sntp::timestamp::{iso8601, signed_secs};
use openfeo_reconcile::time::{DesiredTime, desired, server_specs};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::TimeFact;
use tracing::{debug, info};

use crate::dhcp4::seed;
use crate::version::build_epoch;

/// The salt of the clock fallback of [`seed`].
const SEED_SALT: u64 = 0x0054_494d;

/// The one time task.
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    let publisher = publisher.clone();
    let world_rx = world_rx.clone();
    supervisor.spawn("time", move || {
        let publisher = publisher.clone();
        let world_rx = world_rx.clone();
        async move { run(&publisher, world_rx).await }
    });
}

/// What a World asks of a time service that is running on `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Nothing,
    /// Other servers: the core is reconfigured as it runs.
    Configure,
    /// Other LANs: the listeners are bound again.
    Rebind,
}

fn change(current: &DesiredTime, next: &DesiredTime) -> Change {
    if next == current {
        Change::Nothing
    } else if next.listeners == current.listeners {
        Change::Configure
    } else {
        Change::Rebind
    }
}

/// The index of each listener's bridge once every one exists, or `None` when the LANs changed
/// first. A bridge need not have carrier: a LAN with no cable in must not keep the time service
/// from the others.
async fn bridges(
    world_rx: &mut WorldRx,
    current: &DesiredTime,
) -> Result<Option<Vec<(String, u32)>>, TaskError> {
    loop {
        {
            let world = world_rx.borrow_and_update();
            if desired(&world).listeners != current.listeners {
                return Ok(None);
            }
            let found: Option<Vec<(String, u32)>> = current
                .listeners
                .iter()
                .map(|listener| {
                    world
                        .links
                        .get(listener)
                        .map(|link| (listener.clone(), link.index))
                })
                .collect();
            if found.is_some() {
                return Ok(found);
            }
        }
        world_rx
            .changed()
            .await
            .map_err(|_| "world publisher gone")?;
    }
}

/// The task: run the time service on the LANs the World has, and when they change (a LAN added
/// or removed) bind again from the start. That is the config changing, not a failure.
async fn run(publisher: &Publisher, mut world_rx: WorldRx) -> Result<(), TaskError> {
    loop {
        serve(publisher, &mut world_rx).await?;
        info!("time: the LANs changed; binding again");
    }
}

/// Serve until the LANs change: wait for every LAN bridge, run the driver on the box's clock,
/// log what it says, publish the clock's state, and follow the World. New servers reconfigure
/// the core live; a bridge recreated is a failure the supervisor restarts.
async fn serve(publisher: &Publisher, world_rx: &mut WorldRx) -> Result<(), TaskError> {
    let mut current = desired(&world_rx.borrow());
    let Some(indexes) = bridges(world_rx, &current).await? else {
        return Ok(());
    };
    // The World moved on while the bridges came up: a WAN lease, say.
    current = desired(&world_rx.borrow_and_update());
    let failed = |err: DriverError| TaskError::from(format!("time: {err}"));
    let mut driver = SntpDriver::new(
        SntpDriverConfig {
            servers: server_specs(&current),
            learned: current.learned.clone(),
            resolver: Some(LOCAL_RESOLVER),
            listeners: current.listeners.clone(),
            floor_unix_secs: build_epoch(),
            seed: seed(SEED_SALT),
        },
        SystemClock::new(),
    )
    .map_err(failed)?;
    if !current.listeners.is_empty() {
        info!("time serving on {}", current.listeners.join(", "));
    }
    info!("{}", servers_line(&current));
    let mut last_fact = TimeFact::default();
    loop {
        tokio::select! {
            events = driver.step() => {
                for event in events.map_err(failed)? {
                    log_event(&event);
                }
                let time_fact = fact_from(&driver.state());
                if time_fact != last_fact {
                    publisher.update(|world| world.time = time_fact);
                    last_fact = time_fact;
                }
            }
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                let next = {
                    let world = world_rx.borrow_and_update();
                    for (ifname, index) in &indexes {
                        if let Some(link) = world.links.get(ifname)
                            && link.index != *index
                        {
                            // The bridge was recreated: the listener is bound to the old one.
                            return Err(format!(
                                "time: {ifname} changed index {index} -> {}; restarting",
                                link.index
                            )
                            .into());
                        }
                    }
                    desired(&world)
                };
                match change(&current, &next) {
                    Change::Nothing => continue,
                    Change::Rebind => return Ok(()),
                    Change::Configure => {}
                }
                for event in driver.configure(server_specs(&next), next.learned.clone()) {
                    log_event(&event);
                }
                info!("{}", servers_line(&next));
                current = next;
            }
        }
    }
}

/// One event to the console, or to the log at debug for the routine ones.
fn log_event(event: &Event) {
    if let Some(line) = event_line(event) {
        info!("{line}");
    } else {
        debug!("{}", debug_line(event));
    }
}

/// `time servers 0.pool.ntp.org 1.pool.ntp.org 203.0.113.1 (configured, learned from wan0)`.
fn servers_line(desired: &DesiredTime) -> String {
    let mut names: Vec<String> = desired.servers.clone();
    names.extend(desired.learned.iter().map(Ipv4Addr::to_string));
    if names.is_empty() {
        return "time no servers".to_owned();
    }
    let mut sources = vec!["configured".to_owned()];
    if let Some(wan) = &desired.learned_from {
        sources.push(format!("learned from {wan}"));
    }
    format!("time servers {} ({})", names.join(" "), sources.join(", "))
}

/// The console contract for one event; `None` for the ones that stay at debug.
fn event_line(event: &Event) -> Option<String> {
    match event {
        Event::Step {
            server,
            offset_ns,
            stratum,
        } => Some(format!(
            "time step {} from {server} stratum {stratum}",
            signed_secs(*offset_ns)
        )),
        Event::Synced {
            server,
            offset_ns,
            delay_ns,
            stratum,
        } => Some(format!(
            "time synced offset={} delay={} source={server} stratum={stratum}",
            signed_secs(*offset_ns),
            signed_secs(*delay_ns).trim_start_matches('+')
        )),
        Event::Refused {
            server,
            transmit_unix_secs,
            floor_unix_secs,
        } => Some(format!(
            "time refused {} from {server}: before the build floor {}",
            iso8601(*transmit_unix_secs),
            iso8601(i64::try_from(*floor_unix_secs).unwrap_or(i64::MAX))
        )),
        Event::ServerDown(server) => Some(format!("time server {server} down")),
        Event::ServerUnsynced(server) => Some(format!("time server {server} has no time")),
        Event::ServerUnusable { server, code } => Some(format!(
            "time server {server} unusable: kiss of death {}",
            String::from_utf8_lossy(code).trim_end_matches('\0')
        )),
        Event::LostSync { rounds } => Some(format!(
            "time lost sync: no valid answer for {rounds} polls"
        )),
        Event::Configured { .. }
        | Event::NoServers
        | Event::Slewed { .. }
        | Event::Rejected { .. } => None,
    }
}

/// The debug line of an event [`event_line`] keeps off the console.
fn debug_line(event: &Event) -> String {
    match event {
        Event::Configured { servers } => format!("time configured with {servers} servers"),
        Event::NoServers => "time no servers to ask".to_owned(),
        Event::Slewed { server, offset_ns } => {
            format!("time slew {} from {server}", signed_secs(*offset_ns))
        }
        Event::Rejected { server, reason } => {
            format!("time rejected an answer from {server}: {reason:?}")
        }
        other => format!("{other:?}"),
    }
}

/// The fact for `state`, with the offset in milliseconds.
fn fact_from(state: &SyncState) -> TimeFact {
    TimeFact {
        synced: state.synced,
        source: state.source,
        stratum: state.stratum,
        offset_ms: state.offset_ns / 1_000_000,
        last_sync_unix: state.last_sync_unix_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{PortMap, PortMapEntry, file};
    use openfeo_proto_sntp::client::SyncState;
    use openfeo_world::{Dhcp4Fact, World};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const VM_DHCP: &str = include_str!("../../../harness/fixtures/vm-dhcp.toml");

    /// The lab's DHCP configuration on the lab's three ports, with the lease Kea hands out.
    fn dhcp_world() -> World {
        let ports = PortMap {
            ports: ["pci-0000:00:03.0", "pci-0000:00:04.0", "pci-0000:00:05.0"]
                .iter()
                .enumerate()
                .map(|(i, id)| PortMapEntry {
                    id: (*id).to_owned(),
                    name: format!("p{i}"),
                })
                .collect(),
        };
        let mut world = World::new(file::parse(VM_DHCP).unwrap(), ports);
        let server = Ipv4Addr::new(203, 0, 113, 1);
        world.dhcp4 = Arc::new(BTreeMap::from([(
            "wan0".to_owned(),
            Dhcp4Fact {
                address: "203.0.113.100/24".parse().unwrap(),
                server,
                gateway: Some(server),
                routes: vec![],
                dns: vec![server],
                ntp: vec![server],
                domain: Some("isp.example".to_owned()),
                mtu: None,
            },
        )]));
        world
    }

    /// The DHCP world with a second LAN, `lan1` on `p3` at `192.168.2.1/24`.
    fn two_lans() -> World {
        let mut world = dhcp_world();
        let mut config = (*world.config).clone();
        config.lans.push(openfeo_config::Lan {
            name: "lan1".to_owned(),
            ports: vec!["p3".to_owned()],
            ipv4: "192.168.2.1/24".to_owned(),
            ..openfeo_config::Lan::default()
        });
        world.config = Arc::new(config);
        world
    }

    fn link(name: &str, index: u32, carrier: bool) -> openfeo_world::LinkFact {
        openfeo_world::LinkFact {
            index,
            name: name.to_owned(),
            up: true,
            carrier,
            mac: None,
            mtu: 1500,
            link_local6: None,
            speed_mbps: None,
        }
    }

    #[test]
    fn the_task_s_desired_state_follows_a_changed_config() {
        let before = desired(&dhcp_world());
        let after = desired(&two_lans());
        assert_eq!(before.listeners, ["br-lan0"]);
        assert_eq!(after.listeners, ["br-lan0", "br-lan1"]);
        assert_eq!(change(&before, &after), Change::Rebind);
        // Other servers are taken as it runs.
        let mut world = dhcp_world();
        let mut config = (*world.config).clone();
        config
            .system
            .get_or_insert_with(Default::default)
            .ntp_servers = vec!["192.0.2.123".to_owned()];
        world.config = Arc::new(config);
        let typed = desired(&world);
        assert_eq!(typed.servers, ["192.0.2.123"]);
        assert_eq!(change(&before, &typed), Change::Configure);
        assert_eq!(change(&before, &before), Change::Nothing);
    }

    /// As for DNS: a LAN with no cable in must not keep the time service from the others.
    #[tokio::test(start_paused = true)]
    async fn the_bridges_are_awaited_without_their_carrier() {
        let (publisher, world_rx) = Publisher::new(two_lans());
        let current = desired(&publisher.current());
        let waiting = {
            let current = current.clone();
            let mut world_rx = world_rx.clone();
            tokio::spawn(async move { bridges(&mut world_rx, &current).await })
        };
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!waiting.is_finished(), "no bridge exists yet");
        publisher.update(|world| {
            let links = Arc::make_mut(&mut world.links);
            links.insert("br-lan0".to_owned(), link("br-lan0", 7, true));
            links.insert("br-lan1".to_owned(), link("br-lan1", 8, false));
        });
        assert_eq!(
            waiting.await.unwrap().unwrap(),
            Some(vec![("br-lan0".to_owned(), 7), ("br-lan1".to_owned(), 8)])
        );
        // A change of LANs while waiting ends the wait.
        let (publisher, mut world_rx) = Publisher::new(two_lans());
        let waiting = tokio::spawn(async move { bridges(&mut world_rx, &current).await });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let one = dhcp_world().config.clone();
        publisher.update(|world| world.config = one);
        assert_eq!(waiting.await.unwrap().unwrap(), None);
    }

    #[test]
    fn server_and_event_lines_follow_the_contract() {
        let mut d = desired(&dhcp_world());
        assert_eq!(
            servers_line(&d),
            "time servers 0.pool.ntp.org 1.pool.ntp.org 203.0.113.1 (configured, learned from wan0)"
        );
        d.learned.clear();
        d.learned_from = None;
        assert_eq!(
            servers_line(&d),
            "time servers 0.pool.ntp.org 1.pool.ntp.org (configured)"
        );
        let server = Ipv4Addr::new(203, 0, 113, 1);
        assert_eq!(
            event_line(&Event::Step {
                server,
                offset_ns: 7_200_012_000_000,
                stratum: 2,
            }),
            Some("time step +7200.012s from 203.0.113.1 stratum 2".into())
        );
        assert_eq!(
            event_line(&Event::Synced {
                server,
                offset_ns: 3_000_000,
                delay_ns: 12_000_000,
                stratum: 2,
            }),
            Some("time synced offset=+0.003s delay=0.012s source=203.0.113.1 stratum=2".into())
        );
        assert_eq!(
            event_line(&Event::Refused {
                server,
                transmit_unix_secs: 1_377_993_600,
                floor_unix_secs: 1_793_448_000,
            }),
            Some(
                "time refused 2013-09-01T00:00:00Z from 203.0.113.1: before the build floor 2026-10-31T12:00:00Z"
                    .into()
            )
        );
        assert_eq!(
            event_line(&Event::ServerDown(server)),
            Some("time server 203.0.113.1 down".into())
        );
        assert_eq!(
            event_line(&Event::ServerUnsynced(server)),
            Some("time server 203.0.113.1 has no time".into())
        );
        assert_eq!(
            event_line(&Event::ServerUnusable {
                server,
                code: *b"DENY",
            }),
            Some("time server 203.0.113.1 unusable: kiss of death DENY".into())
        );
        assert_eq!(
            event_line(&Event::LostSync { rounds: 4 }),
            Some("time lost sync: no valid answer for 4 polls".into())
        );
        assert_eq!(event_line(&Event::Configured { servers: 3 }), None);
        assert_eq!(
            event_line(&Event::Slewed {
                server,
                offset_ns: 1,
            }),
            None
        );
    }

    #[test]
    fn the_fact_mirrors_the_state_in_milliseconds() {
        let state = SyncState {
            synced: true,
            source: Some(Ipv4Addr::new(203, 0, 113, 1)),
            stratum: 2,
            offset_ns: -2_500_000,
            last_sync_unix_secs: Some(1_793_448_000),
            ..SyncState::default()
        };
        assert_eq!(
            fact_from(&state),
            TimeFact {
                synced: true,
                source: Some(Ipv4Addr::new(203, 0, 113, 1)),
                stratum: 2,
                offset_ms: -2,
                last_sync_unix: Some(1_793_448_000),
            }
        );
    }
}
