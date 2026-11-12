// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DNS forwarder task (SPEC §7.7): one supervised task driving
//! `openfeo_net::dns::DnsDriver` on every LAN bridge, reconfiguring it live as the WAN's
//! learned servers and the LAN leases change. Every line logged here is a contract with the
//! harness scenarios.

use std::sync::Arc;

use openfeo_net::dhcp4::DriverError;
use openfeo_net::dns::{DnsDriver, DnsDriverConfig, Listener};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_proto_dns::Name;
use openfeo_proto_dns::forwarder::Event;
use openfeo_reconcile::dns::{DesiredDns, desired, forwarder_config};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use tokio::time::Instant;
use tracing::{debug, info};

use crate::dhcp4::seed;

/// The salt of the clock fallback of [`seed`].
const SEED_SALT: u64 = 0x0044_4e53;

/// The one DNS task. It is started whatever the config: with no LAN to listen on it waits for
/// a config that has one.
pub fn spawn(supervisor: &Supervisor, _publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    let world_rx = world_rx.clone();
    supervisor.spawn("dns", move || {
        let world_rx = world_rx.clone();
        async move { run(world_rx).await }
    });
}

/// What a World asks of a forwarder that is serving `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Nothing,
    /// Other upstreams or local names: the core is reconfigured as it runs.
    Configure,
    /// Other LANs, or a LAN's other address: the sockets are bound again.
    Rebind,
}

fn change(current: &DesiredDns, next: &DesiredDns) -> Change {
    if next == current {
        Change::Nothing
    } else if next.listeners == current.listeners {
        Change::Configure
    } else {
        Change::Rebind
    }
}

/// The index of each listener's bridge once every one exists, or `None` when the LANs changed
/// first. A bridge need not have carrier: a LAN with no cable in must not keep DNS from the
/// others, and the sockets are bound to the device, which is there either way.
async fn bridges(
    world_rx: &mut WorldRx,
    current: &DesiredDns,
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
                        .get(&listener.ifname)
                        .map(|link| (listener.ifname.clone(), link.index))
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

/// The task: serve the LANs the World has, and when they change (a LAN added or removed, an
/// address moved) bind again from the start. That is not a failure: it is the config
/// changing, and it counts toward nothing.
async fn run(mut world_rx: WorldRx) -> Result<(), TaskError> {
    let mut waiting = false;
    loop {
        if desired(&world_rx.borrow_and_update()).listeners.is_empty() {
            if !waiting {
                info!("dns not started: no LAN to listen on");
                waiting = true;
            }
            world_rx
                .changed()
                .await
                .map_err(|_| "world publisher gone")?;
            continue;
        }
        waiting = false;
        serve(&mut world_rx).await?;
        info!("dns: the LANs changed; binding again");
    }
}

/// Serve until the LANs change: wait for every LAN bridge, run the driver, log what it says, and
/// follow the World. New upstreams or local names reconfigure the core live; a bridge recreated
/// is a failure the supervisor restarts.
async fn serve(world_rx: &mut WorldRx) -> Result<(), TaskError> {
    let mut current = desired(&world_rx.borrow());
    let Some(indexes) = bridges(world_rx, &current).await? else {
        return Ok(());
    };
    // The World moved on while the bridges came up: leases, a WAN lease.
    current = desired(&world_rx.borrow_and_update());
    let config = forwarder_config(&current);
    let local_names = config.local.len();
    let failed = |err: DriverError| TaskError::from(format!("dns: {err}"));
    let listeners: Vec<String> = current
        .listeners
        .iter()
        .map(|listener| listener.ifname.clone())
        .collect();
    let mut sockets = Vec::new();
    for listener in &current.listeners {
        sockets.push(Listener {
            ifname: listener.ifname.clone(),
            v6: false,
        });
        if !listener.address6.is_empty() {
            sockets.push(Listener {
                ifname: listener.ifname.clone(),
                v6: true,
            });
        }
    }
    let mut driver = DnsDriver::new(DnsDriverConfig {
        listeners: sockets,
        loopback: true,
        forwarder: config,
        seed: seed(SEED_SALT),
    })
    .map_err(failed)?;
    info!("dns listening on {}", listeners.join(", "));
    info!("{}", upstreams_line(&current));
    info!("dns local names {local_names}");
    let mut rebind = Throttle::new(NOISY_WINDOW);
    loop {
        tokio::select! {
            events = driver.step() => {
                for event in events.map_err(failed)? {
                    log_event(&event, &mut rebind);
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
                            // The bridge was recreated: the sockets are bound to the old one.
                            return Err(format!(
                                "dns: {ifname} changed index {index} -> {}; restarting",
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
                for event in driver.configure(forwarder_config(&next)) {
                    log_event(&event, &mut rebind);
                }
                for line in change_lines(&current, &next) {
                    info!("{line}");
                }
                current = next;
            }
        }
    }
}

/// One event to the console: rebinding drops at most once per window, since a LAN client can
/// provoke them at will.
fn log_event(event: &Event, rebind: &mut Throttle) {
    let Some(line) = event_line(event) else {
        return;
    };
    if !matches!(event, Event::RebindDropped { .. }) {
        info!("{line}");
    } else if let Some(line) = rebind.line(Instant::now(), &line) {
        info!("{line}");
    } else {
        debug!("{line}");
    }
}

/// What a change of the desired state says on the console: the upstreams line when the
/// upstreams or where they came from changed, the local-names line when their number did. A
/// change to anything else (a lease's address arriving before the route that lets its server
/// in, ADR-0019) says nothing, so "no upstreams" is announced once, not once per change.
fn change_lines(current: &DesiredDns, next: &DesiredDns) -> Vec<String> {
    let mut lines = Vec::new();
    if next.upstreams != current.upstreams
        || next.learned_from != current.learned_from
        || next.wan_upstreams != current.wan_upstreams
    {
        lines.push(upstreams_line(next));
    }
    let local_names = forwarder_config(next).local.len();
    if local_names != forwarder_config(current).local.len() {
        lines.push(format!("dns local names {local_names}"));
    }
    lines
}

/// `dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)`, or
/// `dns no upstreams: only local names resolve`.
fn upstreams_line(desired: &DesiredDns) -> String {
    if desired.upstreams.is_empty() {
        return "dns no upstreams: only local names resolve".to_owned();
    }
    let addrs: Vec<String> = desired.upstreams.iter().map(ToString::to_string).collect();
    let mut sources = Vec::new();
    if desired
        .upstreams
        .iter()
        .any(|upstream| !desired.wan_upstreams.contains(upstream))
        || desired.learned_from.is_none()
    {
        sources.push("configured".to_owned());
    }
    if let Some(wan) = &desired.learned_from {
        sources.push(format!("learned from {wan}"));
    }
    format!("dns upstreams {} ({})", addrs.join(" "), sources.join(", "))
}

/// The console contract for one event; `None` for the ones the upstreams line covers.
fn event_line(event: &Event) -> Option<String> {
    match event {
        Event::UpstreamDown(upstream) => Some(format!("dns upstream {upstream} down")),
        Event::UpstreamUp(upstream) => Some(format!("dns upstream {upstream} up")),
        Event::RebindDropped { name, addr, client } => Some(format!(
            "dns rebind dropped {} -> {addr} for {client}",
            plain(name)
        )),
        Event::Blocked { name, client } => {
            Some(format!("dns blocked {} for {client}", plain(name)))
        }
        Event::Configured { .. } | Event::NoUpstreams => None,
    }
}

/// A name as people write it, without the trailing dot.
fn plain(name: &Name) -> String {
    let text = name.to_string();
    if name.is_root() {
        text
    } else {
        text.trim_end_matches('.').to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{PortMap, PortMapEntry, file};
    use openfeo_world::World;
    use std::net::Ipv4Addr;

    const VM_STATIC: &str = include_str!("../../../harness/fixtures/vm-static.toml");

    /// The lab's static configuration on the lab's three ports: the WAN's port must be known
    /// for the WAN to be active and its servers learned.
    fn static_world() -> World {
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
        World::new(file::parse(VM_STATIC).unwrap(), ports)
    }

    #[test]
    fn upstream_lines_follow_the_contract() {
        let mut d = desired(&static_world());
        assert_eq!(
            upstreams_line(&d),
            "dns upstreams 203.0.113.1 (learned from wan0)"
        );
        d.upstreams.insert(0, Ipv4Addr::new(9, 9, 9, 9).into());
        assert_eq!(
            upstreams_line(&d),
            "dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)"
        );
        d.learned_from = None;
        d.upstreams = vec![Ipv4Addr::new(9, 9, 9, 9).into()];
        assert_eq!(upstreams_line(&d), "dns upstreams 9.9.9.9 (configured)");
        d.upstreams.clear();
        assert_eq!(
            upstreams_line(&d),
            "dns no upstreams: only local names resolve"
        );
    }

    /// A lease's address joins the desired state before its route lets the learned server in:
    /// that change says nothing about upstreams, and nothing about local names either.
    #[test]
    fn a_change_that_leaves_the_upstreams_alone_does_not_announce_them_again() {
        let before = desired(&static_world());
        let mut after = before.clone();
        after.wan_addrs.push(Ipv4Addr::new(203, 0, 113, 100).into());
        assert_eq!(change_lines(&before, &after), Vec::<String>::new());
        let mut learned = before.clone();
        learned
            .upstreams
            .insert(0, Ipv4Addr::new(9, 9, 9, 9).into());
        assert_eq!(
            change_lines(&before, &learned),
            vec!["dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)".to_owned()]
        );
        let mut named = before.clone();
        named.local.push(openfeo_reconcile::dns::DesiredLocalName {
            name: "nas".to_owned(),
            addr: Ipv4Addr::new(192, 168, 1, 10).into(),
        });
        let lines = change_lines(&before, &named);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("dns local names "), "{lines:?}");
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

    /// The static world with a second LAN, `lan1` on `p3` at `192.168.2.1/24`.
    fn two_lans() -> World {
        let mut world = static_world();
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

    #[test]
    fn a_lan_added_later_gets_a_listener() {
        let before = desired(&static_world());
        let after = desired(&two_lans());
        let names = |d: &DesiredDns| -> Vec<String> {
            d.listeners.iter().map(|l| l.ifname.clone()).collect()
        };
        assert_eq!(names(&before), ["br-lan0"]);
        assert_eq!(names(&after), ["br-lan0", "br-lan1"]);
        assert_eq!(change(&before, &after), Change::Rebind);
        assert_eq!(change(&after, &before), Change::Rebind);
    }

    #[test]
    fn only_a_change_of_lans_rebinds() {
        let before = desired(&static_world());
        assert_eq!(change(&before, &before), Change::Nothing);
        let mut learned = before.clone();
        learned
            .upstreams
            .insert(0, Ipv4Addr::new(9, 9, 9, 9).into());
        assert_eq!(change(&before, &learned), Change::Configure);
        let mut moved = before.clone();
        moved.listeners[0].address = Ipv4Addr::new(192, 168, 9, 1);
        assert_eq!(change(&before, &moved), Change::Rebind);
    }

    /// The bridges are waited for until they exist, not until something is plugged into each:
    /// a LAN with no cable in must not keep DNS from every other LAN.
    #[tokio::test(start_paused = true)]
    async fn the_bridges_are_awaited_without_their_carrier() {
        let (publisher, mut world_rx) = Publisher::new(two_lans());
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
        let found = waiting.await.unwrap().unwrap();
        assert_eq!(
            found,
            Some(vec![("br-lan0".to_owned(), 7), ("br-lan1".to_owned(), 8)])
        );
        // A change of LANs while waiting ends the wait: the task starts again from the new set.
        let (publisher, _) = Publisher::new(two_lans());
        world_rx = publisher.subscribe();
        let waiting = tokio::spawn(async move { bridges(&mut world_rx, &current).await });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let one = static_world().config.clone();
        publisher.update(|world| world.config = one);
        assert_eq!(waiting.await.unwrap().unwrap(), None);
    }

    /// A router with no LAN has nothing to listen on: the task waits for a config that has one
    /// (until now it was never started, and a LAN added later got no DNS).
    #[tokio::test(start_paused = true)]
    async fn a_router_with_no_lan_starts_dns_when_one_is_added() {
        let mut world = static_world();
        let mut config = (*world.config).clone();
        config.lans.clear();
        world.config = Arc::new(config);
        let (publisher, world_rx) = Publisher::new(world);
        let task = tokio::spawn(run(world_rx));
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert!(!task.is_finished(), "waiting for a LAN, not gone");
        // A LAN, and its bridge: the task goes on to bind, which cannot work here (no such
        // device, and port 53 is not ours); that it tried is the point.
        let with_lan = static_world().config.clone();
        publisher.update(|world| {
            world.config = with_lan;
            Arc::make_mut(&mut world.links).insert("br-lan0".to_owned(), link("br-lan0", 7, true));
        });
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the task went on once there was a LAN")
            .unwrap();
        let err = ended.expect_err("binding fails in a unit test").to_string();
        assert!(err.starts_with("dns: "), "{err}");
    }

    #[test]
    fn event_lines_follow_the_contract() {
        assert_eq!(
            event_line(&Event::UpstreamDown(Ipv4Addr::new(9, 9, 9, 9).into())),
            Some("dns upstream 9.9.9.9 down".into())
        );
        assert_eq!(
            event_line(&Event::UpstreamUp(Ipv4Addr::new(9, 9, 9, 9).into())),
            Some("dns upstream 9.9.9.9 up".into())
        );
        assert_eq!(
            event_line(&Event::RebindDropped {
                name: "evil.isp.example".parse().unwrap(),
                addr: Ipv4Addr::new(192, 168, 1, 5).into(),
                client: Ipv4Addr::new(192, 168, 1, 50).into(),
            }),
            Some("dns rebind dropped evil.isp.example -> 192.168.1.5 for 192.168.1.50".into())
        );
        assert_eq!(
            event_line(&Event::Configured {
                upstreams: 1,
                local: 2,
            }),
            None
        );
    }
}
