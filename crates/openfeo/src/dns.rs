// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DNS forwarder task (SPEC §7.7): one supervised task driving
//! `openfeo_net::dns::DnsDriver` on every LAN bridge, reconfiguring it live as the WAN's
//! learned servers and the LAN leases change. Every line logged here is a contract with the
//! harness scenarios.

use std::net::Ipv4Addr;
use std::sync::Arc;

use openfeo_net::dhcp4::DriverError;
use openfeo_net::dns::{DnsDriver, DnsDriverConfig};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_proto_dns::Name;
use openfeo_proto_dns::forwarder::Event;
use openfeo_reconcile::dns::{DesiredDns, desired, forwarder_config};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use tokio::time::Instant;
use tracing::{debug, info};

use crate::dhcp4::{seed, wait_for_link};

/// The salt of the clock fallback of [`seed`].
const SEED_SALT: u64 = 0x0044_4e53;

/// The one DNS task, when there is a LAN to listen on.
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    if desired(&publisher.current()).listeners.is_empty() {
        info!("dns not started: no LAN to listen on");
        return;
    }
    let world_rx = world_rx.clone();
    supervisor.spawn("dns", move || {
        let world_rx = world_rx.clone();
        async move { run(world_rx).await }
    });
}

/// The task: wait for every LAN bridge, run the driver, log what it says, and follow the World:
/// new upstreams or local names reconfigure the core live; a bridge recreated or a LAN added or
/// removed restarts the task so the sockets follow.
async fn run(mut world_rx: WorldRx) -> Result<(), TaskError> {
    let mut current = desired(&world_rx.borrow());
    let mut indexes = Vec::new();
    for listener in &current.listeners {
        let (index, _mac) = wait_for_link(&mut world_rx, &listener.ifname).await?;
        indexes.push((listener.ifname.clone(), index));
    }
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
    let mut driver = DnsDriver::new(DnsDriverConfig {
        listeners: listeners.clone(),
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
                if next == current {
                    continue;
                }
                if next.listeners != current.listeners {
                    return Err("dns: the LANs changed; restarting".into());
                }
                let config = forwarder_config(&next);
                let local_names = config.local.len();
                for event in driver.configure(config) {
                    log_event(&event, &mut rebind);
                }
                info!("{}", upstreams_line(&next));
                info!("dns local names {local_names}");
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

/// `dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)`, or
/// `dns no upstreams: only local names resolve`.
fn upstreams_line(desired: &DesiredDns) -> String {
    if desired.upstreams.is_empty() {
        return "dns no upstreams: only local names resolve".to_owned();
    }
    let addrs: Vec<String> = desired.upstreams.iter().map(Ipv4Addr::to_string).collect();
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
        d.upstreams.insert(0, Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(
            upstreams_line(&d),
            "dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)"
        );
        d.learned_from = None;
        d.upstreams = vec![Ipv4Addr::new(9, 9, 9, 9)];
        assert_eq!(upstreams_line(&d), "dns upstreams 9.9.9.9 (configured)");
        d.upstreams.clear();
        assert_eq!(
            upstreams_line(&d),
            "dns no upstreams: only local names resolve"
        );
    }

    #[test]
    fn event_lines_follow_the_contract() {
        assert_eq!(
            event_line(&Event::UpstreamDown(Ipv4Addr::new(9, 9, 9, 9))),
            Some("dns upstream 9.9.9.9 down".into())
        );
        assert_eq!(
            event_line(&Event::UpstreamUp(Ipv4Addr::new(9, 9, 9, 9))),
            Some("dns upstream 9.9.9.9 up".into())
        );
        assert_eq!(
            event_line(&Event::RebindDropped {
                name: "evil.isp.example".parse().unwrap(),
                addr: Ipv4Addr::new(192, 168, 1, 5).into(),
                client: Ipv4Addr::new(192, 168, 1, 50),
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
