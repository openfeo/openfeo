// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 server tasks (SPEC §7.6): one supervised task per `[lans.dhcp]` LAN, each driving
//! `openfeo_net::dhcp4_server::ServerDriver` on the LAN's bridge, publishing the leases as
//! World facts for the DNS forwarder and the panel, and keeping the lease database under
//! `/state/leases`, written at most once per five seconds (SPEC §5.2). Every line logged here
//! is a contract with the harness scenarios.

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::Ipv4Net;
use openfeo_config::load::STATE_FILE_MODE;
use openfeo_config::validate::parse_mac;
use openfeo_config::{Dhcp4ServerLease, Dhcp4ServerLeases, file};
use openfeo_net::dhcp4::DriverError;
use openfeo_net::dhcp4_server::{ServerDriver, ServerDriverConfig};
use openfeo_platform::atomic;
use openfeo_proto_dhcp4::identity::{from_hex, hex};
use openfeo_proto_dhcp4::server::Timestamp;
use openfeo_proto_dhcp4::{LeaseRecord, ServerEvent};
use openfeo_reconcile::bridge_name;
use openfeo_reconcile::dhcp::{DesiredDhcpServer, server_config, servers};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::{LeaseFact, MacAddr};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dhcp4::{LEASES_DIR, mac_text, wait_for_link};
use crate::throttle::{NOISY_WINDOW, Throttle};

/// The least time between two writes of a lease database (SPEC §5.2).
pub const SAVE_INTERVAL: Duration = Duration::from_secs(5);

/// The events after which the leases differ, so the facts and the database must follow.
pub(crate) fn changes_leases(event: &ServerEvent) -> bool {
    matches!(
        event,
        ServerEvent::Granted(_)
            | ServerEvent::Renewed(_)
            | ServerEvent::Released(_)
            | ServerEvent::Expired(_)
            | ServerEvent::Declined { .. }
    )
}

/// `/state/leases/dhcp4-server-<lan>.toml`.
#[must_use]
pub fn server_lease_path(lan: &str) -> PathBuf {
    Path::new(LEASES_DIR).join(format!("dhcp4-server-{lan}.toml"))
}

/// One task per LAN the configuration gives a DHCPv4 server.
pub fn spawn_all(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    for lan in servers(&publisher.current()).into_keys() {
        let publisher = publisher.clone();
        let world_rx = world_rx.clone();
        supervisor.spawn(format!("dhcp4-server-{lan}"), move || {
            let lan = lan.clone();
            let publisher = publisher.clone();
            let world_rx = world_rx.clone();
            async move { run(&lan, &publisher, world_rx).await }
        });
    }
}

/// The task: wait for the bridge, restore the lease database, run the driver, publish what it
/// says, write the database when it changes (at most once per [`SAVE_INTERVAL`]).
async fn run(lan: &str, publisher: &Publisher, mut world_rx: WorldRx) -> Result<(), TaskError> {
    let bridge = bridge_name(lan);
    let (ifindex, mac) = wait_for_link(&mut world_rx, &bridge).await?;
    let desired = servers(&world_rx.borrow()).remove(lan);
    let Some(desired) = desired else {
        info!("lan {lan} dhcp server not configured");
        return Ok(());
    };
    let path = server_lease_path(lan);
    let records = read_leases(&path, lan, 0, unix_now());
    let failed = |err: DriverError| TaskError::from(format!("dhcp4 server {lan}: {err}"));
    let mut driver = ServerDriver::new(ServerDriverConfig {
        ifname: bridge.clone(),
        ifindex,
        mac,
        server: server_config(&desired),
        leases: records.clone(),
    })
    .map_err(failed)?;
    info!("{}", serving_line(lan, &desired));
    if !records.is_empty() {
        info!("lan {lan} dhcp restored {} leases", records.len());
    }
    publish_facts(lan, &driver, publisher);
    let mut last_save: Option<Instant> = None;
    let mut save_at: Option<Instant> = None;
    let mut noisy = Throttle::new(NOISY_WINDOW);
    loop {
        tokio::select! {
            events = driver.step() => {
                for event in events.map_err(failed)? {
                    let line = event_line(lan, &event);
                    if matches!(event, ServerEvent::Exhausted { .. } | ServerEvent::Conflict { .. }) {
                        // A LAN can provoke these at packet rate: one per window on the console.
                        match noisy.admit(Instant::now()) {
                            Some(0) => info!("{line}"),
                            Some(held) => info!(
                                "{line} (and {held} more such lines in the last {}s)",
                                NOISY_WINDOW.as_secs()
                            ),
                            None => debug!("{line}"),
                        }
                    } else {
                        info!("{line}");
                    }
                    if changes_leases(&event) {
                        publish_facts(lan, &driver, publisher);
                        if save_at.is_none() {
                            save_at = Some(next_save(last_save, Instant::now()));
                        }
                    }
                }
            }
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                let index = world_rx
                    .borrow_and_update()
                    .links
                    .get(&bridge)
                    .map(|link| link.index);
                if let Some(index) = index
                    && index != ifindex
                {
                    // The bridge was recreated: the sockets are bound to the old index.
                    return Err(format!(
                        "dhcp4 server {lan}: {bridge} changed index {ifindex} -> {index}; restarting"
                    )
                    .into());
                }
            }
            () = sleep_until(save_at) => {
                save_leases(&path, lan, &driver);
                last_save = Some(Instant::now());
                save_at = None;
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// When the next write may happen: now, unless the last one was under [`SAVE_INTERVAL`] ago.
#[must_use]
pub fn next_save(last: Option<Instant>, now: Instant) -> Instant {
    last.map_or(now, |last| (last + SAVE_INTERVAL).max(now))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The file's leases for `lan` as the core's records: wall-clock times become the driver's
/// clock (`now` and `unix_now` are the same instant), expired ones are dropped, as is anything
/// that does not parse. Another LAN's file yields nothing.
#[must_use]
pub fn records_from_file(
    file: &Dhcp4ServerLeases,
    lan: &str,
    now: Timestamp,
    unix_now: u64,
) -> Vec<LeaseRecord> {
    if file.lan != lan {
        return Vec::new();
    }
    file.leases
        .iter()
        .filter(|lease| lease.expires_unix > unix_now)
        .filter_map(|lease| {
            Some(LeaseRecord {
                address: lease.address.parse().ok()?,
                mac: parse_mac(&lease.mac)?,
                client_id: if lease.client_id.is_empty() {
                    None
                } else {
                    Some(from_hex(&lease.client_id)?)
                },
                hostname: (!lease.hostname.is_empty()).then(|| lease.hostname.clone()),
                granted_at: now.saturating_sub(unix_now.saturating_sub(lease.granted_unix)),
                expires_at: now + (lease.expires_unix - unix_now),
            })
        })
        .collect()
}

/// The core's records as the file, with wall-clock times.
#[must_use]
pub fn file_from_records(
    lan: &str,
    records: &[LeaseRecord],
    now: Timestamp,
    unix_now: u64,
) -> Dhcp4ServerLeases {
    Dhcp4ServerLeases {
        lan: lan.to_owned(),
        leases: records
            .iter()
            .map(|record| Dhcp4ServerLease {
                mac: mac_text(record.mac),
                client_id: record.client_id.as_deref().map(hex).unwrap_or_default(),
                address: record.address.to_string(),
                hostname: record.hostname.clone().unwrap_or_default(),
                granted_unix: unix_now.saturating_sub(now.saturating_sub(record.granted_at)),
                expires_unix: unix_now + record.expires_at.saturating_sub(now),
            })
            .collect(),
    }
}

/// The records as facts, ascending by address, with wall-clock expiry.
#[must_use]
pub fn facts_from(records: &[LeaseRecord], now: Timestamp, unix_now: u64) -> Vec<LeaseFact> {
    let mut facts: Vec<LeaseFact> = records
        .iter()
        .map(|record| LeaseFact {
            address: record.address,
            mac: MacAddr(record.mac),
            hostname: record.hostname.clone(),
            expires_unix: unix_now + record.expires_at.saturating_sub(now),
        })
        .collect();
    facts.sort_by_key(|fact| fact.address);
    facts
}

fn read_leases(path: &Path, lan: &str, now: Timestamp, unix_now: u64) -> Vec<LeaseRecord> {
    match fs::read_to_string(path) {
        Ok(text) => match file::parse_dhcp4_server_leases(&text) {
            Ok(leases) => records_from_file(&leases, lan, now, unix_now),
            Err(err) => {
                warn!(
                    "lan {lan} dhcp ignoring unreadable lease database {}: {err}",
                    path.display()
                );
                Vec::new()
            }
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => {
            warn!("lan {lan} dhcp cannot read {}: {err}", path.display());
            Vec::new()
        }
    }
}

fn save_leases(path: &Path, lan: &str, driver: &ServerDriver) {
    let leases = file_from_records(lan, &driver.leases(), driver.now(), unix_now());
    let result = file::render_dhcp4_server_leases(&leases)
        .map_err(|err| io::Error::other(err.to_string()))
        .and_then(|text| {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            atomic::write(path, text.as_bytes(), STATE_FILE_MODE)
        });
    match result {
        Ok(()) => debug!(
            "lan {lan} dhcp {} leases saved to {}",
            leases.leases.len(),
            path.display()
        ),
        Err(err) => warn!(
            "lan {lan} dhcp cannot save leases to {}: {err}",
            path.display()
        ),
    }
}

fn publish_facts(lan: &str, driver: &ServerDriver, publisher: &Publisher) {
    let facts = facts_from(&driver.leases(), driver.now(), unix_now());
    publisher.update(|world| {
        Arc::make_mut(&mut world.leases).insert(lan.to_owned(), facts);
    });
}

/// `lan lan0 dhcp serving 192.168.1.0/24 pool 192.168.1.100-192.168.1.200 statics=1 lease=43200s`.
fn serving_line(lan: &str, desired: &DesiredDhcpServer) -> String {
    let network = Ipv4Net::new(desired.server, desired.prefix).map_or_else(
        |_| desired.server.to_string(),
        |net| net.trunc().to_string(),
    );
    format!(
        "lan {lan} dhcp serving {network} pool {}-{} statics={} lease={}s",
        desired.pool.0,
        desired.pool.1,
        desired.reservations.len(),
        desired.lease_secs
    )
}

/// The console contract for one event.
fn event_line(lan: &str, event: &ServerEvent) -> String {
    let at =
        |address: Ipv4Addr, mac: [u8; 6], word: &str| format!("{address} {word} {}", mac_text(mac));
    match event {
        ServerEvent::Offered { address, mac } => {
            format!("lan {lan} dhcp offer {}", at(*address, *mac, "to"))
        }
        ServerEvent::Granted(record) => format!(
            "lan {lan} dhcp lease granted {} host={} lease={}s",
            at(record.address, record.mac, "to"),
            record.hostname.as_deref().unwrap_or("-"),
            record.expires_at.saturating_sub(record.granted_at)
        ),
        ServerEvent::Renewed(record) => format!(
            "lan {lan} dhcp lease renewed {}",
            at(record.address, record.mac, "to")
        ),
        ServerEvent::Nak {
            address,
            mac,
            reason,
        } => format!("lan {lan} dhcp nak {} ({reason})", at(*address, *mac, "to")),
        ServerEvent::Informed { address, mac } => {
            format!("lan {lan} dhcp inform {}", at(*address, *mac, "from"))
        }
        ServerEvent::Released(record) => format!(
            "lan {lan} dhcp lease released {}",
            at(record.address, record.mac, "by")
        ),
        ServerEvent::Declined { address, mac } => {
            format!("lan {lan} dhcp declined {}", at(*address, *mac, "by"))
        }
        ServerEvent::Expired(record) => format!(
            "lan {lan} dhcp lease expired {}",
            at(record.address, record.mac, "of")
        ),
        ServerEvent::Conflict { address, mac } => format!(
            "lan {lan} dhcp conflict {}",
            at(*address, *mac, "answered by")
        ),
        ServerEvent::Exhausted { mac } => {
            format!("lan {lan} dhcp pool exhausted for {}", mac_text(*mac))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{Dhcp4ServerLease, Dhcp4ServerLeases, PortMap, file};
    use openfeo_proto_dhcp4::{NakReason, Reservation, Server, ServerConfig};
    use openfeo_reconcile::dhcp::servers;
    use openfeo_world::{LeaseFact, MacAddr, World};

    const VM_STATIC: &str = include_str!("../../../harness/fixtures/vm-static.toml");
    const MAC: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0x10, 0x10];
    const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 0x0b];

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn static_world() -> World {
        World::new(file::parse(VM_STATIC).unwrap(), PortMap::default())
    }

    fn config() -> ServerConfig {
        ServerConfig {
            server: ip("192.168.1.1"),
            prefix: 24,
            pool: (ip("192.168.1.100"), ip("192.168.1.200")),
            lease_secs: 43_200,
            dns: vec![],
            domain: Some("home.arpa".into()),
            reservations: vec![Reservation {
                mac: MAC,
                client_id: None,
                address: ip("192.168.1.10"),
                hostname: Some("nas".into()),
            }],
        }
    }

    /// Review finding: a DECLINE removes the lease in the core, so the facts and the database
    /// must follow, as for every other lease change.
    #[test]
    fn every_event_that_changes_the_leases_republishes_and_saves() {
        let record = LeaseRecord {
            address: ip("192.168.1.100"),
            mac: MAC_A,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at: 43_200,
        };
        for event in [
            ServerEvent::Granted(record.clone()),
            ServerEvent::Renewed(record.clone()),
            ServerEvent::Released(record.clone()),
            ServerEvent::Expired(record),
            ServerEvent::Declined {
                address: ip("192.168.1.100"),
                mac: MAC_A,
            },
        ] {
            assert!(changes_leases(&event), "{event:?}");
        }
        for event in [
            ServerEvent::Offered {
                address: ip("192.168.1.100"),
                mac: MAC_A,
            },
            ServerEvent::Nak {
                address: ip("192.168.1.100"),
                mac: MAC_A,
                reason: NakReason::InUse,
            },
            ServerEvent::Informed {
                address: ip("192.168.1.50"),
                mac: MAC_A,
            },
            ServerEvent::Conflict {
                address: ip("192.168.1.100"),
                mac: MAC_B,
            },
            ServerEvent::Exhausted { mac: MAC_A },
        ] {
            assert!(!changes_leases(&event), "{event:?}");
        }
    }

    #[test]
    fn lease_file_round_trips_through_records_with_wall_clock_conversion() {
        let records = vec![LeaseRecord {
            address: ip("192.168.1.10"),
            mac: MAC,
            client_id: Some(vec![0xff, 1, 2]),
            hostname: Some("nas".into()),
            granted_at: 100,
            expires_at: 43_300,
        }];
        let file = file_from_records("lan0", &records, 200, 1_800_000_200);
        assert_eq!(file.lan, "lan0");
        assert_eq!(
            file.leases[0],
            Dhcp4ServerLease {
                mac: "52:54:00:fe:10:10".into(),
                client_id: "ff0102".into(),
                address: "192.168.1.10".into(),
                hostname: "nas".into(),
                granted_unix: 1_800_000_100,
                expires_unix: 1_800_043_300,
            }
        );
        assert_eq!(
            records_from_file(&file, "lan0", 0, 1_800_000_200),
            vec![LeaseRecord {
                granted_at: 0,
                expires_at: 43_100,
                ..records[0].clone()
            }]
        );
    }

    #[test]
    fn restored_leases_outside_the_subnet_or_expired_are_dropped() {
        let lease = |mac: &str, address: &str, expires_unix| Dhcp4ServerLease {
            mac: mac.into(),
            address: address.into(),
            expires_unix,
            ..Default::default()
        };
        let file = Dhcp4ServerLeases {
            lan: "lan0".into(),
            leases: vec![
                lease("52:54:00:fe:10:10", "192.168.1.10", 1_800_000_000),
                lease("52:54:00:fe:10:11", "10.0.0.5", 1_800_009_000),
                lease("nope", "192.168.1.12", 1_800_009_000),
                lease("52:54:00:fe:10:13", "192.168.1.113", 1_800_009_000),
            ],
        };
        let records = records_from_file(&file, "lan0", 50, 1_800_000_100);
        assert_eq!(
            records
                .iter()
                .map(|r| r.address.to_string())
                .collect::<Vec<_>>(),
            vec!["10.0.0.5", "192.168.1.113"],
            "the file keeps what parses and has not expired; the subnet and pool checks are Server::new's"
        );
        assert_eq!(
            Server::new(config(), records, 50).leases().len(),
            1,
            "Server::new drops 10.0.0.5"
        );
        assert_eq!(
            records_from_file(&file, "lan1", 50, 1_800_000_100),
            Vec::new(),
            "another LAN's file is ignored"
        );
    }

    #[test]
    fn saves_are_at_most_one_per_interval() {
        let t0 = Instant::now();
        assert_eq!(next_save(None, t0), t0);
        assert_eq!(
            next_save(Some(t0), t0 + Duration::from_secs(1)),
            t0 + SAVE_INTERVAL
        );
        assert_eq!(
            next_save(Some(t0), t0 + Duration::from_secs(9)),
            t0 + Duration::from_secs(9)
        );
    }

    #[test]
    fn console_lines_follow_the_contract() {
        let record = LeaseRecord {
            address: ip("192.168.1.100"),
            mac: MAC_A,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at: 43_200,
        };
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Offered {
                    address: ip("192.168.1.100"),
                    mac: MAC_A
                }
            ),
            "lan lan0 dhcp offer 192.168.1.100 to 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line("lan0", &ServerEvent::Granted(record.clone())),
            "lan lan0 dhcp lease granted 192.168.1.100 to 02:00:00:00:00:0a host=- lease=43200s"
        );
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Granted(LeaseRecord {
                    hostname: Some("nas".into()),
                    ..record.clone()
                })
            ),
            "lan lan0 dhcp lease granted 192.168.1.100 to 02:00:00:00:00:0a host=nas lease=43200s"
        );
        assert_eq!(
            event_line("lan0", &ServerEvent::Renewed(record.clone())),
            "lan lan0 dhcp lease renewed 192.168.1.100 to 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Nak {
                    address: ip("192.168.1.77"),
                    mac: MAC_A,
                    reason: NakReason::OutsidePool
                }
            ),
            "lan lan0 dhcp nak 192.168.1.77 to 02:00:00:00:00:0a (outside pool)"
        );
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Informed {
                    address: ip("192.168.1.50"),
                    mac: MAC_A
                }
            ),
            "lan lan0 dhcp inform 192.168.1.50 from 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line("lan0", &ServerEvent::Released(record.clone())),
            "lan lan0 dhcp lease released 192.168.1.100 by 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Declined {
                    address: ip("192.168.1.100"),
                    mac: MAC_A
                }
            ),
            "lan lan0 dhcp declined 192.168.1.100 by 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line("lan0", &ServerEvent::Expired(record)),
            "lan lan0 dhcp lease expired 192.168.1.100 of 02:00:00:00:00:0a"
        );
        assert_eq!(
            event_line(
                "lan0",
                &ServerEvent::Conflict {
                    address: ip("192.168.1.100"),
                    mac: MAC_B
                }
            ),
            "lan lan0 dhcp conflict 192.168.1.100 answered by 02:00:00:00:00:0b"
        );
        assert_eq!(
            event_line("lan0", &ServerEvent::Exhausted { mac: MAC_A }),
            "lan lan0 dhcp pool exhausted for 02:00:00:00:00:0a"
        );
        let desired = &servers(&static_world())["lan0"];
        assert_eq!(
            serving_line("lan0", desired),
            "lan lan0 dhcp serving 192.168.1.0/24 pool 192.168.1.100-192.168.1.200 statics=1 lease=43200s"
        );
    }

    #[test]
    fn facts_carry_wall_clock_expiry_sorted_by_address() {
        let records = vec![
            LeaseRecord {
                address: ip("192.168.1.120"),
                mac: MAC_B,
                client_id: None,
                hostname: None,
                granted_at: 0,
                expires_at: 300,
            },
            LeaseRecord {
                address: ip("192.168.1.10"),
                mac: MAC_A,
                client_id: None,
                hostname: Some("nas".into()),
                granted_at: 0,
                expires_at: 500,
            },
        ];
        let facts = facts_from(&records, 100, 1_800_000_000);
        assert_eq!(
            facts[0],
            LeaseFact {
                address: ip("192.168.1.10"),
                mac: MacAddr(MAC_A),
                hostname: Some("nas".into()),
                expires_unix: 1_800_000_400
            }
        );
        assert_eq!(facts[1].expires_unix, 1_800_000_200);
        assert_eq!(
            server_lease_path("lan0").to_str(),
            Some("/state/leases/dhcp4-server-lan0.toml")
        );
    }
}
