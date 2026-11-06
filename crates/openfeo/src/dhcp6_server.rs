// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The stateless DHCPv6 responder task (SPEC §7.3): one supervised task that answers
//! Information-Requests on every LAN bridge that advertises, each on its own task with the
//! router's DUID, the LAN's resolvers and the search domain, reconfigured live as the World
//! changes and stopped when the LAN stops advertising. Every line logged here is a contract
//! with the harness scenarios.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use openfeo_net::dhcp6::ServerSocket;
use openfeo_proto_dhcp4::identity::duid_ll;
use openfeo_proto_dhcp6::server::{Config, INFORMATION_REFRESH_TIME, reply};
use openfeo_reconcile::dhcp6_server::{DesiredResponder, desired};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::dhcp4::{DUID_PATH, load_or_create_duid, lowest_port_mac, wait_for_link};

/// The DHCPv6 message buffer.
const RECEIVE_BUFFER: usize = 1500;

/// The one responder task, when a LAN advertises.
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    if desired(&publisher.current()).is_empty() {
        info!("dhcp6-server not started: no LAN advertises");
        return;
    }
    let world_rx = world_rx.clone();
    supervisor.spawn("dhcp6-server", move || {
        let world_rx = world_rx.clone();
        async move { run(world_rx).await }
    });
}

/// One LAN's responder on its own task, told what to answer through a watch; `None` stops it.
/// Dropping the guard aborts the task.
struct Lan {
    tx: watch::Sender<Option<DesiredResponder>>,
    handle: JoinHandle<()>,
}

impl Drop for Lan {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn run(mut world_rx: WorldRx) -> Result<(), TaskError> {
    let duid = {
        let world = world_rx.borrow_and_update();
        let lowest = lowest_port_mac(&world).unwrap_or([0; 6]);
        match load_or_create_duid(Path::new(DUID_PATH), lowest) {
            Ok((duid, _)) => duid,
            Err(err) => {
                warn!("dhcp6-server: cannot keep {DUID_PATH}: {err}; using an unsaved DUID");
                duid_ll(lowest)
            }
        }
    };
    let mut lans: BTreeMap<String, Lan> = BTreeMap::new();
    loop {
        let wanted = desired(&world_rx.borrow_and_update());
        for responder in &wanted {
            match lans.get(&responder.ifname) {
                Some(lan) if !lan.handle.is_finished() => {
                    lan.tx.send_if_modified(|current| {
                        if current.as_ref() == Some(responder) {
                            false
                        } else {
                            *current = Some(responder.clone());
                            true
                        }
                    });
                }
                _ => {
                    let (tx, rx) = watch::channel(Some(responder.clone()));
                    let handle = tokio::spawn(lan_task(rx, world_rx.clone(), duid.clone()));
                    lans.insert(responder.ifname.clone(), Lan { tx, handle });
                }
            }
        }
        for (ifname, lan) in &lans {
            if !wanted.iter().any(|responder| &responder.ifname == ifname) {
                lan.tx.send_replace(None);
            }
        }
        lans.retain(|_, lan| !lan.handle.is_finished() || lan.tx.borrow().is_some());
        world_rx
            .changed()
            .await
            .map_err(|_| "world publisher gone")?;
    }
}

async fn lan_task(
    mut rx: watch::Receiver<Option<DesiredResponder>>,
    mut world_rx: WorldRx,
    duid: Vec<u8>,
) {
    let Some(responder) = rx.borrow().clone() else {
        return;
    };
    if let Err(err) = serve(&responder, &mut rx, &mut world_rx, duid).await {
        warn!("dhcp6-server {}: {err}", responder.ifname);
    }
}

async fn serve(
    responder: &DesiredResponder,
    rx: &mut watch::Receiver<Option<DesiredResponder>>,
    world_rx: &mut WorldRx,
    duid: Vec<u8>,
) -> Result<(), TaskError> {
    let (index, _mac) = loop {
        tokio::select! {
            link = wait_for_link(world_rx, &responder.ifname) => break link?,
            changed = rx.changed() => {
                if changed.is_err() || rx.borrow_and_update().is_none() {
                    return Ok(());
                }
            }
        }
    };
    let socket = ServerSocket::open(index, &responder.ifname)
        .map_err(|err| TaskError::from(format!("dhcp6-server {}: {err}", responder.ifname)))?;
    let mut current = rx
        .borrow_and_update()
        .clone()
        .unwrap_or_else(|| responder.clone());
    let mut config = server_config(&current, &duid);
    info!("{}", serving_line(&current));
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    loop {
        tokio::select! {
            received = socket.recv(&mut buf) => {
                let (from, len) = received
                    .map_err(|err| TaskError::from(format!("dhcp6-server {}: {err}", current.ifname)))?;
                if let Some(answer) = reply(&config, &buf[..len]) {
                    match socket.send_to(from, &answer) {
                        Ok(()) => debug!("dhcp6-server {} answered {}", current.ifname, from.ip()),
                        Err(err) => debug!("dhcp6-server {}: send to {from}: {err}", current.ifname),
                    }
                }
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let Some(next) = rx.borrow_and_update().clone() else {
                    info!("{}", stopped_line(&current.ifname));
                    return Ok(());
                };
                if next != current {
                    info!("{}", serving_line(&next));
                    config = server_config(&next, &duid);
                    current = next;
                }
            }
        }
    }
}

fn server_config(responder: &DesiredResponder, duid: &[u8]) -> Config {
    Config {
        duid: duid.to_vec(),
        dns: responder.dns.clone(),
        domains: vec![responder.domain.clone()],
        refresh_secs: INFORMATION_REFRESH_TIME,
    }
}

/// `dhcp6-server br-lan0 serving fd12:3456:789a:1::1,2001:db8:100:1::1 home.arpa`.
fn serving_line(responder: &DesiredResponder) -> String {
    format!(
        "dhcp6-server {} serving {} {}",
        responder.ifname,
        responder
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        responder.domain
    )
}

/// `dhcp6-server br-lan0 stopped`.
fn stopped_line(ifname: &str) -> String {
    format!("dhcp6-server {ifname} stopped")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responder() -> DesiredResponder {
        DesiredResponder {
            ifname: "br-lan0".to_owned(),
            lan: "lan0".to_owned(),
            dns: vec![
                "fd12:3456:789a:1::1".parse().unwrap(),
                "2001:db8:100:1::1".parse().unwrap(),
            ],
            domain: "home.arpa".to_owned(),
        }
    }

    #[test]
    fn lines_follow_the_contract() {
        assert_eq!(
            serving_line(&responder()),
            "dhcp6-server br-lan0 serving fd12:3456:789a:1::1,2001:db8:100:1::1 home.arpa"
        );
        assert_eq!(stopped_line("br-lan0"), "dhcp6-server br-lan0 stopped");
    }

    #[test]
    fn the_server_config_carries_the_duid_the_resolvers_and_the_domain() {
        let config = server_config(&responder(), &[0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
        assert_eq!(config.duid, vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
        assert_eq!(config.dns, responder().dns);
        assert_eq!(config.domains, vec!["home.arpa".to_owned()]);
        assert_eq!(config.refresh_secs, INFORMATION_REFRESH_TIME);
    }
}
