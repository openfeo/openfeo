// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router-advertisement task (SPEC §7.3): one supervised task that runs an
//! `openfeo_proto_ndp::server::Server` on every LAN bridge that advertises, reconfiguring each
//! live as the World changes (the router lifetime most of all: 1800 while the WAN has an IPv6
//! route, 0 the moment it does not), and saying goodbye for a LAN that stops advertising. Every
//! line logged here is a contract with the harness scenarios.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use openfeo_net::ndp::{ALL_NODES, NdpSocket, Role};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_proto_ndp::server::{Config, Input, Output, Server};
use openfeo_reconcile::ra::{DesiredRa, desired};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dhcp4::{seed, wait_for_link};

/// The salt of the clock fallback of [`seed`].
const SEED_SALT: u64 = 0x0052_4144;
/// The ICMPv6 message buffer; advertisements and solicitations are far smaller.
const RECEIVE_BUFFER: usize = 1500;

/// The one advertisement task, when a LAN advertises.
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    if desired(&publisher.current()).is_empty() {
        info!("ra not started: no LAN advertises");
        return;
    }
    let world_rx = world_rx.clone();
    supervisor.spawn("ra", move || {
        let world_rx = world_rx.clone();
        async move { run(world_rx).await }
    });
}

/// One LAN's server, driven on its own task and told what to advertise through a watch; `None`
/// says goodbye.
struct Lan {
    tx: watch::Sender<Option<DesiredRa>>,
    handle: JoinHandle<()>,
}

/// The task: follow the World, start a server per advertising LAN, pass each change on, and
/// stop a server whose LAN left.
async fn run(mut world_rx: WorldRx) -> Result<(), TaskError> {
    let mut lans: BTreeMap<String, Lan> = BTreeMap::new();
    loop {
        let wanted = desired(&world_rx.borrow_and_update());
        for ra in &wanted {
            match lans.get(&ra.ifname) {
                Some(lan) if !lan.handle.is_finished() => {
                    lan.tx.send_if_modified(|current| {
                        if current.as_ref() == Some(ra) {
                            false
                        } else {
                            *current = Some(ra.clone());
                            true
                        }
                    });
                }
                _ => {
                    let (tx, rx) = watch::channel(Some(ra.clone()));
                    let handle = tokio::spawn(lan_task(rx, world_rx.clone()));
                    lans.insert(ra.ifname.clone(), Lan { tx, handle });
                }
            }
        }
        for (ifname, lan) in &lans {
            if !wanted.iter().any(|ra| &ra.ifname == ifname) {
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

/// The server of one LAN: wait for the bridge, open the socket, advertise, follow the watch.
async fn lan_task(mut rx: watch::Receiver<Option<DesiredRa>>, mut world_rx: WorldRx) {
    let Some(ra) = rx.borrow().clone() else {
        return;
    };
    if let Err(err) = serve(&ra, &mut rx, &mut world_rx).await {
        warn!("ra {}: {err}", ra.ifname);
    }
}

async fn serve(
    ra: &DesiredRa,
    rx: &mut watch::Receiver<Option<DesiredRa>>,
    world_rx: &mut WorldRx,
) -> Result<(), TaskError> {
    let (index, mac) = wait_for_link(world_rx, &ra.ifname).await?;
    let socket = NdpSocket::open(index, &ra.ifname, Role::Server)
        .map_err(|err| TaskError::from(format!("ra {}: {err}", ra.ifname)))?;
    let mut current = rx.borrow_and_update().clone().unwrap_or_else(|| ra.clone());
    let mut server = Server::new(server_config(&current, mac), seed(SEED_SALT));
    let start = Instant::now();
    let now = |start: Instant| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut sends = Throttle::new(NOISY_WINDOW);
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    info!("{}", started_line(&current));
    send_all(
        &socket,
        server.handle(Input::Start, now(start)),
        &mut sends,
        &current.ifname,
    );
    loop {
        let timer = server
            .next_timeout()
            .map(|at| start + Duration::from_millis(at));
        tokio::select! {
            received = socket.recv(&mut buf) => {
                let received = received.map_err(|err| TaskError::from(format!("ra {}: {err}", current.ifname)))?;
                let input = Input::Solicitation {
                    from: received.from,
                    hop_limit: received.hop_limit,
                    bytes: buf[..received.len].to_vec(),
                };
                send_all(&socket, server.handle(input, now(start)), &mut sends, &current.ifname);
            }
            () = wait_until(timer) => {
                let outputs = server.handle(Input::Timeout, now(start));
                let stopped = outputs.contains(&Output::Stopped);
                send_all(&socket, outputs, &mut sends, &current.ifname);
                if stopped {
                    info!("{}", stopped_line(&current.ifname));
                    return Ok(());
                }
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let next = rx.borrow_and_update().clone();
                let Some(next) = next else {
                    let outputs = server.handle(Input::Stop, now(start));
                    let stopped = outputs.contains(&Output::Stopped);
                    send_all(&socket, outputs, &mut sends, &current.ifname);
                    if stopped {
                        info!("{}", stopped_line(&current.ifname));
                        return Ok(());
                    }
                    continue;
                };
                if next.router_lifetime != current.router_lifetime {
                    info!("{}", lifetime_line(&next));
                }
                let outputs = server.handle(Input::Configure(server_config(&next, mac)), now(start));
                send_all(&socket, outputs, &mut sends, &current.ifname);
                current = next;
            }
        }
    }
}

/// Sleep until `at`, or forever when there is no timer.
async fn wait_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// What the core says to send, sent; a send that fails (the bridge has no link-local address
/// yet) is logged at most once per window, the core's next timer tries again.
fn send_all(socket: &NdpSocket, outputs: Vec<Output>, sends: &mut Throttle, ifname: &str) {
    for output in outputs {
        if let Output::Advertise(bytes) = output
            && let Err(err) = socket.send(ALL_NODES, &bytes)
        {
            let line = format!("ra {ifname}: send: {err}");
            if let Some(line) = sends.line(Instant::now(), &line) {
                warn!("{line}");
            } else {
                debug!("{line}");
            }
        }
    }
}

fn server_config(ra: &DesiredRa, mac: [u8; 6]) -> Config {
    Config {
        prefix: ra.prefix,
        mac,
        router: ra.router,
        mtu: ra.mtu,
        domain: ra.domain.clone(),
        router_lifetime: ra.router_lifetime,
    }
}

/// `ra br-lan0 advertising 2001:db8:1:222::/64 lifetime 1800`.
fn started_line(ra: &DesiredRa) -> String {
    format!(
        "ra {} advertising {} lifetime {}",
        ra.ifname, ra.prefix, ra.router_lifetime
    )
}

/// `ra br-lan0 lifetime 0 (wan0 has no ipv6 route)` or `ra br-lan0 lifetime 1800`.
fn lifetime_line(ra: &DesiredRa) -> String {
    if ra.router_lifetime == 0 {
        format!("ra {} lifetime 0 ({} has no ipv6 route)", ra.ifname, ra.wan)
    } else {
        format!("ra {} lifetime {}", ra.ifname, ra.router_lifetime)
    }
}

/// `ra br-lan0 stopped`.
fn stopped_line(ifname: &str) -> String {
    format!("ra {ifname} stopped")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ra(lifetime: u16) -> DesiredRa {
        DesiredRa {
            ifname: "br-lan0".to_owned(),
            wan: "wan0".to_owned(),
            prefix: "2001:db8:1:222::/64".parse().unwrap(),
            router: "2001:db8:1:222::1".parse().unwrap(),
            mtu: Some(1500),
            domain: "home.arpa".to_owned(),
            router_lifetime: lifetime,
        }
    }

    /// The console contract the harness scenarios match.
    #[test]
    fn ra_lines_follow_the_contract() {
        assert_eq!(
            started_line(&ra(1800)),
            "ra br-lan0 advertising 2001:db8:1:222::/64 lifetime 1800"
        );
        assert_eq!(
            lifetime_line(&ra(0)),
            "ra br-lan0 lifetime 0 (wan0 has no ipv6 route)"
        );
        assert_eq!(lifetime_line(&ra(1800)), "ra br-lan0 lifetime 1800");
        assert_eq!(stopped_line("br-lan0"), "ra br-lan0 stopped");
    }

    #[test]
    fn the_server_config_carries_the_desired_advertisement() {
        let config = server_config(&ra(1800), [1, 2, 3, 4, 5, 6]);
        assert_eq!(config.prefix.to_string(), "2001:db8:1:222::/64");
        assert_eq!(config.router.to_string(), "2001:db8:1:222::1");
        assert_eq!(config.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(config.mtu, Some(1500));
        assert_eq!(config.domain, "home.arpa");
        assert_eq!(config.router_lifetime, 1800);
    }
}
