// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router-advertisement task (SPEC §7.3): one supervised task that runs an
//! `openfeo_proto_ndp::server::Server` on every LAN bridge that advertises, reconfiguring each
//! live as the World changes (the router lifetime most of all: 1800 while the WAN has an IPv6
//! route, 0 the moment it does not; the prefixes as delegations come, go and deprecate), and
//! saying goodbye for a LAN that stops advertising. Lifetimes travel to the core as deadlines
//! on the process clock, so every advertisement carries what is left. Every line logged here
//! is a contract with the harness scenarios.

use std::collections::BTreeMap;
use std::sync::Arc;

use openfeo_net::ndp::{ALL_NODES, NdpSocket, Resend, Role, tentative_link_local};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_proto_ndp::server::{
    Config, Input, Lifetime, Output, PIO_PREFERRED, PIO_VALID, Pio, ROUTE_INFO_LIFETIME, Rio,
    Server,
};
use openfeo_proto_ndp::wire::Preference;
use openfeo_reconcile::lan6::Source;
use openfeo_reconcile::ra::{
    DEPRECATION_SECS, DesiredPio, DesiredRa, PioLifetimes, desired, wanted,
};
use openfeo_runtime::clock;
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
/// Milliseconds per second, for deadlines.
const MS: u64 = 1000;

/// The one advertisement task, when a LAN advertises.
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    if !wanted(&publisher.current()) {
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
/// says goodbye. Dropping the guard aborts the task, so nothing outlives the task that spawned
/// it (#28).
struct Lan {
    tx: watch::Sender<Option<DesiredRa>>,
    handle: JoinHandle<()>,
}

impl Drop for Lan {
    fn drop(&mut self) {
        self.handle.abort();
    }
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
    // A LAN told to stop before its bridge ever came up has nothing to say goodbye for (#28).
    let (index, mac) = loop {
        tokio::select! {
            link = wait_for_link(world_rx, &ra.ifname) => break link?,
            changed = rx.changed() => {
                if changed.is_err() || rx.borrow_and_update().is_none() {
                    return Ok(());
                }
            }
        }
    };
    let socket = NdpSocket::open(index, &ra.ifname, Role::Server)
        .map_err(|err| TaskError::from(format!("ra {}: {err}", ra.ifname)))?;
    let mut current = rx.borrow_and_update().clone().unwrap_or_else(|| ra.clone());
    let mut server = Server::new(server_config(&current, mac), seed(SEED_SALT));
    let mut sends = Throttle::new(NOISY_WINDOW);
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    info!("{}", started_line(&current));
    let mut pending = send_all(
        &socket,
        server.handle(Input::Start, clock::uptime_ms()),
        &mut sends,
        &current.ifname,
    );
    loop {
        let timer = server
            .next_timeout()
            .map(|at| Instant::from_std(clock::instant_at(at)));
        tokio::select! {
            () = wait_until(pending.as_ref().map(|resend| resend.at)) => {
                // The bridge's link-local address was tentative a second ago (#34).
                if let Some(resend) = pending.take() {
                    match resend.retry(&socket) {
                        Ok(next) => pending = next,
                        Err(err) => warn!("ra {}: send: {err}", current.ifname),
                    }
                }
            }
            received = socket.recv(&mut buf) => {
                let received = received.map_err(|err| TaskError::from(format!("ra {}: {err}", current.ifname)))?;
                let input = Input::Solicitation {
                    from: received.from,
                    hop_limit: received.hop_limit,
                    bytes: buf[..received.len].to_vec(),
                };
                pending = send_all(&socket, server.handle(input, clock::uptime_ms()), &mut sends, &current.ifname).or(pending);
            }
            () = wait_until(timer) => {
                let outputs = server.handle(Input::Timeout, clock::uptime_ms());
                let stopped = outputs.contains(&Output::Stopped);
                pending = send_all(&socket, outputs, &mut sends, &current.ifname).or(pending);
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
                    let outputs = server.handle(Input::Stop, clock::uptime_ms());
                    let stopped = outputs.contains(&Output::Stopped);
                    send_all(&socket, outputs, &mut sends, &current.ifname);
                    if stopped {
                        info!("{}", stopped_line(&current.ifname));
                        return Ok(());
                    }
                    continue;
                };
                for line in change_lines(&current, &next) {
                    info!("{line}");
                }
                let outputs = server.handle(Input::Configure(server_config(&next, mac)), clock::uptime_ms());
                pending = send_all(&socket, outputs, &mut sends, &current.ifname).or(pending);
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

/// What the core says to send, sent. A send refused while the bridge's link-local address is
/// tentative comes back as a [`Resend`] for the loop to retry in a second (#34); any other
/// failure is logged at most once per window, and the core's next timer tries again.
fn send_all(
    socket: &NdpSocket,
    outputs: Vec<Output>,
    sends: &mut Throttle,
    ifname: &str,
) -> Option<Resend> {
    let mut pending = None;
    for output in outputs {
        if let Output::Advertise(bytes) = output
            && let Err(err) = socket.send(ALL_NODES, &bytes)
        {
            if tentative_link_local(&err) {
                debug!("ra {ifname}: send: {err}; again in a second");
                pending = Some(Resend::new(ALL_NODES, bytes));
                continue;
            }
            let line = format!("ra {ifname}: send: {err}");
            if let Some(line) = sends.line(Instant::now(), &line) {
                warn!("{line}");
            } else {
                debug!("{line}");
            }
        }
    }
    pending
}

/// The core's configuration: the bridge's MAC as the World knows it, or the one the link had
/// when the task started; every prefix with its lifetimes as deadlines on the process clock.
fn server_config(ra: &DesiredRa, mac: [u8; 6]) -> Config {
    Config {
        prefixes: ra.prefixes.iter().map(pio).collect(),
        mac: ra.mac.map_or(mac, |mac| mac.0),
        rdnss: ra.rdnss.clone(),
        mtu: ra.mtu,
        domain: ra.domain.clone(),
        router_lifetime: ra.router_lifetime,
        other: ra.other,
        routes: ra
            .routes
            .iter()
            .map(|prefix| Rio {
                prefix: *prefix,
                lifetime: ROUTE_INFO_LIFETIME,
                preference: Preference::Medium,
            })
            .collect(),
    }
}

/// `obtained + secs` as a deadline, or `None` for an infinite lifetime.
fn deadline(obtained_ms: u64, secs: u32) -> Option<u64> {
    (secs != u32::MAX).then(|| obtained_ms.saturating_add(u64::from(secs) * MS))
}

/// One prefix's lifetimes (SPEC §7.3): the defaults for a routed or ULA prefix; what is left of
/// the delegation, capped at the defaults, for one in force (RFC 7084 L-13); preferred 0 and
/// valid the lower of the remainder and two hours for a stale one; preferred 0 and valid
/// counting down to the deadline for one being deprecated.
fn pio(desired: &DesiredPio) -> Pio {
    let (valid, preferred) = match desired.lifetimes {
        PioLifetimes::Static => (Lifetime::Fixed(PIO_VALID), Lifetime::Fixed(PIO_PREFERRED)),
        PioLifetimes::FromDelegation {
            obtained_ms,
            preferred_secs,
            valid_secs,
        } => (
            deadline(obtained_ms, valid_secs).map_or(Lifetime::Fixed(PIO_VALID), |at| {
                Lifetime::Until { at, cap: PIO_VALID }
            }),
            deadline(obtained_ms, preferred_secs).map_or(Lifetime::Fixed(PIO_PREFERRED), |at| {
                Lifetime::Until {
                    at,
                    cap: PIO_PREFERRED,
                }
            }),
        ),
        PioLifetimes::Stale {
            obtained_ms,
            valid_secs,
        } => (
            deadline(obtained_ms, valid_secs).map_or(Lifetime::Fixed(DEPRECATION_SECS), |at| {
                Lifetime::Until {
                    at,
                    cap: DEPRECATION_SECS,
                }
            }),
            Lifetime::Fixed(0),
        ),
        PioLifetimes::Deprecated { until_ms } => (
            Lifetime::Until {
                at: until_ms,
                cap: DEPRECATION_SECS,
            },
            Lifetime::Fixed(0),
        ),
    };
    Pio {
        prefix: desired.prefix,
        valid,
        preferred,
    }
}

/// `2001:db8:100:1::/64 (wan0 delegation), fd12:3456:789a:1::/64 (ula)`: each prefix with
/// where it came from, `(routed)`, `(<wan> delegation)`, `(ula)` or `(deprecated)`.
fn prefixes_text(ra: &DesiredRa) -> String {
    ra.prefixes
        .iter()
        .map(|pio| {
            let origin = match (&pio.lifetimes, &pio.source) {
                (PioLifetimes::Deprecated { .. }, _) => "deprecated".to_owned(),
                (_, Source::Routed) => "routed".to_owned(),
                (_, Source::Delegated { wan, .. }) => format!("{wan} delegation"),
                (_, Source::Ula) => "ula".to_owned(),
            };
            format!("{} ({origin})", pio.prefix)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `ra br-lan0 advertising 2001:db8:1:222::/64 (routed), fd12:3456:789a:1::/64 (ula) lifetime 1800`.
fn started_line(ra: &DesiredRa) -> String {
    format!(
        "ra {} advertising {} lifetime {}",
        ra.ifname,
        prefixes_text(ra),
        ra.router_lifetime
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

/// `ra br-lan0 deprecating 2001:db8:200:1::/64`.
fn deprecating_line(ifname: &str, pio: &DesiredPio) -> String {
    format!("ra {ifname} deprecating {}", pio.prefix)
}

/// `ra br-lan0 stopped`.
fn stopped_line(ifname: &str) -> String {
    format!("ra {ifname} stopped")
}

/// The console lines a change from `current` to `next` deserves: the lifetime when it changed,
/// each prefix that is newly deprecated, and the prefix list when it changed in any other way.
fn change_lines(current: &DesiredRa, next: &DesiredRa) -> Vec<String> {
    let mut lines = Vec::new();
    if next.router_lifetime != current.router_lifetime {
        lines.push(lifetime_line(next));
    }
    let was_deprecated = |pio: &DesiredPio| {
        current.prefixes.iter().any(|old| {
            old.prefix == pio.prefix && matches!(old.lifetimes, PioLifetimes::Deprecated { .. })
        })
    };
    let mut deprecated = false;
    for pio in &next.prefixes {
        if matches!(pio.lifetimes, PioLifetimes::Deprecated { .. }) && !was_deprecated(pio) {
            lines.push(deprecating_line(&next.ifname, pio));
            deprecated = true;
        }
    }
    let same_set = current.prefixes.len() == next.prefixes.len()
        && current
            .prefixes
            .iter()
            .zip(&next.prefixes)
            .all(|(a, b)| a.prefix == b.prefix && a.source == b.source);
    if !same_set || deprecated {
        lines.push(started_line(next));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn ra(lifetime: u16) -> DesiredRa {
        DesiredRa {
            ifname: "br-lan0".to_owned(),
            wan: "wan0".to_owned(),
            lan: "lan0".to_owned(),
            prefixes: vec![
                DesiredPio {
                    prefix: net("2001:db8:100:1::/64"),
                    source: Source::Delegated {
                        wan: "wan0".to_owned(),
                        parent: net("2001:db8:100::/56"),
                    },
                    lifetimes: PioLifetimes::FromDelegation {
                        obtained_ms: 10_000,
                        preferred_secs: 40,
                        valid_secs: 60,
                    },
                },
                DesiredPio {
                    prefix: net("fd12:3456:789a:1::/64"),
                    source: Source::Ula,
                    lifetimes: PioLifetimes::Static,
                },
            ],
            rdnss: vec![
                "fd12:3456:789a:1::1".parse().unwrap(),
                "2001:db8:100:1::1".parse().unwrap(),
            ],
            mac: None,
            mtu: Some(1500),
            domain: "home.arpa".to_owned(),
            router_lifetime: lifetime,
            other: true,
            routes: vec![net("fd12:3456:789a::/48"), net("2001:db8:100::/56")],
        }
    }

    fn deprecated(until_ms: u64) -> DesiredPio {
        DesiredPio {
            prefix: net("2001:db8:200:1::/64"),
            source: Source::Delegated {
                wan: "wan0".to_owned(),
                parent: net("2001:db8:200::/56"),
            },
            lifetimes: PioLifetimes::Deprecated { until_ms },
        }
    }

    /// The console contract the harness scenarios match.
    #[test]
    fn ra_lines_follow_the_contract() {
        assert_eq!(
            started_line(&ra(1800)),
            "ra br-lan0 advertising 2001:db8:100:1::/64 (wan0 delegation), fd12:3456:789a:1::/64 (ula) lifetime 1800"
        );
        let mut routed = ra(1800);
        routed.prefixes[0] = DesiredPio {
            prefix: net("2001:db8:1:222::/64"),
            source: Source::Routed,
            lifetimes: PioLifetimes::Static,
        };
        assert_eq!(
            started_line(&routed),
            "ra br-lan0 advertising 2001:db8:1:222::/64 (routed), fd12:3456:789a:1::/64 (ula) lifetime 1800"
        );
        assert_eq!(
            lifetime_line(&ra(0)),
            "ra br-lan0 lifetime 0 (wan0 has no ipv6 route)"
        );
        assert_eq!(lifetime_line(&ra(1800)), "ra br-lan0 lifetime 1800");
        assert_eq!(
            deprecating_line("br-lan0", &deprecated(70_000)),
            "ra br-lan0 deprecating 2001:db8:200:1::/64"
        );
        assert_eq!(stopped_line("br-lan0"), "ra br-lan0 stopped");
    }

    #[test]
    fn a_change_says_what_changed() {
        assert_eq!(change_lines(&ra(1800), &ra(1800)), Vec::<String>::new());
        assert_eq!(
            change_lines(&ra(1800), &ra(0)),
            vec!["ra br-lan0 lifetime 0 (wan0 has no ipv6 route)".to_owned()]
        );
        let mut gone = ra(1800);
        gone.prefixes.push(deprecated(70_000));
        assert_eq!(
            change_lines(&ra(1800), &gone),
            vec![
                "ra br-lan0 deprecating 2001:db8:200:1::/64".to_owned(),
                "ra br-lan0 advertising 2001:db8:100:1::/64 (wan0 delegation), fd12:3456:789a:1::/64 (ula), 2001:db8:200:1::/64 (deprecated) lifetime 1800".to_owned(),
            ]
        );
        assert_eq!(
            change_lines(&gone, &gone),
            Vec::<String>::new(),
            "a prefix already deprecated is not announced again"
        );
        let mut renewed = ra(1800);
        renewed.prefixes[0].lifetimes = PioLifetimes::FromDelegation {
            obtained_ms: 20_000,
            preferred_secs: 40,
            valid_secs: 60,
        };
        assert_eq!(
            change_lines(&ra(1800), &renewed),
            Vec::<String>::new(),
            "a renewal changes lifetimes, not the list"
        );
    }

    #[test]
    fn delegation_lifetimes_are_remainders_capped_and_never_negative() {
        let config = server_config(&ra(1800), [1, 2, 3, 4, 5, 6]);
        assert_eq!(config.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(config.mtu, Some(1500));
        assert_eq!(config.domain, "home.arpa");
        assert_eq!(config.router_lifetime, 1800);
        assert!(config.other);
        assert_eq!(config.rdnss.len(), 2);
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].lifetime, ROUTE_INFO_LIFETIME);
        let delegated = &config.prefixes[0];
        assert_eq!(
            delegated.valid,
            Lifetime::Until {
                at: 70_000,
                cap: PIO_VALID
            }
        );
        assert_eq!(
            delegated.preferred,
            Lifetime::Until {
                at: 50_000,
                cap: PIO_PREFERRED
            }
        );
        assert_eq!(delegated.valid.secs(20_000), 50);
        assert_eq!(delegated.preferred.secs(20_000), 30);
        assert_eq!(delegated.valid.secs(80_000), 0, "never negative");
        assert_eq!(config.prefixes[1].valid, Lifetime::Fixed(PIO_VALID));
        assert_eq!(config.prefixes[1].preferred, Lifetime::Fixed(PIO_PREFERRED));
        let mut infinite = ra(1800);
        infinite.prefixes[0].lifetimes = PioLifetimes::FromDelegation {
            obtained_ms: 10_000,
            preferred_secs: u32::MAX,
            valid_secs: u32::MAX,
        };
        let config = server_config(&infinite, [0; 6]);
        assert_eq!(
            config.prefixes[0].valid,
            Lifetime::Fixed(PIO_VALID),
            "capped"
        );
        let mut stale = ra(0);
        stale.prefixes[0].lifetimes = PioLifetimes::Stale {
            obtained_ms: 10_000,
            valid_secs: 60,
        };
        let config = server_config(&stale, [0; 6]);
        assert_eq!(config.prefixes[0].preferred, Lifetime::Fixed(0));
        assert_eq!(
            config.prefixes[0].valid,
            Lifetime::Until {
                at: 70_000,
                cap: DEPRECATION_SECS
            }
        );
    }

    #[test]
    fn a_deprecated_prefix_counts_down_to_its_deadline() {
        let mut gone = ra(1800);
        gone.prefixes.push(deprecated(70_000));
        let config = server_config(&gone, [0; 6]);
        let pio = &config.prefixes[2];
        assert_eq!(pio.preferred, Lifetime::Fixed(0));
        assert_eq!(
            pio.valid,
            Lifetime::Until {
                at: 70_000,
                cap: DEPRECATION_SECS
            }
        );
        assert_eq!(pio.valid.secs(10_000), 60);
        assert_eq!(pio.valid.secs(69_500), 1);
        assert_eq!(pio.valid.secs(70_000), 0);
    }

    #[tokio::test]
    async fn a_lan_guard_aborts_its_task_when_dropped() {
        let (tx, _rx) = watch::channel(None);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _guard = SendOnDrop(Some(done_tx));
            std::future::pending::<()>().await;
        });
        let lan = Lan { tx, handle };
        assert!(!lan.handle.is_finished());
        drop(lan);
        tokio::time::timeout(std::time::Duration::from_secs(1), done_rx)
            .await
            .expect("aborted within a second")
            .expect_err("the task's guard dropped the sender");
    }

    struct SendOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for SendOnDrop {
        fn drop(&mut self) {
            drop(self.0.take());
        }
    }
}
