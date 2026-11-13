// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The IPv6 side of a WAN (SPEC §7.3): the stable-privacy secret the box keeps for life under
//! `/state/identity` (SPEC §5.2), from which the kernel derives the WAN ports' link-local
//! addresses and the client its RFC 7217 addresses; and the task that runs the
//! router-advertisement client on every WAN with `[wans.ipv6]`, publishing what it learns as
//! the WAN's IPv6 fact. Every line logged here is a contract with the harness scenarios.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read as _};
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openfeo_config::load::STATE_FILE_MODE;
use openfeo_net::ndp::{ALL_ROUTERS, NdpSocket, RESEND_AFTER, Resend, Role, transient_send_error};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_platform::atomic;
use openfeo_proto_dhcp4::identity::{from_hex, hex};
use openfeo_proto_ndp::client::{Client, Config, Input, Learned, Note, Output};
use openfeo_proto_ndp::wire::Preference as WirePreference;
use openfeo_reconcile::slices::{RaClientSlice, ra_clients};
use openfeo_runtime::Publisher;
use openfeo_runtime::supervise::{BoxedTask, Stop, TaskError};
use openfeo_runtime::world::WorldRx;
use openfeo_world::{Preference, WanIpv6Fact, World};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dhcp4::{LinkChange, link_change, wait_for_link, wait_for_netdev};
use crate::family::Family;

/// The ICMPv6 message buffer; advertisements are far smaller.
const RECEIVE_BUFFER: usize = 1500;

/// The box's IPv6 stable-privacy secret as 32 lowercase hex digits (SPEC §5.2 `identity/`).
pub const IPV6_SECRET_PATH: &str = "/state/identity/ipv6-secret";

/// The secret at `path`, or a fresh random one written there (mode 0600); `true` when it was
/// just made. A file that is not 32 hex digits is replaced with a warning.
///
/// # Errors
///
/// When the file cannot be read for a reason other than its absence, cannot be written, or
/// `/dev/urandom` cannot be read.
pub fn load_or_create_ipv6_secret(path: &Path) -> io::Result<([u8; 16], bool)> {
    match fs::read_to_string(path) {
        Ok(text) => {
            if let Some(secret) = from_hex(text.trim())
                && let Ok(secret) = <[u8; 16]>::try_from(secret)
            {
                return Ok((secret, false));
            }
            warn!("identity: {}: not a secret; replacing it", path.display());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let secret = random_secret()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic::write(
        path,
        format!("{}\n", hex(&secret)).as_bytes(),
        STATE_FILE_MODE,
    )?;
    Ok((secret, true))
}

/// Sixteen bytes from the kernel's random pool.
///
/// # Errors
///
/// When `/dev/urandom` cannot be opened or read in full.
pub fn random_secret() -> io::Result<[u8; 16]> {
    let mut secret = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    Ok(secret)
}

/// The router-advertisement client of every WAN with `[wans.ipv6]` in mode `auto` (SPEC §7.3),
/// kept in step with the config by its manager ([`crate::family`]). Without a persisted secret
/// the client still runs, with an all-zero secret: addresses stay stable but are no longer
/// private, which the router said on the console when it failed to keep the secret.
#[derive(Clone, Copy)]
pub struct RaClients {
    /// The IPv6 stable-privacy secret (`identity/`), or zeros.
    pub secret: [u8; 16],
}

impl Family for RaClients {
    type Slice = RaClientSlice;
    const PREFIX: &'static str = "ipv6";

    fn wanted(&self, world: &World) -> BTreeMap<String, RaClientSlice> {
        ra_clients(&world.config)
    }

    fn run(
        &self,
        key: &str,
        slice: &RaClientSlice,
        publisher: Arc<Publisher>,
        world_rx: WorldRx,
        mut stop: Stop,
    ) -> BoxedTask {
        let task = WanTask {
            wan: key.to_owned(),
            port: slice.port.clone(),
            netdev: slice.netdev.clone(),
            gateway: slice.gateway,
            secret: self.secret,
        };
        Box::pin(async move {
            // The client has nothing to say on its way out: a stop ends it wherever it waits.
            tokio::select! {
                ended = run(&task, &publisher, world_rx) => ended,
                () = stop.requested() => {
                    info!("{}", stopped_line(&task.wan));
                    Ok(())
                }
            }
        })
    }

    fn withdraw(&self, key: &str, world: &mut World) {
        Arc::make_mut(&mut world.ipv6).remove(key);
    }
}

fn stopped_line(wan: &str) -> String {
    format!("wan {wan} ipv6 stopped")
}

#[derive(Debug, Clone)]
struct WanTask {
    wan: String,
    /// The WAN's port (or VLAN sub-interface): where the MAC comes from.
    port: String,
    /// The interface the WAN's IPv6 runs on: the port, or `ppp-<wan>` over PPPoE (ADR-0023).
    netdev: String,
    /// A typed default (SPEC §7.3): logged once; the routing reconciler uses it.
    gateway: Option<Ipv6Addr>,
    secret: [u8; 16],
}

/// The task: wait for the port, run the client on its ICMPv6 socket, publish what it learns,
/// and tell it about carrier changes.
async fn run(
    task: &WanTask,
    publisher: &Publisher,
    mut world_rx: WorldRx,
) -> Result<(), TaskError> {
    // Over PPPoE the netdev has no MAC and a new index every session; the solicitations then
    // carry no link-layer option (RFC 4861 §4.1).
    let (mut ifindex, mac) = if task.netdev == task.port {
        let (index, mac) = wait_for_link(&mut world_rx, &task.port).await?;
        (index, Some(mac))
    } else {
        (wait_for_netdev(&mut world_rx, &task.netdev).await?, None)
    };
    let failed =
        |err: openfeo_net::dhcp4::DriverError| TaskError::from(format!("ipv6 {}: {err}", task.wan));
    let mut socket = NdpSocket::open(ifindex, &task.netdev, Role::Client).map_err(failed)?;
    let mut client = Client::new(Config {
        ifname: task.netdev.clone(),
        secret: task.secret,
        mac,
    });
    if let Some(gateway) = task.gateway {
        info!("{}", gateway_line(&task.wan, gateway));
    }
    let start = Instant::now();
    let now = |start: Instant| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut sends = Throttle::new(NOISY_WINDOW);
    let mut link_local = None;
    let mut last = Learned::default();
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    let mut carrier = true;
    announce_link_local(task, &world_rx, &mut link_local);
    let mut pending = act(
        task,
        publisher,
        &socket,
        &mut sends,
        &mut last,
        client.handle(Input::LinkUp, now(start)),
    );
    loop {
        let timer = client
            .next_timeout()
            .map(|at| start + Duration::from_millis(at));
        let outputs = tokio::select! {
            () = wait_until(pending.as_ref().map(|resend| resend.at)) => {
                // The link-local address was tentative a second ago (#34).
                if let Some(resend) = pending.take() {
                    match resend.retry(&socket) {
                        Ok(next) => pending = next,
                        Err(err) => warn!("ipv6 {}: solicit: {err}", task.wan),
                    }
                }
                Vec::new()
            }
            received = socket.recv(&mut buf) => {
                let received = received.map_err(failed)?;
                client.handle(
                    Input::Advertisement {
                        from: received.from,
                        hop_limit: received.hop_limit,
                        bytes: buf[..received.len].to_vec(),
                    },
                    now(start),
                )
            }
            () = wait_until(timer) => client.handle(Input::Timeout, now(start)),
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                announce_link_local(task, &world_rx, &mut link_local);
                let change = link_change(
                    (ifindex, carrier),
                    world_rx.borrow_and_update().links.get(&task.netdev),
                );
                match change {
                    LinkChange::None => continue,
                    LinkChange::Down => {
                        carrier = false;
                        client.handle(Input::LinkDown, now(start))
                    }
                    LinkChange::Up => {
                        carrier = true;
                        client.handle(Input::LinkUp, now(start))
                    }
                    LinkChange::Reopen(index) => {
                        info!("{}", replaced_line(&task.wan, &task.netdev, index));
                        let mut outputs = if carrier {
                            client.handle(Input::LinkDown, now(start))
                        } else {
                            Vec::new()
                        };
                        socket = NdpSocket::open(index, &task.netdev, Role::Client).map_err(failed)?;
                        ifindex = index;
                        carrier = true;
                        pending = None;
                        outputs.extend(client.handle(Input::LinkUp, now(start)));
                        outputs
                    }
                }
            }
        };
        if let Some(resend) = act(task, publisher, &socket, &mut sends, &mut last, outputs) {
            pending = Some(resend);
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

/// `wan wan0 ipv6 ppp-wan0 replaced (index 9)`: a new netdev under the WAN's name (a PPP
/// session's new unit); the client starts over on it with its learned facts kept.
fn replaced_line(wan: &str, netdev: &str, index: u32) -> String {
    format!("wan {wan} ipv6 {netdev} replaced (index {index})")
}

/// `wan0 ipv6 link-local fe80::…`, once the kernel has made the port's address and whenever it
/// changes.
fn announce_link_local(task: &WanTask, world_rx: &WorldRx, known: &mut Option<Ipv6Addr>) {
    let current = world_rx
        .borrow()
        .links
        .get(&task.netdev)
        .and_then(|link| link.link_local6);
    if current.is_some() && current != *known {
        *known = current;
        if let Some(addr) = current {
            info!("{}", link_local_line(&task.wan, addr));
        }
    }
}

/// What the core says to do: solicitations sent (a failure logged once per window: the port has
/// no link-local address yet, and the core's next timer tries again), the learned set published
/// as the WAN's fact and told on the console, notes told. A solicitation refused while the
/// link-local address is tentative comes back as a [`Resend`] for the loop to retry (#34).
fn act(
    task: &WanTask,
    publisher: &Publisher,
    socket: &NdpSocket,
    sends: &mut Throttle,
    last: &mut Learned,
    outputs: Vec<Output>,
) -> Option<Resend> {
    let mut pending = None;
    for output in outputs {
        match output {
            Output::Solicit(bytes) => {
                if let Err(err) = socket.send(ALL_ROUTERS, &bytes) {
                    if let Some(after) = send_retry(&err) {
                        debug!(
                            "ipv6 {}: solicit: {err}; again in {} s",
                            task.wan,
                            after.as_secs()
                        );
                        pending = Some(Resend::new(ALL_ROUTERS, bytes));
                        continue;
                    }
                    let line = format!("ipv6 {}: solicit: {err}", task.wan);
                    if let Some(line) = sends.line(Instant::now(), &line) {
                        warn!("{line}");
                    } else {
                        debug!("{line}");
                    }
                }
            }
            Output::Learned(learned) => {
                for line in learned_lines(&task.wan, last, &learned) {
                    info!("{line}");
                }
                let fact = fact_from(&learned, openfeo_runtime::clock::uptime_ms());
                publisher.update(|world| {
                    let facts = Arc::make_mut(&mut world.ipv6);
                    if learned == Learned::default() {
                        facts.remove(&task.wan);
                    } else {
                        facts.insert(task.wan.clone(), fact);
                    }
                });
                *last = learned;
            }
            Output::Note(note) => {
                if let Some(line) = note_line(&task.wan, &note) {
                    info!("{line}");
                }
            }
        }
    }
    pending
}

/// How long to wait before sending again, when `err` is the kernel refusing a link-local
/// source it has not finished checking (#34); `None` for every other failure.
pub(crate) fn send_retry(err: &openfeo_net::dhcp4::DriverError) -> Option<Duration> {
    transient_send_error(err).then_some(RESEND_AFTER)
}

/// The learned set as the reconcilers see it; the addresses' lifetimes count from `now_ms`,
/// the moment the client emitted them.
#[must_use]
pub fn fact_from(learned: &Learned, now_ms: u64) -> WanIpv6Fact {
    WanIpv6Fact {
        router: learned.router,
        addresses: learned
            .addresses
            .iter()
            .map(|addr| openfeo_world::Lifetimed {
                net: addr.net,
                obtained_ms: now_ms,
                preferred_secs: addr.preferred,
                valid_secs: addr.valid,
            })
            .collect(),
        on_link: learned.on_link.clone(),
        routes: learned
            .routes
            .iter()
            .map(|route| {
                (
                    route.prefix,
                    route.via,
                    match route.preference {
                        WirePreference::Low => Preference::Low,
                        WirePreference::Medium => Preference::Medium,
                        WirePreference::High => Preference::High,
                    },
                )
            })
            .collect(),
        dns: learned.dns.clone(),
        search: learned.search.clone(),
        mtu: learned.mtu,
    }
}

/// `wan0 ipv6 link-local fe80::1`.
fn link_local_line(wan: &str, addr: Ipv6Addr) -> String {
    format!("wan {wan} ipv6 link-local {addr}")
}

/// `wan0 ipv6 gateway fe80::1 (configured)`.
fn gateway_line(wan: &str, gateway: Ipv6Addr) -> String {
    format!("wan {wan} ipv6 gateway {gateway} (configured)")
}

/// What changed between two learned sets, one line each: the router (`wan0 ipv6 router
/// fe80::1 (learned)` or `wan0 ipv6 router none`), each new address, the resolvers.
fn learned_lines(wan: &str, before: &Learned, after: &Learned) -> Vec<String> {
    let mut lines = Vec::new();
    if after.router != before.router {
        lines.push(match after.router {
            Some(router) => format!("wan {wan} ipv6 router {router} (learned)"),
            None => format!("wan {wan} ipv6 router none"),
        });
    }
    // By address, not by lifetimes: a refresh is not news.
    for addr in after
        .addresses
        .iter()
        .filter(|addr| !before.addresses.iter().any(|b| b.net == addr.net))
    {
        lines.push(format!("wan {wan} ipv6 address {}", addr.net));
    }
    if after.dns != before.dns && !after.dns.is_empty() {
        let dns: Vec<String> = after.dns.iter().map(ToString::to_string).collect();
        lines.push(format!(
            "wan {wan} ipv6 resolvers {} (rdnss)",
            dns.join(" ")
        ));
    }
    lines
}

/// The console line for a note, when it deserves one.
fn note_line(wan: &str, note: &Note) -> Option<String> {
    match note {
        Note::StillSoliciting => Some(format!("wan {wan} ipv6 still soliciting")),
        Note::LinkLocalResolverDropped(addr) => Some(format!(
            "wan {wan} ipv6 resolver {addr} dropped: link-local"
        )),
        Note::Ignored(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_proto_ndp::client::{LearnedAddress, Route};
    use std::os::unix::fs::PermissionsExt as _;

    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    fn ipv6_wan(
        name: &str,
        port: &str,
        ipv6: Option<openfeo_config::Ipv6Wan>,
    ) -> openfeo_config::Wan {
        openfeo_config::Wan {
            name: name.to_owned(),
            port: port.to_owned(),
            kind: Some(openfeo_config::wan::Kind::Dhcp(
                openfeo_config::DhcpWan::default(),
            )),
            ipv6,
            ..openfeo_config::Wan::default()
        }
    }

    fn world_with(wans: Vec<openfeo_config::Wan>) -> openfeo_world::World {
        openfeo_world::World::new(
            openfeo_config::Config {
                wans,
                ..openfeo_config::Config::default()
            },
            openfeo_config::PortMap::default(),
        )
    }

    const FAMILY: RaClients = RaClients { secret: [7; 16] };

    #[test]
    fn the_stopped_line_is_the_contract() {
        assert_eq!(stopped_line("wan0"), "wan wan0 ipv6 stopped");
    }

    #[test]
    fn the_family_wants_one_client_per_wan_that_carries_ipv6() {
        let off = openfeo_config::Ipv6Wan {
            mode: "disabled".to_owned(),
            ..openfeo_config::Ipv6Wan::default()
        };
        let world = world_with(vec![
            ipv6_wan("wan0", "p0", Some(openfeo_config::Ipv6Wan::default())),
            ipv6_wan("wan1", "p1", None),
            ipv6_wan("wan2", "p4", Some(off)),
        ]);
        let wanted = FAMILY.wanted(&world);
        assert_eq!(wanted.keys().collect::<Vec<_>>(), ["wan0"]);
        assert_eq!(wanted["wan0"].netdev, "p0");
    }

    #[test]
    fn withdrawing_takes_what_the_wan_learned() {
        let mut world = world_with(Vec::new());
        for wan in ["wan0", "wan1"] {
            Arc::make_mut(&mut world.ipv6).insert(wan.to_owned(), WanIpv6Fact::default());
        }
        FAMILY.withdraw("wan0", &mut world);
        assert_eq!(world.ipv6.keys().collect::<Vec<_>>(), ["wan1"]);
        FAMILY.withdraw("wan9", &mut world);
    }

    /// The client says nothing on its way out, so a stop ends it wherever it is waiting: here
    /// for a port with no link.
    #[tokio::test(start_paused = true)]
    async fn a_task_stops_at_once_wherever_it_waits() {
        let (publisher, world_rx) = Publisher::new(world_with(vec![ipv6_wan(
            "wan0",
            "p0",
            Some(openfeo_config::Ipv6Wan::default()),
        )]));
        let publisher = Arc::new(publisher);
        let slice = FAMILY.wanted(&publisher.current())["wan0"].clone();
        let supervisor = openfeo_runtime::Supervisor::new(openfeo_runtime::HealthTracker::new());
        let task = supervisor.spawn_stoppable("ipv6-wan0", move |stop| {
            FAMILY.run("wan0", &slice, publisher.clone(), world_rx.clone(), stop)
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        let asked = tokio::time::Instant::now();
        task.stop().await;
        assert!(
            asked.elapsed() < Duration::from_millis(1),
            "took {:?}: the task did not hear the stop",
            asked.elapsed()
        );
    }

    /// #27: an advertisement that only refreshes the lifetimes prints no address line.
    #[test]
    fn learned_lines_name_an_address_once_whatever_its_lifetimes() {
        let addr = |preferred, valid| LearnedAddress {
            net: "2001:db8:ffff:0:1234::/64".parse().unwrap(),
            preferred,
            valid,
        };
        let before = Learned {
            addresses: vec![addr(1800, 3600)],
            ..Learned::default()
        };
        let after = Learned {
            addresses: vec![addr(1700, 3500)],
            ..Learned::default()
        };
        assert_eq!(learned_lines("wan0", &before, &after), Vec::<String>::new());
        assert_eq!(
            learned_lines("wan0", &Learned::default(), &after),
            vec!["wan wan0 ipv6 address 2001:db8:ffff:0:1234::/64".to_owned()]
        );
    }

    #[test]
    fn fact_from_carries_every_learned_field() {
        let learned = Learned {
            router: Some(ll(1)),
            addresses: vec![LearnedAddress {
                net: "2001:db8:ffff:0:1234::/64".parse().unwrap(),
                preferred: 1800,
                valid: 3600,
            }],
            on_link: vec!["2001:db8:ffff::/64".parse().unwrap()],
            routes: vec![Route {
                prefix: "2001:db8:2::/48".parse().unwrap(),
                via: ll(1),
                preference: WirePreference::High,
            }],
            dns: vec!["2001:db8:ffff::1".parse().unwrap()],
            search: vec!["isp.example".to_owned()],
            mtu: Some(1492),
        };
        let fact = fact_from(&learned, 7_000);
        assert_eq!(fact.router, Some(ll(1)));
        assert_eq!(
            fact.addresses,
            vec![openfeo_world::Lifetimed {
                net: "2001:db8:ffff:0:1234::/64".parse().unwrap(),
                obtained_ms: 7_000,
                preferred_secs: 1800,
                valid_secs: 3600,
            }]
        );
        assert_eq!(fact.on_link, learned.on_link);
        assert_eq!(
            fact.routes,
            vec![("2001:db8:2::/48".parse().unwrap(), ll(1), Preference::High)]
        );
        assert_eq!(fact.dns, learned.dns);
        assert_eq!(fact.search, learned.search);
        assert_eq!(fact.mtu, Some(1492));
    }

    #[test]
    fn eaddrnotavail_schedules_a_retry_instead_of_a_warning() {
        use openfeo_net::dhcp4::DriverError;
        // EADDRNOTAVAIL is 99 and ENETDOWN 100 on Linux.
        let tentative = DriverError::Io {
            what: "send ICMPv6",
            source: std::io::Error::from_raw_os_error(99),
        };
        assert_eq!(send_retry(&tentative), Some(RESEND_AFTER));
        let down = DriverError::Io {
            what: "send ICMPv6",
            source: std::io::Error::from_raw_os_error(100),
        };
        assert_eq!(send_retry(&down), None);
    }

    /// The console contract the harness scenarios match.
    #[test]
    fn ipv6_lines_follow_the_contract() {
        assert_eq!(
            link_local_line("wan0", ll(1)),
            "wan wan0 ipv6 link-local fe80::1"
        );
        assert_eq!(
            gateway_line("wan0", ll(1)),
            "wan wan0 ipv6 gateway fe80::1 (configured)"
        );
        assert_eq!(
            replaced_line("wan0", "ppp-wan0", 9),
            "wan wan0 ipv6 ppp-wan0 replaced (index 9)"
        );
        let learned = Learned {
            router: Some(ll(1)),
            addresses: vec![LearnedAddress {
                net: "2001:db8:ffff:0:1234::/64".parse().unwrap(),
                preferred: 1800,
                valid: 3600,
            }],
            dns: vec!["2001:db8:ffff::1".parse().unwrap()],
            ..Learned::default()
        };
        assert_eq!(
            learned_lines("wan0", &Learned::default(), &learned),
            vec![
                "wan wan0 ipv6 router fe80::1 (learned)".to_owned(),
                "wan wan0 ipv6 address 2001:db8:ffff:0:1234::/64".to_owned(),
                "wan wan0 ipv6 resolvers 2001:db8:ffff::1 (rdnss)".to_owned(),
            ]
        );
        let withdrawn = Learned {
            router: None,
            ..learned.clone()
        };
        assert_eq!(
            learned_lines("wan0", &learned, &withdrawn),
            vec!["wan wan0 ipv6 router none".to_owned()]
        );
        assert_eq!(
            learned_lines("wan0", &learned, &learned),
            Vec::<String>::new()
        );
        assert_eq!(
            note_line("wan0", &Note::StillSoliciting),
            Some("wan wan0 ipv6 still soliciting".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::LinkLocalResolverDropped(ll(53))),
            Some("wan wan0 ipv6 resolver fe80::35 dropped: link-local".to_owned())
        );
        assert_eq!(note_line("wan0", &Note::Ignored("x")), None);
    }

    #[test]
    fn a_missing_secret_is_made_persisted_and_read_back_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity").join("ipv6-secret");
        let (secret, new) = load_or_create_ipv6_secret(&path).unwrap();
        assert!(new);
        assert_ne!(secret, [0; 16], "sixteen random bytes, not zeros");
        let (again, new) = load_or_create_ipv6_secret(&path).unwrap();
        assert!(!new);
        assert_eq!(again, secret);
    }

    #[test]
    fn a_corrupt_secret_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipv6-secret");
        let (first, _) = load_or_create_ipv6_secret(&path).unwrap();
        for junk in ["not hex at all\n", "abcd\n", ""] {
            fs::write(&path, junk).unwrap();
            let (replaced, new) = load_or_create_ipv6_secret(&path).unwrap();
            assert!(new, "{junk:?} is replaced");
            assert_ne!(replaced, first);
        }
    }

    #[test]
    fn the_secret_file_is_mode_0600_and_32_hex_digits_plus_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipv6-secret");
        let (secret, _) = load_or_create_ipv6_secret(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("{}\n", hex(&secret)));
        assert_eq!(text.trim().len(), 32);
        assert!(text.trim().bytes().all(|b| b.is_ascii_hexdigit()));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
