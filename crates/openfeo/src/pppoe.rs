// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE WAN task (SPEC §7.2, ADR-0023): one supervised task per `[wans.pppoe]` WAN, after
//! the shape of the DHCPv4 and DHCPv6 tasks. It waits for the port, runs discovery on it until
//! a session is bound, attaches the kernel session (the unit's netdev is born for the links
//! applier to rename, size and raise), publishes `PppoeFact`, runs the PPP session core over the
//! unit and channel descriptors (LCP, authentication, IPCP, IPV6CP) and fills the fact in as
//! they settle. When the session ends the fact is withdrawn first (the routes and addresses go
//! with it), our PADT goes out when we and not the access concentrator ended it, the kernel
//! session is dropped (the netdev vanishes), and the task waits: 1 s doubling to 60 s between
//! attempts, back to 1 s after a session that stayed up a minute, at once when carrier returns
//! after a loss, the full 60 s after an authentication failure. A configuration change restarts
//! the task, as it does every task. Nothing here prints the password.

use std::fmt::{self, Write as _};
use std::sync::Arc;
use std::time::Duration;

use openfeo_config::wan;
use openfeo_net::pppoe::{Discovery, Session as KernelSession, dev_ppp_unavailable};
use openfeo_proto_ppp::discovery::{self, Client as DiscoveryClient};
use openfeo_proto_ppp::ipcp::Ipv4Up;
use openfeo_proto_ppp::ipv6cp::Ipv6Up;
use openfeo_proto_ppp::lcp::{AuthProto, ECHO_MISSES};
use openfeo_proto_ppp::session::{self, Input, Output, Reason, Session};
use openfeo_runtime::clock;
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::{PppIpv4, PppIpv6, PppoeFact};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dhcp4::{mac_text, seed, wait_for_link};

/// The PPP payload without RFC 4638.
const DEFAULT_PAYLOAD: u16 = 1492;
/// The largest PPP payload asked for with RFC 4638: Ethernet's.
const MAX_PAYLOAD: u16 = 1500;
/// What PPPoE and PPP add to a payload on the wire: the port MTU a payload needs is this more.
const PPPOE_OVERHEAD: u32 = 8;
/// Room for the largest frame either descriptor hands over, protocol included.
const RECEIVE_BUFFER: usize = 2048;
/// The wait after a kernel without PPP or a refused attach: nothing shorter helps.
const NO_PPP_WAIT: Duration = Duration::from_secs(60);
const SEED_SALT: u64 = 0x7070_6f65;

/// One supervised task per `[wans.pppoe]` WAN in the current configuration. Without a persisted
/// IPv6 secret the IPV6CP identifier derives from an all-zero one, as the `ipv6` task's
/// addresses do.
pub fn spawn_all(
    supervisor: &Supervisor,
    publisher: &Arc<Publisher>,
    world_rx: &WorldRx,
    secret: Option<[u8; 16]>,
) {
    let config = publisher.current().config.clone();
    for wan in &config.wans {
        let Some(wan::Kind::Pppoe(pppoe)) = &wan.kind else {
            continue;
        };
        let task = WanTask {
            wan: wan.name.clone(),
            port: openfeo_reconcile::wan_ifname(wan),
            username: pppoe.username.clone(),
            password: pppoe.password.clone().into_bytes(),
            service: (!pppoe.service.is_empty()).then(|| pppoe.service.clone()),
            ac: (!pppoe.ac.is_empty()).then(|| pppoe.ac.clone()),
            secret: secret.unwrap_or([0; 16]),
        };
        let publisher = publisher.clone();
        let world_rx = world_rx.clone();
        supervisor.spawn(format!("pppoe-{}", wan.name), move || {
            let task = task.clone();
            let publisher = publisher.clone();
            let world_rx = world_rx.clone();
            async move { run(&task, &publisher, world_rx).await }
        });
    }
}

#[derive(Clone)]
struct WanTask {
    wan: String,
    /// The port (or VLAN sub-interface) discovery and the session run on.
    port: String,
    username: String,
    password: Vec<u8>,
    service: Option<String>,
    ac: Option<String>,
    secret: [u8; 16],
}

impl fmt::Debug for WanTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WanTask")
            .field("wan", &self.wan)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("service", &self.service)
            .field("ac", &self.ac)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Why a session ended, for the console and the backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cause {
    /// The PPP session core said so.
    Session(Reason),
    /// The access concentrator sent a PADT.
    Padt,
    /// The kernel closed a descriptor under us.
    Lost(String),
}

/// The wait between attempts (SPEC §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Backoff {
    wait: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_secs(1);
    const LONGEST: Duration = Duration::from_secs(60);
    /// A session up this long was a working line: the ladder starts over after it.
    const STABLE: Duration = Duration::from_secs(60);

    pub(crate) fn new() -> Self {
        Backoff { wait: Self::FIRST }
    }

    /// How long to wait after a session that ended with `cause` having been up `up_for`:
    /// nothing after carrier loss (carrier's return is the signal), the full minute after an
    /// authentication failure (the account may be locked), otherwise the ladder.
    pub(crate) fn next(&mut self, cause: &Cause, up_for: Duration) -> Duration {
        match cause {
            Cause::Session(Reason::CarrierLost) => return Duration::ZERO,
            Cause::Session(Reason::AuthFailed(_)) => {
                self.wait = Self::LONGEST;
                return Self::LONGEST;
            }
            _ => {}
        }
        if up_for > Self::STABLE {
            self.wait = Self::FIRST;
        }
        let wait = self.wait;
        self.wait = (self.wait * 2).min(Self::LONGEST);
        wait
    }
}

/// What discovery bound.
#[derive(Debug, Clone)]
struct Found {
    id: u16,
    ac_mac: [u8; 6],
    ac_name: String,
    max_payload: Option<u16>,
}

/// How a session ended.
#[derive(Debug)]
struct Ended {
    cause: Cause,
    uptime: Duration,
    auth: Option<AuthProto>,
}

/// The task: port, discovery, kernel session, PPP; again after every end.
async fn run(
    task: &WanTask,
    publisher: &Publisher,
    mut world_rx: WorldRx,
) -> Result<(), TaskError> {
    let wan = &task.wan;
    let failed =
        |err: openfeo_net::dhcp4::DriverError| TaskError::from(format!("pppoe {wan}: {err}"));
    let mut backoff = Backoff::new();
    loop {
        let (ifindex, _) = wait_for_link(&mut world_rx, &task.port).await?;
        let port_mtu = world_rx
            .borrow()
            .links
            .get(&task.port)
            .map_or(1500, |link| link.mtu);
        let max_payload = offered_payload(port_mtu);
        info!(
            "{}",
            discovering_line(
                wan,
                &task.port,
                task.service.as_deref(),
                max_payload.unwrap_or(DEFAULT_PAYLOAD)
            )
        );
        let socket = Discovery::open(ifindex, &task.port).map_err(failed)?;
        let mut client = DiscoveryClient::new(
            discovery::Config {
                service: task.service.clone(),
                ac: task.ac.clone(),
                max_payload,
            },
            seed(SEED_SALT ^ u64::from(ifindex)),
        );
        let Some(found) = discover(task, &socket, &mut client, &mut world_rx).await? else {
            // Carrier went while discovering: wait for it again.
            continue;
        };
        info!(
            "{}",
            session_line(
                wan,
                found.id,
                found.ac_mac,
                &found.ac_name,
                found.max_payload
            )
        );
        let kernel = match KernelSession::attach(&task.port, found.id, found.ac_mac) {
            Ok(kernel) => kernel,
            Err(err) => {
                if dev_ppp_unavailable(&err) {
                    warn!("{}", no_ppp_line(wan, &err.to_string(), NO_PPP_WAIT));
                } else {
                    warn!(
                        "pppoe {wan}: cannot attach the session: {err}; retry in {} s",
                        NO_PPP_WAIT.as_secs()
                    );
                }
                send_padt(&socket, &mut client);
                tokio::time::sleep(NO_PPP_WAIT).await;
                continue;
            }
        };
        let mtu = found.max_payload.unwrap_or(DEFAULT_PAYLOAD);
        publish_session(publisher, wan, &found, kernel.unit(), mtu);
        let ended = run_session(
            task,
            publisher,
            &socket,
            &mut client,
            &kernel,
            mtu,
            &mut world_rx,
        )
        .await;
        publisher.update(|world| {
            Arc::make_mut(&mut world.pppoe).remove(wan);
        });
        drop(kernel);
        let ended = ended?;
        let wait = backoff.next(&ended.cause, ended.uptime);
        announce_end(wan, &ended, wait);
        if ended.cause != Cause::Padt {
            send_padt(&socket, &mut client);
        }
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// The fact as discovery and the kernel know it; LCP, IPCP and IPV6CP fill the rest in.
fn publish_session(publisher: &Publisher, wan: &str, found: &Found, unit: u32, mtu: u16) {
    publisher.update(|world| {
        Arc::make_mut(&mut world.pppoe).insert(
            wan.to_owned(),
            PppoeFact {
                session_id: found.id,
                ac_mac: found.ac_mac,
                ac_name: found.ac_name.clone(),
                unit,
                mtu: u32::from(mtu),
                ipv4: None,
                ipv6: None,
                up_since_ms: clock::uptime_ms(),
            },
        );
    });
}

/// The console's account of a session's end, with the wait before the next attempt.
fn announce_end(wan: &str, ended: &Ended, wait: Duration) {
    match &ended.cause {
        Cause::Session(Reason::AuthFailed(message)) => {
            info!(
                "{}",
                auth_failed_line(wan, auth_name(ended.auth), message, wait)
            );
        }
        Cause::Session(Reason::Stopped) => info!("{}", stopped_line(wan)),
        Cause::Session(Reason::CarrierLost) => {
            info!("{}", down_line(wan, &ended.cause, ended.uptime, None));
        }
        _ => info!("{}", down_line(wan, &ended.cause, ended.uptime, Some(wait))),
    }
}

/// Discovery on the port until a session is bound, or carrier goes (`None`).
async fn discover(
    task: &WanTask,
    socket: &Discovery,
    client: &mut DiscoveryClient,
    world_rx: &mut WorldRx,
) -> Result<Option<Found>, TaskError> {
    let wan = &task.wan;
    let start = Instant::now();
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    let mut pending = client.handle(discovery::Input::Start, millis(start));
    loop {
        for output in pending.drain(..) {
            match output {
                discovery::Output::Send { to, bytes } => {
                    if let Err(err) = socket.send(to, &bytes) {
                        debug!("pppoe {wan}: discovery send: {err}");
                    }
                }
                discovery::Output::Session {
                    id,
                    ac_mac,
                    ac_name,
                    max_payload,
                } => {
                    return Ok(Some(Found {
                        id,
                        ac_mac,
                        ac_name,
                        max_payload,
                    }));
                }
                discovery::Output::Closed(_) => {}
                discovery::Output::Note(note) => debug!("pppoe {wan}: discovery: {note:?}"),
            }
        }
        let timer = client
            .next_timeout()
            .map(|at| start + Duration::from_millis(at));
        pending = tokio::select! {
            received = socket.recv(&mut buf) => {
                let (from, len) = received
                    .map_err(|err| TaskError::from(format!("pppoe {wan}: {err}")))?;
                client.handle(
                    discovery::Input::Packet { from, bytes: buf[..len].to_vec() },
                    millis(start),
                )
            }
            () = wait_until(timer) => client.handle(discovery::Input::Timeout, millis(start)),
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                if port_has_carrier(world_rx, &task.port) {
                    Vec::new()
                } else {
                    client.handle(discovery::Input::Stop, millis(start));
                    return Ok(None);
                }
            }
        };
    }
}

/// The PPP session over the kernel descriptors until it ends.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    task: &WanTask,
    publisher: &Publisher,
    socket: &Discovery,
    client: &mut DiscoveryClient,
    kernel: &KernelSession,
    mtu: u16,
    world_rx: &mut WorldRx,
) -> Result<Ended, TaskError> {
    let wan = &task.wan;
    let start = Instant::now();
    let mut ppp = Session::new(
        session::Config {
            username: task.username.clone(),
            password: task.password.clone(),
            mru: mtu,
            secret: task.secret,
            wan: wan.clone(),
        },
        seed(SEED_SALT ^ u64::from(kernel.unit())),
    );
    let mut auth = None;
    let mut cause: Option<Cause> = None;
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    let mut disc_buf = vec![0u8; RECEIVE_BUFFER];
    let mut pending = ppp.handle(Input::Start, millis(start));
    loop {
        for output in pending.drain(..) {
            if let Some((reason, uptime_ms)) = act(task, publisher, kernel, &mut auth, output) {
                return Ok(Ended {
                    cause: cause.take().unwrap_or(Cause::Session(reason)),
                    uptime: Duration::from_millis(uptime_ms),
                    auth,
                });
            }
        }
        let timer = ppp
            .next_timeout()
            .map(|at| start + Duration::from_millis(at));
        pending = tokio::select! {
            received = kernel.recv(&mut buf) => match received {
                Ok((protocol, len)) => ppp.handle(
                    Input::Frame { protocol, payload: buf[..len].to_vec() },
                    millis(start),
                ),
                Err(err) => {
                    cause = Some(Cause::Lost(err.to_string()));
                    ppp.handle(Input::CarrierLost, millis(start))
                }
            },
            received = socket.recv(&mut disc_buf) => {
                let (from, len) = received
                    .map_err(|err| TaskError::from(format!("pppoe {wan}: {err}")))?;
                let outputs = client.handle(
                    discovery::Input::Packet { from, bytes: disc_buf[..len].to_vec() },
                    millis(start),
                );
                if outputs
                    .iter()
                    .any(|output| matches!(output, discovery::Output::Closed(discovery::Reason::Padt)))
                {
                    cause = Some(Cause::Padt);
                    ppp.handle(Input::CarrierLost, millis(start))
                } else {
                    Vec::new()
                }
            }
            () = wait_until(timer) => ppp.handle(Input::Timeout, millis(start)),
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                if port_has_carrier(world_rx, &task.port) {
                    Vec::new()
                } else {
                    ppp.handle(Input::CarrierLost, millis(start))
                }
            }
        };
    }
}

/// Do what the session core asked: frames out, the MRU to the kernel, the fact filled in and
/// the console told. `Some` with the reason and uptime when it said the session is down.
fn act(
    task: &WanTask,
    publisher: &Publisher,
    kernel: &KernelSession,
    auth: &mut Option<AuthProto>,
    output: Output,
) -> Option<(Reason, u64)> {
    let wan = &task.wan;
    match output {
        Output::Send { protocol, payload } => {
            if let Err(err) = kernel.send(protocol, &payload) {
                debug!("pppoe {wan}: send {protocol:#06x}: {err}");
            }
        }
        Output::Mru(mru) => {
            if let Err(err) = kernel.set_mru(mru) {
                warn!("pppoe {wan}: set mru {mru}: {err}");
            }
        }
        Output::LcpUp { mru, auth: proto } => {
            *auth = proto;
            info!("{}", lcp_line(wan, mru, proto));
        }
        Output::AuthOk(proto) => info!("{}", auth_ok_line(wan, proto, &task.username)),
        Output::Ipv4Up(up) => {
            info!("{}", ipcp_line(wan, &up));
            update_fact(publisher, wan, |fact| {
                fact.ipv4 = Some(PppIpv4 {
                    local: up.local,
                    peer: up.peer,
                    dns: up.dns.clone(),
                });
            });
        }
        Output::Ipv4Down => update_fact(publisher, wan, |fact| fact.ipv4 = None),
        Output::Ipv6Up(up) => {
            info!("{}", ipv6cp_line(wan, &up));
            update_fact(publisher, wan, |fact| {
                fact.ipv6 = Some(PppIpv6 {
                    local_iid: up.local_iid,
                    peer_iid: up.peer_iid,
                });
            });
        }
        Output::Ipv6Down => update_fact(publisher, wan, |fact| fact.ipv6 = None),
        Output::Down { reason, uptime_ms } => return Some((reason, uptime_ms)),
        Output::Note(note) => debug!("pppoe {wan}: {note:?}"),
    }
    None
}

/// Our PADT, when the discovery client still holds a session.
fn send_padt(socket: &Discovery, client: &mut DiscoveryClient) {
    for output in client.handle(discovery::Input::Stop, clock::uptime_ms()) {
        if let discovery::Output::Send { to, bytes } = output
            && let Err(err) = socket.send(to, &bytes)
        {
            debug!("pppoe: padt: {err}");
        }
    }
}

fn update_fact(publisher: &Publisher, wan: &str, change: impl FnOnce(&mut PppoeFact)) {
    publisher.update(|world| {
        if let Some(fact) = Arc::make_mut(&mut world.pppoe).get_mut(wan) {
            change(fact);
        }
    });
}

fn port_has_carrier(world_rx: &mut WorldRx, port: &str) -> bool {
    world_rx
        .borrow_and_update()
        .links
        .get(port)
        .is_some_and(|link| link.up && link.carrier)
}

/// The PPP payload to ask for with PPP-Max-Payload: `min(1500, port MTU − 8)` when that is
/// above 1492 (the port carries baby jumbo frames), else nothing.
fn offered_payload(port_mtu: u32) -> Option<u16> {
    let payload = port_mtu
        .saturating_sub(PPPOE_OVERHEAD)
        .min(u32::from(MAX_PAYLOAD));
    u16::try_from(payload)
        .ok()
        .filter(|payload| *payload > DEFAULT_PAYLOAD)
}

fn millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Sleep until `at`, or forever when there is no timer.
async fn wait_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

fn auth_name(auth: Option<AuthProto>) -> &'static str {
    match auth {
        Some(AuthProto::Pap) => "pap",
        Some(AuthProto::ChapMd5) => "chap",
        Some(AuthProto::Other { .. }) => "unsupported",
        None => "none",
    }
}

/// The first eighty printable bytes of a peer's message: what the console shows of it.
fn printable(message: &str) -> String {
    message
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect()
}

fn iid_text(iid: u64) -> String {
    format!(
        "{:04x}:{:04x}:{:04x}:{:04x}",
        (iid >> 48) & 0xffff,
        (iid >> 32) & 0xffff,
        (iid >> 16) & 0xffff,
        iid & 0xffff
    )
}

fn cause_text(cause: &Cause) -> String {
    match cause {
        Cause::Padt => "padt from ac".to_owned(),
        Cause::Lost(err) => format!("session lost ({err})"),
        Cause::Session(reason) => match reason {
            Reason::KeepaliveLost => format!("keepalive lost ({ECHO_MISSES} echoes)"),
            Reason::TerminatedByPeer => "terminated by peer".to_owned(),
            Reason::AuthFailed(_) => "auth failed".to_owned(),
            Reason::NoNetworkProtocol => "no network protocol".to_owned(),
            Reason::AuthProtocolUnsupported => "auth protocol not supported".to_owned(),
            Reason::LcpFailed => "lcp failed".to_owned(),
            Reason::CarrierLost => "carrier lost".to_owned(),
            Reason::Stopped => "stopped".to_owned(),
        },
    }
}

/// `pppoe wan0 discovering on p0 (service any, max payload 1500)`.
fn discovering_line(wan: &str, port: &str, service: Option<&str>, max_payload: u16) -> String {
    let service = service.map_or_else(|| "any".to_owned(), |name| format!("{name:?}"));
    format!("pppoe {wan} discovering on {port} (service {service}, max payload {max_payload})")
}

/// `pppoe wan0 session 0x0001 with 52:54:00:fe:00:01 ac "isp" max payload 1500`, or
/// `… max payload 1492 (no RFC 4638)`.
fn session_line(
    wan: &str,
    id: u16,
    ac_mac: [u8; 6],
    ac_name: &str,
    max_payload: Option<u16>,
) -> String {
    let payload = max_payload.map_or_else(
        || format!("{DEFAULT_PAYLOAD} (no RFC 4638)"),
        |payload| payload.to_string(),
    );
    format!(
        "pppoe {wan} session {id:#06x} with {} ac {ac_name:?} max payload {payload}",
        mac_text(ac_mac)
    )
}

/// `pppoe wan0 lcp up mru 1500 auth chap`.
fn lcp_line(wan: &str, mru: u16, auth: Option<AuthProto>) -> String {
    format!("pppoe {wan} lcp up mru {mru} auth {}", auth_name(auth))
}

/// `pppoe wan0 auth chap ok as openfeo@isp.example`.
fn auth_ok_line(wan: &str, proto: &str, username: &str) -> String {
    format!("pppoe {wan} auth {proto} ok as {username}")
}

/// `pppoe wan0 auth pap failed: Login incorrect; retry in 60 s`.
fn auth_failed_line(wan: &str, proto: &str, message: &str, retry: Duration) -> String {
    format!(
        "pppoe {wan} auth {proto} failed: {}; retry in {} s",
        printable(message),
        retry.as_secs()
    )
}

/// `pppoe wan0 ipcp up 203.0.113.100 peer 203.0.113.1 dns 203.0.113.1`.
fn ipcp_line(wan: &str, up: &Ipv4Up) -> String {
    let peer = up
        .peer
        .map_or_else(|| "unnumbered".to_owned(), |peer| peer.to_string());
    let dns = if up.dns.is_empty() {
        "none".to_owned()
    } else {
        up.dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("pppoe {wan} ipcp up {} peer {peer} dns {dns}", up.local)
}

/// `pppoe wan0 ipv6cp up local 0000:0000:0000:0001 peer 0000:0000:0000:0002`.
fn ipv6cp_line(wan: &str, up: &Ipv6Up) -> String {
    format!(
        "pppoe {wan} ipv6cp up local {} peer {}",
        iid_text(up.local_iid),
        iid_text(up.peer_iid)
    )
}

/// `pppoe wan0 down: keepalive lost (3 echoes) after 1234 s; retry in 1 s`; no retry after
/// carrier loss (carrier's return is the retry).
fn down_line(wan: &str, cause: &Cause, uptime: Duration, retry: Option<Duration>) -> String {
    let mut line = format!(
        "pppoe {wan} down: {} after {} s",
        cause_text(cause),
        uptime.as_secs()
    );
    if let Some(retry) = retry {
        let _ = write!(line, "; retry in {} s", retry.as_secs());
    }
    line
}

/// `pppoe wan0 stopped`.
fn stopped_line(wan: &str) -> String {
    format!("pppoe {wan} stopped")
}

/// `pppoe wan0 no ppp in this kernel: open /dev/ppp: …; retry in 60 s`.
fn no_ppp_line(wan: &str, err: &str, retry: Duration) -> String {
    format!(
        "pppoe {wan} no ppp in this kernel: {err}; retry in {} s",
        retry.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openfeo_proto_ppp::ipcp::Ipv4Up;
    use openfeo_proto_ppp::ipv6cp::Ipv6Up;
    use openfeo_proto_ppp::lcp::AuthProto;
    use openfeo_proto_ppp::session::Reason;

    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn backoff_doubles_to_sixty_and_resets_after_a_minute_up() {
        let mut backoff = Backoff::new();
        let short = secs(5);
        let waits: Vec<u64> = (0..8)
            .map(|_| {
                backoff
                    .next(&Cause::Session(Reason::KeepaliveLost), short)
                    .as_secs()
            })
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(
            backoff.next(&Cause::Session(Reason::TerminatedByPeer), secs(61)),
            secs(1),
            "a session that stayed up a minute resets the ladder"
        );
        assert_eq!(
            backoff.next(&Cause::Session(Reason::CarrierLost), short),
            Duration::ZERO,
            "carrier loss waits for carrier, not the clock"
        );
        assert_eq!(
            backoff.next(&Cause::Padt, short),
            secs(2),
            "and leaves the ladder where it was"
        );
    }

    #[test]
    fn auth_failure_waits_sixty_seconds_from_the_first() {
        let mut backoff = Backoff::new();
        let failed = Cause::Session(Reason::AuthFailed("Login incorrect".to_owned()));
        assert_eq!(backoff.next(&failed, secs(2)), secs(60));
        assert_eq!(backoff.next(&failed, secs(2)), secs(60));
        assert_eq!(
            backoff.next(&Cause::Session(Reason::KeepaliveLost), secs(2)),
            secs(60),
            "the account may be locked: nothing hurries after an auth failure"
        );
        assert_eq!(
            backoff.next(&Cause::Session(Reason::KeepaliveLost), secs(90)),
            secs(1)
        );
    }

    /// The console contract the harness scenarios match (the design's Console section).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn lines_follow_the_contract() {
        let ac_mac = [0x52, 0x54, 0x00, 0xfe, 0x00, 0x01];
        assert_eq!(
            discovering_line("wan0", "p0", None, 1500),
            "pppoe wan0 discovering on p0 (service any, max payload 1500)"
        );
        assert_eq!(
            discovering_line("wan0", "p0.101", Some("isp-svc"), 1492),
            "pppoe wan0 discovering on p0.101 (service \"isp-svc\", max payload 1492)"
        );
        assert_eq!(
            session_line("wan0", 1, ac_mac, "isp", Some(1500)),
            "pppoe wan0 session 0x0001 with 52:54:00:fe:00:01 ac \"isp\" max payload 1500"
        );
        assert_eq!(
            session_line("wan0", 1, ac_mac, "isp", None),
            "pppoe wan0 session 0x0001 with 52:54:00:fe:00:01 ac \"isp\" max payload 1492 (no RFC 4638)"
        );
        assert_eq!(
            lcp_line("wan0", 1500, Some(AuthProto::ChapMd5)),
            "pppoe wan0 lcp up mru 1500 auth chap"
        );
        assert_eq!(
            lcp_line("wan0", 1492, Some(AuthProto::Pap)),
            "pppoe wan0 lcp up mru 1492 auth pap"
        );
        assert_eq!(
            lcp_line("wan0", 1492, None),
            "pppoe wan0 lcp up mru 1492 auth none"
        );
        assert_eq!(
            auth_ok_line("wan0", "chap", "openfeo@isp.example"),
            "pppoe wan0 auth chap ok as openfeo@isp.example"
        );
        assert_eq!(
            auth_failed_line("wan0", "pap", "Login incorrect", secs(60)),
            "pppoe wan0 auth pap failed: Login incorrect; retry in 60 s"
        );
        assert_eq!(
            auth_failed_line("wan0", "chap", "bad\x07 secret\n", secs(60)),
            "pppoe wan0 auth chap failed: bad secret; retry in 60 s",
            "only printable bytes of the peer's message"
        );
        let long = "x".repeat(100);
        assert!(
            auth_failed_line("wan0", "pap", &long, secs(60))
                .contains(&format!("failed: {}; retry", "x".repeat(80))),
            "at most eighty of them"
        );
        let local = "203.0.113.100".parse().unwrap();
        assert_eq!(
            ipcp_line(
                "wan0",
                &Ipv4Up {
                    local,
                    peer: Some("203.0.113.1".parse().unwrap()),
                    dns: vec![
                        "203.0.113.1".parse().unwrap(),
                        "203.0.113.2".parse().unwrap()
                    ],
                }
            ),
            "pppoe wan0 ipcp up 203.0.113.100 peer 203.0.113.1 dns 203.0.113.1,203.0.113.2"
        );
        assert_eq!(
            ipcp_line(
                "wan0",
                &Ipv4Up {
                    local,
                    peer: None,
                    dns: vec![],
                }
            ),
            "pppoe wan0 ipcp up 203.0.113.100 peer unnumbered dns none"
        );
        assert_eq!(
            ipv6cp_line(
                "wan0",
                &Ipv6Up {
                    local_iid: 1,
                    peer_iid: 2
                }
            ),
            "pppoe wan0 ipv6cp up local 0000:0000:0000:0001 peer 0000:0000:0000:0002"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::KeepaliveLost),
                secs(1234),
                Some(secs(1))
            ),
            "pppoe wan0 down: keepalive lost (3 echoes) after 1234 s; retry in 1 s"
        );
        assert_eq!(
            down_line("wan0", &Cause::Padt, secs(1234), Some(secs(1))),
            "pppoe wan0 down: padt from ac after 1234 s; retry in 1 s"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::TerminatedByPeer),
                secs(1234),
                Some(secs(1))
            ),
            "pppoe wan0 down: terminated by peer after 1234 s; retry in 1 s"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::CarrierLost),
                secs(1234),
                None
            ),
            "pppoe wan0 down: carrier lost after 1234 s"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::NoNetworkProtocol),
                secs(3),
                Some(secs(2))
            ),
            "pppoe wan0 down: no network protocol after 3 s; retry in 2 s"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::AuthProtocolUnsupported),
                secs(3),
                Some(secs(2))
            ),
            "pppoe wan0 down: auth protocol not supported after 3 s; retry in 2 s"
        );
        assert_eq!(
            down_line(
                "wan0",
                &Cause::Session(Reason::LcpFailed),
                secs(3),
                Some(secs(2))
            ),
            "pppoe wan0 down: lcp failed after 3 s; retry in 2 s"
        );
        assert_eq!(stopped_line("wan0"), "pppoe wan0 stopped");
        assert_eq!(offered_payload(1500), None, "a 1500-byte port carries 1492");
        assert_eq!(offered_payload(1508), Some(1500));
        assert_eq!(
            offered_payload(1504),
            Some(1496),
            "what the port carries, no more"
        );
        assert_eq!(
            offered_payload(9000),
            Some(1500),
            "and never above Ethernet's"
        );
        assert_eq!(
            no_ppp_line(
                "wan0",
                "open /dev/ppp: Permission denied (os error 13)",
                secs(60)
            ),
            "pppoe wan0 no ppp in this kernel: open /dev/ppp: Permission denied (os error 13); retry in 60 s"
        );
    }
}
