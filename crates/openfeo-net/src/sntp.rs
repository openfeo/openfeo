// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The SNTP driver (SPEC §7.10): one [`Client`] behind a UDP socket towards the servers, a
//! listener on port 123 of every LAN bridge answering from the client's state, and a clock the
//! client's decisions move. Server names are resolved through the box's own forwarder.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{SockProtocol, SockType};
use openfeo_proto_dns::Name;
pub use openfeo_proto_sntp::ServerSpec;
use openfeo_proto_sntp::client::{Client, Config, Event, Input, Output, SyncState};
use openfeo_proto_sntp::responder::respond;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::bound::bound_socket;
use crate::clock::Clock;
use crate::dhcp4::{DriverError, RECEIVE_BUFFER, io_err, is_transient, wait_until};
use crate::resolve::lookup_a;
use crate::throttle::{NOISY_WINDOW, Throttle};

/// The port we serve and the servers listen on.
pub const SNTP_PORT: u16 = 123;
/// How often a name that resolved is resolved again.
pub const RESOLVE_INTERVAL: Duration = Duration::from_secs(1024);
/// How soon a name that did not resolve is tried again.
pub const RESOLVE_RETRY: Duration = Duration::from_secs(16);
/// Resolution results the lookup tasks may queue.
const INBOX: usize = 64;
/// How long to wait after a socket error the link will cure.
const TRANSIENT_WAIT: Duration = Duration::from_secs(1);

/// The servers, the clock floor and where to listen.
#[derive(Debug, Clone)]
pub struct SntpDriverConfig {
    /// Configured, in order.
    pub servers: Vec<ServerSpec>,
    /// The WAN's, after them.
    pub learned: Vec<Ipv4Addr>,
    /// The forwarder that resolves names; `None` skips every name (the sandbox suite).
    pub resolver: Option<SocketAddr>,
    /// LAN bridges to answer on.
    pub listeners: Vec<String>,
    pub floor_unix_secs: u64,
    pub seed: u64,
}

/// Counters for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SntpStats {
    /// Requests sent to servers.
    pub sent: u64,
    /// Datagrams from servers handed to the core.
    pub replies: u64,
    /// LAN clients answered.
    pub served: u64,
}

/// A name's lookup came back.
struct Resolved {
    name: Name,
    addrs: Vec<Ipv4Addr>,
    ok: bool,
}

/// What the driver knows about one name.
#[derive(Debug, Clone)]
struct Lookup {
    addrs: Vec<Ipv4Addr>,
    at: Instant,
    ok: bool,
}

/// Runs one [`Client`] and serves the LANs.
pub struct SntpDriver<C: Clock> {
    client: Client,
    clock: C,
    query: UdpSocket,
    servers: Vec<ServerSpec>,
    learned: Vec<Ipv4Addr>,
    resolver: Option<SocketAddr>,
    floor_unix_secs: u64,
    resolved: BTreeMap<Name, Lookup>,
    in_flight: BTreeSet<Name>,
    inbox: mpsc::Receiver<Resolved>,
    inbox_tx: mpsc::Sender<Resolved>,
    /// What the listeners answer from.
    shared: Arc<Mutex<SyncState>>,
    served: Arc<AtomicU64>,
    stats: SntpStats,
    tasks: Vec<JoinHandle<()>>,
    clock_failures: Throttle,
    send_failures: Throttle,
    rng: u64,
}

impl<C: Clock> std::fmt::Debug for SntpDriver<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SntpDriver")
            .field("servers", &self.servers)
            .field("learned", &self.learned)
            .field("state", self.client.state())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<C: Clock> SntpDriver<C> {
    /// Open the sockets, start the listeners and the core. Call it inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// When a socket cannot be opened, bound or registered.
    pub fn new(config: SntpDriverConfig, clock: C) -> Result<SntpDriver<C>, DriverError> {
        let query = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(io_err("bind the time socket"))?;
        query
            .set_nonblocking(true)
            .map_err(io_err("time socket non-blocking"))?;
        let query = UdpSocket::from_std(query).map_err(io_err("register the time socket"))?;
        let shared = Arc::new(Mutex::new(SyncState::default()));
        let served = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for ifname in &config.listeners {
            let fd = bound_socket(
                Some(ifname),
                Ipv4Addr::UNSPECIFIED,
                SNTP_PORT,
                SockType::Datagram,
                SockProtocol::Udp,
            )?;
            let socket = UdpSocket::from_std(std::net::UdpSocket::from(fd))
                .map_err(io_err("register SNTP listener"))?;
            tasks.push(tokio::spawn(serve_loop(
                ifname.clone(),
                socket,
                clock.clone(),
                Arc::clone(&shared),
                Arc::clone(&served),
            )));
        }
        let (inbox_tx, inbox) = mpsc::channel(INBOX);
        let core = Config {
            servers: core_servers(&config.servers, &BTreeMap::new(), &config.learned),
            floor_unix_secs: config.floor_unix_secs,
        };
        let mut driver = SntpDriver {
            client: Client::new(core, config.seed),
            clock,
            query,
            servers: config.servers,
            learned: config.learned,
            resolver: config.resolver,
            floor_unix_secs: config.floor_unix_secs,
            resolved: BTreeMap::new(),
            in_flight: BTreeSet::new(),
            inbox,
            inbox_tx,
            shared,
            served,
            stats: SntpStats::default(),
            tasks,
            clock_failures: Throttle::new(NOISY_WINDOW),
            send_failures: Throttle::new(NOISY_WINDOW),
            rng: config.seed | 1,
        };
        driver.refresh_names();
        Ok(driver)
    }

    /// Wait for the next reply, timer or resolution, feed the core, do what it says, and return
    /// what the caller should know.
    ///
    /// # Errors
    ///
    /// When the time socket cannot be read, or the lookup tasks are gone.
    pub async fn step(&mut self) -> Result<Vec<Event>, DriverError> {
        self.refresh_names();
        // The core's deadlines are in the clock's monotonic milliseconds, whatever clock it is.
        let poll_at = self.client.next_poll().map(|ms| {
            Instant::now() + Duration::from_millis(ms.saturating_sub(self.clock.now().mono_ms))
        });
        let resolve_at = self.next_resolution();
        let mut buf = vec![0u8; RECEIVE_BUFFER];
        let input = tokio::select! {
            () = wait_until(poll_at) => Some(Input::Poll),
            () = wait_until(resolve_at) => None,
            received = self.query.recv_from(&mut buf) => match received {
                Ok((len, SocketAddr::V4(peer))) if peer.port() == SNTP_PORT => {
                    self.stats.replies += 1;
                    Some(Input::Reply { server: *peer.ip(), bytes: buf[..len].to_vec() })
                }
                Ok((_, peer)) => {
                    debug!("time: datagram from {peer} is no server's; dropped");
                    None
                }
                Err(err) if is_transient(&err) => {
                    warn!("time: socket: {err}; waiting for the link");
                    tokio::time::sleep(TRANSIENT_WAIT).await;
                    None
                }
                Err(err) => return Err(io_err("receive on the time socket")(err)),
            },
            resolved = self.inbox.recv() => {
                let resolved = resolved.ok_or_else(|| {
                    io_err("time resolver inbox")(std::io::Error::other("every lookup task is gone"))
                })?;
                self.in_flight.remove(&resolved.name);
                if !resolved.ok {
                    debug!("time: {} did not resolve; trying again in {}s", resolved.name, RESOLVE_RETRY.as_secs());
                }
                let lookup = Lookup::after(
                    self.resolved.get(&resolved.name),
                    resolved.addrs,
                    resolved.ok,
                    Instant::now(),
                );
                self.resolved.insert(resolved.name, lookup);
                return Ok(self.reconfigure_core());
            }
        };
        let Some(input) = input else {
            return Ok(Vec::new());
        };
        let outputs = self.client.handle(input, self.clock.now());
        Ok(self.perform(outputs))
    }

    /// Replace the servers live. Call it inside the runtime: lookups are spawned.
    pub fn configure(&mut self, servers: Vec<ServerSpec>, learned: Vec<Ipv4Addr>) -> Vec<Event> {
        self.servers = servers;
        self.learned = learned;
        let names: BTreeSet<Name> = self
            .servers
            .iter()
            .filter_map(|spec| match spec {
                ServerSpec::Name(name) => Some(name.clone()),
                ServerSpec::Address(_) => None,
            })
            .collect();
        self.resolved.retain(|name, _| names.contains(name));
        self.in_flight.retain(|name| names.contains(name));
        let events = self.reconfigure_core();
        self.refresh_names();
        events
    }

    /// What the core knows about the clock.
    #[must_use]
    pub fn state(&self) -> SyncState {
        *self.client.state()
    }

    #[must_use]
    pub fn stats(&self) -> SntpStats {
        SntpStats {
            served: self.served.load(Ordering::Relaxed),
            ..self.stats
        }
    }

    #[must_use]
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Give the core the addresses the specs resolve to now, when they changed.
    fn reconfigure_core(&mut self) -> Vec<Event> {
        let addrs: BTreeMap<Name, Vec<Ipv4Addr>> = self
            .resolved
            .iter()
            .map(|(name, lookup)| (name.clone(), lookup.addrs.clone()))
            .collect();
        let servers = core_servers(&self.servers, &addrs, &self.learned);
        if servers == self.client.config().servers {
            return Vec::new();
        }
        let now = self.clock.now();
        let outputs = self.client.handle(
            Input::Configure(Config {
                servers,
                floor_unix_secs: self.floor_unix_secs,
            }),
            now,
        );
        self.perform(outputs)
    }

    /// Start a lookup for every name that is due and not already in flight.
    fn refresh_names(&mut self) {
        let Some(resolver) = self.resolver else {
            return;
        };
        let now = Instant::now();
        let due: Vec<Name> = self
            .servers
            .iter()
            .filter_map(|spec| match spec {
                ServerSpec::Name(name) => Some(name.clone()),
                ServerSpec::Address(_) => None,
            })
            .filter(|name| !self.in_flight.contains(name))
            .filter(|name| {
                self.resolved
                    .get(name)
                    .is_none_or(|lookup| lookup.due() <= now)
            })
            .collect();
        for name in due {
            self.in_flight.insert(name.clone());
            let tx = self.inbox_tx.clone();
            let id = self.fresh_id();
            tokio::spawn(async move {
                let (addrs, ok) = match lookup_a(&name, resolver, id).await {
                    Ok(addrs) => (addrs, true),
                    Err(err) => {
                        debug!("time: resolve {name}: {err}");
                        (Vec::new(), false)
                    }
                };
                let _ = tx.send(Resolved { name, addrs, ok }).await;
            });
        }
    }

    /// When the next name is due for another lookup.
    fn next_resolution(&self) -> Option<Instant> {
        self.resolver?;
        self.servers
            .iter()
            .filter_map(|spec| match spec {
                ServerSpec::Name(name) => Some(name),
                ServerSpec::Address(_) => None,
            })
            .filter(|name| !self.in_flight.contains(name))
            .filter_map(|name| self.resolved.get(name).map(Lookup::due))
            .min()
    }

    /// Send what the core wants sent, move the clock as it decides, keep the events.
    fn perform(&mut self, outputs: Vec<Output>) -> Vec<Event> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                Output::Send { server, bytes } => {
                    let to = SocketAddr::V4(SocketAddrV4::new(server, SNTP_PORT));
                    match self.query.try_send_to(&bytes, to) {
                        Ok(_) => self.stats.sent += 1,
                        Err(err) => {
                            // Every poll ends here while the servers have no route (before the
                            // WAN comes up): one line per window, the rest counted. The core
                            // hears of it, so the round moves on without a failure counted.
                            let line = format!("time: request to {server} failed: {err}");
                            if let Some(line) = self.send_failures.line(Instant::now(), &line) {
                                warn!("{line}");
                            } else {
                                debug!("{line}");
                            }
                            let now = self.clock.now();
                            let more = self.client.handle(Input::Unreachable { server }, now);
                            events.extend(self.perform(more));
                        }
                    }
                }
                Output::Step(ns) => self.move_clock("step", ns, C::step),
                Output::Slew(ns) => self.move_clock("slew", ns, C::slew),
                Output::Event(event) => {
                    match event {
                        // Every adopted sample, slews included: `Synced` is only the first one
                        // and the steps, and the kernel forgets within hours.
                        Event::Synced { .. } | Event::Slewed { .. } => self.mark_synced(true),
                        Event::LostSync { .. } => self.mark_synced(false),
                        _ => {}
                    }
                    events.push(event);
                }
            }
        }
        if let Ok(mut shared) = self.shared.lock() {
            *shared = *self.client.state();
        }
        events
    }

    /// Apply one clock decision; a refusal (no `CAP_SYS_TIME`) is logged once per window.
    fn move_clock(&mut self, what: &str, ns: i64, apply: fn(&C, i64) -> std::io::Result<()>) {
        if let Err(err) = apply(&self.clock, ns) {
            let line = format!("time: cannot {what} the clock by {ns}ns: {err}");
            self.clock_failure(&line);
        }
    }

    /// Tell the kernel the clock is synced (on every adopted sample: it grows its own error
    /// estimate and raises `STA_UNSYNC` again within hours) or that the sync is lost; a refusal
    /// is logged like a refused step.
    fn mark_synced(&mut self, synced: bool) {
        if let Err(err) = self.clock.set_synced(synced) {
            let state = if synced { "synced" } else { "unsynced" };
            let line = format!("time: cannot mark the clock {state}: {err}");
            self.clock_failure(&line);
        }
    }

    fn clock_failure(&mut self, line: &str) {
        if let Some(line) = self.clock_failures.line(Instant::now(), line) {
            warn!("{line}");
        } else {
            debug!("{line}");
        }
    }

    /// A query id for the resolver (xorshift; the seed is the task's randomness).
    fn fresh_id(&mut self) -> u16 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        u16::try_from(self.rng & 0xffff).unwrap_or(1)
    }
}

impl<C: Clock> Drop for SntpDriver<C> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Lookup {
    /// The record after a lookup came back: the new addresses when it succeeded, the ones it had
    /// before when it did not (a name that stops resolving keeps the servers it named, so the
    /// core keeps polling them and can lose sync like any other), and the time for the retry.
    fn after(previous: Option<&Lookup>, addrs: Vec<Ipv4Addr>, ok: bool, now: Instant) -> Lookup {
        Lookup {
            addrs: if ok {
                addrs
            } else {
                previous
                    .map(|lookup| lookup.addrs.clone())
                    .unwrap_or_default()
            },
            at: now,
            ok,
        }
    }

    /// When this name should be resolved again.
    fn due(&self) -> Instant {
        self.at
            + if self.ok {
                RESOLVE_INTERVAL
            } else {
                RESOLVE_RETRY
            }
    }
}

/// The addresses the core polls: `servers` in order with each name's resolved addresses in its
/// place (a name not in `resolved` contributes nothing), then `learned`, without repeats.
pub(crate) fn core_servers(
    servers: &[ServerSpec],
    resolved: &BTreeMap<Name, Vec<Ipv4Addr>>,
    learned: &[Ipv4Addr],
) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut push = |addr: Ipv4Addr| {
        if !out.contains(&addr) {
            out.push(addr);
        }
    };
    for spec in servers {
        match spec {
            ServerSpec::Address(addr) => push(*addr),
            ServerSpec::Name(name) => {
                for addr in resolved.get(name).into_iter().flatten() {
                    push(*addr);
                }
            }
        }
    }
    for addr in learned {
        push(*addr);
    }
    out
}

/// Answer every client on one LAN from the shared state and the clock, forever.
async fn serve_loop<C: Clock>(
    ifname: String,
    socket: UdpSocket,
    clock: C,
    shared: Arc<Mutex<SyncState>>,
    served: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let state = shared.lock().map(|state| *state).unwrap_or_default();
                if let Some(reply) = respond(&buf[..len], clock.now().unix_ns, &state) {
                    match socket.send_to(&reply, peer).await {
                        Ok(_) => {
                            served.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(err) => debug!("time {ifname}: reply to {peer} failed: {err}"),
                    }
                }
            }
            Err(err) => {
                let why = if is_transient(&err) {
                    "waiting for the link"
                } else {
                    "waiting before trying again"
                };
                warn!("time {ifname}: listener: {err}; {why}");
                tokio::time::sleep(TRANSIENT_WAIT).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    /// Review finding: a name that stops resolving (the forwarder has no upstream during a WAN
    /// outage) must keep the addresses it had, or the core is left with nothing to poll, never
    /// loses sync, and the LAN is told the router is synced indefinitely.
    #[test]
    fn a_failed_lookup_keeps_the_addresses_it_had() {
        let now = Instant::now();
        let first = Lookup::after(None, vec![ip("203.0.113.1")], true, now);
        assert_eq!(
            (first.addrs.clone(), first.ok, first.due()),
            (vec![ip("203.0.113.1")], true, now + RESOLVE_INTERVAL)
        );
        let failed = Lookup::after(Some(&first), Vec::new(), false, now);
        assert_eq!(
            (failed.addrs.clone(), failed.ok, failed.due()),
            (vec![ip("203.0.113.1")], false, now + RESOLVE_RETRY)
        );
        let changed = Lookup::after(Some(&failed), vec![ip("203.0.113.2")], true, now);
        assert_eq!(changed.addrs, vec![ip("203.0.113.2")]);
        let never = Lookup::after(None, Vec::new(), false, now);
        assert!(never.addrs.is_empty() && !never.ok);
    }

    #[test]
    fn the_core_sees_resolved_names_then_the_learned_servers_without_repeats() {
        let pool: Name = "0.pool.ntp.org".parse().unwrap();
        let resolved = BTreeMap::from([(pool.clone(), vec![ip("203.0.113.1"), ip("203.0.113.2")])]);
        let servers = vec![
            ServerSpec::Address(ip("9.9.9.9")),
            ServerSpec::Name(pool),
            ServerSpec::Name("unresolved.example".parse().unwrap()),
        ];
        assert_eq!(
            core_servers(&servers, &resolved, &[ip("203.0.113.1"), ip("203.0.113.9")]),
            vec![
                ip("9.9.9.9"),
                ip("203.0.113.1"),
                ip("203.0.113.2"),
                ip("203.0.113.9"),
            ]
        );
    }
}
