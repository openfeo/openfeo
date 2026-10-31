// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DNS forwarder driver (SPEC §7.7): one [`Forwarder`] behind a UDP socket and a TCP
//! listener on every LAN bridge, a small pool of UDP sockets towards the upstreams, and a TCP
//! connection to an upstream when it truncates. Socket tasks feed one inbox; `step` drains it
//! one message at a time, so the core sees a single ordered stream.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{Backlog, SockProtocol, SockType, listen};
use openfeo_proto_dns::Timestamp;
use openfeo_proto_dns::cache::CacheStats;
use openfeo_proto_dns::forwarder::{self, Event, Forwarder, Input, Output, QueryId, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::bound::bound_socket;
use crate::dhcp4::{DriverError, RECEIVE_BUFFER, io_err, is_transient, socket_err, wait_until};
use crate::throttle::{NOISY_WINDOW, Throttle};

/// The port we serve and the upstreams listen on.
pub const DNS_PORT: u16 = 53;
/// UDP sockets towards the upstreams, with kernel-chosen ports; one is picked per query.
pub const UPSTREAM_SOCKETS: usize = 4;
/// TCP clients served at once; the rest wait in the listen queue.
pub const TCP_CLIENTS_MAX: usize = 64;
/// A TCP client that sends nothing for this long is closed.
pub const TCP_IDLE: Duration = Duration::from_secs(10);
/// How long a TCP exchange with an upstream may take in all.
pub const TCP_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Messages the socket tasks may queue before they wait for `step`.
const INBOX: usize = 256;
/// The listen queue of each TCP listener.
const BACKLOG: i32 = 128;
/// The loopback device, for the box's own lookups.
const LOOPBACK: &str = "lo";
/// How long to wait after a socket error the link will cure.
const TRANSIENT_WAIT: Duration = Duration::from_secs(1);

/// The forwarder and where it listens.
#[derive(Debug, Clone)]
pub struct DnsDriverConfig {
    /// Bridge names (`br-<lan>`), for `SO_BINDTODEVICE`.
    pub listeners: Vec<String>,
    /// Also listen on `127.0.0.1:53` for the box's own lookups (time server names, later TLS
    /// and updates).
    pub loopback: bool,
    pub forwarder: forwarder::Config,
    /// Randomness for the upstream query ids.
    pub seed: u64,
}

/// Counters for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsStats {
    /// Client queries handed to the core.
    pub queries: u64,
    /// Replies sent to clients.
    pub replies: u64,
    /// Queries sent to upstreams, over either transport.
    pub forwarded: u64,
}

/// What the socket tasks deliver.
enum Incoming {
    Udp {
        listener: usize,
        peer: SocketAddr,
        bytes: Vec<u8>,
    },
    Tcp {
        peer: SocketAddr,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Vec<u8>>,
    },
    UpstreamUdp {
        upstream: Ipv4Addr,
        bytes: Vec<u8>,
    },
    UpstreamTcp {
        upstream: Ipv4Addr,
        bytes: Vec<u8>,
    },
}

/// Where a client's reply goes.
enum ClientHandle {
    Udp { listener: usize, peer: SocketAddr },
    Tcp(oneshot::Sender<Vec<u8>>),
}

/// Runs one [`Forwarder`] on every LAN.
pub struct DnsDriver {
    forwarder: Forwarder,
    inbox: mpsc::Receiver<Incoming>,
    /// Cloned into the tasks `step` spawns.
    inbox_tx: mpsc::Sender<Incoming>,
    /// The UDP socket of each listener, for the replies.
    listeners: Vec<Arc<UdpSocket>>,
    upstream: Vec<Arc<UdpSocket>>,
    clients: HashMap<QueryId, ClientHandle>,
    next_id: QueryId,
    start: Instant,
    stats: DnsStats,
    tasks: Vec<JoinHandle<()>>,
    /// Console lines a send that fails may produce: one per window each.
    forward_failures: Throttle,
    reply_failures: Throttle,
}

impl std::fmt::Debug for DnsDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsDriver")
            .field("listeners", &self.listeners.len())
            .field("pending", &self.forwarder.pending())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl DnsDriver {
    /// Open the sockets, start the tasks that read them and the core. Call it inside a tokio
    /// runtime: the sockets are registered with the reactor and the tasks spawned on it.
    ///
    /// # Errors
    ///
    /// When a socket cannot be opened, bound or registered.
    pub fn new(config: DnsDriverConfig) -> Result<DnsDriver, DriverError> {
        let (inbox_tx, inbox) = mpsc::channel(INBOX);
        let mut listeners = Vec::new();
        let mut tasks = Vec::new();
        let tcp_clients = Arc::new(Semaphore::new(TCP_CLIENTS_MAX));
        for (index, ifname) in config.listeners.iter().enumerate() {
            let udp = Arc::new(listener_udp(ifname)?);
            tasks.push(tokio::spawn(udp_listener_loop(
                index,
                ifname.clone(),
                Arc::clone(&udp),
                inbox_tx.clone(),
            )));
            listeners.push(udp);
            tasks.push(tokio::spawn(tcp_accept_loop(
                ifname.clone(),
                listener_tcp(ifname)?,
                inbox_tx.clone(),
                Arc::clone(&tcp_clients),
            )));
        }
        if config.loopback {
            let index = listeners.len();
            let udp = Arc::new(loopback_udp()?);
            tasks.push(tokio::spawn(udp_listener_loop(
                index,
                LOOPBACK.to_owned(),
                Arc::clone(&udp),
                inbox_tx.clone(),
            )));
            listeners.push(udp);
            tasks.push(tokio::spawn(tcp_accept_loop(
                LOOPBACK.to_owned(),
                loopback_tcp()?,
                inbox_tx.clone(),
                Arc::clone(&tcp_clients),
            )));
        }
        let mut upstream = Vec::new();
        for _ in 0..UPSTREAM_SOCKETS {
            let socket = Arc::new(upstream_udp()?);
            tasks.push(tokio::spawn(upstream_udp_loop(
                Arc::clone(&socket),
                inbox_tx.clone(),
            )));
            upstream.push(socket);
        }
        Ok(DnsDriver {
            forwarder: Forwarder::new(config.forwarder, config.seed),
            inbox,
            inbox_tx,
            listeners,
            upstream,
            clients: HashMap::new(),
            next_id: 1,
            start: Instant::now(),
            stats: DnsStats::default(),
            tasks,
            forward_failures: Throttle::new(NOISY_WINDOW),
            reply_failures: Throttle::new(NOISY_WINDOW),
        })
    }

    /// Wait for the next message or timer, feed it to the core, do what it says, and return
    /// what the caller should know.
    ///
    /// # Errors
    ///
    /// When the socket tasks are gone, which does not happen while the driver lives.
    pub async fn step(&mut self) -> Result<Vec<Event>, DriverError> {
        let deadline = self
            .forwarder
            .next_timeout()
            .map(|at| self.start + Duration::from_millis(at));
        let incoming = tokio::select! {
            () = wait_until(deadline) => None,
            incoming = self.inbox.recv() => Some(incoming.ok_or_else(|| {
                io_err("DNS inbox")(std::io::Error::other("every socket task is gone"))
            })?),
        };
        let input = match incoming {
            None => Input::Timeout,
            Some(incoming) => match self.admit(incoming) {
                Some(input) => input,
                None => return Ok(Vec::new()),
            },
        };
        let now = self.now();
        let outputs = self.forwarder.handle(input, now);
        Ok(self.perform(outputs))
    }

    /// Replace the core's settings live: upstreams, local names, allow list. The cache stays.
    pub fn configure(&mut self, config: forwarder::Config) -> Vec<Event> {
        let now = self.now();
        let outputs = self.forwarder.handle(Input::Configure(config), now);
        self.perform(outputs)
    }

    #[must_use]
    pub fn stats(&self) -> DnsStats {
        self.stats
    }

    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.forwarder.cache_stats()
    }

    /// Milliseconds since the driver started, rounded up: the core's clock.
    fn now(&self) -> Timestamp {
        ceil_millis(self.start.elapsed())
    }

    /// Turn a socket task's message into the core's input, remembering where a client's reply
    /// goes. `None` for a client we do not serve.
    fn admit(&mut self, incoming: Incoming) -> Option<Input> {
        match incoming {
            Incoming::Udp {
                listener,
                peer,
                bytes,
            } => {
                let client = client_v4(peer)?;
                let id = self.take_id(ClientHandle::Udp { listener, peer });
                Some(Input::Query {
                    id,
                    client,
                    transport: Transport::Udp,
                    bytes,
                })
            }
            Incoming::Tcp { peer, bytes, reply } => {
                let client = client_v4(peer)?;
                let id = self.take_id(ClientHandle::Tcp(reply));
                Some(Input::Query {
                    id,
                    client,
                    transport: Transport::Tcp,
                    bytes,
                })
            }
            Incoming::UpstreamUdp { upstream, bytes } => Some(Input::UpstreamReply {
                upstream,
                transport: Transport::Udp,
                bytes,
            }),
            Incoming::UpstreamTcp { upstream, bytes } => Some(Input::UpstreamReply {
                upstream,
                transport: Transport::Tcp,
                bytes,
            }),
        }
    }

    fn take_id(&mut self, handle: ClientHandle) -> QueryId {
        let id = self.next_id;
        self.next_id += 1;
        self.clients.insert(id, handle);
        self.stats.queries += 1;
        id
    }

    /// Send what the core wants sent, keep the events.
    fn perform(&mut self, outputs: Vec<Output>) -> Vec<Event> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                Output::Reply { id, bytes } => self.reply(id, bytes),
                Output::Forward {
                    upstream,
                    transport: Transport::Udp,
                    bytes,
                } => self.forward_udp(upstream, &bytes),
                Output::Forward {
                    upstream,
                    transport: Transport::Tcp,
                    bytes,
                } => {
                    self.stats.forwarded += 1;
                    tokio::spawn(upstream_tcp(upstream, bytes, self.inbox_tx.clone()));
                }
                Output::Event(event) => events.push(event),
                Output::Drop { id } => {
                    // Nothing will ever answer: forget the client; a TCP client sees its
                    // connection close.
                    self.clients.remove(&id);
                }
            }
        }
        events
    }

    /// A reply to the client the id belongs to. A send that fails is logged, not fatal: the
    /// client retries.
    fn reply(&mut self, id: QueryId, bytes: Vec<u8>) {
        let Some(handle) = self.clients.remove(&id) else {
            debug!("dns: reply for an unknown query {id}");
            return;
        };
        self.stats.replies += 1;
        match handle {
            ClientHandle::Udp { listener, peer } => {
                if let Some(socket) = self.listeners.get(listener)
                    && let Err(err) = socket.try_send_to(&bytes, peer)
                {
                    // A LAN host can provoke this at packet rate (an off-link source address).
                    let line = format!("dns: reply to {peer} failed: {err}");
                    if let Some(line) = self.reply_failures.line(Instant::now(), &line) {
                        warn!("{line}");
                    } else {
                        debug!("{line}");
                    }
                }
            }
            ClientHandle::Tcp(reply) => {
                // The client may have gone; nothing to do then.
                let _ = reply.send(bytes);
            }
        }
    }

    /// The upstream query over the pool socket its id selects.
    fn forward_udp(&mut self, upstream: Ipv4Addr, bytes: &[u8]) {
        let index = bytes
            .first_chunk::<2>()
            .map_or(0, |id| usize::from(u16::from_be_bytes(*id)))
            % self.upstream.len().max(1);
        let Some(socket) = self.upstream.get(index) else {
            return;
        };
        let to = SocketAddr::V4(SocketAddrV4::new(upstream, DNS_PORT));
        match socket.try_send_to(bytes, to) {
            Ok(_) => self.stats.forwarded += 1,
            Err(err) => {
                // Every LAN query ends here while the upstreams have no route (before the WAN
                // lease, during an outage): one line per window, the rest counted.
                let line = format!("dns: forward to {upstream} failed: {err}");
                if let Some(line) = self.forward_failures.line(Instant::now(), &line) {
                    warn!("{line}");
                } else {
                    debug!("{line}");
                }
            }
        }
    }
}

impl Drop for DnsDriver {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A UDP socket on port 53 of one bridge: `SO_REUSEADDR` so every bridge may have one,
/// `SO_BINDTODEVICE` so each hears its own LAN and answers out of it.
fn listener_udp(ifname: &str) -> Result<UdpSocket, DriverError> {
    let fd = bound_socket(
        Some(ifname),
        Ipv4Addr::UNSPECIFIED,
        DNS_PORT,
        SockType::Datagram,
        SockProtocol::Udp,
    )?;
    UdpSocket::from_std(std::net::UdpSocket::from(fd)).map_err(io_err("register UDP listener"))
}

/// The TCP listener on port 53 of one bridge, with the same options.
fn listener_tcp(ifname: &str) -> Result<TcpListener, DriverError> {
    let fd = bound_socket(
        Some(ifname),
        Ipv4Addr::UNSPECIFIED,
        DNS_PORT,
        SockType::Stream,
        SockProtocol::Tcp,
    )?;
    let backlog = Backlog::new(BACKLOG).map_err(socket_err("listen queue"))?;
    listen(&fd, backlog).map_err(socket_err("listen on TCP port 53"))?;
    TcpListener::from_std(std::net::TcpListener::from(fd)).map_err(io_err("register TCP listener"))
}

/// The UDP socket on `127.0.0.1:53` for the box's own lookups; `SO_REUSEADDR` as the bridge
/// sockets have it, or the kernel refuses the port next to their wildcard binding.
fn loopback_udp() -> Result<UdpSocket, DriverError> {
    let fd = bound_socket(
        Some(LOOPBACK),
        Ipv4Addr::LOCALHOST,
        DNS_PORT,
        SockType::Datagram,
        SockProtocol::Udp,
    )?;
    UdpSocket::from_std(std::net::UdpSocket::from(fd))
        .map_err(io_err("register loopback UDP listener"))
}

/// The TCP listener on `127.0.0.1:53`.
fn loopback_tcp() -> Result<TcpListener, DriverError> {
    let fd = bound_socket(
        Some(LOOPBACK),
        Ipv4Addr::LOCALHOST,
        DNS_PORT,
        SockType::Stream,
        SockProtocol::Tcp,
    )?;
    let backlog = Backlog::new(BACKLOG).map_err(socket_err("listen queue"))?;
    listen(&fd, backlog).map_err(socket_err("listen on TCP 127.0.0.1:53"))?;
    TcpListener::from_std(std::net::TcpListener::from(fd))
        .map_err(io_err("register loopback TCP listener"))
}

/// A UDP socket towards the upstreams, on a kernel-chosen port.
fn upstream_udp() -> Result<UdpSocket, DriverError> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(io_err("bind upstream socket"))?;
    socket
        .set_nonblocking(true)
        .map_err(io_err("upstream socket non-blocking"))?;
    UdpSocket::from_std(socket).map_err(io_err("register upstream socket"))
}

/// Every datagram on one listener into the inbox.
async fn udp_listener_loop(
    index: usize,
    ifname: String,
    socket: Arc<UdpSocket>,
    inbox: mpsc::Sender<Incoming>,
) {
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let message = Incoming::Udp {
                    listener: index,
                    peer,
                    bytes: buf[..len].to_vec(),
                };
                if inbox.send(message).await.is_err() {
                    return;
                }
            }
            Err(err) => {
                let why = if is_transient(&err) {
                    "waiting for the link"
                } else {
                    "waiting before trying again"
                };
                warn!("dns {ifname}: UDP listener: {err}; {why}");
                tokio::time::sleep(TRANSIENT_WAIT).await;
            }
        }
    }
}

/// Every connection on one listener gets a task, `TCP_CLIENTS_MAX` of them at once.
async fn tcp_accept_loop(
    ifname: String,
    listener: TcpListener,
    inbox: mpsc::Sender<Incoming>,
    clients: Arc<Semaphore>,
) {
    loop {
        let Ok(permit) = Arc::clone(&clients).acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok((stream, peer)) => {
                let inbox = inbox.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    tcp_client(stream, peer, inbox).await;
                });
            }
            Err(err) => {
                warn!("dns {ifname}: TCP accept: {err}");
                tokio::time::sleep(TRANSIENT_WAIT).await;
            }
        }
    }
}

/// One TCP client: framed queries in, framed replies out, one at a time, until it closes,
/// goes quiet for `TCP_IDLE`, or sends something the core will not answer.
async fn tcp_client(mut stream: TcpStream, peer: SocketAddr, inbox: mpsc::Sender<Incoming>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; RECEIVE_BUFFER];
    loop {
        let message = loop {
            if let Some((consumed, message)) = unframe(&buf) {
                let message = message.to_vec();
                buf.drain(..consumed);
                break message;
            }
            match tokio::time::timeout(TCP_IDLE, stream.read(&mut chunk)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => return,
                Ok(Ok(len)) => buf.extend_from_slice(&chunk[..len]),
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let incoming = Incoming::Tcp {
            peer,
            bytes: message,
            reply: reply_tx,
        };
        if inbox.send(incoming).await.is_err() {
            return;
        }
        let Ok(reply) = reply_rx.await else {
            return;
        };
        if stream.write_all(&frame(&reply)).await.is_err() {
            return;
        }
    }
}

/// Every datagram on one upstream socket into the inbox, when it comes from port 53.
async fn upstream_udp_loop(socket: Arc<UdpSocket>, inbox: mpsc::Sender<Incoming>) {
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, SocketAddr::V4(peer))) if peer.port() == DNS_PORT => {
                let message = Incoming::UpstreamUdp {
                    upstream: *peer.ip(),
                    bytes: buf[..len].to_vec(),
                };
                if inbox.send(message).await.is_err() {
                    return;
                }
            }
            Ok((_, peer)) => debug!("dns: datagram from {peer} is no upstream's; dropped"),
            Err(err) => {
                let why = if is_transient(&err) {
                    "waiting for the link"
                } else {
                    "waiting before trying again"
                };
                warn!("dns: upstream socket: {err}; {why}");
                tokio::time::sleep(TRANSIENT_WAIT).await;
            }
        }
    }
}

/// One query to one upstream over TCP; its reply into the inbox. A failure sends nothing: the
/// core's timer takes it from there.
async fn upstream_tcp(upstream: Ipv4Addr, query: Vec<u8>, inbox: mpsc::Sender<Incoming>) {
    let exchange = async {
        let mut stream =
            TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(upstream, DNS_PORT))).await?;
        stream.write_all(&frame(&query)).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut reply).await?;
        Ok::<Vec<u8>, std::io::Error>(reply)
    };
    match tokio::time::timeout(TCP_UPSTREAM_TIMEOUT, exchange).await {
        Ok(Ok(bytes)) => {
            let _ = inbox.send(Incoming::UpstreamTcp { upstream, bytes }).await;
        }
        Ok(Err(err)) => debug!("dns: TCP to {upstream}: {err}"),
        Err(_) => debug!("dns: TCP to {upstream}: no reply within {TCP_UPSTREAM_TIMEOUT:?}"),
    }
}

/// The client's IPv4 address; IPv6 peers are not served in M1.
pub(crate) fn client_v4(peer: SocketAddr) -> Option<Ipv4Addr> {
    match peer {
        SocketAddr::V4(peer) => Some(*peer.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// `message` behind its two-byte big-endian length, as TCP carries DNS (RFC 1035 §4.2.2).
pub(crate) fn frame(message: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    let mut framed = Vec::with_capacity(usize::from(len) + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&message[..usize::from(len)]);
    framed
}

/// The first whole message in `buf` and how many bytes it took, when it is all there.
pub(crate) fn unframe(buf: &[u8]) -> Option<(usize, &[u8])> {
    let (len, rest) = buf.split_first_chunk::<2>()?;
    let len = usize::from(u16::from_be_bytes(*len));
    let message = rest.get(..len)?;
    Some((len + 2, message))
}

/// Whole milliseconds, rounded up, so a timer the core arms always waits its full length.
fn ceil_millis(elapsed: Duration) -> Timestamp {
    let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    millis + Timestamp::from(!elapsed.subsec_nanos().is_multiple_of(1_000_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_framing_round_trips_and_waits_for_whole_messages() {
        let framed = frame(&[1, 2, 3]);
        assert_eq!(framed, vec![0, 3, 1, 2, 3]);
        assert_eq!(unframe(&framed), Some((5, &[1u8, 2, 3][..])));
        assert_eq!(unframe(&framed[..4]), None);
        assert_eq!(unframe(&[0]), None);
        let two = [frame(&[9]), frame(&[8, 8])].concat();
        assert_eq!(unframe(&two), Some((3, &[9u8][..])));
    }

    #[test]
    fn only_ipv4_clients_are_served_in_m1() {
        assert_eq!(
            client_v4("192.168.1.50:5353".parse().unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 50))
        );
        assert_eq!(client_v4("[fe80::1]:5353".parse().unwrap()), None);
    }
}
