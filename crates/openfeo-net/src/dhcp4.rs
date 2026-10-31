// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 client driver (SPEC §7.2): an `AF_PACKET` socket bound to the WAN port while the
//! client has no address (replies may be unicast to an address the kernel does not own yet),
//! a UDP socket with `SO_BINDTODEVICE` once bound (so a busy WAN's traffic is not copied to
//! userspace), and the one timer the sans-IO [`Client`] asks for. Every packet in and out is
//! the core's decision; this module only moves bytes and keeps time.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn, bind, recv, sendto,
    setsockopt, socket, sockopt,
};
use openfeo_proto_dhcp4::udp;
use openfeo_proto_dhcp4::wire::{CLIENT_PORT, SERVER_PORT};
use openfeo_proto_dhcp4::{Client, ClientConfig, Input, Lease, Output, State, Timestamp, Unbound};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::sys;

const ETH_P_IP: u16 = 0x0800;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// Larger than any DHCP message a server may send us (we advertise 1500).
pub(crate) const RECEIVE_BUFFER: usize = 4096;

/// One WAN port's client: which interface, who we are, what to start from.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Kernel interface name, for `SO_BINDTODEVICE`.
    pub ifname: String,
    /// Kernel interface index, for the packet socket.
    pub ifindex: u32,
    /// The port's hardware address.
    pub mac: [u8; 6],
    pub client: ClientConfig,
    /// The last lease, confirmed with INIT-REBOOT; `None` starts with DISCOVER.
    pub initial_lease: Option<Lease>,
    /// Seeds transaction ids and retransmission jitter.
    pub seed: u64,
}

/// What the core decided, minus the packets this module already sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Discover,
    Offer { address: Ipv4Addr, server: Ipv4Addr },
    Request(Ipv4Addr),
    Bound { lease: Lease, renewed: bool },
    Rebooting(Ipv4Addr),
    Unbound(Unbound),
}

/// Counters for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub discovers: u32,
    pub requests: u32,
    /// DHCP payloads handed to the core.
    pub received: u32,
}

/// A socket could not be made or read; sends only log.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("{what}: {source}")]
    Socket {
        what: &'static str,
        #[source]
        source: nix::Error,
    },
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("interface index {0} does not fit a packet-socket address")]
    Address(u32),
    #[error("bind {kind} {addr}{}: {source}", device.as_deref().map(|d| format!(" on {d}")).unwrap_or_default())]
    Bind {
        kind: &'static str,
        addr: std::net::SocketAddrV4,
        device: Option<String>,
        #[source]
        source: nix::Error,
    },
}

pub(crate) fn socket_err(what: &'static str) -> impl Fn(nix::Error) -> DriverError {
    move |source| DriverError::Socket { what, source }
}

pub(crate) fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> DriverError {
    move |source| DriverError::Io { what, source }
}

enum Transport {
    /// Unaddressed: IPv4 frames of the interface, filtered to UDP port 68 here.
    Raw(AsyncFd<OwnedFd>),
    /// Addressed: the kernel delivers UDP port 68 on the interface.
    Udp(UdpSocket),
}

/// Runs one [`Client`] on one interface.
pub struct Driver {
    config: DriverConfig,
    client: Client,
    transport: Transport,
    start: Instant,
    stats: Stats,
    /// Events produced before the caller asked for them (by `new` and `link`).
    pending: Vec<Event>,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("ifname", &self.config.ifname)
            .field("state", &self.client.state())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Driver {
    /// Open the packet socket on the interface and start the core (DISCOVER, or INIT-REBOOT
    /// when `config.initial_lease` is given); the resulting events come from the first
    /// [`Driver::step`]. Call it inside a tokio runtime: the socket is registered with the
    /// reactor.
    ///
    /// # Errors
    ///
    /// When the packet socket cannot be opened or bound.
    pub fn new(config: DriverConfig) -> Result<Driver, DriverError> {
        let transport = Transport::Raw(raw_socket(config.ifindex)?);
        let client = Client::new(config.client.clone(), config.seed);
        let mut driver = Driver {
            config,
            client,
            transport,
            start: Instant::now(),
            stats: Stats::default(),
            pending: Vec::new(),
        };
        let outputs = driver.client.handle(
            Input::Start {
                lease: driver.config.initial_lease.clone(),
            },
            0,
        );
        let events = driver.perform(outputs)?;
        driver.pending.extend(events);
        Ok(driver)
    }

    /// Wait for the next packet or timer, feed it to the core, do what it says, and return
    /// what the caller should know. Returns an empty list for a frame that was not for us.
    ///
    /// # Errors
    ///
    /// When the socket cannot be read or a socket for a new phase cannot be opened.
    pub async fn step(&mut self) -> Result<Vec<Event>, DriverError> {
        if !self.pending.is_empty() {
            return Ok(std::mem::take(&mut self.pending));
        }
        let deadline = self
            .client
            .next_timeout()
            .map(|at| self.start + Duration::from_millis(at));
        let mut buf = vec![0u8; RECEIVE_BUFFER];
        let received = tokio::select! {
            () = wait_until(deadline) => None,
            packet = receive(&self.transport, &mut buf) => Some(packet?),
        };
        let now = self.now();
        let outputs = match received {
            None => self.client.handle(Input::Timeout, now),
            Some(None) => return Ok(Vec::new()),
            Some(Some(payload)) => {
                self.stats.received += 1;
                debug!("dhcp4 {}: {} bytes in", self.config.ifname, payload.len());
                self.client.handle(Input::Packet(payload), now)
            }
        };
        self.perform(outputs)
    }

    /// Carrier changed: the core re-confirms or pauses, and the events say which.
    ///
    /// # Errors
    ///
    /// When a socket for a new phase cannot be opened.
    pub fn link(&mut self, up: bool) -> Result<Vec<Event>, DriverError> {
        let now = self.now();
        if up && matches!(self.transport, Transport::Raw(_)) {
            // A packet socket whose device went down may have been unbound; take a fresh one.
            self.transport = Transport::Raw(raw_socket(self.config.ifindex)?);
        }
        let input = if up { Input::LinkUp } else { Input::LinkDown };
        let outputs = self.client.handle(input, now);
        self.perform(outputs)
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.client.state()
    }

    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn now(&self) -> Timestamp {
        Timestamp::try_from(self.start.elapsed().as_millis()).unwrap_or(Timestamp::MAX)
    }

    /// Send what the core wants sent, switch sockets as the phase changes, keep the rest.
    fn perform(&mut self, outputs: Vec<Output>) -> Result<Vec<Event>, DriverError> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                Output::Send { src, dst, payload } => self.send(src, dst, &payload),
                Output::Bound { lease, renewed } => {
                    self.use_udp()?;
                    events.push(Event::Bound { lease, renewed });
                }
                // Rebooting keeps the current socket: at start it is the raw one; after a link
                // flap the address is still configured, the REQUEST goes out over UDP and the
                // core asks for a unicast reply, so a busy WAN is not copied to userspace.
                Output::Rebooting(address) => events.push(Event::Rebooting(address)),
                Output::Unbound(why) => {
                    self.use_raw()?;
                    events.push(Event::Unbound(why));
                }
                Output::Discover => {
                    self.stats.discovers += 1;
                    events.push(Event::Discover);
                }
                Output::Offer { address, server } => events.push(Event::Offer { address, server }),
                Output::Request(address) => {
                    self.stats.requests += 1;
                    events.push(Event::Request(address));
                }
            }
        }
        Ok(events)
    }

    /// A send that fails is logged, not fatal: the core retransmits.
    fn send(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) {
        let result = match &self.transport {
            Transport::Raw(fd) => {
                let frame = udp::encapsulate(src, dst, CLIENT_PORT, SERVER_PORT, payload);
                match sys::link_addr(self.config.ifindex, ETH_P_IP, Some(BROADCAST_MAC)) {
                    Some(addr) => sendto(fd.as_raw_fd(), &frame, &addr, MsgFlags::empty())
                        .map(|_| ())
                        .map_err(|err| err.to_string()),
                    None => Err("no packet-socket address".to_owned()),
                }
            }
            Transport::Udp(socket) => socket
                .try_send_to(payload, SocketAddr::V4(SocketAddrV4::new(dst, SERVER_PORT)))
                .map(|_| ())
                .map_err(|err| err.to_string()),
        };
        match result {
            Ok(()) => debug!(
                "dhcp4 {}: {} bytes out {src} -> {dst}",
                self.config.ifname,
                payload.len()
            ),
            Err(err) => warn!("dhcp4 {}: send to {dst} failed: {err}", self.config.ifname),
        }
    }

    fn use_udp(&mut self) -> Result<(), DriverError> {
        if matches!(self.transport, Transport::Udp(_)) {
            return Ok(());
        }
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::Udp,
        )
        .map_err(socket_err("open UDP socket"))?;
        setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(socket_err("SO_REUSEADDR"))?;
        setsockopt(&fd, sockopt::Broadcast, &true).map_err(socket_err("SO_BROADCAST"))?;
        setsockopt(
            &fd,
            sockopt::BindToDevice,
            &OsString::from(&self.config.ifname),
        )
        .map_err(socket_err("SO_BINDTODEVICE"))?;
        bind(fd.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, CLIENT_PORT))
            .map_err(socket_err("bind UDP port 68"))?;
        let socket = UdpSocket::from_std(std::net::UdpSocket::from(fd))
            .map_err(io_err("register UDP socket"))?;
        self.transport = Transport::Udp(socket);
        Ok(())
    }

    fn use_raw(&mut self) -> Result<(), DriverError> {
        if matches!(self.transport, Transport::Raw(_)) {
            return Ok(());
        }
        self.transport = Transport::Raw(raw_socket(self.config.ifindex)?);
        Ok(())
    }
}

/// An `AF_PACKET` datagram socket for IPv4 frames, bound to `ifindex`, non-blocking.
fn raw_socket(ifindex: u32) -> Result<AsyncFd<OwnedFd>, DriverError> {
    let fd = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        SockProtocol::EthIp,
    )
    .map_err(socket_err("open packet socket"))?;
    let addr = sys::link_addr(ifindex, ETH_P_IP, None).ok_or(DriverError::Address(ifindex))?;
    bind(fd.as_raw_fd(), &addr).map_err(socket_err("bind packet socket"))?;
    sys::register(fd).map_err(io_err("register packet socket"))
}

/// Errors the kernel reports on a socket whose device went down or away: the core's timers and
/// the next link-up recover from them, so they are logged, not fatal.
pub(crate) fn is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENETDOWN | libc::ENXIO | libc::ENODEV)
    )
}

pub(crate) async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The next DHCP payload for us: from a raw IPv4 frame to UDP port 68 (anything else is
/// `None`), or from the UDP socket.
async fn receive(transport: &Transport, buf: &mut [u8]) -> Result<Option<Vec<u8>>, DriverError> {
    match transport {
        Transport::Raw(fd) => loop {
            let mut guard = fd
                .readable()
                .await
                .map_err(io_err("wait for packet socket"))?;
            match guard.try_io(|inner| {
                recv(inner.as_raw_fd(), buf, MsgFlags::empty()).map_err(std::io::Error::from)
            }) {
                Ok(Ok(len)) => {
                    return Ok(match udp::decapsulate(&buf[..len]) {
                        Ok(datagram) if datagram.dport == CLIENT_PORT => {
                            Some(datagram.payload.to_vec())
                        }
                        _ => None,
                    });
                }
                Ok(Err(err)) if is_transient(&err) => {
                    warn!("dhcp4: packet socket: {err}; waiting for the link");
                    return Ok(None);
                }
                Ok(Err(err)) => return Err(io_err("receive on packet socket")(err)),
                Err(_would_block) => {}
            }
        },
        Transport::Udp(socket) => {
            let (len, _) = match socket.recv_from(buf).await {
                Ok(received) => received,
                Err(err) if is_transient(&err) => {
                    warn!("dhcp4: UDP socket: {err}; waiting for the link");
                    return Ok(None);
                }
                Err(err) => return Err(io_err("receive on UDP socket")(err)),
            };
            Ok(Some(buf[..len].to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_errors_are_transient_but_others_are_not() {
        for errno in [libc::ENETDOWN, libc::ENXIO, libc::ENODEV] {
            assert!(
                is_transient(&std::io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
        for errno in [libc::EBADF, libc::EINVAL, libc::EPERM] {
            assert!(
                !is_transient(&std::io::Error::from_raw_os_error(errno)),
                "{errno}"
            );
        }
        assert!(!is_transient(&std::io::Error::other("no errno")));
    }
}
