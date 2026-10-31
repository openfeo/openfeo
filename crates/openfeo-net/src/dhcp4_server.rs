// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 server driver (SPEC §7.6): runs one [`Server`] on one LAN bridge over a UDP
//! socket bound to the device for the ordinary traffic and a packet socket bound to ARP, which
//! sends the probes, reads the replies and carries every reply as a frame with our own checksums
//! (ADR-0014).

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType, SockaddrIn, bind, recv, sendto,
    setsockopt, socket, sockopt,
};
use openfeo_proto_dhcp4::arp::{self, ArpOp, ArpPacket, ETH_P_ARP};
use openfeo_proto_dhcp4::server::{Input, Output, Timestamp};
use openfeo_proto_dhcp4::udp;
use openfeo_proto_dhcp4::wire::{CLIENT_PORT, SERVER_PORT};
use openfeo_proto_dhcp4::{Destination, LeaseRecord, Server, ServerConfig, ServerEvent};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::dhcp4::{DriverError, RECEIVE_BUFFER, io_err, is_transient, socket_err, wait_until};
use crate::sys;

const ETH_P_IP: u16 = 0x0800;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// An ARP packet with room for padding.
const ARP_BUFFER: usize = 128;
/// How long to wait after a socket error the link will cure.
const TRANSIENT_WAIT: Duration = Duration::from_secs(1);

/// One LAN's server: which bridge, what to serve, what it served before.
#[derive(Debug, Clone)]
pub struct ServerDriverConfig {
    /// Kernel interface name (`br-<lan>`), for `SO_BINDTODEVICE`.
    pub ifname: String,
    /// Kernel interface index, for the packet socket.
    pub ifindex: u32,
    /// The bridge's hardware address: the sender of the ARP probes.
    pub mac: [u8; 6],
    pub server: ServerConfig,
    /// The leases restored from the state disk.
    pub leases: Vec<LeaseRecord>,
}

/// Counters for tests and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// DHCP payloads handed to the core.
    pub received: u32,
    /// Replies sent.
    pub sent: u32,
    /// ARP probes sent.
    pub probes: u32,
}

/// Runs one [`Server`] on one bridge.
pub struct ServerDriver {
    config: ServerDriverConfig,
    server: Server,
    udp: UdpSocket,
    /// Bound to ARP: probes out, replies in, and the link-layer unicast DHCP replies out.
    packet: AsyncFd<OwnedFd>,
    start: Instant,
    stats: ServerStats,
}

impl std::fmt::Debug for ServerDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerDriver")
            .field("ifname", &self.config.ifname)
            .field("leases", &self.server.leases().len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ServerDriver {
    /// Open the sockets and start the core with the restored leases. Call it inside a tokio
    /// runtime: the sockets are registered with the reactor.
    ///
    /// # Errors
    ///
    /// When a socket cannot be opened or bound.
    pub fn new(config: ServerDriverConfig) -> Result<ServerDriver, DriverError> {
        let udp = udp_socket(&config.ifname)?;
        let packet = arp_socket(config.ifindex)?;
        let server = Server::new(config.server.clone(), config.leases.clone(), 0);
        Ok(ServerDriver {
            config,
            server,
            udp,
            packet,
            start: Instant::now(),
            stats: ServerStats::default(),
        })
    }

    /// Wait for the next packet, ARP reply or timer, feed it to the core, do what it says, and
    /// return what the caller should know. Empty for a frame that was nothing to us.
    ///
    /// # Errors
    ///
    /// When a socket cannot be read.
    pub async fn step(&mut self) -> Result<Vec<ServerEvent>, DriverError> {
        let deadline = self
            .server
            .next_timeout()
            .map(|at| self.start + Duration::from_secs(at));
        let mut udp_buf = vec![0u8; RECEIVE_BUFFER];
        let mut arp_buf = [0u8; ARP_BUFFER];
        let input = tokio::select! {
            () = wait_until(deadline) => Some(Input::Timeout),
            packet = receive_udp(&self.udp, &mut udp_buf) => packet?.map(Input::Packet),
            reply = receive_arp(&self.packet, &mut arp_buf) => reply?,
        };
        let Some(input) = input else {
            return Ok(Vec::new());
        };
        if let Input::Packet(payload) = &input {
            self.stats.received += 1;
            debug!("dhcp4 {}: {} bytes in", self.config.ifname, payload.len());
        }
        let now = self.now();
        let outputs = self.server.handle(input, now);
        Ok(self.perform(outputs))
    }

    /// Seconds since the driver started, rounded up: the core's clock. Rounding up means a
    /// timer the core arms for `now + 1` always waits at least a second, so a probe late in a
    /// second does not expire almost at once.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        ceil_secs(self.start.elapsed())
    }

    /// The active leases, ascending by address.
    #[must_use]
    pub fn leases(&self) -> Vec<LeaseRecord> {
        self.server.leases()
    }

    #[must_use]
    pub fn stats(&self) -> ServerStats {
        self.stats
    }

    /// Send what the core wants sent, probe what it wants probed, keep the events.
    fn perform(&mut self, outputs: Vec<Output>) -> Vec<ServerEvent> {
        let mut events = Vec::new();
        for output in outputs {
            match output {
                Output::Send { to, payload } => self.send(to, &payload),
                Output::Probe { address } => self.probe(address),
                Output::Event(event) => events.push(event),
            }
        }
        events
    }

    /// A send that fails is logged, not fatal: the client retransmits. Every reply is a frame
    /// of our own making over the packet socket, checksums included: a UDP socket's broadcast
    /// over a veth or virtio link carries an offloaded, partial checksum that a raw-socket
    /// client drops (ADR-0014).
    fn send(&mut self, to: Destination, payload: &[u8]) {
        let (ip, mac) = match to {
            Destination::Broadcast => (Ipv4Addr::BROADCAST, BROADCAST_MAC),
            Destination::Link { ip, mac } => (ip, mac),
        };
        let frame = udp::encapsulate(
            self.config.server.server,
            ip,
            SERVER_PORT,
            CLIENT_PORT,
            payload,
        );
        match self.send_frame(&frame, ETH_P_IP, mac) {
            Ok(()) => {
                self.stats.sent += 1;
                debug!(
                    "dhcp4 {}: {} bytes out to {to:?}",
                    self.config.ifname,
                    payload.len()
                );
            }
            Err(err) => warn!("dhcp4 {}: send to {to:?} failed: {err}", self.config.ifname),
        }
    }

    /// "Who has `address`?" from the bridge's own address, broadcast.
    fn probe(&mut self, address: Ipv4Addr) {
        let request = arp::request(self.config.mac, self.config.server.server, address).encode();
        match self.send_frame(&request, ETH_P_ARP, BROADCAST_MAC) {
            Ok(()) => {
                self.stats.probes += 1;
                debug!("dhcp4 {}: probing {address}", self.config.ifname);
            }
            Err(err) => warn!(
                "dhcp4 {}: probe of {address} failed: {err}",
                self.config.ifname
            ),
        }
    }

    /// One frame of `protocol` to `dest` out of the bridge, over the packet socket.
    fn send_frame(&self, frame: &[u8], protocol: u16, dest: [u8; 6]) -> Result<(), String> {
        let addr = sys::link_addr(self.config.ifindex, protocol, Some(dest))
            .ok_or_else(|| "no packet-socket address".to_owned())?;
        sendto(self.packet.as_raw_fd(), frame, &addr, MsgFlags::empty())
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

/// The UDP socket: port 67 on the device only; it only receives.
fn udp_socket(ifname: &str) -> Result<UdpSocket, DriverError> {
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        SockProtocol::Udp,
    )
    .map_err(socket_err("open UDP socket"))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(socket_err("SO_REUSEADDR"))?;
    setsockopt(&fd, sockopt::BindToDevice, &OsString::from(ifname))
        .map_err(socket_err("SO_BINDTODEVICE"))?;
    bind(fd.as_raw_fd(), &SockaddrIn::new(0, 0, 0, 0, SERVER_PORT))
        .map_err(socket_err("bind UDP port 67"))?;
    UdpSocket::from_std(std::net::UdpSocket::from(fd)).map_err(io_err("register UDP socket"))
}

/// An `AF_PACKET` datagram socket bound to the interface for ARP (the bind sets the protocol),
/// non-blocking. Sending names its own protocol per frame, so DHCP replies go out of it too.
fn arp_socket(ifindex: u32) -> Result<AsyncFd<OwnedFd>, DriverError> {
    let fd = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(socket_err("open packet socket"))?;
    let addr = sys::link_addr(ifindex, ETH_P_ARP, None).ok_or(DriverError::Address(ifindex))?;
    bind(fd.as_raw_fd(), &addr).map_err(socket_err("bind packet socket to ARP"))?;
    sys::register(fd).map_err(io_err("register packet socket"))
}

/// The next DHCP payload from the UDP socket; `None` after a transient error, once it has
/// waited a moment for the link.
async fn receive_udp(socket: &UdpSocket, buf: &mut [u8]) -> Result<Option<Vec<u8>>, DriverError> {
    match socket.recv_from(buf).await {
        Ok((len, _)) => Ok(Some(buf[..len].to_vec())),
        Err(err) if is_transient(&err) => {
            warn!("dhcp4 server: UDP socket: {err}; waiting for the link");
            tokio::time::sleep(TRANSIENT_WAIT).await;
            Ok(None)
        }
        Err(err) => Err(io_err("receive on UDP socket")(err)),
    }
}

/// The next ARP reply as a probe input; `None` for any other ARP frame or a transient error.
async fn receive_arp(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<Option<Input>, DriverError> {
    loop {
        let mut guard = fd
            .readable()
            .await
            .map_err(io_err("wait for packet socket"))?;
        match guard.try_io(|inner| {
            recv(inner.as_raw_fd(), buf, MsgFlags::empty()).map_err(std::io::Error::from)
        }) {
            Ok(Ok(len)) => return Ok(probe_reply(&buf[..len])),
            Ok(Err(err)) if is_transient(&err) => {
                warn!("dhcp4 server: packet socket: {err}; waiting for the link");
                tokio::time::sleep(TRANSIENT_WAIT).await;
                return Ok(None);
            }
            Ok(Err(err)) => return Err(io_err("receive on packet socket")(err)),
            Err(_would_block) => {}
        }
    }
}

/// Whole seconds, rounded up.
pub(crate) fn ceil_secs(elapsed: Duration) -> Timestamp {
    elapsed.as_secs() + Timestamp::from(elapsed.subsec_nanos() > 0)
}

/// An ARP reply, as the core wants to hear about it.
pub(crate) fn probe_reply(frame: &[u8]) -> Option<Input> {
    match ArpPacket::decode(frame) {
        Ok(ArpPacket {
            op: ArpOp::Reply,
            sender_mac,
            sender_ip,
            ..
        }) => Some(Input::ProbeReply {
            address: sender_ip,
            mac: sender_mac,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_proto_dhcp4::arp::{self, ArpOp, ArpPacket};

    /// Review finding: the core's clock must round up, or a probe armed late in a second
    /// waits almost nothing.
    #[test]
    fn the_clock_rounds_up_so_every_timer_lasts_its_full_length() {
        assert_eq!(ceil_secs(Duration::from_millis(5_950)), 6);
        assert_eq!(ceil_secs(Duration::from_millis(5_001)), 6);
        assert_eq!(ceil_secs(Duration::from_secs(5)), 5);
        assert_eq!(ceil_secs(Duration::ZERO), 0);
    }

    #[test]
    fn arp_replies_become_probe_inputs_and_requests_do_not() {
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: [9; 6],
            sender_ip: "192.168.1.100".parse().unwrap(),
            target_mac: [1; 6],
            target_ip: "192.168.1.1".parse().unwrap(),
        };
        assert_eq!(
            probe_reply(&reply.encode()),
            Some(Input::ProbeReply {
                address: "192.168.1.100".parse().unwrap(),
                mac: [9; 6]
            })
        );
        let request = arp::request(
            [9; 6],
            "192.168.1.100".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        );
        assert_eq!(probe_reply(&request.encode()), None);
        assert_eq!(probe_reply(&[0; 5]), None);
    }
}
