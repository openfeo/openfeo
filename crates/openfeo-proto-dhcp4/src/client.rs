// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 client state machine (RFC 2131 §4.4) without sockets or clocks (SPEC §6.3):
//! `Client::handle(input, now)` turns a packet, a timer expiry or a link event into packets to
//! send and facts to publish; the driver in `openfeo-net` owns the sockets and arms the timer
//! [`Client::next_timeout`] asks for. Time is the driver's monotonic clock in milliseconds.

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

use thiserror::Error;

use crate::wire::{ClasslessRoute, DhcpOption, FLAG_BROADCAST, Message, MessageType, Op};

/// Milliseconds on the driver's monotonic clock.
pub type Timestamp = u64;
/// Option 55, what SPEC §7.2 asks for: subnet mask, router, DNS, domain name, broadcast, MTU,
/// classless routes (121 and 249), NTP, renewal and rebinding times.
pub const PARAMETERS: [u8; 11] = [1, 3, 6, 15, 28, 26, 121, 249, 42, 58, 59];

const MS: Timestamp = 1000;
const MAX_MESSAGE_SIZE: u16 = 1500;
/// Retransmission waits for DISCOVER and REQUEST: 4 s doubling to 64 s, ±1 s (RFC 2131 §4.1).
const FIRST_BACKOFF: Timestamp = 4 * MS;
const MAX_BACKOFF: Timestamp = 64 * MS;
const JITTER: Timestamp = MS;
/// RENEWING and REBINDING retransmit at half the time left, never sooner than this (§4.4.5).
const MIN_RETRANSMIT: Timestamp = 60 * MS;
/// REQUESTING and REBOOTING give up after this many sends and go back to INIT.
const MAX_REQUEST_SENDS: u8 = 3;
const INFINITE: u32 = u32::MAX;
/// A lease MTU outside this is ignored.
const MTU_RANGE: RangeInclusive<u16> = 576..=9216;
const UNSPEC: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;

/// What a client is: its hardware address, identifier and the options it volunteers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// `chaddr`.
    pub mac: [u8; 6],
    /// Option 61, as [`crate::identity::client_id`] builds it.
    pub client_id: Vec<u8>,
    /// Option 12 when configured.
    pub hostname: Option<String>,
    /// Option 60 when configured.
    pub vendor_class: Option<Vec<u8>>,
    /// Option 57; 1500 unless changed.
    pub max_message_size: u16,
}

impl ClientConfig {
    #[must_use]
    pub fn new(mac: [u8; 6], client_id: Vec<u8>) -> Self {
        ClientConfig {
            mac,
            client_id,
            hostname: None,
            vendor_class: None,
            max_message_size: MAX_MESSAGE_SIZE,
        }
    }
}

/// What an ACK gave us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Addr,
    /// From the subnet mask, or the address class when the server sent none.
    pub prefix: u8,
    /// Option 54: where renewals go.
    pub server: Ipv4Addr,
    /// Option 3's first router; `None` when classless routes are present (RFC 3442).
    pub gateway: Option<Ipv4Addr>,
    /// Option 121, else 249, else empty.
    pub routes: Vec<ClasslessRoute>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// Option 26 inside `576..=9216`.
    pub mtu: Option<u16>,
    pub ntp: Vec<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub lease_secs: u32,
    pub t1_secs: u32,
    pub t2_secs: u32,
}

/// Why an ACK is not a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LeaseError {
    #[error("no address (yiaddr is 0.0.0.0)")]
    NoAddress,
    #[error("no server identifier")]
    NoServer,
    #[error("no lease time")]
    NoLeaseTime,
}

impl Lease {
    /// The lease an ACK (or OFFER) describes.
    ///
    /// # Errors
    ///
    /// When `yiaddr` is unset or option 54 or 51 is missing.
    pub fn from_ack(msg: &Message) -> Result<Lease, LeaseError> {
        if msg.yiaddr.is_unspecified() {
            return Err(LeaseError::NoAddress);
        }
        let Some(DhcpOption::ServerIdentifier(server)) = msg.option(54) else {
            return Err(LeaseError::NoServer);
        };
        let Some(DhcpOption::AddressLeaseTime(lease_secs)) = msg.option(51) else {
            return Err(LeaseError::NoLeaseTime);
        };
        let mask = match msg.option(1) {
            Some(DhcpOption::SubnetMask(mask)) => Some(*mask),
            _ => None,
        };
        let routes = match (msg.option(121), msg.option(249)) {
            (Some(DhcpOption::ClasslessStaticRoute(routes)), _)
            | (_, Some(DhcpOption::MsClasslessStaticRoute(routes))) => routes.clone(),
            _ => Vec::new(),
        };
        let gateway = match msg.option(3) {
            Some(DhcpOption::Router(list)) if routes.is_empty() => list.first().copied(),
            _ => None,
        };
        let t1 = match msg.option(58) {
            Some(DhcpOption::Renewal(t1)) => Some(*t1),
            _ => None,
        };
        let t2 = match msg.option(59) {
            Some(DhcpOption::Rebinding(t2)) => Some(*t2),
            _ => None,
        };
        let (t1_secs, t2_secs) = timers(*lease_secs, t1, t2);
        Ok(Lease {
            address: msg.yiaddr,
            prefix: prefix_of(mask, msg.yiaddr),
            server: *server,
            gateway,
            routes,
            dns: match msg.option(6) {
                Some(DhcpOption::DomainNameServer(dns)) => dns.clone(),
                _ => Vec::new(),
            },
            domain: match msg.option(15) {
                Some(DhcpOption::DomainName(domain)) => Some(domain.clone()),
                _ => None,
            },
            mtu: match msg.option(26) {
                Some(DhcpOption::InterfaceMtu(mtu)) if MTU_RANGE.contains(mtu) => Some(*mtu),
                _ => None,
            },
            ntp: match msg.option(42) {
                Some(DhcpOption::NtpServers(ntp)) => ntp.clone(),
                _ => Vec::new(),
            },
            broadcast: match msg.option(28) {
                Some(DhcpOption::BroadcastAddr(broadcast)) => Some(*broadcast),
                _ => None,
            },
            lease_secs: *lease_secs,
            t1_secs,
            t2_secs,
        })
    }

    /// Where the default route goes: the `0.0.0.0/0` classless route when routes are present,
    /// else the router option.
    #[must_use]
    pub fn default_gateway(&self) -> Option<Ipv4Addr> {
        if self.routes.is_empty() {
            self.gateway
        } else {
            self.routes
                .iter()
                .find(|route| route.prefix == 0)
                .map(|route| route.via)
        }
    }

    /// A lease of `0xffffffff` seconds never renews or expires.
    #[must_use]
    pub fn is_infinite(&self) -> bool {
        self.lease_secs == INFINITE
    }
}

/// The prefix length of a contiguous mask, or the address's class when there is none.
fn prefix_of(mask: Option<Ipv4Addr>, address: Ipv4Addr) -> u8 {
    if let Some(mask) = mask {
        let bits = u32::from(mask);
        if bits.leading_ones() + bits.trailing_zeros() == 32 {
            return u8::try_from(bits.leading_ones()).unwrap_or(32);
        }
    }
    match address.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

/// T1 and T2: the server's when both are present and ordered (`0 < T1 < T2 < lease`), else
/// 0.5 and 0.875 of the lease (RFC 2131 §4.4.5); both infinite for an infinite lease.
fn timers(lease: u32, t1: Option<u32>, t2: Option<u32>) -> (u32, u32) {
    if lease == INFINITE {
        return (INFINITE, INFINITE);
    }
    match (t1, t2) {
        (Some(t1), Some(t2)) if t1 > 0 && t1 < t2 && t2 < lease => (t1, t2),
        _ => (
            lease / 2,
            u32::try_from(u64::from(lease) * 7 / 8).unwrap_or(lease),
        ),
    }
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Begin: INIT without a lease, INIT-REBOOT with the last one.
    Start { lease: Option<Lease> },
    /// A DHCP message received on the interface.
    Packet(Vec<u8>),
    /// The timer of [`Client::next_timeout`] fired.
    Timeout,
    /// Carrier came back.
    LinkUp,
    /// Carrier went away.
    LinkDown,
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send `payload` as UDP 68 → 67 from `src` to `dst`.
    Send {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        payload: Vec<u8>,
    },
    /// A lease is in force; `renewed` when it continues an existing one.
    Bound { lease: Lease, renewed: bool },
    /// Confirming this address with INIT-REBOOT.
    Rebooting(Ipv4Addr),
    /// The lease is gone.
    Unbound(Unbound),
    /// A DISCOVER went out.
    Discover,
    /// An OFFER was accepted.
    Offer { address: Ipv4Addr, server: Ipv4Addr },
    /// A REQUEST for this address went out.
    Request(Ipv4Addr),
}

/// Why a lease is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unbound {
    /// The server refused, with its option 56 text when it sent one.
    Nak(Option<String>),
    Expired,
    RebootTimedOut,
}

/// RFC 2131 §4.4's states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Rebooting,
}

/// One interface's client.
#[derive(Debug)]
pub struct Client {
    config: ClientConfig,
    rng: u64,
    state: State,
    carrier: bool,
    xid: u32,
    /// When the current acquisition or renewal began, for `secs`.
    started: Timestamp,
    timeout: Option<Timestamp>,
    /// The next DISCOVER/REQUEST retransmission wait.
    backoff: Timestamp,
    /// REQUESTs sent in REQUESTING or REBOOTING.
    sends: u8,
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    lease: Option<Lease>,
    /// When the lease was last acknowledged: T1, T2 and expiry count from here.
    bound_at: Timestamp,
}

impl Client {
    /// A client in INIT; `seed` feeds its transaction ids and jitter.
    #[must_use]
    pub fn new(config: ClientConfig, seed: u64) -> Client {
        Client {
            config,
            rng: seed | 1,
            state: State::Init,
            carrier: true,
            xid: 0,
            started: 0,
            timeout: None,
            backoff: FIRST_BACKOFF,
            sends: 0,
            offer: None,
            lease: None,
            bound_at: 0,
        }
    }

    /// Feed one input at `now`; do what comes back.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Start { lease } => {
                self.carrier = true;
                match lease {
                    Some(lease) => self.reboot(lease, now, &mut out),
                    None => self.discover(now, &mut out),
                }
            }
            Input::Packet(bytes) => self.packet(&bytes, now, &mut out),
            Input::Timeout => self.expire_timer(now, &mut out),
            Input::LinkDown => {
                self.carrier = false;
                self.timeout = None;
            }
            Input::LinkUp => {
                self.carrier = true;
                self.link_up(now, &mut out);
            }
        }
        out
    }

    /// When to feed [`Input::Timeout`]; `None` while nothing is pending.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.timeout
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The lease in force or being confirmed.
    #[must_use]
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    fn discover(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.state = State::Selecting;
        self.xid = self.random_xid();
        self.started = now;
        self.backoff = FIRST_BACKOFF;
        self.sends = 0;
        self.offer = None;
        self.send_discover(now, out);
    }

    fn reboot(&mut self, lease: Lease, now: Timestamp, out: &mut Vec<Output>) {
        self.state = State::Rebooting;
        self.xid = self.random_xid();
        self.started = now;
        self.backoff = FIRST_BACKOFF;
        self.sends = 0;
        out.push(Output::Rebooting(lease.address));
        self.lease = Some(lease);
        self.send_reboot_request(now, out);
    }

    fn send_discover(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let message = self.message(MessageType::Discover, now, UNSPEC, true, Vec::new());
        out.push(Output::Discover);
        out.push(send(UNSPEC, BROADCAST, &message));
        self.sends += 1;
        self.arm_backoff(now);
    }

    /// REQUEST in SELECTING: the offered address and the chosen server, broadcast.
    fn send_select_request(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some((address, server)) = self.offer else {
            return self.discover(now, out);
        };
        let extra = vec![
            DhcpOption::RequestedIpAddress(address),
            DhcpOption::ServerIdentifier(server),
        ];
        let message = self.message(MessageType::Request, now, UNSPEC, true, extra);
        out.push(Output::Request(address));
        out.push(send(UNSPEC, BROADCAST, &message));
        self.sends += 1;
        self.arm_backoff(now);
    }

    /// REQUEST in INIT-REBOOT: the remembered address, no server, broadcast (RFC 2131 §4.3.2).
    fn send_reboot_request(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some(address) = self.lease.as_ref().map(|lease| lease.address) else {
            return self.discover(now, out);
        };
        let extra = vec![DhcpOption::RequestedIpAddress(address)];
        let message = self.message(MessageType::Request, now, UNSPEC, true, extra);
        out.push(Output::Request(address));
        out.push(send(UNSPEC, BROADCAST, &message));
        self.sends += 1;
        self.arm_backoff(now);
    }

    /// REQUEST in RENEWING (unicast to the server) or REBINDING (broadcast): `ciaddr` set.
    fn send_renew_request(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some((address, server, deadline)) = self.lease.as_ref().map(|lease| {
            let deadline = if self.state == State::Renewing {
                self.deadline(lease.t2_secs)
            } else {
                self.deadline(lease.lease_secs)
            };
            (lease.address, lease.server, deadline)
        }) else {
            return self.discover(now, out);
        };
        let dst = if self.state == State::Renewing {
            server
        } else {
            BROADCAST
        };
        let message = self.message(MessageType::Request, now, address, false, Vec::new());
        out.push(Output::Request(address));
        out.push(send(address, dst, &message));
        let half = deadline.saturating_sub(now) / 2;
        self.timeout = Some((now + half.max(MIN_RETRANSMIT)).min(deadline));
    }

    fn expire_timer(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        if !self.carrier {
            return;
        }
        match self.state {
            State::Init => {}
            State::Selecting => self.send_discover(now, out),
            State::Requesting => {
                if self.sends < MAX_REQUEST_SENDS {
                    self.send_select_request(now, out);
                } else {
                    self.discover(now, out);
                }
            }
            State::Rebooting => {
                if self.sends < MAX_REQUEST_SENDS {
                    self.send_reboot_request(now, out);
                } else {
                    out.push(Output::Unbound(Unbound::RebootTimedOut));
                    self.lease = None;
                    self.discover(now, out);
                }
            }
            State::Bound => {
                let t1 = self
                    .lease
                    .as_ref()
                    .map(|lease| self.deadline(lease.t1_secs));
                match t1 {
                    Some(t1) if now >= t1 => {
                        self.state = State::Renewing;
                        self.started = now;
                        self.send_renew_request(now, out);
                    }
                    Some(t1) => self.timeout = Some(t1),
                    None => self.discover(now, out),
                }
            }
            State::Renewing => {
                let t2 = self
                    .lease
                    .as_ref()
                    .map(|lease| self.deadline(lease.t2_secs));
                if t2.is_some_and(|t2| now >= t2) {
                    self.state = State::Rebinding;
                }
                self.send_renew_request(now, out);
            }
            State::Rebinding => {
                let expiry = self
                    .lease
                    .as_ref()
                    .map(|lease| self.deadline(lease.lease_secs));
                if expiry.is_none_or(|expiry| now >= expiry) {
                    out.push(Output::Unbound(Unbound::Expired));
                    self.lease = None;
                    self.discover(now, out);
                } else {
                    self.send_renew_request(now, out);
                }
            }
        }
    }

    fn packet(&mut self, bytes: &[u8], now: Timestamp, out: &mut Vec<Output>) {
        let Ok(msg) = Message::decode(bytes) else {
            return;
        };
        if msg.op != Op::BootReply || msg.xid != self.xid || msg.chaddr[..6] != self.config.mac {
            return;
        }
        let Some(kind) = msg.message_type() else {
            return;
        };
        match (self.state, kind) {
            (State::Selecting, MessageType::Offer) => {
                let Some(DhcpOption::ServerIdentifier(server)) = msg.option(54) else {
                    return;
                };
                if msg.yiaddr.is_unspecified() {
                    return;
                }
                self.offer = Some((msg.yiaddr, *server));
                self.state = State::Requesting;
                self.sends = 0;
                self.backoff = FIRST_BACKOFF;
                out.push(Output::Offer {
                    address: msg.yiaddr,
                    server: *server,
                });
                self.send_select_request(now, out);
            }
            (
                State::Requesting | State::Rebooting | State::Renewing | State::Rebinding,
                MessageType::Ack,
            ) => {
                let Ok(lease) = Lease::from_ack(&msg) else {
                    return;
                };
                let renewed = matches!(self.state, State::Renewing | State::Rebinding);
                self.state = State::Bound;
                self.bound_at = now;
                self.timeout = (!lease.is_infinite()).then(|| self.deadline(lease.t1_secs));
                self.lease = Some(lease.clone());
                out.push(Output::Bound { lease, renewed });
            }
            (State::Requesting, MessageType::Nak) => self.discover(now, out),
            (State::Rebooting | State::Renewing | State::Rebinding, MessageType::Nak) => {
                let text = match msg.option(56) {
                    Some(DhcpOption::Message(text)) => Some(text.clone()),
                    _ => None,
                };
                out.push(Output::Unbound(Unbound::Nak(text)));
                self.lease = None;
                self.discover(now, out);
            }
            _ => {}
        }
    }

    fn link_up(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        match self.state {
            State::Init => {}
            State::Selecting => self.discover(now, out),
            State::Requesting => {
                self.sends = 0;
                self.backoff = FIRST_BACKOFF;
                self.send_select_request(now, out);
            }
            State::Rebooting => {
                self.sends = 0;
                self.backoff = FIRST_BACKOFF;
                self.send_reboot_request(now, out);
            }
            State::Bound | State::Renewing | State::Rebinding => {
                if let Some(lease) = self.lease.clone() {
                    self.reboot(lease, now, out);
                }
            }
        }
    }

    /// `bound_at + secs`, saturating.
    fn deadline(&self, secs: u32) -> Timestamp {
        self.bound_at
            .saturating_add(Timestamp::from(secs).saturating_mul(MS))
    }

    /// Arm the retransmission timer at the current backoff ±1 s and double the backoff.
    fn arm_backoff(&mut self, now: Timestamp) {
        let jitter = self.random() % (2 * JITTER + 1);
        let wait = (self.backoff + jitter).saturating_sub(JITTER);
        self.timeout = Some(now + wait);
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }

    /// A BOOTREQUEST of `kind` with the client's standing options and `extra`.
    fn message(
        &self,
        kind: MessageType,
        now: Timestamp,
        ciaddr: Ipv4Addr,
        broadcast: bool,
        extra: Vec<DhcpOption>,
    ) -> Message {
        let mut options = vec![
            DhcpOption::MessageType(kind),
            DhcpOption::ClientIdentifier(self.config.client_id.clone()),
        ];
        if let Some(hostname) = &self.config.hostname {
            options.push(DhcpOption::HostName(hostname.clone()));
        }
        if let Some(vendor_class) = &self.config.vendor_class {
            options.push(DhcpOption::VendorClass(vendor_class.clone()));
        }
        options.push(DhcpOption::MaxMessageSize(self.config.max_message_size));
        options.push(DhcpOption::ParameterRequestList(PARAMETERS.to_vec()));
        options.extend(extra);
        let mut hardware = [0u8; 16];
        hardware[..6].copy_from_slice(&self.config.mac);
        Message {
            op: Op::BootRequest,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: self.xid,
            secs: u16::try_from(now.saturating_sub(self.started) / MS).unwrap_or(u16::MAX),
            flags: if broadcast { FLAG_BROADCAST } else { 0 },
            ciaddr,
            yiaddr: UNSPEC,
            siaddr: UNSPEC,
            giaddr: UNSPEC,
            chaddr: hardware,
            sname: [0; 64],
            file: [0; 128],
            options,
        }
    }

    /// xorshift64: good enough for transaction ids and jitter.
    fn random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn random_xid(&mut self) -> u32 {
        u32::try_from(self.random() & 0xffff_ffff).unwrap_or(1)
    }
}

fn send(src: Ipv4Addr, dst: Ipv4Addr, message: &Message) -> Output {
    Output::Send {
        src,
        dst,
        payload: message.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DhcpOption, FLAG_BROADCAST, Message, MessageType, Op};
    use std::net::Ipv4Addr;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xfe, 0x00, 0x00];
    const CLIENT_ID: [u8; 5] = [0xff, 1, 2, 3, 4];
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 100);
    const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const ALL: Ipv4Addr = Ipv4Addr::BROADCAST;
    const SEC: Timestamp = 1000;

    fn client() -> Client {
        Client::new(ClientConfig::new(MAC, CLIENT_ID.to_vec()), 42)
    }

    /// The one packet among `outputs`: `(src, dst, decoded)`.
    fn sent(outputs: &[Output]) -> (Ipv4Addr, Ipv4Addr, Message) {
        let mut sends = outputs.iter().filter_map(|output| match output {
            Output::Send { src, dst, payload } => {
                Some((*src, *dst, Message::decode(payload).unwrap()))
            }
            _ => None,
        });
        let first = sends
            .next()
            .unwrap_or_else(|| panic!("no packet in {outputs:?}"));
        assert!(
            sends.next().is_none(),
            "more than one packet in {outputs:?}"
        );
        first
    }

    fn has<F: Fn(&Output) -> bool>(outputs: &[Output], pred: F) -> bool {
        outputs.iter().any(pred)
    }

    /// Subnet mask, router, DNS, lease 60 s, T1 20 s, T2 40 s.
    fn lease_options() -> Vec<DhcpOption> {
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![SERVER]),
            DhcpOption::DomainNameServer(vec![SERVER]),
            DhcpOption::AddressLeaseTime(60),
            DhcpOption::Renewal(20),
            DhcpOption::Rebinding(40),
        ]
    }

    /// A server reply of `kind` to `request`, offering [`OFFERED`] with `options`.
    fn reply(request: &Message, kind: MessageType, options: Vec<DhcpOption>) -> Vec<u8> {
        let mut message = Message {
            op: Op::BootReply,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: 0,
            ciaddr: ANY,
            yiaddr: OFFERED,
            siaddr: ANY,
            giaddr: ANY,
            chaddr: request.chaddr,
            sname: [0; 64],
            file: [0; 128],
            options: vec![
                DhcpOption::MessageType(kind),
                DhcpOption::ServerIdentifier(SERVER),
            ],
        };
        message.options.extend(options);
        message.encode()
    }

    /// Start at 0, OFFER at 500 ms, ACK with `options` at 1 s: a BOUND client and its lease.
    fn bound_with(options: Vec<DhcpOption>) -> (Client, Lease) {
        let mut c = client();
        let out = c.handle(Input::Start { lease: None }, 0);
        let (_, _, discover) = sent(&out);
        let out = c.handle(
            Input::Packet(reply(&discover, MessageType::Offer, options.clone())),
            500,
        );
        let (_, _, request) = sent(&out);
        let out = c.handle(
            Input::Packet(reply(&request, MessageType::Ack, options)),
            SEC,
        );
        match out.as_slice() {
            [
                Output::Bound {
                    lease,
                    renewed: false,
                },
            ] => (c, lease.clone()),
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    fn bound() -> (Client, Lease) {
        bound_with(lease_options())
    }

    #[test]
    fn start_sends_a_broadcast_discover_with_the_requested_options() {
        let config = ClientConfig {
            hostname: Some("openfeo-lab".to_owned()),
            ..ClientConfig::new(MAC, CLIENT_ID.to_vec())
        };
        let mut c = Client::new(config, 42);
        let out = c.handle(Input::Start { lease: None }, 0);
        assert!(has(&out, |o| matches!(o, Output::Discover)));
        let (src, dst, m) = sent(&out);
        assert_eq!((src, dst), (ANY, ALL));
        assert_eq!(m.op, Op::BootRequest);
        assert_eq!(m.message_type(), Some(MessageType::Discover));
        assert_eq!((m.htype, m.hlen), (1, 6));
        assert_eq!(m.flags & FLAG_BROADCAST, FLAG_BROADCAST);
        assert_eq!(&m.chaddr[..6], &MAC);
        assert_eq!(m.ciaddr, ANY);
        assert_eq!(
            m.option(61),
            Some(&DhcpOption::ClientIdentifier(CLIENT_ID.to_vec()))
        );
        assert_eq!(
            m.option(55),
            Some(&DhcpOption::ParameterRequestList(PARAMETERS.to_vec()))
        );
        assert_eq!(m.option(57), Some(&DhcpOption::MaxMessageSize(1500)));
        assert_eq!(
            m.option(12),
            Some(&DhcpOption::HostName("openfeo-lab".to_owned()))
        );
        assert_eq!(m.option(60), None, "no vendor class unless configured");
        assert_eq!(c.state(), State::Selecting);
        let timeout = c.next_timeout().unwrap();
        assert!((3 * SEC..=5 * SEC).contains(&timeout), "{timeout}");
    }

    #[test]
    fn discover_retransmits_with_backoff_capped_at_64s() {
        let mut c = client();
        let out = c.handle(Input::Start { lease: None }, 0);
        let (_, _, first) = sent(&out);
        let mut last = 0;
        for gap_secs in [4u64, 8, 16, 32, 64, 64, 64] {
            let timeout = c.next_timeout().unwrap();
            let gap = timeout - last;
            let expected = gap_secs * SEC;
            assert!(
                (expected - SEC..=expected + SEC).contains(&gap),
                "gap {gap} ms, expected {expected} ± 1000"
            );
            let out = c.handle(Input::Timeout, timeout);
            assert!(has(&out, |o| matches!(o, Output::Discover)));
            let (_, _, m) = sent(&out);
            assert_eq!(m.message_type(), Some(MessageType::Discover));
            assert_eq!(m.xid, first.xid, "one acquisition keeps its xid");
            assert_eq!(
                u64::from(m.secs),
                timeout / SEC,
                "secs since acquisition began"
            );
            last = timeout;
        }
        assert_eq!(c.state(), State::Selecting);
    }

    #[test]
    fn offer_is_requested_and_ack_binds() {
        let mut c = client();
        let out = c.handle(Input::Start { lease: None }, 0);
        let (_, _, discover) = sent(&out);

        let out = c.handle(
            Input::Packet(reply(&discover, MessageType::Offer, lease_options())),
            500,
        );
        assert!(out.contains(&Output::Offer {
            address: OFFERED,
            server: SERVER
        }));
        assert!(out.contains(&Output::Request(OFFERED)));
        let (src, dst, request) = sent(&out);
        assert_eq!((src, dst), (ANY, ALL));
        assert_eq!(request.message_type(), Some(MessageType::Request));
        assert_eq!(
            request.option(50),
            Some(&DhcpOption::RequestedIpAddress(OFFERED))
        );
        assert_eq!(
            request.option(54),
            Some(&DhcpOption::ServerIdentifier(SERVER))
        );
        assert_eq!(request.ciaddr, ANY);
        assert_eq!(request.xid, discover.xid);
        assert_eq!(request.flags & FLAG_BROADCAST, FLAG_BROADCAST);
        assert_eq!(c.state(), State::Requesting);

        let out = c.handle(
            Input::Packet(reply(&request, MessageType::Ack, lease_options())),
            SEC,
        );
        let lease = match out.as_slice() {
            [
                Output::Bound {
                    lease,
                    renewed: false,
                },
            ] => lease.clone(),
            other => panic!("expected Bound, got {other:?}"),
        };
        assert_eq!(lease.address, OFFERED);
        assert_eq!(lease.prefix, 24);
        assert_eq!(lease.server, SERVER);
        assert_eq!(lease.gateway, Some(SERVER));
        assert_eq!(lease.default_gateway(), Some(SERVER));
        assert_eq!(lease.dns, vec![SERVER]);
        assert_eq!(
            (lease.lease_secs, lease.t1_secs, lease.t2_secs),
            (60, 20, 40)
        );
        assert!(!lease.is_infinite());
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.lease(), Some(&lease));
        assert_eq!(c.next_timeout(), Some(SEC + 20 * SEC));
    }

    #[test]
    fn t1_renews_by_unicast_to_the_server() {
        let (mut c, lease) = bound();
        let out = c.handle(Input::Timeout, 21 * SEC);
        assert_eq!(c.state(), State::Renewing);
        assert!(out.contains(&Output::Request(OFFERED)));
        let (src, dst, request) = sent(&out);
        assert_eq!((src, dst), (OFFERED, SERVER));
        assert_eq!(request.message_type(), Some(MessageType::Request));
        assert_eq!(request.ciaddr, OFFERED);
        assert_eq!(request.option(50), None);
        assert_eq!(request.option(54), None);
        assert_eq!(request.flags & FLAG_BROADCAST, 0);
        assert_eq!(request.secs, 0, "secs restart with the renewal");
        assert_eq!(c.lease(), Some(&lease), "the lease stays while renewing");

        let out = c.handle(
            Input::Packet(reply(&request, MessageType::Ack, lease_options())),
            21 * SEC + 500,
        );
        assert_eq!(
            out,
            vec![Output::Bound {
                lease: lease.clone(),
                renewed: true
            }]
        );
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.next_timeout(), Some(21 * SEC + 500 + 20 * SEC));
    }

    #[test]
    fn t2_rebinds_by_broadcast_and_expiry_unbinds() {
        let (mut c, _) = bound();
        c.handle(Input::Timeout, 21 * SEC);
        assert_eq!(c.state(), State::Renewing);
        assert_eq!(
            c.next_timeout(),
            Some(41 * SEC),
            "the 60 s floor would pass T2, so T2 is next"
        );

        let out = c.handle(Input::Timeout, 41 * SEC);
        assert_eq!(c.state(), State::Rebinding);
        let (src, dst, request) = sent(&out);
        assert_eq!((src, dst), (OFFERED, ALL));
        assert_eq!(request.ciaddr, OFFERED);
        assert_eq!(request.option(54), None);
        assert_eq!(
            request.flags & FLAG_BROADCAST,
            0,
            "we still have an address"
        );
        assert_eq!(c.next_timeout(), Some(61 * SEC), "expiry is next");

        let out = c.handle(Input::Timeout, 61 * SEC);
        assert!(out.contains(&Output::Unbound(Unbound::Expired)));
        assert!(has(&out, |o| matches!(o, Output::Discover)));
        let (src, dst, m) = sent(&out);
        assert_eq!((src, dst), (ANY, ALL));
        assert_eq!(m.message_type(), Some(MessageType::Discover));
        assert_eq!(c.state(), State::Selecting);
        assert_eq!(c.lease(), None);
    }

    #[test]
    fn renew_retransmits_at_half_remaining_never_below_60s() {
        let (mut c, lease) = bound_with(vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::AddressLeaseTime(7200),
        ]);
        assert_eq!((lease.t1_secs, lease.t2_secs), (3600, 6300));
        let t2 = SEC + 6300 * SEC;
        let mut now = SEC + 3600 * SEC;
        assert_eq!(c.next_timeout(), Some(now));
        let mut sends = 0;
        loop {
            let out = c.handle(Input::Timeout, now);
            if c.state() == State::Rebinding {
                break;
            }
            sends += 1;
            let (_, dst, _) = sent(&out);
            assert_eq!(dst, SERVER);
            let half = (t2 - now) / 2;
            let expected = (now + half.max(60 * SEC)).min(t2);
            let next = c.next_timeout().unwrap();
            assert_eq!(next, expected, "after a send at {now}");
            now = next;
        }
        assert!(sends > 5, "{sends} sends");
        assert_eq!(now, t2);
    }

    #[test]
    fn timers_default_when_missing_or_inconsistent() {
        let out = client().handle(Input::Start { lease: None }, 0);
        let (_, _, discover) = sent(&out);
        let ack = |options: Vec<DhcpOption>| {
            let mut m = Message::decode(&reply(&discover, MessageType::Ack, Vec::new())).unwrap();
            m.options.extend(options);
            m
        };
        let lease = Lease::from_ack(&ack(vec![DhcpOption::AddressLeaseTime(60)])).unwrap();
        assert_eq!(
            (lease.t1_secs, lease.t2_secs),
            (30, 52),
            "absent: 0.5 and 0.875"
        );
        let lease = Lease::from_ack(&ack(vec![
            DhcpOption::AddressLeaseTime(60),
            DhcpOption::Renewal(50),
            DhcpOption::Rebinding(40),
        ]))
        .unwrap();
        assert_eq!((lease.t1_secs, lease.t2_secs), (30, 52), "T1 >= T2");
        let lease = Lease::from_ack(&ack(vec![
            DhcpOption::AddressLeaseTime(60),
            DhcpOption::Renewal(20),
            DhcpOption::Rebinding(70),
        ]))
        .unwrap();
        assert_eq!((lease.t1_secs, lease.t2_secs), (30, 52), "T2 >= lease");
        let lease = Lease::from_ack(&ack(vec![DhcpOption::AddressLeaseTime(u32::MAX)])).unwrap();
        assert!(lease.is_infinite());
        assert_eq!(lease.prefix, 24, "class C default without a mask");

        let (c, lease) = bound_with(vec![DhcpOption::AddressLeaseTime(u32::MAX)]);
        assert!(lease.is_infinite());
        assert_eq!(c.next_timeout(), None, "an infinite lease never renews");
    }

    #[test]
    fn requesting_gives_up_after_three_sends_and_discovers_again() {
        let mut c = client();
        let out = c.handle(Input::Start { lease: None }, 0);
        let (_, _, discover) = sent(&out);
        let out = c.handle(
            Input::Packet(reply(&discover, MessageType::Offer, lease_options())),
            500,
        );
        let (_, _, first) = sent(&out);
        assert_eq!(first.message_type(), Some(MessageType::Request));
        for _ in 0..2 {
            let timeout = c.next_timeout().unwrap();
            let out = c.handle(Input::Timeout, timeout);
            let (_, _, again) = sent(&out);
            assert_eq!(again.message_type(), Some(MessageType::Request));
            assert_eq!(c.state(), State::Requesting);
        }
        let timeout = c.next_timeout().unwrap();
        let out = c.handle(Input::Timeout, timeout);
        let (_, _, m) = sent(&out);
        assert_eq!(m.message_type(), Some(MessageType::Discover));
        assert!(has(&out, |o| matches!(o, Output::Discover)));
        assert_eq!(c.state(), State::Selecting);
        assert_eq!(c.lease(), None);
    }
}
