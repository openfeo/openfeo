// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The sans-IO DHCPv4 server core (SPEC §7.6, RFC 2131 §4.3): one LAN's pool, reservations
//! and leases. `Server::handle(Input, now) -> Vec<Output>`; no sockets, no clocks. The driver
//! in `openfeo-net` sends the packets and probes, and feeds back what arrives.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::wire::{DhcpOption, FLAG_BROADCAST, Message, MessageType, Op};

/// Seconds on the driver's monotonic clock (the client core counts milliseconds; a server's
/// times are lease times, whole seconds on the wire).
pub type Timestamp = u64;

/// The lease time when the configuration gives none (SPEC §8.2's example).
pub const DEFAULT_LEASE_SECS: u32 = 43_200;
/// The shortest lease the configuration may ask for.
pub const MIN_LEASE_SECS: u32 = 60;
/// How long an offered address stays out of other clients' reach.
pub const OFFER_HOLD: Timestamp = 60;
/// How long a probe waits for an answer before the address counts as free.
pub const PROBE_TIMEOUT: Timestamp = 1;
/// How long an address answered by another host, or declined, stays out of use.
pub const CONFLICT_HOLD: Timestamp = 600;
/// Probes per DISCOVER before the server gives up on it.
pub const MAX_PROBES: u8 = 3;
/// The longest DNS label.
pub const MAX_LABEL: usize = 63;

/// A static lease: the address a client always gets, with the name it resolves as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub mac: [u8; 6],
    /// When set, the reservation matches the client identifier rather than the MAC.
    pub client_id: Option<Vec<u8>>,
    pub address: Ipv4Addr,
    pub hostname: Option<String>,
}

/// One LAN's server settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// The LAN address: option 54, option 3 and the default option 6.
    pub server: Ipv4Addr,
    pub prefix: u8,
    /// Inclusive, host addresses inside the subnet.
    pub pool: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    /// Empty means `[server]`.
    pub dns: Vec<Ipv4Addr>,
    /// Option 42; empty means `[server]`, which serves SNTP (SPEC §7.10).
    pub ntp: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub reservations: Vec<Reservation>,
}

/// One active lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    pub address: Ipv4Addr,
    pub mac: [u8; 6],
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub granted_at: Timestamp,
    pub expires_at: Timestamp,
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// A DHCP message received on the LAN.
    Packet(Vec<u8>),
    /// An ARP reply: `mac` claims `address`.
    ProbeReply { address: Ipv4Addr, mac: [u8; 6] },
    /// The timer of [`Server::next_timeout`] fired.
    Timeout,
}

/// Where a reply goes (RFC 2131 §4.1): broadcast, or to the client's own hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// 255.255.255.255:68.
    Broadcast,
    /// Link-layer unicast to the client's hardware address, whether it has no address yet
    /// (`yiaddr`) or speaks from one (`ciaddr`): a reply never goes through the kernel's IP
    /// path, whose offloaded checksums a raw-socket client rejects on virtual links (ADR-0014).
    Link { ip: Ipv4Addr, mac: [u8; 6] },
}

/// Why a REQUEST was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NakReason {
    WrongNetwork,
    OutsidePool,
    Reserved,
    InUse,
    WrongAddress,
}

impl fmt::Display for NakReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NakReason::WrongNetwork => "wrong network",
            NakReason::OutsidePool => "outside pool",
            NakReason::Reserved => "reserved for another client",
            NakReason::InUse => "in use by another client",
            NakReason::WrongAddress => "not this client's address",
        })
    }
}

/// What happened, for the console, the facts and the lease database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    Offered {
        address: Ipv4Addr,
        mac: [u8; 6],
    },
    /// A new address for this client.
    Granted(LeaseRecord),
    /// The same address acknowledged again.
    Renewed(LeaseRecord),
    Nak {
        address: Ipv4Addr,
        mac: [u8; 6],
        reason: NakReason,
    },
    Informed {
        address: Ipv4Addr,
        mac: [u8; 6],
    },
    Released(LeaseRecord),
    Declined {
        address: Ipv4Addr,
        mac: [u8; 6],
    },
    Expired(LeaseRecord),
    /// A probe was answered by `mac`.
    Conflict {
        address: Ipv4Addr,
        mac: [u8; 6],
    },
    /// Nothing left to offer `mac`.
    Exhausted {
        mac: [u8; 6],
    },
    /// The address reserved for `mac` answered the probe from `by`: the client gets no offer
    /// until the squatter lets go.
    ReservationInUse {
        address: Ipv4Addr,
        mac: [u8; 6],
        by: [u8; 6],
    },
}

/// What the server wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send `payload` as UDP 67 → 68.
    Send {
        to: Destination,
        payload: Vec<u8>,
    },
    /// ARP for `address` before offering it.
    Probe {
        address: Ipv4Addr,
    },
    Event(ServerEvent),
}

/// The client identifier (option 61), else `0x01` and the MAC.
type Identity = Vec<u8>;

/// An address promised, or about to be promised, to one client.
#[derive(Debug, Clone)]
struct Offer {
    address: Ipv4Addr,
    mac: [u8; 6],
    /// The DISCOVER being answered: header fields and echoed options for the OFFER.
    discover: Message,
    /// The probe deadline while the address is being probed.
    probing: Option<Timestamp>,
    probes: u8,
    hold_until: Timestamp,
}

/// One LAN's server.
#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    leases: BTreeMap<Ipv4Addr, LeaseRecord>,
    /// When a lease on the address last ended, for reusing addresses longest-expired first.
    history: BTreeMap<Ipv4Addr, Timestamp>,
    offers: BTreeMap<Identity, Offer>,
    /// Addresses answered by someone else or declined, and until when.
    abandoned: BTreeMap<Ipv4Addr, Timestamp>,
}

impl Server {
    /// A server with the leases that still fit: active, inside the subnet and the pool (or the
    /// client's own reservation), not the server's address, not another client's reservation,
    /// with at most a lease time left.
    #[must_use]
    pub fn new(config: ServerConfig, leases: Vec<LeaseRecord>, now: Timestamp) -> Server {
        let mut server = Server {
            config,
            leases: BTreeMap::new(),
            history: BTreeMap::new(),
            offers: BTreeMap::new(),
            abandoned: BTreeMap::new(),
        };
        let lease_secs = Timestamp::from(server.config.lease_secs);
        for lease in leases {
            let identity = record_identity(&lease);
            let its_reservation = server
                .reservation_for(&identity, lease.mac)
                .is_some_and(|reservation| reservation.address == lease.address);
            if lease.expires_at > now
                && server.is_host_address(lease.address)
                && !server.reserved_for_other(lease.address, &identity, lease.mac)
                && (server.in_pool(lease.address) || its_reservation)
            {
                // A file written or read under a wrong wall clock cannot make a lease outlive
                // its lease time; a pool shrunk before the reboot drops what fell outside it.
                let capped = LeaseRecord {
                    expires_at: lease.expires_at.min(now + lease_secs),
                    granted_at: lease.granted_at.min(now),
                    ..lease
                };
                server.leases.entry(capped.address).or_insert(capped);
            }
        }
        server
    }

    /// Feed one input at `now` and collect what to do about it.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        match input {
            Input::Packet(bytes) => match accepted(&bytes) {
                Some((msg, MessageType::Discover)) => self.discover(msg, now),
                Some((msg, MessageType::Request)) => self.request(&msg, now),
                Some((msg, MessageType::Release)) => self.release(&msg, now),
                Some((msg, MessageType::Decline)) => self.decline(&msg, now),
                Some((msg, MessageType::Inform)) => self.inform(&msg),
                _ => Vec::new(),
            },
            Input::ProbeReply { address, mac } => self.probe_reply(address, mac, now),
            Input::Timeout => self.timeout(now),
        }
    }

    /// When [`Server::handle`] next wants an [`Input::Timeout`].
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        let leases = self.leases.values().map(|lease| lease.expires_at);
        let offers = self
            .offers
            .values()
            .map(|offer| offer.probing.unwrap_or(offer.hold_until));
        let abandons = self.abandoned.values().copied();
        leases.chain(offers).chain(abandons).min()
    }

    /// The active leases, ascending by address.
    #[must_use]
    pub fn leases(&self) -> Vec<LeaseRecord> {
        self.leases.values().cloned().collect()
    }

    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    fn discover(&mut self, msg: Message, now: Timestamp) -> Vec<Output> {
        let identity = identity_of(&msg);
        let mac = chaddr6(&msg);
        if let Some(offer) = self.offers.get_mut(&identity) {
            if offer.probing.is_some() {
                return Vec::new();
            }
            offer.discover = slim_for_offer(msg);
            offer.hold_until = now + OFFER_HOLD;
            // Re-sent, not announced again: a client that keeps discovering is not a console line
            // per second.
            return self.offer_outputs(&identity, false);
        }
        let requested = requested_address(&msg);
        let Some(address) = self.candidate(&identity, mac, requested) else {
            return vec![Output::Event(ServerEvent::Exhausted { mac })];
        };
        let own = self
            .lease_of(&identity)
            .is_some_and(|lease| lease.address == address);
        let offer = Offer {
            address,
            mac,
            discover: slim_for_offer(msg),
            probing: (!own).then_some(now + PROBE_TIMEOUT),
            probes: 1,
            hold_until: now + OFFER_HOLD,
        };
        self.offers.insert(identity.clone(), offer);
        if own {
            self.offer_outputs(&identity, true)
        } else {
            vec![Output::Probe { address }]
        }
    }

    /// The OFFER for the pending offer of `identity`, with an `Offered` event when `announce`.
    fn offer_outputs(&self, identity: &[u8], announce: bool) -> Vec<Output> {
        let Some(offer) = self.offers.get(identity) else {
            return Vec::new();
        };
        let hostname = self
            .reservation_for(identity, offer.mac)
            .and_then(|reservation| reservation.hostname.clone());
        let message = self.reply(
            &offer.discover,
            MessageType::Offer,
            offer.address,
            hostname.as_deref(),
            true,
        );
        let mut outputs = Vec::with_capacity(2);
        if announce {
            outputs.push(Output::Event(ServerEvent::Offered {
                address: offer.address,
                mac: offer.mac,
            }));
        }
        outputs.push(Output::Send {
            to: destination(&offer.discover, offer.address),
            payload: message.encode(),
        });
        outputs
    }

    fn probe_reply(&mut self, address: Ipv4Addr, mac: [u8; 6], now: Timestamp) -> Vec<Output> {
        let Some(identity) = self
            .offers
            .iter()
            .find(|(_, offer)| offer.probing.is_some() && offer.address == address)
            .map(|(identity, _)| identity.clone())
        else {
            return Vec::new();
        };
        let offer_mac = self.offers[&identity].mac;
        if mac == offer_mac {
            return self.complete_offer(&identity, now);
        }
        let mut outputs = vec![Output::Event(ServerEvent::Conflict { address, mac })];
        self.abandoned.insert(address, now + CONFLICT_HOLD);
        let (probes, requested) = {
            let offer = &self.offers[&identity];
            (offer.probes, requested_address(&offer.discover))
        };
        let next = (probes < MAX_PROBES)
            .then(|| self.candidate(&identity, offer_mac, requested))
            .flatten();
        if let Some(next) = next {
            if let Some(offer) = self.offers.get_mut(&identity) {
                offer.address = next;
                offer.probes += 1;
                offer.probing = Some(now + PROBE_TIMEOUT);
            }
            outputs.push(Output::Probe { address: next });
        } else {
            self.offers.remove(&identity);
            let reserved = self
                .reservation_for(&identity, offer_mac)
                .is_some_and(|reservation| reservation.address == address);
            outputs.push(Output::Event(if reserved {
                ServerEvent::ReservationInUse {
                    address,
                    mac: offer_mac,
                    by: mac,
                }
            } else {
                ServerEvent::Exhausted { mac: offer_mac }
            }));
        }
        outputs
    }

    /// The probe is over: offer the address.
    fn complete_offer(&mut self, identity: &[u8], now: Timestamp) -> Vec<Output> {
        if let Some(offer) = self.offers.get_mut(identity) {
            offer.probing = None;
            offer.hold_until = now + OFFER_HOLD;
        }
        self.offer_outputs(identity, true)
    }

    fn timeout(&mut self, now: Timestamp) -> Vec<Output> {
        let mut outputs = Vec::new();
        let expired: Vec<Ipv4Addr> = self
            .leases
            .values()
            .filter(|lease| lease.expires_at <= now)
            .map(|lease| lease.address)
            .collect();
        for address in expired {
            if let Some(lease) = self.leases.remove(&address) {
                self.history.insert(address, lease.expires_at);
                outputs.push(Output::Event(ServerEvent::Expired(lease)));
            }
        }
        let probed: Vec<Identity> = self
            .offers
            .iter()
            .filter(|(_, offer)| offer.probing.is_some_and(|deadline| deadline <= now))
            .map(|(identity, _)| identity.clone())
            .collect();
        for identity in probed {
            outputs.extend(self.complete_offer(&identity, now));
        }
        self.offers
            .retain(|_, offer| offer.probing.is_some() || offer.hold_until > now);
        self.abandoned.retain(|_, until| *until > now);
        outputs
    }

    /// RFC 2131 §4.3.2: the address the client means depends on its state (SELECTING names
    /// our offer with option 54, INIT-REBOOT asks for option 50 with no server, RENEWING and
    /// REBINDING speak from `ciaddr`); then the same verdict for all of them.
    fn request(&mut self, msg: &Message, now: Timestamp) -> Vec<Output> {
        let identity = identity_of(msg);
        let server_id = match msg.option(54) {
            Some(DhcpOption::ServerIdentifier(id)) => Some(*id),
            _ => None,
        };
        let address = match (server_id, requested_address(msg), msg.ciaddr) {
            (Some(id), _, _) if id != self.config.server => {
                // The client chose another server: our offer is void.
                self.offers.remove(&identity);
                return Vec::new();
            }
            (_, Some(address), _) => address,
            // RENEWING or REBINDING: the address is `ciaddr`, whether or not the client names
            // us as well (some do, against RFC 2131 §4.3.2).
            (_, None, ciaddr) if ciaddr != Ipv4Addr::UNSPECIFIED => ciaddr,
            _ => return Vec::new(),
        };
        match self.refusal(address, &identity, chaddr6(msg)) {
            Some(reason) => self.nak(msg, address, reason),
            None => self.ack(msg, address, now),
        }
    }

    /// Why `identity` may not have `address`, if it may not. An authoritative server: an
    /// unknown client asking for a free pool address is adopted, one asking for anything else
    /// is refused so it starts over at once.
    fn refusal(&self, address: Ipv4Addr, identity: &[u8], mac: [u8; 6]) -> Option<NakReason> {
        if !self.is_host_address(address) {
            return Some(NakReason::WrongNetwork);
        }
        if self.reserved_for_other(address, identity, mac) {
            return Some(NakReason::Reserved);
        }
        let reservation = self
            .reservation_for(identity, mac)
            .map(|reservation| reservation.address);
        if reservation.is_some_and(|reserved| reserved != address) {
            return Some(NakReason::WrongAddress);
        }
        if !self.free_for(address, identity, mac) {
            return Some(NakReason::InUse);
        }
        if !self.in_pool(address) && reservation != Some(address) {
            return Some(NakReason::OutsidePool);
        }
        None
    }

    /// Commit the lease and acknowledge it.
    fn ack(&mut self, msg: &Message, address: Ipv4Addr, now: Timestamp) -> Vec<Output> {
        let identity = identity_of(msg);
        let mac = chaddr6(msg);
        let reserved_name = self
            .reservation_for(&identity, mac)
            .and_then(|reservation| reservation.hostname.clone());
        let previous_lease = self.lease_of(&identity).cloned();
        let hostname = reserved_name
            .clone()
            .or_else(|| match msg.option(12) {
                Some(DhcpOption::HostName(name)) => sanitise_hostname(name),
                _ => None,
            })
            .or_else(|| {
                previous_lease
                    .as_ref()
                    .and_then(|lease| lease.hostname.clone())
            });
        let previous = previous_lease.map(|lease| lease.address);
        if let Some(previous) = previous
            && previous != address
        {
            self.leases.remove(&previous);
            self.history.insert(previous, now);
        }
        self.offers.remove(&identity);
        self.history.remove(&address);
        let record = LeaseRecord {
            address,
            mac,
            client_id: match msg.option(61) {
                Some(DhcpOption::ClientIdentifier(id)) if !id.is_empty() => Some(id.clone()),
                _ => None,
            },
            hostname,
            granted_at: now,
            expires_at: now + Timestamp::from(self.config.lease_secs),
        };
        self.leases.insert(address, record.clone());
        let reply = self.reply(
            msg,
            MessageType::Ack,
            address,
            reserved_name.as_deref(),
            true,
        );
        let event = if previous == Some(address) {
            ServerEvent::Renewed(record)
        } else {
            ServerEvent::Granted(record)
        };
        vec![
            Output::Event(event),
            Output::Send {
                to: destination(msg, address),
                payload: reply.encode(),
            },
        ]
    }

    /// Refuse, broadcast (RFC 2131 §4.3.2: `giaddr` is zero), with the reason as option 56.
    fn nak(&self, msg: &Message, address: Ipv4Addr, reason: NakReason) -> Vec<Output> {
        let mut reply = self.reply(msg, MessageType::Nak, Ipv4Addr::UNSPECIFIED, None, false);
        reply
            .options
            .insert(2, DhcpOption::Message(reason.to_string()));
        vec![
            Output::Event(ServerEvent::Nak {
                address,
                mac: chaddr6(msg),
                reason,
            }),
            Output::Send {
                to: Destination::Broadcast,
                payload: reply.encode(),
            },
        ]
    }

    /// DHCPINFORM (RFC 2131 §4.3.5): the options for an address the client already has, with
    /// no lease time.
    fn inform(&self, msg: &Message) -> Vec<Output> {
        if msg.ciaddr == Ipv4Addr::UNSPECIFIED {
            return Vec::new();
        }
        let mac = chaddr6(msg);
        let hostname = self
            .reservation_for(&identity_of(msg), mac)
            .and_then(|reservation| reservation.hostname.clone());
        let reply = self.reply(
            msg,
            MessageType::Ack,
            Ipv4Addr::UNSPECIFIED,
            hostname.as_deref(),
            false,
        );
        vec![
            Output::Event(ServerEvent::Informed {
                address: msg.ciaddr,
                mac,
            }),
            Output::Send {
                to: Destination::Link {
                    ip: msg.ciaddr,
                    mac,
                },
                payload: reply.encode(),
            },
        ]
    }

    /// DHCPRELEASE: the client gives `ciaddr` back.
    fn release(&mut self, msg: &Message, now: Timestamp) -> Vec<Output> {
        if !self.addressed_to_us(msg) {
            return Vec::new();
        }
        let identity = identity_of(msg);
        let ours = self
            .leases
            .get(&msg.ciaddr)
            .is_some_and(|lease| record_identity(lease) == identity);
        if !ours {
            return Vec::new();
        }
        let Some(lease) = self.leases.remove(&msg.ciaddr) else {
            return Vec::new();
        };
        self.history.insert(lease.address, now);
        vec![Output::Event(ServerEvent::Released(lease))]
    }

    /// DHCPDECLINE: the client found option 50 in use; the address rests for `CONFLICT_HOLD`.
    fn decline(&mut self, msg: &Message, now: Timestamp) -> Vec<Output> {
        if !self.addressed_to_us(msg) {
            return Vec::new();
        }
        let identity = identity_of(msg);
        let mac = chaddr6(msg);
        let Some(address) = requested_address(msg) else {
            return Vec::new();
        };
        let ours = self
            .leases
            .get(&address)
            .is_some_and(|lease| record_identity(lease) == identity)
            || self
                .offers
                .get(&identity)
                .is_some_and(|offer| offer.address == address);
        if !ours {
            return Vec::new();
        }
        self.leases.remove(&address);
        self.offers.remove(&identity);
        self.abandoned.insert(address, now + CONFLICT_HOLD);
        vec![Output::Event(ServerEvent::Declined { address, mac })]
    }

    /// Option 54 is ours, or absent.
    fn addressed_to_us(&self, msg: &Message) -> bool {
        match msg.option(54) {
            Some(DhcpOption::ServerIdentifier(id)) => *id == self.config.server,
            _ => true,
        }
    }

    /// RFC 2131 §4.3.1's choice for a DISCOVER: the reservation, the current lease, the
    /// requested address, else the pool walked lowest-never-leased first, then longest-expired.
    fn candidate(
        &self,
        identity: &[u8],
        mac: [u8; 6],
        requested: Option<Ipv4Addr>,
    ) -> Option<Ipv4Addr> {
        if let Some(reservation) = self.reservation_for(identity, mac)
            && self.is_host_address(reservation.address)
        {
            return Some(reservation.address);
        }
        if let Some(lease) = self.lease_of(identity)
            && !self.reserved_for_other(lease.address, identity, mac)
        {
            return Some(lease.address);
        }
        if let Some(address) = requested
            && self.in_pool(address)
            && self.free_for(address, identity, mac)
        {
            return Some(address);
        }
        let mut longest_expired: Option<(Timestamp, Ipv4Addr)> = None;
        for address in self.pool_addresses() {
            if !self.free_for(address, identity, mac) || self.reserved(address) {
                continue;
            }
            match self.history.get(&address) {
                None if !self.leases.contains_key(&address) => return Some(address),
                Some(&ended) if longest_expired.is_none_or(|(best, _)| ended < best) => {
                    longest_expired = Some((ended, address));
                }
                _ => {}
            }
        }
        longest_expired.map(|(_, address)| address)
    }

    /// Nothing stands between `identity` and `address`: it is a host address of the subnet,
    /// not the server's, not reserved for or leased, offered or abandoned by anyone else.
    fn free_for(&self, address: Ipv4Addr, identity: &[u8], mac: [u8; 6]) -> bool {
        self.is_host_address(address)
            && !self.reserved_for_other(address, identity, mac)
            && !self.abandoned.contains_key(&address)
            && self
                .leases
                .get(&address)
                .is_none_or(|lease| record_identity(lease) == identity)
            && !self
                .offers
                .iter()
                .any(|(other, offer)| offer.address == address && other.as_slice() != identity)
    }

    fn pool_addresses(&self) -> impl Iterator<Item = Ipv4Addr> {
        (u32::from(self.config.pool.0)..=u32::from(self.config.pool.1)).map(Ipv4Addr::from)
    }

    fn in_pool(&self, address: Ipv4Addr) -> bool {
        (u32::from(self.config.pool.0)..=u32::from(self.config.pool.1))
            .contains(&u32::from(address))
    }

    /// Inside the subnet, and neither the network, the broadcast nor the server's address.
    fn is_host_address(&self, address: Ipv4Addr) -> bool {
        let mask = mask(self.config.prefix);
        let network = u32::from(self.config.server) & mask;
        let addr = u32::from(address);
        addr & mask == network
            && addr != network
            && addr != network | !mask
            && address != self.config.server
    }

    fn reservation_for(&self, identity: &[u8], mac: [u8; 6]) -> Option<&Reservation> {
        self.config
            .reservations
            .iter()
            .find(|reservation| reservation_matches(reservation, identity, mac))
    }

    fn reserved(&self, address: Ipv4Addr) -> bool {
        self.config
            .reservations
            .iter()
            .any(|reservation| reservation.address == address)
    }

    fn reserved_for_other(&self, address: Ipv4Addr, identity: &[u8], mac: [u8; 6]) -> bool {
        self.config.reservations.iter().any(|reservation| {
            reservation.address == address && !reservation_matches(reservation, identity, mac)
        })
    }

    fn lease_of(&self, identity: &[u8]) -> Option<&LeaseRecord> {
        self.leases
            .values()
            .find(|lease| record_identity(lease) == identity)
    }

    /// A reply to `request` (RFC 2131 Table 3): header fields copied, our options.
    fn reply(
        &self,
        request: &Message,
        kind: MessageType,
        yiaddr: Ipv4Addr,
        hostname: Option<&str>,
        with_lease: bool,
    ) -> Message {
        let mut options = vec![
            DhcpOption::MessageType(kind),
            DhcpOption::ServerIdentifier(self.config.server),
        ];
        if with_lease {
            let lease = self.config.lease_secs;
            options.push(DhcpOption::AddressLeaseTime(lease));
            options.push(DhcpOption::Renewal(lease / 2));
            options.push(DhcpOption::Rebinding(
                u32::try_from(u64::from(lease) * 7 / 8).unwrap_or(lease),
            ));
        }
        if kind != MessageType::Nak {
            let mask = mask(self.config.prefix);
            options.push(DhcpOption::SubnetMask(Ipv4Addr::from(mask)));
            options.push(DhcpOption::Router(vec![self.config.server]));
            options.push(DhcpOption::DomainNameServer(
                if self.config.dns.is_empty() {
                    vec![self.config.server]
                } else {
                    self.config.dns.clone()
                },
            ));
            options.push(DhcpOption::NtpServers(if self.config.ntp.is_empty() {
                vec![self.config.server]
            } else {
                self.config.ntp.clone()
            }));
            if let Some(domain) = &self.config.domain {
                options.push(DhcpOption::DomainName(domain.clone()));
            }
            options.push(DhcpOption::BroadcastAddr(Ipv4Addr::from(
                u32::from(self.config.server) | !mask,
            )));
            if let Some(hostname) = hostname {
                options.push(DhcpOption::HostName(hostname.to_owned()));
            }
        }
        if let Some(DhcpOption::ClientIdentifier(id)) = request.option(61)
            && !id.is_empty()
        {
            options.push(DhcpOption::ClientIdentifier(id.clone()));
        }
        Message {
            op: Op::BootReply,
            htype: request.htype,
            hlen: request.hlen,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: if kind == MessageType::Ack {
                request.ciaddr
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            yiaddr,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            sname: [0; 64],
            file: [0; 128],
            options,
        }
    }
}

/// What an offer keeps of the DISCOVER it answers: the header fields the OFFER echoes and the
/// two options read later (50, the requested address; 61, the client identifier). `sname`,
/// `file` and every other option go, so a pending offer costs a few dozen bytes, not a packet.
fn slim_for_offer(mut msg: Message) -> Message {
    msg.options.retain(|option| {
        matches!(
            option,
            DhcpOption::RequestedIpAddress(_) | DhcpOption::ClientIdentifier(_)
        )
    });
    msg.sname = [0; 64];
    msg.file = [0; 128];
    msg
}

/// A client's hostname as a DNS label, or nothing (SPEC §7.6 "sanitised to DNS labels"): the
/// text before the first dot, ASCII lowercase, every run of other characters one hyphen, no
/// hyphen at either end, at most [`MAX_LABEL`] bytes.
#[must_use]
pub fn sanitise_hostname(raw: &str) -> Option<String> {
    let first = raw.split('.').next().unwrap_or("");
    let mut label = String::with_capacity(first.len().min(MAX_LABEL));
    let mut pending_hyphen = false;
    for c in first.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_hyphen && !label.is_empty() {
                label.push('-');
            }
            pending_hyphen = false;
            label.push(c.to_ascii_lowercase());
        } else {
            pending_hyphen = true;
        }
    }
    label.truncate(MAX_LABEL);
    while label.ends_with('-') {
        label.pop();
    }
    (!label.is_empty()).then_some(label)
}

/// The message, if it is a client's request this server handles.
fn accepted(bytes: &[u8]) -> Option<(Message, MessageType)> {
    let msg = Message::decode(bytes).ok()?;
    if msg.op != Op::BootRequest
        || msg.htype != 1
        || msg.hlen != 6
        || msg.giaddr != Ipv4Addr::UNSPECIFIED
    {
        return None;
    }
    let kind = msg.message_type()?;
    matches!(
        kind,
        MessageType::Discover
            | MessageType::Request
            | MessageType::Release
            | MessageType::Decline
            | MessageType::Inform
    )
    .then_some((msg, kind))
}

fn chaddr6(msg: &Message) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&msg.chaddr[..6]);
    mac
}

fn identity_of(msg: &Message) -> Identity {
    match msg.option(61) {
        Some(DhcpOption::ClientIdentifier(id)) if !id.is_empty() => id.clone(),
        _ => mac_identity(chaddr6(msg)),
    }
}

fn record_identity(lease: &LeaseRecord) -> Identity {
    lease
        .client_id
        .clone()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| mac_identity(lease.mac))
}

fn mac_identity(mac: [u8; 6]) -> Identity {
    let mut identity = Vec::with_capacity(7);
    identity.push(1);
    identity.extend_from_slice(&mac);
    identity
}

fn reservation_matches(reservation: &Reservation, identity: &[u8], mac: [u8; 6]) -> bool {
    match &reservation.client_id {
        Some(id) => id.as_slice() == identity,
        None => reservation.mac == mac,
    }
}

fn requested_address(msg: &Message) -> Option<Ipv4Addr> {
    match msg.option(50) {
        Some(DhcpOption::RequestedIpAddress(address)) => Some(*address),
        _ => None,
    }
}

/// Where the reply to `request` goes (RFC 2131 §4.1, `giaddr` being zero).
fn destination(request: &Message, yiaddr: Ipv4Addr) -> Destination {
    if request.ciaddr != Ipv4Addr::UNSPECIFIED {
        Destination::Link {
            ip: request.ciaddr,
            mac: chaddr6(request),
        }
    } else if request.flags & FLAG_BROADCAST != 0 {
        Destination::Broadcast
    } else {
        Destination::Link {
            ip: yiaddr,
            mac: chaddr6(request),
        }
    }
}

fn mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        32.. => u32::MAX,
        bits => u32::MAX << (32 - u32::from(bits)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DhcpOption, FLAG_BROADCAST, Message, MessageType, Op};

    const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 0x0b];
    const MAC_C: [u8; 6] = [2, 0, 0, 0, 0, 0x0c];
    const MAC_X: [u8; 6] = [2, 0, 0, 0, 0, 0x1a];
    const MAC_Y: [u8; 6] = [2, 0, 0, 0, 0, 0x1b];
    const MAC_Z: [u8; 6] = [2, 0, 0, 0, 0, 0x1c];
    const MAC_NAS: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0x10, 0x10];
    const MAC_SQUATTER: [u8; 6] = [2, 0, 0, 0, 0, 0x99];

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn config() -> ServerConfig {
        config_with_pool(ip("192.168.1.100"), ip("192.168.1.200"))
    }

    fn config_with_pool(first: Ipv4Addr, last: Ipv4Addr) -> ServerConfig {
        ServerConfig {
            server: ip("192.168.1.1"),
            prefix: 24,
            pool: (first, last),
            lease_secs: 43_200,
            dns: vec![],
            ntp: vec![],
            domain: Some("home.arpa".into()),
            reservations: vec![Reservation {
                mac: MAC_NAS,
                client_id: None,
                address: ip("192.168.1.10"),
                hostname: Some("nas".into()),
            }],
        }
    }

    fn message(
        kind: MessageType,
        mac: [u8; 6],
        xid: u32,
        ciaddr: Ipv4Addr,
        mut options: Vec<DhcpOption>,
    ) -> Message {
        let mut hardware = [0u8; 16];
        hardware[..6].copy_from_slice(&mac);
        options.insert(0, DhcpOption::MessageType(kind));
        Message {
            op: Op::BootRequest,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: hardware,
            sname: [0; 64],
            file: [0; 128],
            options,
        }
    }

    fn discover(mac: [u8; 6], xid: u32, options: Vec<DhcpOption>) -> Vec<u8> {
        message(
            MessageType::Discover,
            mac,
            xid,
            Ipv4Addr::UNSPECIFIED,
            options,
        )
        .encode()
    }

    fn discover_with_hlen(mac: [u8; 6], xid: u32, hlen: u8) -> Vec<u8> {
        let mut m = message(
            MessageType::Discover,
            mac,
            xid,
            Ipv4Addr::UNSPECIFIED,
            vec![],
        );
        m.hlen = hlen;
        m.encode()
    }

    fn request(mac: [u8; 6], xid: u32, ciaddr: Ipv4Addr, options: Vec<DhcpOption>) -> Vec<u8> {
        message(MessageType::Request, mac, xid, ciaddr, options).encode()
    }

    fn inform(mac: [u8; 6], xid: u32, ciaddr: Ipv4Addr) -> Vec<u8> {
        message(
            MessageType::Inform,
            mac,
            xid,
            ciaddr,
            vec![DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 28])],
        )
        .encode()
    }

    fn release(mac: [u8; 6], xid: u32, ciaddr: Ipv4Addr) -> Vec<u8> {
        message(
            MessageType::Release,
            mac,
            xid,
            ciaddr,
            vec![DhcpOption::ServerIdentifier(ip("192.168.1.1"))],
        )
        .encode()
    }

    fn decline(mac: [u8; 6], xid: u32, address: Ipv4Addr) -> Vec<u8> {
        message(
            MessageType::Decline,
            mac,
            xid,
            Ipv4Addr::UNSPECIFIED,
            vec![
                DhcpOption::RequestedIpAddress(address),
                DhcpOption::ServerIdentifier(ip("192.168.1.1")),
            ],
        )
        .encode()
    }

    fn sends(outputs: &[Output]) -> Vec<(Destination, Message)> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Send { to, payload } => Some((*to, Message::decode(payload).unwrap())),
                _ => None,
            })
            .collect()
    }

    fn events(outputs: &[Output]) -> Vec<ServerEvent> {
        outputs
            .iter()
            .filter_map(|output| match output {
                Output::Event(event) => Some(event.clone()),
                _ => None,
            })
            .collect()
    }

    /// DISCOVER at `now`, probe timeout, and the offered address.
    fn offered(s: &mut Server, mac: [u8; 6], now: Timestamp) -> Ipv4Addr {
        s.handle(Input::Packet(discover(mac, 0x7777, vec![])), now);
        let out = s.handle(Input::Timeout, now + PROBE_TIMEOUT);
        let sent = sends(&out);
        assert_eq!(sent.len(), 1, "one OFFER expected, got {out:?}");
        sent[0].1.yiaddr
    }

    /// SPEC §7.6: the leases name an NTP server, the router itself unless configured.
    #[test]
    fn offers_carry_the_ntp_servers_the_router_by_default() {
        let offer_with = |cfg: ServerConfig| -> Message {
            let mut s = Server::new(cfg, vec![], 0);
            s.handle(Input::Packet(discover([2, 0, 0, 0, 0, 1], 1, vec![])), 0);
            sends(&s.handle(Input::Timeout, PROBE_TIMEOUT)).remove(0).1
        };
        assert_eq!(
            offer_with(config()).option(42),
            Some(&DhcpOption::NtpServers(vec![ip("192.168.1.1")])),
            "ntp empty: the router"
        );
        let mut with_ntp = config();
        with_ntp.ntp = vec![ip("203.0.113.1")];
        assert_eq!(
            offer_with(with_ntp).option(42),
            Some(&DhcpOption::NtpServers(vec![ip("203.0.113.1")]))
        );
    }

    #[test]
    fn discover_probes_the_first_free_pool_address_then_offers_it_after_the_timeout() {
        let mut s = Server::new(config(), vec![], 0);
        let out = s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        assert_eq!(
            out,
            vec![Output::Probe {
                address: ip("192.168.1.100")
            }]
        );
        assert_eq!(s.next_timeout(), Some(PROBE_TIMEOUT));
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        let (to, offer) = sends(&out).remove(0);
        assert_eq!(
            to,
            Destination::Link {
                ip: ip("192.168.1.100"),
                mac: MAC_A
            }
        );
        assert_eq!(offer.op, Op::BootReply);
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(
            (
                offer.xid,
                offer.yiaddr,
                offer.ciaddr,
                offer.secs,
                offer.hops
            ),
            (1, ip("192.168.1.100"), Ipv4Addr::UNSPECIFIED, 0, 0)
        );
        assert_eq!(
            offer.option(54),
            Some(&DhcpOption::ServerIdentifier(ip("192.168.1.1")))
        );
        assert_eq!(
            offer.option(51),
            Some(&DhcpOption::AddressLeaseTime(43_200))
        );
        assert_eq!(offer.option(58), Some(&DhcpOption::Renewal(21_600)));
        assert_eq!(offer.option(59), Some(&DhcpOption::Rebinding(37_800)));
        assert_eq!(
            offer.option(1),
            Some(&DhcpOption::SubnetMask(ip("255.255.255.0")))
        );
        assert_eq!(
            offer.option(3),
            Some(&DhcpOption::Router(vec![ip("192.168.1.1")]))
        );
        assert_eq!(
            offer.option(6),
            Some(&DhcpOption::DomainNameServer(vec![ip("192.168.1.1")]))
        );
        assert_eq!(
            offer.option(15),
            Some(&DhcpOption::DomainName("home.arpa".into()))
        );
        assert_eq!(
            offer.option(28),
            Some(&DhcpOption::BroadcastAddr(ip("192.168.1.255")))
        );
        assert_eq!(offer.option(12), None);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Offered {
                address: ip("192.168.1.100"),
                mac: MAC_A
            }]
        );
    }

    #[test]
    fn a_probe_reply_from_another_host_abandons_the_address_and_probes_the_next() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        let out = s.handle(
            Input::ProbeReply {
                address: ip("192.168.1.100"),
                mac: MAC_SQUATTER,
            },
            0,
        );
        assert_eq!(
            out,
            vec![
                Output::Event(ServerEvent::Conflict {
                    address: ip("192.168.1.100"),
                    mac: MAC_SQUATTER
                }),
                Output::Probe {
                    address: ip("192.168.1.101")
                }
            ]
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.101"));
        // .100 stays abandoned for CONFLICT_HOLD: a second client is probed at .102
        s.handle(Input::Packet(discover(MAC_B, 2, vec![])), 2);
        assert_eq!(s.next_timeout(), Some(2 + PROBE_TIMEOUT));
        let out = s.handle(Input::Timeout, 2 + PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.102"));
        let mut s2 = Server::new(config(), vec![], 0);
        s2.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        let out = s2.handle(
            Input::ProbeReply {
                address: ip("192.168.1.100"),
                mac: MAC_A,
            },
            0,
        );
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.100"),
            "a reply from the requester itself is not a conflict"
        );
    }

    #[test]
    fn three_conflicts_exhaust_one_discover() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        let mut last = Vec::new();
        for n in 100..103u8 {
            last = s.handle(
                Input::ProbeReply {
                    address: Ipv4Addr::new(192, 168, 1, n),
                    mac: MAC_SQUATTER,
                },
                0,
            );
        }
        assert_eq!(
            last,
            vec![
                Output::Event(ServerEvent::Conflict {
                    address: ip("192.168.1.102"),
                    mac: MAC_SQUATTER
                }),
                Output::Event(ServerEvent::Exhausted { mac: MAC_A }),
            ],
            "the third conflict ends the attempt without a fourth probe"
        );
        assert_eq!(
            s.handle(
                Input::ProbeReply {
                    address: ip("192.168.1.102"),
                    mac: MAC_SQUATTER
                },
                0
            ),
            Vec::new(),
            "a stray reply is ignored"
        );
        assert_eq!(
            s.next_timeout(),
            Some(CONFLICT_HOLD),
            "only the abandons remain"
        );
    }

    #[test]
    fn a_reservation_is_offered_without_consulting_the_pool() {
        let mut s = Server::new(config(), vec![], 0);
        let out = s.handle(
            Input::Packet(discover(
                MAC_NAS,
                7,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))],
            )),
            0,
        );
        assert_eq!(
            out,
            vec![Output::Probe {
                address: ip("192.168.1.10")
            }]
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        let (_, offer) = sends(&out).remove(0);
        assert_eq!(offer.yiaddr, ip("192.168.1.10"));
        assert_eq!(offer.option(12), Some(&DhcpOption::HostName("nas".into())));
    }

    #[test]
    fn a_requested_free_pool_address_is_honoured_and_a_held_one_is_not() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(
            Input::Packet(discover(
                MAC_A,
                1,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))],
            )),
            0,
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.150"));
        s.handle(
            Input::Packet(discover(
                MAC_B,
                2,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))],
            )),
            2,
        );
        let out = s.handle(Input::Timeout, 2 + PROBE_TIMEOUT);
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.100"),
            "B gets the lowest free address, not A's offer"
        );
        let mut s = Server::new(config(), vec![], 0);
        s.handle(
            Input::Packet(discover(
                MAC_A,
                1,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.10"))],
            )),
            0,
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.100"),
            "a reserved address is never offered to another client"
        );
    }

    #[test]
    fn repeated_discovers_from_one_client_reuse_one_offer() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        s.handle(Input::Timeout, PROBE_TIMEOUT);
        for t in 2..40u32 {
            let out = s.handle(Input::Packet(discover(MAC_A, t, vec![])), t.into());
            let sent = sends(&out);
            assert_eq!(sent.len(), 1, "no probe, the offer is re-sent at once");
            assert_eq!(sent[0].1.yiaddr, ip("192.168.1.100"));
        }
        s.handle(Input::Packet(discover(MAC_B, 99, vec![])), 40);
        let out = s.handle(Input::Timeout, 40 + PROBE_TIMEOUT);
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.101"),
            "A's offer still holds .100"
        );
        let out = s.handle(Input::Timeout, 40 + OFFER_HOLD + 1);
        assert_eq!(out, Vec::new(), "holds expire silently");
        s.handle(
            Input::Packet(discover(MAC_C, 5, vec![])),
            40 + OFFER_HOLD + 2,
        );
        let out = s.handle(Input::Timeout, 40 + OFFER_HOLD + 2 + PROBE_TIMEOUT);
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.100"),
            "the expired hold frees .100"
        );
    }

    #[test]
    fn the_pool_is_walked_never_leased_first_then_longest_expired_then_exhausted() {
        let lease = |n: u8, mac: [u8; 6], expires_at| LeaseRecord {
            address: Ipv4Addr::new(192, 168, 1, n),
            mac,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at,
        };
        let mut s = Server::new(
            config_with_pool(ip("192.168.1.100"), ip("192.168.1.102")),
            vec![
                lease(100, MAC_X, 50),
                lease(101, MAC_Y, 80),
                lease(102, MAC_Z, 10_000),
            ],
            0,
        );
        let expired = events(&s.handle(Input::Timeout, 100));
        assert_eq!(
            expired.len(),
            2,
            "both .100 and .101 expire by t=100: {expired:?}"
        );
        s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 100);
        let out = s.handle(Input::Timeout, 100 + PROBE_TIMEOUT);
        assert_eq!(
            sends(&out)[0].1.yiaddr,
            ip("192.168.1.100"),
            "no never-leased address left: the one expired longest ago comes first"
        );
        s.handle(Input::Packet(discover(MAC_B, 2, vec![])), 102);
        let out = s.handle(Input::Timeout, 102 + PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.101"));
        let out = s.handle(Input::Packet(discover(MAC_C, 3, vec![])), 104);
        assert_eq!(
            out,
            vec![Output::Event(ServerEvent::Exhausted { mac: MAC_C })],
            ".102 is leased, .100 and .101 are held: nothing to probe"
        );
    }

    #[test]
    fn giaddr_relayed_foreign_op_and_server_messages_are_ignored() {
        let mut s = Server::new(config(), vec![], 0);
        let mut relayed = Message::decode(&discover(MAC_A, 1, vec![])).unwrap();
        relayed.giaddr = ip("10.0.0.1");
        assert_eq!(s.handle(Input::Packet(relayed.encode()), 0), Vec::new());
        let mut offer = Message::decode(&discover(MAC_A, 1, vec![])).unwrap();
        offer.options = vec![DhcpOption::MessageType(MessageType::Offer)];
        assert_eq!(s.handle(Input::Packet(offer.encode()), 0), Vec::new());
        assert_eq!(s.handle(Input::Packet(vec![0u8; 10]), 0), Vec::new());
        assert_eq!(
            s.handle(Input::Packet(discover_with_hlen(MAC_A, 1, 16)), 0),
            Vec::new()
        );
        let mut reply = Message::decode(&discover(MAC_A, 1, vec![])).unwrap();
        reply.op = Op::BootReply;
        assert_eq!(s.handle(Input::Packet(reply.encode()), 0), Vec::new());
        assert_eq!(s.next_timeout(), None, "nothing was remembered");
    }

    fn our_request(mac: [u8; 6], xid: u32, address: Ipv4Addr) -> Vec<u8> {
        request(
            mac,
            xid,
            Ipv4Addr::UNSPECIFIED,
            vec![
                DhcpOption::ServerIdentifier(ip("192.168.1.1")),
                DhcpOption::RequestedIpAddress(address),
            ],
        )
    }

    #[test]
    fn selecting_request_for_our_offer_is_acked_and_granted() {
        let mut s = Server::new(config(), vec![], 0);
        let addr = offered(&mut s, MAC_A, 0);
        let out = s.handle(
            Input::Packet(request(
                MAC_A,
                1,
                Ipv4Addr::UNSPECIFIED,
                vec![
                    DhcpOption::ServerIdentifier(ip("192.168.1.1")),
                    DhcpOption::RequestedIpAddress(addr),
                    DhcpOption::HostName("Andy's iPhone".into()),
                ],
            )),
            3,
        );
        let (to, ack) = sends(&out).remove(0);
        assert_eq!(
            to,
            Destination::Link {
                ip: addr,
                mac: MAC_A
            }
        );
        assert_eq!(ack.message_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr, addr);
        assert_eq!(ack.option(51), Some(&DhcpOption::AddressLeaseTime(43_200)));
        let record = LeaseRecord {
            address: addr,
            mac: MAC_A,
            client_id: None,
            hostname: Some("andy-s-iphone".into()),
            granted_at: 3,
            expires_at: 3 + 43_200,
        };
        assert_eq!(events(&out), vec![ServerEvent::Granted(record.clone())]);
        assert_eq!(s.leases(), vec![record]);
        assert_eq!(s.next_timeout(), Some(3 + 43_200));
    }

    #[test]
    fn selecting_request_for_another_server_is_ignored_and_frees_the_offer() {
        let mut s = Server::new(config(), vec![], 0);
        let addr = offered(&mut s, MAC_A, 0);
        let out = s.handle(
            Input::Packet(request(
                MAC_A,
                1,
                Ipv4Addr::UNSPECIFIED,
                vec![
                    DhcpOption::ServerIdentifier(ip("192.168.1.254")),
                    DhcpOption::RequestedIpAddress(addr),
                ],
            )),
            3,
        );
        assert_eq!(out, Vec::new());
        assert_eq!(offered(&mut s, MAC_B, 4), addr, "A's hold is gone");
    }

    #[test]
    fn selecting_request_for_a_reserved_address_is_naked_broadcast() {
        let mut s = Server::new(config(), vec![], 0);
        let _ = offered(&mut s, MAC_A, 0);
        let out = s.handle(Input::Packet(our_request(MAC_A, 1, ip("192.168.1.10"))), 3);
        let (to, nak) = sends(&out).remove(0);
        assert_eq!(to, Destination::Broadcast);
        assert_eq!(nak.message_type(), Some(MessageType::Nak));
        assert_eq!(
            (nak.yiaddr, nak.ciaddr),
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(nak.option(51), None);
        assert_eq!(
            nak.option(56),
            Some(&DhcpOption::Message("reserved for another client".into()))
        );
        assert_eq!(
            events(&out),
            vec![ServerEvent::Nak {
                address: ip("192.168.1.10"),
                mac: MAC_A,
                reason: NakReason::Reserved
            }]
        );
    }

    #[test]
    fn init_reboot_is_adopted_inside_the_pool_and_naked_outside() {
        let mut s = Server::new(config(), vec![], 0);
        let reboot = |mac, xid, addr: &str| {
            request(
                mac,
                xid,
                Ipv4Addr::UNSPECIFIED,
                vec![DhcpOption::RequestedIpAddress(ip(addr))],
            )
        };
        let out = s.handle(Input::Packet(reboot(MAC_A, 1, "192.168.1.150")), 0);
        assert_eq!(sends(&out)[0].1.message_type(), Some(MessageType::Ack));
        assert!(
            matches!(events(&out)[0], ServerEvent::Granted(ref r) if r.address == ip("192.168.1.150"))
        );
        let out = s.handle(Input::Packet(reboot(MAC_B, 2, "192.168.1.77")), 1);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Nak {
                address: ip("192.168.1.77"),
                mac: MAC_B,
                reason: NakReason::OutsidePool
            }]
        );
        let out = s.handle(Input::Packet(reboot(MAC_B, 3, "10.0.0.5")), 2);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Nak {
                address: ip("10.0.0.5"),
                mac: MAC_B,
                reason: NakReason::WrongNetwork
            }]
        );
        let out = s.handle(Input::Packet(reboot(MAC_B, 4, "192.168.1.150")), 3);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Nak {
                address: ip("192.168.1.150"),
                mac: MAC_B,
                reason: NakReason::InUse
            }]
        );
    }

    #[test]
    fn reserved_client_requesting_another_address_is_naked_then_offered_its_reservation() {
        let mut s = Server::new(config(), vec![], 0);
        let out = s.handle(
            Input::Packet(request(
                MAC_NAS,
                1,
                Ipv4Addr::UNSPECIFIED,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))],
            )),
            0,
        );
        assert_eq!(
            events(&out),
            vec![ServerEvent::Nak {
                address: ip("192.168.1.150"),
                mac: MAC_NAS,
                reason: NakReason::WrongAddress
            }]
        );
        assert_eq!(offered(&mut s, MAC_NAS, 1), ip("192.168.1.10"));
    }

    #[test]
    fn renewing_and_rebinding_are_acked_unicast_to_ciaddr_as_renewals() {
        let mut s = Server::new(config(), vec![], 0);
        let addr = offered(&mut s, MAC_A, 0);
        s.handle(Input::Packet(our_request(MAC_A, 1, addr)), 3);
        let out = s.handle(Input::Packet(request(MAC_A, 2, addr, vec![])), 21_603);
        let (to, ack) = sends(&out).remove(0);
        assert_eq!(
            to,
            Destination::Link {
                ip: addr,
                mac: MAC_A
            }
        );
        assert_eq!((ack.yiaddr, ack.ciaddr), (addr, addr));
        assert!(
            matches!(events(&out)[0], ServerEvent::Renewed(ref r) if r.expires_at == 21_603 + 43_200 && r.granted_at == 21_603)
        );
        let mut broadcast = Message::decode(&request(MAC_A, 3, addr, vec![])).unwrap();
        broadcast.flags = FLAG_BROADCAST;
        let out = s.handle(Input::Packet(broadcast.encode()), 40_000);
        assert_eq!(
            sends(&out)[0].0,
            Destination::Link {
                ip: addr,
                mac: MAC_A
            },
            "ciaddr wins over the broadcast flag"
        );
    }

    #[test]
    fn restored_lease_is_renewed_not_granted_after_a_reboot() {
        let record = LeaseRecord {
            address: ip("192.168.1.120"),
            mac: MAC_A,
            client_id: None,
            hostname: Some("pc".into()),
            granted_at: 0,
            expires_at: 40_000,
        };
        let mut s = Server::new(config(), vec![record], 100);
        let out = s.handle(
            Input::Packet(request(
                MAC_A,
                1,
                Ipv4Addr::UNSPECIFIED,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.120"))],
            )),
            100,
        );
        assert!(
            matches!(events(&out)[0], ServerEvent::Renewed(ref r) if r.hostname.as_deref() == Some("pc"))
        );
    }

    #[test]
    fn inform_is_acked_with_options_and_no_lease_time() {
        let mut s = Server::new(config(), vec![], 0);
        let out = s.handle(Input::Packet(inform(MAC_A, 9, ip("192.168.1.50"))), 0);
        let (to, ack) = sends(&out).remove(0);
        assert_eq!(
            to,
            Destination::Link {
                ip: ip("192.168.1.50"),
                mac: MAC_A
            }
        );
        assert_eq!(
            (ack.yiaddr, ack.ciaddr),
            (Ipv4Addr::UNSPECIFIED, ip("192.168.1.50"))
        );
        assert_eq!(
            ack.option(6),
            Some(&DhcpOption::DomainNameServer(vec![ip("192.168.1.1")]))
        );
        assert_eq!(ack.option(51), None);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Informed {
                address: ip("192.168.1.50"),
                mac: MAC_A
            }]
        );
        assert_eq!(s.leases(), Vec::new());
    }

    #[test]
    fn release_frees_and_decline_abandons() {
        let mut s = Server::new(config(), vec![], 0);
        let addr = offered(&mut s, MAC_A, 0);
        s.handle(Input::Packet(our_request(MAC_A, 1, addr)), 3);
        let out = s.handle(Input::Packet(release(MAC_A, 2, addr)), 10);
        assert!(matches!(events(&out)[0], ServerEvent::Released(ref r) if r.address == addr));
        assert_eq!(s.leases(), Vec::new());
        let addr2 = offered(&mut s, MAC_B, 11);
        assert_ne!(
            addr2, addr,
            "a released address rejoins the pool behind the never-leased ones"
        );
        let out = s.handle(Input::Packet(decline(MAC_B, 3, addr2)), 12);
        assert_eq!(
            events(&out),
            vec![ServerEvent::Declined {
                address: addr2,
                mac: MAC_B
            }]
        );
        let addr3 = offered(&mut s, MAC_C, 13);
        assert_ne!(addr3, addr2, "a declined address is abandoned");
    }

    #[test]
    fn leases_expire_on_timeout() {
        let mut s = Server::new(config(), vec![], 0);
        let addr = offered(&mut s, MAC_A, 0);
        s.handle(Input::Packet(our_request(MAC_A, 1, addr)), 3);
        assert_eq!(s.handle(Input::Timeout, 43_202), Vec::new());
        let out = s.handle(Input::Timeout, 43_203);
        assert!(matches!(events(&out)[0], ServerEvent::Expired(ref r) if r.address == addr));
        assert_eq!(s.leases(), Vec::new());
    }

    #[test]
    fn client_identifiers_are_echoed_and_distinguish_clients_with_one_mac() {
        let mut s = Server::new(config(), vec![], 0);
        let id1 =
            DhcpOption::ClientIdentifier(vec![0xff, 1, 2, 3, 4, 0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
        let id2 =
            DhcpOption::ClientIdentifier(vec![0xff, 9, 9, 9, 9, 0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
        s.handle(Input::Packet(discover(MAC_A, 1, vec![id1.clone()])), 0);
        let a = sends(&s.handle(Input::Timeout, 1))[0].1.clone();
        assert_eq!(a.option(61), Some(&id1));
        s.handle(Input::Packet(discover(MAC_A, 2, vec![id2])), 2);
        let b = sends(&s.handle(Input::Timeout, 3))[0].1.clone();
        assert_ne!(a.yiaddr, b.yiaddr);
    }

    #[test]
    fn hostnames_are_sanitised_to_labels() {
        assert_eq!(
            sanitise_hostname("Andy's iPhone"),
            Some("andy-s-iphone".into())
        );
        assert_eq!(sanitise_hostname("nas.local"), Some("nas".into()));
        assert_eq!(sanitise_hostname("  "), None);
        assert_eq!(sanitise_hostname("--x--"), Some("x".into()));
        assert_eq!(sanitise_hostname("Ünïcödé"), Some("n-c-d".into()));
        assert_eq!(sanitise_hostname(&"a".repeat(70)), Some("a".repeat(63)));
        assert_eq!(
            sanitise_hostname(&format!("{}-", "a".repeat(62))),
            Some("a".repeat(62))
        );
    }

    /// Review finding: a lease restored from the file that lies outside the current pool (the
    /// range was shrunk before the reboot) must be dropped, or the client is offered it on
    /// DISCOVER and refused it on REQUEST forever; a reservation stays whatever the pool.
    #[test]
    fn new_drops_restored_leases_outside_the_pool_unless_reserved() {
        let lease = |address: &str, mac: [u8; 6]| LeaseRecord {
            address: ip(address),
            mac,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at: 1_000,
        };
        let mut s = Server::new(
            config_with_pool(ip("192.168.1.100"), ip("192.168.1.150")),
            vec![
                lease("192.168.1.180", MAC_A),
                lease("192.168.1.10", MAC_NAS),
                lease("192.168.1.120", MAC_B),
            ],
            0,
        );
        assert_eq!(
            s.leases()
                .iter()
                .map(|l| l.address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.168.1.10", "192.168.1.120"]
        );
        // The client of the dropped lease starts over and gets a pool address, no livelock.
        s.handle(
            Input::Packet(discover(
                MAC_A,
                1,
                vec![DhcpOption::RequestedIpAddress(ip("192.168.1.180"))],
            )),
            0,
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"));
    }

    /// Review finding: a restored lease's remaining time is capped at the lease time, so a box
    /// whose wall clock was wrong when the file was written or read (no RTC, 1970 at boot)
    /// cannot make a lease permanent.
    #[test]
    fn new_caps_a_restored_lease_at_the_lease_time() {
        let record = LeaseRecord {
            address: ip("192.168.1.120"),
            mac: MAC_A,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at: 1_800_000_000,
        };
        let s = Server::new(config(), vec![record], 100);
        assert_eq!(s.leases()[0].expires_at, 100 + 43_200);
        assert_eq!(s.next_timeout(), Some(100 + 43_200));
    }

    /// Review finding: a client that repeats DISCOVER forever gets its offer re-sent but must
    /// not produce an `Offered` event (a console line) each time.
    #[test]
    fn repeated_discovers_do_not_repeat_the_offer_event() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
        let first = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(events(&first).len(), 1, "the first offer is announced");
        let again = s.handle(Input::Packet(discover(MAC_A, 2, vec![])), 2);
        assert_eq!(sends(&again).len(), 1, "the offer is re-sent");
        assert_eq!(events(&again), Vec::new(), "but not announced again");
    }

    /// Seeds for `fuzz/fuzz_targets/dhcp4_server.rs`; run with `--ignored` to refresh them.
    #[test]
    #[ignore = "writes the fuzz corpus seeds"]
    fn write_server_fuzz_corpus() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/dhcp4_server");
        std::fs::create_dir_all(&dir).unwrap();
        let seeds = [
            (
                "seed-discover.bin",
                discover(
                    MAC_A,
                    1,
                    vec![
                        DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 28]),
                        DhcpOption::HostName("pc".into()),
                    ],
                ),
            ),
            (
                "seed-request.bin",
                request(
                    MAC_A,
                    2,
                    Ipv4Addr::UNSPECIFIED,
                    vec![
                        DhcpOption::ServerIdentifier(ip("192.168.1.1")),
                        DhcpOption::RequestedIpAddress(ip("192.168.1.100")),
                    ],
                ),
            ),
            ("seed-inform.bin", inform(MAC_A, 3, ip("192.168.1.50"))),
            ("seed-release.bin", release(MAC_A, 4, ip("192.168.1.100"))),
        ];
        for (name, bytes) in seeds {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }

    #[test]
    fn new_drops_leases_that_no_longer_fit_the_subnet_or_have_expired() {
        let good = LeaseRecord {
            address: ip("192.168.1.120"),
            mac: MAC_A,
            client_id: None,
            hostname: None,
            granted_at: 0,
            expires_at: 100,
        };
        let expired = LeaseRecord {
            address: ip("192.168.1.121"),
            mac: MAC_B,
            expires_at: 10,
            ..good.clone()
        };
        let elsewhere = LeaseRecord {
            address: ip("10.9.8.7"),
            mac: MAC_C,
            ..good.clone()
        };
        let on_reservation = LeaseRecord {
            address: ip("192.168.1.10"),
            mac: MAC_C,
            ..good.clone()
        };
        let s = Server::new(
            config(),
            vec![expired, elsewhere, on_reservation, good.clone()],
            50,
        );
        assert_eq!(s.leases(), vec![good]);
        assert_eq!(s.next_timeout(), Some(100));
    }

    #[test]
    fn a_squatted_reservation_is_reported_as_in_use_not_exhausted() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(Input::Packet(discover(MAC_NAS, 1, vec![])), 0);
        let mut out = Vec::new();
        for i in 0..MAX_PROBES {
            out = s.handle(
                Input::ProbeReply {
                    address: ip("192.168.1.10"),
                    mac: MAC_SQUATTER,
                },
                Timestamp::from(i),
            );
        }
        assert!(
            events(&out).contains(&ServerEvent::ReservationInUse {
                address: ip("192.168.1.10"),
                mac: MAC_NAS,
                by: MAC_SQUATTER,
            }),
            "{out:?}"
        );
        assert!(
            !events(&out)
                .iter()
                .any(|e| matches!(e, ServerEvent::Exhausted { .. }))
        );
    }

    #[test]
    fn a_renewing_request_with_our_server_id_and_ciaddr_is_acknowledged() {
        let mut s = Server::new(config(), vec![], 0);
        let address = offered(&mut s, MAC_A, 0);
        s.handle(
            Input::Packet(request(
                MAC_A,
                1,
                Ipv4Addr::UNSPECIFIED,
                vec![
                    DhcpOption::ServerIdentifier(ip("192.168.1.1")),
                    DhcpOption::RequestedIpAddress(address),
                ],
            )),
            2,
        );
        let out = s.handle(
            Input::Packet(request(
                MAC_A,
                2,
                address,
                vec![DhcpOption::ServerIdentifier(ip("192.168.1.1"))],
            )),
            100,
        );
        assert_eq!(
            sends(&out)[0].1.message_type(),
            Some(MessageType::Ack),
            "{out:?}"
        );
    }

    #[test]
    fn an_empty_client_identifier_is_not_echoed() {
        let mut s = Server::new(config(), vec![], 0);
        s.handle(
            Input::Packet(discover(
                MAC_A,
                1,
                vec![DhcpOption::ClientIdentifier(vec![])],
            )),
            0,
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        assert_eq!(sends(&out)[0].1.option(61), None, "{out:?}");
    }

    /// Pin for the slimmed offer: what it must still carry.
    #[test]
    fn offers_keep_the_requested_address_and_the_client_identifier() {
        let mut s = Server::new(config(), vec![], 0);
        let id = vec![0xff, 1, 2, 3, 4];
        s.handle(
            Input::Packet(discover(
                MAC_A,
                1,
                vec![
                    DhcpOption::ClientIdentifier(id.clone()),
                    DhcpOption::RequestedIpAddress(ip("192.168.1.150")),
                    DhcpOption::Unknown {
                        code: 43,
                        data: vec![1; 200],
                    },
                ],
            )),
            0,
        );
        let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
        let offer = &sends(&out)[0].1;
        assert_eq!(
            (offer.yiaddr, offer.option(61)),
            (ip("192.168.1.150"), Some(&DhcpOption::ClientIdentifier(id)))
        );
    }
}
