// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The WAN's DHCPv6 client core (RFC 8415 §18; SPEC §7.3), in the odhcp6c mould: one
//! exchange at a time asking for a delegated prefix and an address, Rapid Commit when the
//! server offers it, Renew at T1 and Rebind at T2, Rebind with Confirm's timing after a link
//! change or a reboot, and the status codes of §21.13 read the way the spec says. The driver
//! feeds packets, timeouts and carrier changes in; the core answers with bytes to send, a
//! binding when one is in force, the prefixes and addresses that left it, and notes for the
//! console. No sockets, no clocks: `now` is the driver's monotonic milliseconds.

use std::net::Ipv6Addr;
use std::ops::RangeInclusive;

use ipnet::Ipv6Net;

use crate::Timestamp;
use crate::wire::{Dhcp6Option, Message, MessageType, StatusCode};

const MS: Timestamp = 1000;
/// Solicit: initial timeout and the default cap (RFC 8415 §7.6), the cap replaceable by the
/// server's `SOL_MAX_RT` option.
pub const SOL_TIMEOUT: Timestamp = MS;
pub const SOL_MAX_RT: Timestamp = 3600 * MS;
/// Request: timeout, cap and count.
pub const REQ_TIMEOUT: Timestamp = MS;
pub const REQ_MAX_RT: Timestamp = 30 * MS;
pub const REQ_MAX_RC: u32 = 10;
/// Renew and Rebind: timeout and cap; their durations are T2 and the valid lifetimes.
pub const REN_TIMEOUT: Timestamp = 10 * MS;
pub const REN_MAX_RT: Timestamp = 600 * MS;
pub const REB_TIMEOUT: Timestamp = 10 * MS;
pub const REB_MAX_RT: Timestamp = 600 * MS;
/// The Rebind after a link change or a reboot runs on Confirm's parameters (§18.2.12): a
/// silent server costs ten seconds, not the lease.
pub const CNF_TIMEOUT: Timestamp = MS;
pub const CNF_MAX_RT: Timestamp = 4 * MS;
pub const CNF_MAX_RD: Timestamp = 10 * MS;
/// How long a Reply that failed outright (`UnspecFail`) holds the next Solicit off.
pub const FAIL_HOLDOFF: Timestamp = 30 * MS;
/// The least time between a Reply and the next exchange it calls for: a server whose answer
/// leaves T1 already due (its own T1 and T2 of 0 with a lease that has next to no preferred
/// lifetime) is asked again at this pace, never at its own response rate.
pub const REPLY_HOLDOFF: Timestamp = 10 * MS;
/// Only global unicast (`2000::/3`) is taken from a server, for prefixes and addresses alike.
const GLOBAL_UNICAST: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);
/// The shortest delegation accepted; `MAX_DELEGATED_LEN` is the longest.
const MIN_DELEGATED_LEN: u8 = 8;
/// Prefixes and addresses kept from one binding; more are ignored.
pub const MAX_PREFIXES: usize = 8;
pub const MAX_ADDRESSES: usize = 8;
/// A delegated prefix longer than this holds no /64 for a LAN.
pub const MAX_DELEGATED_LEN: u8 = 64;
/// `SOL_MAX_RT` values a server may set (§21.24).
const SOL_MAX_RT_RANGE: RangeInclusive<u32> = 60..=86400;
const INFINITE: u32 = u32::MAX;
/// Option 7: the server's preference in an Advertise.
const OPT_PREFERENCE: u16 = 7;
/// What the client asks for: DNS servers, the domain list and `SOL_MAX_RT`.
const ORO: [u16; 3] = [23, 24, 82];

/// What one WAN's client is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The router's DUID (`identity/duid`).
    pub duid: Vec<u8>,
    /// The IAID of the prefix delegation (`iaid::iaid(iaid::PD, wan)`).
    pub iaid_pd: u32,
    /// The IAID of the address (`iaid::iaid(iaid::NA, wan)`).
    pub iaid_na: u32,
    /// The delegation length asked for, 48 to 64.
    pub pd_hint: u8,
}

/// One delegated prefix or one address with the lifetimes the server gave, in seconds from
/// the binding's `bound_at`; `u32::MAX` is infinite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease6 {
    pub net: Ipv6Net,
    pub preferred: u32,
    pub valid: u32,
}

/// What the server bound to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The server's DUID.
    pub server: Vec<u8>,
    pub prefixes: Vec<Lease6>,
    pub addresses: Vec<Lease6>,
    /// Seconds after `bound_at` at which to Renew and Rebind; `u32::MAX` never.
    pub t1: u32,
    pub t2: u32,
    pub dns: Vec<Ipv6Addr>,
    pub search: Vec<String>,
    /// When the Reply that made this binding arrived, on the driver's clock.
    pub bound_at: Timestamp,
}

impl Binding {
    /// Every prefix and address, prefixes first.
    pub fn nets(&self) -> impl Iterator<Item = Ipv6Net> + '_ {
        self.prefixes
            .iter()
            .chain(&self.addresses)
            .map(|lease| lease.net)
    }

    /// Nothing bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.addresses.is_empty()
    }

    /// The earliest moment a lease's valid lifetime runs out; `None` when none is finite.
    #[must_use]
    pub fn first_expiry(&self) -> Option<Timestamp> {
        self.prefixes
            .iter()
            .chain(&self.addresses)
            .filter_map(|lease| at(self.bound_at, lease.valid))
            .min()
    }

    fn t1_at(&self) -> Option<Timestamp> {
        at(self.bound_at, self.t1)
    }

    fn t2_at(&self) -> Option<Timestamp> {
        at(self.bound_at, self.t2)
    }

    /// Drop every lease whose valid lifetime has run out by `now`, returning what went.
    fn expire(&mut self, now: Timestamp) -> Vec<Ipv6Net> {
        let bound_at = self.bound_at;
        let lapsed = |lease: &Lease6| at(bound_at, lease.valid).is_some_and(|end| end <= now);
        let mut gone: Vec<Ipv6Net> = self
            .prefixes
            .iter()
            .filter(|l| lapsed(l))
            .map(|l| l.net)
            .collect();
        gone.extend(self.addresses.iter().filter(|l| lapsed(l)).map(|l| l.net));
        self.prefixes.retain(|lease| !lapsed(lease));
        self.addresses.retain(|lease| !lapsed(lease));
        gone
    }
}

/// `start` plus `secs`, or `None` for an infinite lifetime.
fn at(start: Timestamp, secs: u32) -> Option<Timestamp> {
    (secs != INFINITE).then(|| start.saturating_add(Timestamp::from(secs) * MS))
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Begin on a link with carrier: Solicit, or Rebind the binding restored from disk.
    Start { binding: Option<Binding> },
    /// A DHCPv6 message received on the interface.
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
    /// Send these bytes to `ff02::1:2` port 547.
    Send(Vec<u8>),
    /// A binding is in force; `renewed` when it continues one.
    Bound { binding: Binding, renewed: bool },
    /// Prefixes and addresses that left the binding since the last `Bound`: lifetime 0 in a
    /// Reply, missing from the Reply that renewed the IA, or expired.
    Gone(Vec<Ipv6Net>),
    /// Something for the console.
    Note(Note),
}

/// Console-worthy events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Soliciting,
    Requesting,
    Renewing,
    Rebinding,
    /// The server had no prefix for us (said once until one arrives).
    NoPrefixAvailable,
    /// The server had no address for us (said once until one arrives).
    NoAddressAvailable,
    /// The exchange starts over, and why.
    Restarting(&'static str),
    /// A message was dropped, and why.
    Ignored(&'static str),
}

/// Which Rebind exchange is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rebind {
    /// At T2, until the valid lifetimes run out.
    Scheduled,
    /// After a link change or a reboot (§18.2.12), on Confirm's timing.
    AfterLinkChange,
}

/// Where the client is (RFC 8415 §18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// The client core for one WAN.
#[derive(Debug)]
pub struct Client {
    config: Config,
    rng: u64,
    state: State,
    carrier: bool,
    xid: u32,
    /// When the current exchange began, for Elapsed Time.
    started: Timestamp,
    timeout: Option<Timestamp>,
    /// The current retransmission timeout and count.
    rt: Timestamp,
    rc: u32,
    /// When the current exchange gives up: T2 for Renew, the first expiry for Rebind, ten
    /// seconds for the Rebind after a link change.
    deadline: Option<Timestamp>,
    /// Which Rebind is in progress: the scheduled one at T2, or the one after a link change,
    /// where silence keeps the binding.
    rebind: Rebind,
    sol_max_rt: Timestamp,
    /// How long to wait before Soliciting again after a Reply that bound nothing: doubles
    /// from [`FAIL_HOLDOFF`] to `sol_max_rt`, back to the start once something is bound.
    nothing_rt: Timestamp,
    /// The best Advertise so far, with its preference.
    advertise: Option<(u8, Message)>,
    /// The Advertise being requested.
    offer: Option<Message>,
    binding: Option<Binding>,
    last_sent: Option<MessageType>,
    no_prefix_noted: bool,
    no_address_noted: bool,
}

impl Client {
    /// A client in INIT; `seed` feeds its transaction ids and jitter.
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Client {
        Client {
            config,
            rng: seed | 1,
            state: State::Init,
            carrier: false,
            xid: 0,
            started: 0,
            timeout: None,
            rt: SOL_TIMEOUT,
            rc: 0,
            deadline: None,
            rebind: Rebind::Scheduled,
            sol_max_rt: SOL_MAX_RT,
            nothing_rt: FAIL_HOLDOFF,
            advertise: None,
            offer: None,
            binding: None,
            last_sent: None,
            no_prefix_noted: false,
            no_address_noted: false,
        }
    }

    /// Feed one input at `now`; do what comes back.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Start { binding } => {
                self.carrier = true;
                self.binding = binding;
                if self.binding.is_some() {
                    self.confirm_rebind(now, &mut out);
                } else {
                    self.solicit(now, &mut out);
                }
            }
            Input::Packet(bytes) => self.packet(&bytes, now, &mut out),
            Input::Timeout => {
                if self.carrier && self.timeout.is_some_and(|due| due <= now) {
                    self.expire_timer(now, &mut out);
                }
            }
            Input::LinkDown => {
                self.carrier = false;
                self.timeout = None;
                self.advertise = None;
            }
            Input::LinkUp => {
                self.carrier = true;
                if self.binding.is_some() {
                    self.confirm_rebind(now, &mut out);
                } else {
                    self.solicit(now, &mut out);
                }
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

    /// The binding in force or being confirmed.
    #[must_use]
    pub fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }

    /// The type of the last message sent, for the sandbox's assertions.
    #[must_use]
    pub fn last_sent(&self) -> Option<MessageType> {
        self.last_sent
    }

    // --- exchanges --------------------------------------------------------------------------

    fn begin(&mut self, state: State, now: Timestamp, irt: Timestamp) {
        self.state = state;
        self.xid = self.random_xid();
        self.started = now;
        self.rc = 0;
        self.rt = self.jittered(irt);
        self.deadline = None;
        self.rebind = Rebind::Scheduled;
    }

    fn solicit(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.begin(State::Soliciting, now, SOL_TIMEOUT);
        self.advertise = None;
        self.offer = None;
        out.push(Output::Note(Note::Soliciting));
        self.send_solicit(now, out);
    }

    /// Solicit again, but only after `holdoff`: a server that answered with nothing or with a
    /// failure is not asked again at once.
    fn solicit_after(&mut self, now: Timestamp, holdoff: Timestamp) {
        self.begin(State::Soliciting, now, SOL_TIMEOUT);
        self.advertise = None;
        self.offer = None;
        self.last_sent = None;
        self.timeout = Some(now.saturating_add(holdoff));
    }

    fn send_solicit(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let mut message = self.message(MessageType::Solicit, now);
        message.options.push(self.ia_pd(&[]));
        message.options.push(self.ia_na(&[]));
        message.options.push(Dhcp6Option::Oro(ORO.to_vec()));
        message.options.push(Dhcp6Option::RapidCommit);
        self.send(&message, now, out);
    }

    fn request(&mut self, now: Timestamp, offer: Message, out: &mut Vec<Output>) {
        self.begin(State::Requesting, now, REQ_TIMEOUT);
        self.offer = Some(offer);
        out.push(Output::Note(Note::Requesting));
        self.send_request(now, out);
    }

    fn send_request(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some(offer) = self.offer.clone() else {
            return;
        };
        let mut message = self.message(MessageType::Request, now);
        if let Some(server) = offer.server_id() {
            message.options.push(Dhcp6Option::ServerId(server.to_vec()));
        }
        let offered_pd = offer
            .options
            .iter()
            .find(|o| matches!(o, Dhcp6Option::IaPd { .. }));
        let offered_na = offer
            .options
            .iter()
            .find(|o| matches!(o, Dhcp6Option::IaNa { .. }));
        message.options.push(match offered_pd {
            Some(Dhcp6Option::IaPd { options, .. }) => self.ia_pd(&leases_in(options, true)),
            _ => self.ia_pd(&[]),
        });
        message.options.push(match offered_na {
            Some(Dhcp6Option::IaNa { options, .. }) => self.ia_na(&leases_in(options, false)),
            _ => self.ia_na(&[]),
        });
        message.options.push(Dhcp6Option::Oro(ORO.to_vec()));
        self.rc += 1;
        self.send(&message, now, out);
    }

    fn renew(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.begin(State::Renewing, now, REN_TIMEOUT);
        self.deadline = self
            .binding
            .as_ref()
            .and_then(|b| b.t2_at().or_else(|| b.first_expiry()));
        out.push(Output::Note(Note::Renewing));
        self.send_refresh(MessageType::Renew, now, out);
    }

    fn rebind(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.begin(State::Rebinding, now, REB_TIMEOUT);
        self.deadline = self.binding.as_ref().and_then(Binding::first_expiry);
        out.push(Output::Note(Note::Rebinding));
        self.send_refresh(MessageType::Rebind, now, out);
    }

    /// The Rebind after a link change or a reboot (RFC 8415 §18.2.12), on Confirm's timing.
    fn confirm_rebind(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.begin(State::Rebinding, now, CNF_TIMEOUT);
        self.rebind = Rebind::AfterLinkChange;
        self.deadline = Some(now.saturating_add(CNF_MAX_RD));
        out.push(Output::Note(Note::Rebinding));
        self.send_refresh(MessageType::Rebind, now, out);
    }

    /// Renew or Rebind: the binding's leases, and an empty IA for what is not bound, so a
    /// prefix is asked for again at every T1 (§18.2.4).
    fn send_refresh(&mut self, kind: MessageType, now: Timestamp, out: &mut Vec<Output>) {
        let Some(binding) = self.binding.clone() else {
            return;
        };
        let mut message = self.message(kind, now);
        if kind == MessageType::Renew {
            message
                .options
                .push(Dhcp6Option::ServerId(binding.server.clone()));
        }
        message.options.push(self.ia_pd(&binding.prefixes));
        message.options.push(self.ia_na(&binding.addresses));
        message.options.push(Dhcp6Option::Oro(ORO.to_vec()));
        self.send(&message, now, out);
    }

    fn message(&self, kind: MessageType, now: Timestamp) -> Message {
        let mut message = Message::new(kind, self.xid);
        message
            .options
            .push(Dhcp6Option::ClientId(self.config.duid.clone()));
        let elapsed = now.saturating_sub(self.started) / 10;
        message.options.push(Dhcp6Option::ElapsedTime(
            u16::try_from(elapsed).unwrap_or(u16::MAX),
        ));
        message
    }

    /// The `IA_PD` with `prefixes`, or with the hint when there are none.
    fn ia_pd(&self, prefixes: &[Lease6]) -> Dhcp6Option {
        let options = if prefixes.is_empty() {
            vec![Dhcp6Option::IaPrefix {
                prefix: Ipv6Net::new(Ipv6Addr::UNSPECIFIED, self.config.pd_hint)
                    .unwrap_or_else(|_| Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 56)),
                preferred: 0,
                valid: 0,
                options: Vec::new(),
            }]
        } else {
            prefixes
                .iter()
                .map(|lease| Dhcp6Option::IaPrefix {
                    prefix: lease.net,
                    preferred: lease.preferred,
                    valid: lease.valid,
                    options: Vec::new(),
                })
                .collect()
        };
        Dhcp6Option::IaPd {
            iaid: self.config.iaid_pd,
            t1: 0,
            t2: 0,
            options,
        }
    }

    fn ia_na(&self, addresses: &[Lease6]) -> Dhcp6Option {
        Dhcp6Option::IaNa {
            iaid: self.config.iaid_na,
            t1: 0,
            t2: 0,
            options: addresses
                .iter()
                .map(|lease| Dhcp6Option::IaAddr {
                    addr: lease.net.addr(),
                    preferred: lease.preferred,
                    valid: lease.valid,
                    options: Vec::new(),
                })
                .collect(),
        }
    }

    fn send(&mut self, message: &Message, now: Timestamp, out: &mut Vec<Output>) {
        self.last_sent = Some(message.kind);
        out.push(Output::Send(message.encode()));
        let due = now.saturating_add(self.rt);
        self.timeout = Some(self.deadline.map_or(due, |deadline| due.min(deadline)));
    }

    // --- timers -----------------------------------------------------------------------------

    fn expire_timer(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        match self.state {
            State::Init | State::Bound => self.bound_timer(now, out),
            State::Soliciting => {
                if let Some((_, advertise)) = self.advertise.take() {
                    self.request(now, advertise, out);
                } else {
                    self.rt = self.next_rt(self.sol_max_rt);
                    self.send_solicit(now, out);
                }
            }
            State::Requesting => {
                if self.rc >= REQ_MAX_RC {
                    out.push(Output::Note(Note::Restarting("no reply to the request")));
                    self.solicit(now, out);
                } else {
                    // The first Request of an exchange begun by `NoBinding` goes at the
                    // initial timeout; every later one backs off.
                    if self.rc > 0 {
                        self.rt = self.next_rt(REQ_MAX_RT);
                    }
                    self.send_request(now, out);
                }
            }
            State::Renewing => {
                if self.deadline.is_some_and(|end| now >= end) {
                    // T2, or the valid lifetimes when T2 never comes: what follows is
                    // whatever the binding calls for now.
                    self.go_bound(now, out);
                } else {
                    self.rt = self.next_rt(REN_MAX_RT);
                    self.send_refresh(MessageType::Renew, now, out);
                }
            }
            State::Rebinding if self.rebind == Rebind::AfterLinkChange => {
                if self.deadline.is_some_and(|end| now >= end) {
                    // Silence keeps the binding with its timers as they were (§18.2.12).
                    self.rebind = Rebind::Scheduled;
                    self.go_bound(now, out);
                } else {
                    self.rt = self.next_rt(CNF_MAX_RT);
                    self.send_refresh(MessageType::Rebind, now, out);
                }
            }
            State::Rebinding => {
                let gone = self
                    .binding
                    .as_mut()
                    .map_or_else(Vec::new, |b| b.expire(now));
                if !gone.is_empty() {
                    out.push(Output::Gone(gone));
                }
                if self.binding.as_ref().is_none_or(Binding::is_empty) {
                    self.binding = None;
                    out.push(Output::Note(Note::Restarting("the binding expired")));
                    self.solicit(now, out);
                } else {
                    self.deadline = self.binding.as_ref().and_then(Binding::first_expiry);
                    self.rt = self.next_rt(REB_MAX_RT);
                    self.send_refresh(MessageType::Rebind, now, out);
                }
            }
        }
    }

    /// Bound and the timer fired: T1 has come.
    fn bound_timer(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        if self.binding.is_some() {
            self.go_bound(now, out);
        } else {
            self.solicit(now, out);
        }
    }

    /// Settle into the binding: wait for T1, or Renew, Rebind or start over, whichever `now`
    /// calls for.
    fn go_bound(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some(binding) = self.binding.as_ref() else {
            self.solicit(now, out);
            return;
        };
        match (binding.t1_at(), binding.t2_at(), binding.first_expiry()) {
            // Nothing finite: nothing to do, ever.
            (None, _, None) => {
                self.state = State::Bound;
                self.timeout = None;
            }
            // The valid lifetimes have run out: start over.
            (_, _, Some(end)) if now >= end => {
                let gone: Vec<Ipv6Net> = binding.nets().collect();
                out.push(Output::Gone(gone));
                self.binding = None;
                out.push(Output::Note(Note::Restarting("the binding expired")));
                self.solicit(now, out);
            }
            // T1 never comes: wait for the expiry.
            (None, _, Some(end)) => {
                self.state = State::Bound;
                self.timeout = Some(end);
            }
            (Some(t1), _, _) if now < t1 => {
                self.state = State::Bound;
                self.timeout = Some(t1);
            }
            // T1 has come: Renew until T2, or for as long as the leases last when T2 never
            // comes (§21.4: an infinite T2 means never Rebind).
            (_, Some(t2), _) if now < t2 => self.renew(now, out),
            (_, None, _) => self.renew(now, out),
            // T2 has come and the leases still stand: Rebind.
            (_, Some(_), _) => self.rebind(now, out),
        }
    }

    // --- packets ----------------------------------------------------------------------------

    fn packet(&mut self, bytes: &[u8], now: Timestamp, out: &mut Vec<Output>) {
        let Ok(message) = Message::decode(bytes) else {
            out.push(Output::Note(Note::Ignored("undecodable message")));
            return;
        };
        if message.xid != self.xid || matches!(self.state, State::Init | State::Bound) {
            out.push(Output::Note(Note::Ignored(
                "not for the exchange in progress",
            )));
            return;
        }
        if message.client_id() != Some(self.config.duid.as_slice()) {
            out.push(Output::Note(Note::Ignored("client identifier is not ours")));
            return;
        }
        let Some(server) = message.server_id().map(<[u8]>::to_vec) else {
            out.push(Output::Note(Note::Ignored("no server identifier")));
            return;
        };
        match (self.state, message.kind) {
            (State::Soliciting, MessageType::Advertise) => self.advertised(message, now, out),
            (State::Soliciting, MessageType::Reply) => {
                if message.has(14) {
                    self.reply(&message, now, out);
                } else {
                    out.push(Output::Note(Note::Ignored("reply without rapid commit")));
                }
            }
            (State::Requesting, MessageType::Reply) => {
                let ours = self
                    .offer
                    .as_ref()
                    .and_then(Message::server_id)
                    .is_some_and(|offered| offered == server);
                if ours {
                    self.reply(&message, now, out);
                } else {
                    out.push(Output::Note(Note::Ignored("reply from another server")));
                }
            }
            (State::Renewing, MessageType::Reply) => {
                let ours = self.binding.as_ref().is_some_and(|b| b.server == server);
                if ours {
                    self.reply(&message, now, out);
                } else {
                    out.push(Output::Note(Note::Ignored("reply from another server")));
                }
            }
            (State::Rebinding, MessageType::Reply) => self.reply(&message, now, out),
            _ => out.push(Output::Note(Note::Ignored("unexpected message type"))),
        }
    }

    fn advertised(&mut self, message: Message, now: Timestamp, out: &mut Vec<Output>) {
        if message
            .status()
            .is_some_and(|(code, _)| code != StatusCode::Success)
        {
            out.push(Output::Note(Note::Ignored(
                "advertise with a failure status",
            )));
            return;
        }
        let usable = message.options.iter().any(|option| match option {
            Dhcp6Option::IaPd { options, .. } => {
                option.status().is_none() && !leases_in(options, true).is_empty()
            }
            Dhcp6Option::IaNa { options, .. } => {
                option.status().is_none() && !leases_in(options, false).is_empty()
            }
            _ => false,
        });
        if !usable {
            out.push(Output::Note(Note::Ignored("advertise offers nothing")));
            return;
        }
        let preference = message
            .options
            .iter()
            .find_map(|option| match option {
                Dhcp6Option::Unknown { code, data } if *code == OPT_PREFERENCE => {
                    data.first().copied()
                }
                _ => None,
            })
            .unwrap_or(0);
        if preference == u8::MAX {
            self.advertise = None;
            self.request(now, message, out);
            return;
        }
        if self
            .advertise
            .as_ref()
            .is_none_or(|(best, _)| preference > *best)
        {
            self.advertise = Some((preference, message));
        }
        // The first RT collects advertisements (§18.2.1); the timer then requests the best.
    }

    #[allow(clippy::too_many_lines)]
    fn reply(&mut self, message: &Message, now: Timestamp, out: &mut Vec<Output>) {
        let server = message.server_id().map(<[u8]>::to_vec).unwrap_or_default();
        if let Some((code, _)) = message.status()
            && code != StatusCode::Success
        {
            match code {
                StatusCode::UseMulticast => {
                    // Everything already goes to the group; send it again.
                    self.resend(now, out);
                }
                StatusCode::NoBinding => self.request_binding(now, &server, out),
                _ => {
                    out.push(Output::Note(Note::Restarting(
                        "the server reported a failure",
                    )));
                    self.solicit_after(now, FAIL_HOLDOFF);
                }
            }
            return;
        }
        if let Some(Dhcp6Option::SolMaxRt(secs)) = message
            .options
            .iter()
            .find(|option| matches!(option, Dhcp6Option::SolMaxRt(_)))
            && SOL_MAX_RT_RANGE.contains(secs)
        {
            self.sol_max_rt = Timestamp::from(*secs) * MS;
        }
        let old = self.binding.clone();
        let mut prefixes: Option<Vec<Lease6>> = None;
        let mut addresses: Option<Vec<Lease6>> = None;
        let mut gone: Vec<Ipv6Net> = Vec::new();
        let (mut t1, mut t2) = (0u32, 0u32);
        let (mut no_prefix, mut no_address) = (false, false);
        for option in &message.options {
            match option {
                Dhcp6Option::IaPd {
                    iaid,
                    t1: ia_t1,
                    t2: ia_t2,
                    options,
                } if *iaid == self.config.iaid_pd => match option.status() {
                    Some((StatusCode::NoBinding, _)) => {
                        self.request_binding(now, &server, out);
                        return;
                    }
                    Some((StatusCode::NoPrefixAvail, _)) => no_prefix = true,
                    Some(_) => prefixes = Some(Vec::new()),
                    None => {
                        gone.extend(zero_valid(options, true));
                        prefixes = Some(leases_in(options, true));
                        (t1, t2) = merge_times(t1, t2, *ia_t1, *ia_t2);
                    }
                },
                Dhcp6Option::IaNa {
                    iaid,
                    t1: ia_t1,
                    t2: ia_t2,
                    options,
                } if *iaid == self.config.iaid_na => match option.status() {
                    Some((StatusCode::NoBinding, _)) => {
                        self.request_binding(now, &server, out);
                        return;
                    }
                    Some((StatusCode::NoAddrsAvail, _)) => no_address = true,
                    Some(_) => addresses = Some(Vec::new()),
                    None => {
                        gone.extend(zero_valid(options, false));
                        addresses = Some(leases_in(options, false));
                        (t1, t2) = merge_times(t1, t2, *ia_t1, *ia_t2);
                    }
                },
                _ => {}
            }
        }
        // An IA the Reply does not mention keeps what it had (§18.2.10.1).
        let prefixes = prefixes
            .or_else(|| {
                (!no_prefix).then(|| old.as_ref().map(|b| b.prefixes.clone()).unwrap_or_default())
            })
            .unwrap_or_default();
        let addresses = addresses
            .or_else(|| {
                (!no_address).then(|| {
                    old.as_ref()
                        .map(|b| b.addresses.clone())
                        .unwrap_or_default()
                })
            })
            .unwrap_or_default();
        let new_nets: Vec<Ipv6Net> = prefixes.iter().chain(&addresses).map(|l| l.net).collect();
        if let Some(old) = &old {
            for net in old.nets() {
                if !new_nets.contains(&net) && !gone.contains(&net) {
                    gone.push(net);
                }
            }
        }
        gone.retain(|net| !new_nets.contains(net));
        let dns = message
            .options
            .iter()
            .find_map(|option| match option {
                Dhcp6Option::DnsServers(addrs) => Some(addrs.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let search = message
            .options
            .iter()
            .find_map(|option| match option {
                Dhcp6Option::DomainList(names) => Some(names.clone()),
                _ => None,
            })
            .unwrap_or_default();
        if !gone.is_empty() {
            out.push(Output::Gone(gone));
        }
        if no_prefix && !self.no_prefix_noted {
            self.no_prefix_noted = true;
            out.push(Output::Note(Note::NoPrefixAvailable));
        }
        if no_address && !self.no_address_noted {
            self.no_address_noted = true;
            out.push(Output::Note(Note::NoAddressAvailable));
        }
        if !prefixes.is_empty() {
            self.no_prefix_noted = false;
        }
        if !addresses.is_empty() {
            self.no_address_noted = false;
        }
        if prefixes.is_empty() && addresses.is_empty() {
            self.binding = None;
            self.offer = None;
            // Nothing bound: keep asking, backing off from the holdoff to the pace the
            // server allows (§18.2.10), so a subscriber provisioned a moment later is served
            // within a minute, not an hour.
            let holdoff = self.nothing_rt;
            self.nothing_rt = self
                .nothing_rt
                .saturating_mul(2)
                .min(self.sol_max_rt.max(FAIL_HOLDOFF));
            self.solicit_after(now, holdoff);
            return;
        }
        self.nothing_rt = FAIL_HOLDOFF;
        let (t1, t2) = default_times(t1, t2, &prefixes, &addresses);
        let binding = Binding {
            server,
            prefixes,
            addresses,
            t1,
            t2,
            dns,
            search,
            bound_at: now,
        };
        let renewed = old.is_some();
        self.binding = Some(binding.clone());
        self.offer = None;
        self.advertise = None;
        out.push(Output::Bound { binding, renewed });
        self.settle(now, out);
    }

    /// After a Reply: arm the next exchange. One whose T1 is already due waits
    /// [`REPLY_HOLDOFF`] first, so nothing is ever sent straight out of an answer.
    fn settle(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let due = self
            .binding
            .as_ref()
            .and_then(Binding::t1_at)
            .is_some_and(|t1| t1 <= now);
        if due {
            self.state = State::Bound;
            self.timeout = Some(now.saturating_add(REPLY_HOLDOFF));
        } else {
            self.go_bound(now, out);
        }
    }

    /// `NoBinding`: the server does not know the binding; ask for it with Request (§18.2.10.1),
    /// or start over when there is none to ask for.
    /// `server` is the one that answered: on a Rebind it may not be the one that bound us,
    /// and a Request names the server it is for (§16.4). The Request goes out on the timer,
    /// so a server that answers every Request with `NoBinding` sets the pace of nothing.
    fn request_binding(&mut self, now: Timestamp, server: &[u8], out: &mut Vec<Output>) {
        let Some(binding) = self.binding.clone() else {
            self.solicit(now, out);
            return;
        };
        let mut offer = Message::new(MessageType::Advertise, 0);
        offer.options.push(Dhcp6Option::ServerId(server.to_vec()));
        offer.options.push(self.ia_pd(&binding.prefixes));
        offer.options.push(self.ia_na(&binding.addresses));
        out.push(Output::Note(Note::Restarting(
            "the server has no binding for us",
        )));
        self.begin(State::Requesting, now, REQ_TIMEOUT);
        self.offer = Some(offer);
        self.last_sent = None;
        self.timeout = Some(now.saturating_add(REQ_TIMEOUT));
    }

    fn resend(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        match self.state {
            State::Soliciting => self.send_solicit(now, out),
            State::Requesting => self.send_request(now, out),
            State::Renewing => self.send_refresh(MessageType::Renew, now, out),
            State::Rebinding => self.send_refresh(MessageType::Rebind, now, out),
            State::Init | State::Bound => {}
        }
    }

    // --- timing -----------------------------------------------------------------------------

    /// xorshift64, as the other cores: good enough for jitter and transaction ids.
    fn random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn random_xid(&mut self) -> u32 {
        let xid = u32::try_from(self.random() & 0x00ff_ffff).unwrap_or(1);
        if xid == 0 { 1 } else { xid }
    }

    /// `value` ± 10 % (RFC 8415 §15's RAND).
    fn jittered(&mut self, value: Timestamp) -> Timestamp {
        let tenth = value / 10;
        let span = tenth.saturating_mul(2).max(1);
        let offset = self.random() % span;
        value.saturating_sub(tenth).saturating_add(offset).max(1)
    }

    /// The next retransmission timeout: twice the last, jittered, capped at `max` (§15).
    fn next_rt(&mut self, max: Timestamp) -> Timestamp {
        let doubled = self.jittered(self.rt.saturating_mul(2));
        if doubled > max {
            self.jittered(max)
        } else {
            doubled
        }
    }
}

/// The usable leases among an IA's options: valid lifetime above 0 and not below the
/// preferred one (§21.22, §21.6), a delegated prefix no longer than [`MAX_DELEGATED_LEN`]; at
/// most [`MAX_PREFIXES`] or [`MAX_ADDRESSES`].
/// A delegation worth having: global unicast, between a /8 and a /64. Anything else (`::/0`,
/// a ULA or multicast range, a link-local prefix) would become a blackhole route and a
/// source rule the server has no business installing.
fn delegation_is_sane(prefix: Ipv6Net) -> bool {
    (MIN_DELEGATED_LEN..=MAX_DELEGATED_LEN).contains(&prefix.prefix_len())
        && GLOBAL_UNICAST.contains(&prefix.trunc())
}

fn leases_in(options: &[Dhcp6Option], prefixes: bool) -> Vec<Lease6> {
    let limit = if prefixes {
        MAX_PREFIXES
    } else {
        MAX_ADDRESSES
    };
    options
        .iter()
        .filter_map(|option| match option {
            Dhcp6Option::IaPrefix {
                prefix,
                preferred,
                valid,
                ..
            } if prefixes && delegation_is_sane(*prefix) => Some(Lease6 {
                net: prefix.trunc(),
                preferred: *preferred,
                valid: *valid,
            }),
            Dhcp6Option::IaAddr {
                addr,
                preferred,
                valid,
                ..
            } if !prefixes && GLOBAL_UNICAST.contains(addr) => Some(Lease6 {
                net: Ipv6Net::from(*addr),
                preferred: *preferred,
                valid: *valid,
            }),
            _ => None,
        })
        .filter(|lease| lease.valid > 0 && lease.preferred <= lease.valid)
        .take(limit)
        .collect()
}

/// The prefixes or addresses an IA withdraws: valid lifetime 0.
fn zero_valid(options: &[Dhcp6Option], prefixes: bool) -> Vec<Ipv6Net> {
    options
        .iter()
        .filter_map(|option| match option {
            Dhcp6Option::IaPrefix { prefix, valid, .. } if prefixes && *valid == 0 => {
                Some(prefix.trunc())
            }
            Dhcp6Option::IaAddr { addr, valid, .. } if !prefixes && *valid == 0 => {
                Some(Ipv6Net::from(*addr))
            }
            _ => None,
        })
        .collect()
}

/// One schedule for both IAs: the earliest T1 and T2 the server set (0 is "the client's").
fn merge_times(t1: u32, t2: u32, ia_t1: u32, ia_t2: u32) -> (u32, u32) {
    let pick = |ours: u32, theirs: u32| match (ours, theirs) {
        (0, t) | (t, 0) => t,
        (a, b) => a.min(b),
    };
    (pick(t1, ia_t1), pick(t2, ia_t2))
}

/// T1 and T2 as bound: the server's, or 0.5 and 0.8 of the shortest preferred lifetime
/// (§21.4, §21.21); never T1 above T2; infinite when every lifetime is.
fn default_times(t1: u32, t2: u32, prefixes: &[Lease6], addresses: &[Lease6]) -> (u32, u32) {
    // The shortest preferred lifetime that is a lifetime at all: a lease the server hands back
    // deprecated (preferred 0, valid still running, RFC 4192 renumbering) must not pull T1 to
    // 0; with nothing preferred, the valid lifetimes stand in.
    let shortest = |pick: fn(&Lease6) -> u32| {
        prefixes
            .iter()
            .chain(addresses)
            .map(pick)
            .filter(|secs| *secs != INFINITE && *secs != 0)
            .min()
    };
    let shortest = shortest(|lease| lease.preferred).or_else(|| shortest(|lease| lease.valid));
    let Some(shortest) = shortest else {
        return (INFINITE, INFINITE);
    };
    let t1 = if t1 == 0 { shortest / 2 } else { t1 };
    let t2 = if t2 == 0 {
        u32::try_from(u64::from(shortest) * 4 / 5).unwrap_or(shortest)
    } else {
        t2
    };
    (t1.min(t2), t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUID: [u8; 10] = [0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0];
    const SERVER: [u8; 10] = [0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const OTHER_SERVER: [u8; 10] = [0, 3, 0, 1, 1, 1, 1, 1, 1, 1];
    const PREFIX: &str = "2001:db8:100::/56";
    const NEW_PREFIX: &str = "2001:db8:200::/56";
    const ADDRESS: &str = "2001:db8:ffff::1a4";

    fn config() -> Config {
        Config {
            duid: DUID.to_vec(),
            iaid_pd: 0x11,
            iaid_na: 0x22,
            pd_hint: 56,
        }
    }

    fn new_client() -> Client {
        Client::new(config(), 0x5eed)
    }

    fn sends(out: &[Output]) -> Vec<Message> {
        out.iter()
            .filter_map(|output| match output {
                Output::Send(bytes) => {
                    Some(Message::decode(bytes).expect("we encode what we decode"))
                }
                _ => None,
            })
            .collect()
    }

    fn sent(out: &[Output]) -> Message {
        sends(out).pop().expect("one message was sent")
    }

    fn bound_output(out: &[Output]) -> Option<(&Binding, bool)> {
        out.iter().find_map(|output| match output {
            Output::Bound { binding, renewed } => Some((binding, *renewed)),
            _ => None,
        })
    }

    fn gone_output(out: &[Output]) -> Option<&Vec<Ipv6Net>> {
        out.iter().find_map(|output| match output {
            Output::Gone(nets) => Some(nets),
            _ => None,
        })
    }

    fn notes(out: &[Output]) -> Vec<Note> {
        out.iter()
            .filter_map(|output| match output {
                Output::Note(note) => Some(note.clone()),
                _ => None,
            })
            .collect()
    }

    fn ia_pd(prefix: &str, preferred: u32, valid: u32, t1: u32, t2: u32) -> Dhcp6Option {
        Dhcp6Option::IaPd {
            iaid: 0x11,
            t1,
            t2,
            options: vec![Dhcp6Option::IaPrefix {
                prefix: prefix.parse().unwrap(),
                preferred,
                valid,
                options: Vec::new(),
            }],
        }
    }

    fn ia_na(addr: &str, preferred: u32, valid: u32, t1: u32, t2: u32) -> Dhcp6Option {
        Dhcp6Option::IaNa {
            iaid: 0x22,
            t1,
            t2,
            options: vec![Dhcp6Option::IaAddr {
                addr: addr.parse().unwrap(),
                preferred,
                valid,
                options: Vec::new(),
            }],
        }
    }

    fn ia_status(iaid: u32, pd: bool, code: StatusCode) -> Dhcp6Option {
        let options = vec![Dhcp6Option::StatusCode {
            code,
            message: String::new(),
        }];
        if pd {
            Dhcp6Option::IaPd {
                iaid,
                t1: 0,
                t2: 0,
                options,
            }
        } else {
            Dhcp6Option::IaNa {
                iaid,
                t1: 0,
                t2: 0,
                options,
            }
        }
    }

    /// A server message answering `request`: its xid, our DUID echoed, `server`, then `ias`
    /// and `extra`.
    fn answer(
        request: &Message,
        kind: MessageType,
        server: &[u8],
        ias: Vec<Dhcp6Option>,
        extra: Vec<Dhcp6Option>,
    ) -> Vec<u8> {
        let mut message = Message::new(kind, request.xid);
        message.options.push(Dhcp6Option::ServerId(server.to_vec()));
        message.options.push(Dhcp6Option::ClientId(DUID.to_vec()));
        message.options.extend(ias);
        message.options.extend(extra);
        message.encode()
    }

    fn resolvers() -> Vec<Dhcp6Option> {
        vec![
            Dhcp6Option::DnsServers(vec!["2001:db8:ffff::1".parse().unwrap()]),
            Dhcp6Option::DomainList(vec!["isp.example".to_owned()]),
            Dhcp6Option::SolMaxRt(3600),
        ]
    }

    /// Start at 0, bind by Rapid Commit at 5 s with T1 `t1`, T2 `t2`, lifetimes 40/`valid`.
    fn bound_with(t1: u32, t2: u32, valid: u32) -> (Client, Binding) {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let reply = answer(
            &solicit,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_pd(PREFIX, 40, valid, t1, t2),
                ia_na(ADDRESS, 40, valid, t1, t2),
            ],
            [vec![Dhcp6Option::RapidCommit], resolvers()].concat(),
        );
        let out = client.handle(Input::Packet(reply), 5_000);
        let (binding, renewed) = bound_output(&out).expect("bound");
        assert!(!renewed);
        (client, binding.clone())
    }

    fn bound() -> (Client, Binding) {
        bound_with(10, 16, 60)
    }

    #[test]
    fn start_solicits_with_pd_hint_na_oro_and_rapid_commit() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        assert_eq!(notes(&out), vec![Note::Soliciting]);
        let solicit = sent(&out);
        assert_eq!(solicit.kind, MessageType::Solicit);
        assert_eq!(solicit.client_id(), Some(&DUID[..]));
        assert!(solicit.options.contains(&Dhcp6Option::IaPd {
            iaid: 0x11,
            t1: 0,
            t2: 0,
            options: vec![Dhcp6Option::IaPrefix {
                prefix: "::/56".parse().unwrap(),
                preferred: 0,
                valid: 0,
                options: Vec::new(),
            }],
        }));
        assert!(solicit.options.contains(&Dhcp6Option::IaNa {
            iaid: 0x22,
            t1: 0,
            t2: 0,
            options: Vec::new(),
        }));
        assert!(
            solicit
                .options
                .contains(&Dhcp6Option::Oro(vec![23, 24, 82]))
        );
        assert!(solicit.options.contains(&Dhcp6Option::ElapsedTime(0)));
        assert!(solicit.options.contains(&Dhcp6Option::RapidCommit));
        let due = client.next_timeout().expect("a retransmission is due");
        assert!((900..=1100).contains(&due), "first RT ±10 %: {due}");
        assert_eq!(client.state(), State::Soliciting);
        assert_eq!(client.last_sent(), Some(MessageType::Solicit));
    }

    #[test]
    fn solicit_retransmits_with_doubling_capped_at_sol_max_rt() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let xid = sent(&out).xid;
        let mut now = client.next_timeout().unwrap();
        let mut last_rt = now;
        let mut reached_cap = false;
        for _ in 0..20 {
            let out = client.handle(Input::Timeout, now);
            let again = sent(&out);
            assert_eq!(again.kind, MessageType::Solicit);
            assert_eq!(again.xid, xid, "one exchange, one xid");
            let elapsed = again
                .options
                .iter()
                .find_map(|option| match option {
                    Dhcp6Option::ElapsedTime(centis) => Some(*centis),
                    _ => None,
                })
                .unwrap();
            assert!(elapsed > 0, "elapsed time counts from the first Solicit");
            let next = client.next_timeout().unwrap();
            let rt = next - now;
            assert!(rt <= SOL_MAX_RT * 11 / 10, "capped: {rt}");
            assert!(
                rt >= last_rt * 18 / 10 || rt >= SOL_MAX_RT * 9 / 10,
                "doubling: {last_rt} -> {rt}"
            );
            reached_cap |= rt >= SOL_MAX_RT * 9 / 10;
            last_rt = rt;
            now = next;
        }
        assert!(reached_cap);
    }

    #[test]
    fn a_rapid_commit_reply_binds_at_once() {
        let (client, binding) = bound();
        assert_eq!(binding.server, SERVER.to_vec());
        assert_eq!(
            binding.prefixes,
            vec![Lease6 {
                net: PREFIX.parse().unwrap(),
                preferred: 40,
                valid: 60
            }]
        );
        assert_eq!(
            binding.addresses,
            vec![Lease6 {
                net: format!("{ADDRESS}/128").parse().unwrap(),
                preferred: 40,
                valid: 60
            }]
        );
        assert_eq!((binding.t1, binding.t2), (10, 16));
        assert_eq!(
            binding.dns,
            vec!["2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap()]
        );
        assert_eq!(binding.search, vec!["isp.example".to_owned()]);
        assert_eq!(binding.bound_at, 5_000);
        assert_eq!(client.state(), State::Bound);
        assert_eq!(client.next_timeout(), Some(15_000), "T1 at bound_at + 10 s");
    }

    #[test]
    fn an_advertise_then_request_then_reply_binds() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let advertise = answer(
            &solicit,
            MessageType::Advertise,
            &SERVER,
            vec![
                ia_pd(PREFIX, 40, 60, 10, 16),
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            Vec::new(),
        );
        let out = client.handle(Input::Packet(advertise), 100);
        assert!(
            sends(&out).is_empty(),
            "advertisements are collected for the first RT"
        );
        let due = client.next_timeout().unwrap();
        let out = client.handle(Input::Timeout, due);
        assert_eq!(notes(&out), vec![Note::Requesting]);
        let request = sent(&out);
        assert_eq!(request.kind, MessageType::Request);
        assert_eq!(request.server_id(), Some(&SERVER[..]));
        assert_ne!(request.xid, solicit.xid, "a new exchange");
        assert!(request.options.iter().any(|option| matches!(
            option,
            Dhcp6Option::IaPd { iaid: 0x11, options, .. }
                if options.contains(&Dhcp6Option::IaPrefix {
                    prefix: PREFIX.parse().unwrap(),
                    preferred: 40,
                    valid: 60,
                    options: Vec::new(),
                })
        )));
        let reply = answer(
            &request,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_pd(PREFIX, 40, 60, 10, 16),
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            resolvers(),
        );
        let out = client.handle(Input::Packet(reply), due + 50);
        let (binding, renewed) = bound_output(&out).expect("bound");
        assert!(!renewed);
        assert_eq!(binding.prefixes[0].net, PREFIX.parse::<Ipv6Net>().unwrap());
        assert_eq!(client.state(), State::Bound);
    }

    #[test]
    fn renew_at_t1_and_rebind_at_t2() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        assert_eq!(notes(&out), vec![Note::Renewing]);
        let renew = sent(&out);
        assert_eq!(renew.kind, MessageType::Renew);
        assert_eq!(renew.server_id(), Some(&SERVER[..]));
        assert!(renew.options.contains(&ia_pd(PREFIX, 40, 60, 0, 0)));
        assert!(renew.options.contains(&ia_na(ADDRESS, 40, 60, 0, 0)));
        assert!(client.next_timeout().unwrap() <= 21_000, "never past T2");
        // Silence until T2.
        let mut now = client.next_timeout().unwrap();
        while now < 21_000 {
            let out = client.handle(Input::Timeout, now);
            assert_eq!(sent(&out).kind, MessageType::Renew);
            now = client.next_timeout().unwrap();
        }
        let out = client.handle(Input::Timeout, 21_000);
        assert_eq!(notes(&out), vec![Note::Rebinding]);
        let rebind = sent(&out);
        assert_eq!(rebind.kind, MessageType::Rebind);
        assert_eq!(rebind.server_id(), None, "Rebind names no server");
        assert!(rebind.options.contains(&ia_pd(PREFIX, 40, 60, 0, 0)));
        let reply = answer(
            &rebind,
            MessageType::Reply,
            &OTHER_SERVER,
            vec![
                ia_pd(PREFIX, 40, 60, 10, 16),
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            resolvers(),
        );
        let out = client.handle(Input::Packet(reply), 21_500);
        let (binding, renewed) = bound_output(&out).expect("rebound");
        assert!(renewed);
        assert_eq!(
            binding.server,
            OTHER_SERVER.to_vec(),
            "any server may answer a Rebind"
        );
        assert_eq!(binding.bound_at, 21_500);
        assert_eq!(client.next_timeout(), Some(31_500));
    }

    #[test]
    fn a_reply_that_replaces_the_prefix_reports_the_old_one_gone() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        let renew = sent(&out);
        let reply = answer(
            &renew,
            MessageType::Reply,
            &SERVER,
            vec![
                Dhcp6Option::IaPd {
                    iaid: 0x11,
                    t1: 10,
                    t2: 16,
                    options: vec![
                        Dhcp6Option::IaPrefix {
                            prefix: PREFIX.parse().unwrap(),
                            preferred: 0,
                            valid: 0,
                            options: Vec::new(),
                        },
                        Dhcp6Option::IaPrefix {
                            prefix: NEW_PREFIX.parse().unwrap(),
                            preferred: 40,
                            valid: 60,
                            options: Vec::new(),
                        },
                    ],
                },
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            resolvers(),
        );
        let out = client.handle(Input::Packet(reply), 15_200);
        assert_eq!(
            gone_output(&out),
            Some(&vec![PREFIX.parse::<Ipv6Net>().unwrap()])
        );
        let (binding, renewed) = bound_output(&out).expect("bound");
        assert!(renewed);
        assert_eq!(
            binding.prefixes.iter().map(|l| l.net).collect::<Vec<_>>(),
            vec![NEW_PREFIX.parse::<Ipv6Net>().unwrap()]
        );
        let gone_at = out
            .iter()
            .position(|o| matches!(o, Output::Gone(_)))
            .unwrap();
        let bound_at = out
            .iter()
            .position(|o| matches!(o, Output::Bound { .. }))
            .unwrap();
        assert!(
            gone_at < bound_at,
            "what left is reported before what stays"
        );
    }

    #[test]
    fn no_prefix_available_keeps_the_address_and_asks_again_at_renew() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let reply = answer(
            &solicit,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_status(0x11, true, StatusCode::NoPrefixAvail),
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            vec![Dhcp6Option::RapidCommit],
        );
        let out = client.handle(Input::Packet(reply), 5_000);
        let (binding, _) = bound_output(&out).expect("the address binds");
        assert_eq!(binding.prefixes, Vec::new());
        assert_eq!(binding.addresses.len(), 1);
        assert_eq!(notes(&out), vec![Note::NoPrefixAvailable]);
        let out = client.handle(Input::Timeout, 15_000);
        let renew = sent(&out);
        assert_eq!(renew.kind, MessageType::Renew);
        assert!(
            renew.options.iter().any(|option| matches!(
                option,
                Dhcp6Option::IaPd { iaid: 0x11, options, .. }
                    if matches!(options.as_slice(), [Dhcp6Option::IaPrefix { valid: 0, .. }])
            )),
            "the Renew asks for a prefix again with the hint: {renew:?}"
        );
        let reply = answer(
            &renew,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_status(0x11, true, StatusCode::NoPrefixAvail),
                ia_na(ADDRESS, 40, 60, 10, 16),
            ],
            Vec::new(),
        );
        let out = client.handle(Input::Packet(reply), 15_100);
        assert!(bound_output(&out).is_some());
        assert_eq!(notes(&out), vec![], "said once until a prefix arrives");
    }

    #[test]
    fn no_prefix_and_no_address_keeps_soliciting_after_a_holdoff() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let reply = answer(
            &solicit,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_status(0x11, true, StatusCode::NoPrefixAvail),
                ia_status(0x22, false, StatusCode::NoAddrsAvail),
            ],
            vec![Dhcp6Option::RapidCommit],
        );
        let out = client.handle(Input::Packet(reply), 5_000);
        assert!(bound_output(&out).is_none());
        assert_eq!(
            notes(&out),
            vec![Note::NoPrefixAvailable, Note::NoAddressAvailable]
        );
        assert_eq!(client.state(), State::Soliciting);
        assert_eq!(client.next_timeout(), Some(5_000 + FAIL_HOLDOFF));
        let out = client.handle(Input::Timeout, 5_000 + FAIL_HOLDOFF);
        assert_eq!(sent(&out).kind, MessageType::Solicit);
    }

    #[test]
    fn no_binding_on_renew_restarts_with_request() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        let renew = sent(&out);
        let reply = answer(
            &renew,
            MessageType::Reply,
            &SERVER,
            vec![ia_status(0x11, true, StatusCode::NoBinding)],
            Vec::new(),
        );
        let out = client.handle(Input::Packet(reply), 15_100);
        assert!(sends(&out).is_empty(), "the Request goes on the timer");
        assert_eq!(client.state(), State::Requesting);
        let out = client.handle(Input::Timeout, 15_100 + REQ_TIMEOUT);
        let request = sent(&out);
        assert_eq!(request.kind, MessageType::Request);
        assert_eq!(request.server_id(), Some(&SERVER[..]));
        assert!(request.options.contains(&ia_pd(PREFIX, 40, 60, 0, 0)));
        assert!(
            client.binding().is_some(),
            "kept until the server says otherwise"
        );
    }

    #[test]
    fn unspec_fail_restarts_with_solicit() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        let renew = sent(&out);
        let reply = answer(
            &renew,
            MessageType::Reply,
            &SERVER,
            Vec::new(),
            vec![Dhcp6Option::StatusCode {
                code: StatusCode::UnspecFail,
                message: "no".to_owned(),
            }],
        );
        let out = client.handle(Input::Packet(reply), 15_100);
        assert!(sends(&out).is_empty(), "held off");
        assert_eq!(client.state(), State::Soliciting);
        assert_eq!(client.next_timeout(), Some(15_100 + FAIL_HOLDOFF));
        let out = client.handle(Input::Timeout, 15_100 + FAIL_HOLDOFF);
        assert_eq!(sent(&out).kind, MessageType::Solicit);
    }

    #[test]
    fn link_down_stops_timers_and_link_up_rebinds_the_binding() {
        let (mut client, binding) = bound_with(60, 90, 120);
        assert_eq!(client.handle(Input::LinkDown, 6_000), Vec::new());
        assert_eq!(client.next_timeout(), None);
        assert!(
            client.handle(Input::Timeout, 65_000).is_empty(),
            "no carrier, no timers"
        );
        let out = client.handle(Input::LinkUp, 7_000);
        assert_eq!(notes(&out), vec![Note::Rebinding]);
        let rebind = sent(&out);
        assert_eq!(rebind.kind, MessageType::Rebind);
        assert!(rebind.options.contains(&ia_pd(PREFIX, 40, 120, 0, 0)));
        assert!(rebind.options.contains(&ia_na(ADDRESS, 40, 120, 0, 0)));
        let due = client.next_timeout().unwrap();
        assert!((7_900..=8_100).contains(&due), "Confirm's first RT: {due}");
        // Ten seconds of silence: the binding and its timers stand.
        let mut now = due;
        let mut rebinds = 1;
        while now < 7_000 + CNF_MAX_RD {
            let out = client.handle(Input::Timeout, now);
            rebinds += sends(&out).len();
            now = client.next_timeout().unwrap();
        }
        assert!(rebinds >= 3, "retransmitted on Confirm's timing: {rebinds}");
        let out = client.handle(Input::Timeout, now);
        assert_eq!(sends(&out), Vec::new());
        assert_eq!(client.state(), State::Bound);
        assert_eq!(client.binding(), Some(&binding));
        assert_eq!(client.next_timeout(), Some(65_000), "T1 as it was");
    }

    #[test]
    fn a_rebind_after_link_up_that_is_answered_rebinds_the_binding() {
        let (mut client, _) = bound_with(60, 90, 120);
        client.handle(Input::LinkDown, 6_000);
        let out = client.handle(Input::LinkUp, 7_000);
        let rebind = sent(&out);
        let reply = answer(
            &rebind,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_pd(PREFIX, 40, 120, 60, 90),
                ia_na(ADDRESS, 40, 120, 60, 90),
            ],
            resolvers(),
        );
        let out = client.handle(Input::Packet(reply), 7_300);
        let (binding, renewed) = bound_output(&out).expect("rebound");
        assert!(renewed);
        assert_eq!(binding.bound_at, 7_300);
        assert_eq!(client.next_timeout(), Some(67_300));
    }

    #[test]
    fn start_with_a_binding_rebinds_first() {
        let (_, binding) = bound_with(60, 90, 120);
        let mut client = new_client();
        let out = client.handle(
            Input::Start {
                binding: Some(binding.clone()),
            },
            0,
        );
        let rebind = sent(&out);
        assert_eq!(rebind.kind, MessageType::Rebind);
        assert!(rebind.options.contains(&ia_pd(PREFIX, 40, 120, 0, 0)));
        assert_eq!(client.binding(), Some(&binding));
        let reply = answer(
            &rebind,
            MessageType::Reply,
            &SERVER,
            vec![
                ia_pd(PREFIX, 40, 120, 60, 90),
                ia_na(ADDRESS, 40, 120, 60, 90),
            ],
            resolvers(),
        );
        let out = client.handle(Input::Packet(reply), 300);
        let (bound, renewed) = bound_output(&out).expect("bound");
        assert!(renewed, "a restored binding continued is a renewal");
        assert_eq!(bound.prefixes, binding.prefixes);
    }

    #[test]
    fn a_valid_lifetime_expiry_is_gone() {
        let (mut client, _) = bound();
        let mut now = 15_000;
        let mut sent_kinds = Vec::new();
        loop {
            let out = client.handle(Input::Timeout, now);
            sent_kinds.extend(sends(&out).into_iter().map(|m| m.kind));
            if let Some(gone) = gone_output(&out) {
                assert_eq!(
                    gone,
                    &vec![
                        PREFIX.parse::<Ipv6Net>().unwrap(),
                        format!("{ADDRESS}/128").parse::<Ipv6Net>().unwrap(),
                    ]
                );
                assert!(now >= 65_000, "the valid lifetime, 60 s from 5 s: {now}");
                assert_eq!(client.state(), State::Soliciting);
                assert_eq!(client.binding(), None);
                assert_eq!(*sent_kinds.last().unwrap(), MessageType::Solicit);
                break;
            }
            now = client.next_timeout().expect("a timer is always pending");
            assert!(now <= 65_100, "nothing waits past the expiry: {now}");
        }
        assert!(sent_kinds.contains(&MessageType::Renew));
        assert!(sent_kinds.contains(&MessageType::Rebind));
    }

    #[test]
    fn a_server_id_mismatch_on_reply_is_ignored() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let advertise = answer(
            &solicit,
            MessageType::Advertise,
            &SERVER,
            vec![ia_pd(PREFIX, 40, 60, 10, 16)],
            Vec::new(),
        );
        client.handle(Input::Packet(advertise), 100);
        let due = client.next_timeout().unwrap();
        let out = client.handle(Input::Timeout, due);
        let request = sent(&out);
        let reply = answer(
            &request,
            MessageType::Reply,
            &OTHER_SERVER,
            vec![ia_pd(PREFIX, 40, 60, 10, 16)],
            Vec::new(),
        );
        let out = client.handle(Input::Packet(reply), due + 10);
        assert_eq!(
            notes(&out),
            vec![Note::Ignored("reply from another server")]
        );
        assert_eq!(client.state(), State::Requesting);
        // A wrong transaction id, and a reply without our identifier.
        let mut wrong_xid = Message::decode(&answer(
            &request,
            MessageType::Reply,
            &SERVER,
            vec![ia_pd(PREFIX, 40, 60, 10, 16)],
            Vec::new(),
        ))
        .unwrap();
        wrong_xid.xid ^= 1;
        let out = client.handle(Input::Packet(wrong_xid.encode()), due + 20);
        assert_eq!(
            notes(&out),
            vec![Note::Ignored("not for the exchange in progress")]
        );
        let mut foreign = Message::new(MessageType::Reply, request.xid);
        foreign.options.push(Dhcp6Option::ServerId(SERVER.to_vec()));
        foreign
            .options
            .push(Dhcp6Option::ClientId(OTHER_SERVER.to_vec()));
        let out = client.handle(Input::Packet(foreign.encode()), due + 30);
        assert_eq!(
            notes(&out),
            vec![Note::Ignored("client identifier is not ours")]
        );
        assert_eq!(client.state(), State::Requesting);
    }

    #[test]
    fn a_preference_of_255_is_requested_at_once_and_the_best_otherwise() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let low = answer(
            &solicit,
            MessageType::Advertise,
            &OTHER_SERVER,
            vec![ia_pd(PREFIX, 40, 60, 10, 16)],
            vec![Dhcp6Option::Unknown {
                code: 7,
                data: vec![10],
            }],
        );
        let high = answer(
            &solicit,
            MessageType::Advertise,
            &SERVER,
            vec![ia_pd(NEW_PREFIX, 40, 60, 10, 16)],
            vec![Dhcp6Option::Unknown {
                code: 7,
                data: vec![20],
            }],
        );
        client.handle(Input::Packet(low), 100);
        client.handle(Input::Packet(high), 200);
        let due = client.next_timeout().unwrap();
        let out = client.handle(Input::Timeout, due);
        assert_eq!(
            sent(&out).server_id(),
            Some(&SERVER[..]),
            "the higher preference"
        );
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let best = answer(
            &solicit,
            MessageType::Advertise,
            &SERVER,
            vec![ia_pd(PREFIX, 40, 60, 10, 16)],
            vec![Dhcp6Option::Unknown {
                code: 7,
                data: vec![255],
            }],
        );
        let out = client.handle(Input::Packet(best), 100);
        assert_eq!(
            sent(&out).kind,
            MessageType::Request,
            "255 is requested at once"
        );
    }

    #[test]
    fn default_times_follow_the_shortest_preferred_lifetime() {
        let lease = |preferred| Lease6 {
            net: PREFIX.parse().unwrap(),
            preferred,
            valid: preferred * 2,
        };
        assert_eq!(default_times(0, 0, &[lease(100)], &[lease(50)]), (25, 40));
        assert_eq!(default_times(30, 0, &[lease(100)], &[]), (30, 80));
        assert_eq!(
            default_times(90, 80, &[lease(100)], &[]),
            (80, 80),
            "T1 never above T2"
        );
        assert_eq!(
            default_times(
                0,
                0,
                &[Lease6 {
                    net: PREFIX.parse().unwrap(),
                    preferred: INFINITE,
                    valid: INFINITE
                }],
                &[]
            ),
            (INFINITE, INFINITE)
        );
    }

    #[test]
    fn default_times_skip_a_lease_with_no_preferred_lifetime() {
        let lease = |preferred, valid| Lease6 {
            net: PREFIX.parse().unwrap(),
            preferred,
            valid,
        };
        // Graceful renumbering (RFC 4192): the old prefix comes back with preferred 0 and a
        // valid lifetime still running; it must not pull T1 and T2 down to 0.
        assert_eq!(
            default_times(0, 0, &[lease(0, 1000), lease(100, 200)], &[]),
            (50, 80)
        );
        // Nothing preferred at all: the valid lifetimes stand in.
        assert_eq!(default_times(0, 0, &[lease(0, 1000)], &[]), (500, 800));
    }

    /// A Reply that leaves T1 already due (the server's own T1 and T2 of 0 with a lease that
    /// has a second of preferred lifetime) is not answered with a Renew or Rebind at once: the
    /// next exchange waits `REPLY_HOLDOFF`, so a server is asked at the client's pace, never
    /// at its own response rate.
    #[test]
    fn a_reply_whose_t1_has_passed_waits_before_the_next_exchange() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let reply = answer(
            &solicit,
            MessageType::Reply,
            &SERVER,
            vec![ia_pd(PREFIX, 1, 1000, 0, 0), ia_na(ADDRESS, 1, 1000, 0, 0)],
            [vec![Dhcp6Option::RapidCommit], resolvers()].concat(),
        );
        let out = client.handle(Input::Packet(reply), 5_000);
        let (binding, _) = bound_output(&out).expect("bound");
        assert_eq!((binding.t1, binding.t2), (0, 0));
        assert!(
            sends(&out).is_empty(),
            "no exchange straight out of a Reply: {out:?}"
        );
        assert_eq!(client.state(), State::Bound);
        assert_eq!(client.next_timeout(), Some(5_000 + REPLY_HOLDOFF));
        let out = client.handle(Input::Timeout, 5_000 + REPLY_HOLDOFF);
        let refresh = sent(&out);
        assert_eq!(refresh.kind, MessageType::Rebind, "T2 has passed too");
        let reply = answer(
            &refresh,
            MessageType::Reply,
            &SERVER,
            vec![ia_pd(PREFIX, 1, 1000, 0, 0), ia_na(ADDRESS, 1, 1000, 0, 0)],
            resolvers(),
        );
        let now = 5_000 + REPLY_HOLDOFF + 100;
        let out = client.handle(Input::Packet(reply), now);
        assert!(bound_output(&out).is_some_and(|(_, renewed)| renewed));
        assert!(sends(&out).is_empty(), "still paced: {out:?}");
        assert_eq!(client.next_timeout(), Some(now + REPLY_HOLDOFF));
    }

    /// `NoBinding` restarts with Request, but on the timer: a server that answers every
    /// Request with `NoBinding` is asked once a second with the usual backoff, not in a loop.
    #[test]
    fn no_binding_is_requested_on_the_timer_not_at_the_servers_pace() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        let renew = sent(&out);
        let reply = answer(
            &renew,
            MessageType::Reply,
            &SERVER,
            vec![ia_status(0x11, true, StatusCode::NoBinding)],
            Vec::new(),
        );
        let out = client.handle(Input::Packet(reply), 15_100);
        assert!(
            sends(&out).is_empty(),
            "the Request waits for the timer: {out:?}"
        );
        assert_eq!(client.state(), State::Requesting);
        assert_eq!(client.next_timeout(), Some(15_100 + REQ_TIMEOUT));
        let out = client.handle(Input::Timeout, 15_100 + REQ_TIMEOUT);
        let request = sent(&out);
        assert_eq!(request.kind, MessageType::Request);
        assert_eq!(request.server_id(), Some(&SERVER[..]));
        assert!(request.options.contains(&ia_pd(PREFIX, 40, 60, 0, 0)));
        let reply = answer(
            &request,
            MessageType::Reply,
            &SERVER,
            vec![ia_status(0x11, true, StatusCode::NoBinding)],
            Vec::new(),
        );
        let now = 15_100 + REQ_TIMEOUT + 50;
        let out = client.handle(Input::Packet(reply), now);
        assert!(sends(&out).is_empty(), "paced again: {out:?}");
        assert_eq!(client.next_timeout(), Some(now + REQ_TIMEOUT));
        assert!(
            client.binding().is_some(),
            "kept until the server says otherwise"
        );
    }

    /// A Rebind may be answered by a server other than the one that bound us; its `NoBinding`
    /// is followed by a Request addressed to that server, not the old one (RFC 8415 §16.4).
    #[test]
    fn no_binding_from_another_server_on_rebind_is_requested_from_that_server() {
        let (mut client, _) = bound();
        let out = client.handle(Input::Timeout, 15_000);
        assert_eq!(sent(&out).kind, MessageType::Renew);
        let out = client.handle(Input::Timeout, 21_000);
        let rebind = sent(&out);
        assert_eq!(rebind.kind, MessageType::Rebind, "T2 at 21 s");
        let reply = answer(
            &rebind,
            MessageType::Reply,
            &OTHER_SERVER,
            vec![ia_status(0x11, true, StatusCode::NoBinding)],
            Vec::new(),
        );
        client.handle(Input::Packet(reply), 21_100);
        let out = client.handle(Input::Timeout, 21_100 + REQ_TIMEOUT);
        let request = sent(&out);
        assert_eq!(request.kind, MessageType::Request);
        assert_eq!(request.server_id(), Some(&OTHER_SERVER[..]));
    }

    /// T2 of `u32::MAX` means never Rebind (RFC 8415 §21.4): the client keeps Renewing past
    /// where T2 would have been, and no timer is ever set in the past.
    #[test]
    fn an_infinite_t2_renews_and_never_rebinds() {
        let (mut client, _) = bound_with(10, u32::MAX, 600);
        let out = client.handle(Input::Timeout, 15_000);
        assert_eq!(sent(&out).kind, MessageType::Renew);
        let due = client.next_timeout().expect("retransmission timer");
        assert!(due > 15_000, "due {due}");
        let out = client.handle(Input::Timeout, 300_000);
        assert_eq!(
            sent(&out).kind,
            MessageType::Renew,
            "still renewing, never rebinding"
        );
        assert!(client.next_timeout().is_some_and(|at| at > 300_000));
    }

    /// With T2 infinite the valid lifetimes still end the binding: past them the client
    /// starts over instead of Rebinding toward a deadline in the past.
    #[test]
    fn a_lapsed_binding_with_infinite_t2_expires_and_solicits() {
        let (mut client, binding) = bound_with(10, u32::MAX, 60);
        let out = client.handle(Input::Timeout, 70_000);
        assert_eq!(
            gone_output(&out).cloned(),
            Some(binding.nets().collect::<Vec<_>>())
        );
        assert_eq!(client.state(), State::Soliciting);
        assert!(client.next_timeout().is_some_and(|at| at > 70_000));
    }

    /// Only global unicast is accepted from a server: a delegation of `::/0`, a ULA, a
    /// multicast or link-local range would otherwise become a blackhole default and a
    /// catch-all source rule.
    #[test]
    fn a_delegation_outside_global_unicast_is_ignored() {
        let prefix = |text: &str| Dhcp6Option::IaPrefix {
            prefix: text.parse().unwrap(),
            preferred: 40,
            valid: 60,
            options: Vec::new(),
        };
        let address = |text: &str| Dhcp6Option::IaAddr {
            addr: text.parse().unwrap(),
            preferred: 40,
            valid: 60,
            options: Vec::new(),
        };
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let solicit = sent(&out);
        let reply = answer(
            &solicit,
            MessageType::Reply,
            &SERVER,
            vec![
                Dhcp6Option::IaPd {
                    iaid: 0x11,
                    t1: 10,
                    t2: 16,
                    options: vec![
                        prefix("::/0"),
                        prefix("::/56"),
                        prefix("fd00::/56"),
                        prefix("ff05::/56"),
                        prefix("fe80::/56"),
                        prefix("2000::/3"),
                        prefix(PREFIX),
                    ],
                },
                Dhcp6Option::IaNa {
                    iaid: 0x22,
                    t1: 10,
                    t2: 16,
                    options: vec![address("fe80::1"), address("::1"), address(ADDRESS)],
                },
            ],
            [vec![Dhcp6Option::RapidCommit], resolvers()].concat(),
        );
        let out = client.handle(Input::Packet(reply), 5_000);
        let (binding, _) = bound_output(&out).expect("bound");
        assert_eq!(
            binding.prefixes.iter().map(|l| l.net).collect::<Vec<_>>(),
            vec![PREFIX.parse::<Ipv6Net>().unwrap()]
        );
        assert_eq!(
            binding.addresses.iter().map(|l| l.net).collect::<Vec<_>>(),
            vec![Ipv6Net::from(ADDRESS.parse::<Ipv6Addr>().unwrap())]
        );
    }

    /// A Reply that binds nothing is followed by another Solicit after `FAIL_HOLDOFF`, then
    /// twice that, up to `SOL_MAX_RT`: a subscriber not yet provisioned at boot gets IPv6
    /// within a minute of being provisioned, not an hour later.
    #[test]
    fn a_reply_that_binds_nothing_is_solicited_again_with_backoff() {
        let mut client = new_client();
        let out = client.handle(Input::Start { binding: None }, 0);
        let mut solicit = sent(&out);
        let mut now = 5_000;
        let mut expected = FAIL_HOLDOFF;
        for _ in 0..8 {
            let reply = answer(
                &solicit,
                MessageType::Reply,
                &SERVER,
                vec![
                    ia_status(0x11, true, StatusCode::NoPrefixAvail),
                    ia_status(0x22, false, StatusCode::NoAddrsAvail),
                ],
                vec![Dhcp6Option::RapidCommit],
            );
            let out = client.handle(Input::Packet(reply), now);
            assert!(sends(&out).is_empty(), "held off: {out:?}");
            assert_eq!(
                client.next_timeout(),
                Some(now + expected),
                "holdoff {expected}"
            );
            now += expected;
            let out = client.handle(Input::Timeout, now);
            solicit = sent(&out);
            assert_eq!(solicit.kind, MessageType::Solicit);
            expected = (expected * 2).min(SOL_MAX_RT);
            now += 100;
        }
        assert_eq!(expected, SOL_MAX_RT, "the pace reached the cap");
    }
}
