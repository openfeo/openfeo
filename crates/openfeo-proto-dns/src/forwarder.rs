// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The forwarder's state machine (SPEC §7.7, sans-IO per §6.3): a client query runs through
//! validation, the local zone, the policy slot, the cache and the upstreams; what comes back
//! is checked for rebinding and cached. `Forwarder::handle(Input, now) -> Vec<Output>`; the
//! driver in `openfeo-net` moves the bytes and keeps time.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::Ipv4Net;

use crate::Timestamp;
use crate::cache::{Cache, CacheStats, Key};
use crate::name::{Name, reverse_addr, reverse_name};
use crate::wire::{
    CLASS_ANY, CLASS_IN, EDNS_UDP_PAYLOAD, Edns, Header, Message, OPCODE_QUERY, RData, Record,
    rcode, rtype,
};

/// How long an upstream has to answer one attempt.
pub const UPSTREAM_TIMEOUT: Timestamp = 2_000;
/// Attempts per client query, each on the next upstream.
pub const MAX_ATTEMPTS: u8 = 3;
/// How long a silent upstream is skipped.
pub const UPSTREAM_DOWN_HOLD: Timestamp = 30_000;
/// The TTL of local answers.
pub const LOCAL_TTL: u32 = 60;
/// The negative TTL of the local zone (its SOA minimum).
pub const LOCAL_NEGATIVE_TTL: u32 = 60;
/// Client queries awaiting an upstream at once; beyond it, SERVFAIL.
pub const MAX_PENDING: usize = 1024;

/// A name the forwarder answers itself: a reservation, a lease or the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord {
    pub name: Name,
    pub addr: Ipv4Addr,
}

/// The forwarder's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// In order of preference.
    pub upstreams: Vec<Ipv4Addr>,
    /// The local zone, `home.arpa` by default.
    pub domain: Name,
    /// `<hostname>.<domain>`.
    pub router_name: Option<Name>,
    /// The LAN addresses: the router's A records, and never a valid upstream answer.
    pub router_addrs: Vec<Ipv4Addr>,
    /// Reverse zones the forwarder is authoritative for, and never a valid upstream answer.
    pub lan_subnets: Vec<Ipv4Net>,
    /// Reservations first, then leases; the first match wins.
    pub local: Vec<LocalRecord>,
    /// Names whose subdomains may resolve to private addresses.
    pub rebind_allow: Vec<Name>,
    pub cache_capacity: usize,
}

/// How a message travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// The driver's token for one client query.
pub type QueryId = u64;

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Query {
        id: QueryId,
        client: Ipv4Addr,
        transport: Transport,
        bytes: Vec<u8>,
    },
    UpstreamReply {
        upstream: Ipv4Addr,
        transport: Transport,
        bytes: Vec<u8>,
    },
    /// The timer of [`Forwarder::next_timeout`] fired.
    Timeout,
    Configure(Config),
}

/// What the forwarder wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Reply {
        id: QueryId,
        bytes: Vec<u8>,
    },
    Forward {
        upstream: Ipv4Addr,
        transport: Transport,
        bytes: Vec<u8>,
    },
    Event(Event),
    /// The query will never be answered (a response, or no header to answer with): the driver
    /// forgets the client.
    Drop {
        id: QueryId,
    },
}

/// What happened, for the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Configured {
        upstreams: usize,
        local: usize,
    },
    /// Once per configuration that leaves none.
    NoUpstreams,
    UpstreamDown(Ipv4Addr),
    UpstreamUp(Ipv4Addr),
    RebindDropped {
        name: Name,
        addr: IpAddr,
        client: Ipv4Addr,
    },
    /// Reserved for the policy; never emitted in M1.
    Blocked {
        name: Name,
        client: Ipv4Addr,
    },
}

/// The policy's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
}

/// The slot for Rustik Block's lists (SPEC §7.7): consulted after the local zone, before the
/// cache. Allows everything in M1.
#[derive(Debug, Default, Clone)]
pub struct Policy;

impl Policy {
    #[must_use]
    pub fn decide(&self, _name: &Name, _qtype: u16, _client: Ipv4Addr) -> Verdict {
        Verdict::Allow
    }
}

/// A client query waiting for an upstream.
#[derive(Debug, Clone)]
struct Pending {
    client: QueryId,
    client_addr: Ipv4Addr,
    transport: Transport,
    /// The client's query, for the reply's header and the OPT decision.
    query: Message,
    upstream: Ipv4Addr,
    upstream_transport: Transport,
    deadline: Timestamp,
    /// Upstreams tried so far, this one included.
    attempts: u8,
}

/// The forwarder.
#[derive(Debug)]
pub struct Forwarder {
    config: Config,
    policy: Policy,
    cache: Cache,
    /// By the id of the query sent upstream.
    pending: BTreeMap<u16, Pending>,
    /// Upstreams marked down, and until when.
    down: BTreeMap<Ipv4Addr, Timestamp>,
    cursor: usize,
    rng: u64,
    no_upstreams_told: bool,
}

impl Forwarder {
    /// A forwarder with `config`; `seed` feeds the upstream query ids.
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Forwarder {
        Forwarder {
            cache: Cache::new(config.cache_capacity),
            config,
            policy: Policy,
            pending: BTreeMap::new(),
            down: BTreeMap::new(),
            cursor: 0,
            rng: seed | 1,
            no_upstreams_told: false,
        }
    }

    /// Feed one input at `now` and collect what to do about it.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        match input {
            Input::Query {
                id,
                client,
                transport,
                bytes,
            } => self.query(id, client, transport, &bytes, now),
            Input::UpstreamReply {
                upstream,
                transport,
                bytes,
            } => self.upstream_reply(upstream, transport, &bytes, now),
            Input::Timeout => self.timeout(now),
            Input::Configure(config) => self.configure(config),
        }
    }

    /// When [`Forwarder::handle`] next wants an [`Input::Timeout`]: the earliest deadline.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Client queries awaiting an upstream.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn query(
        &mut self,
        id: QueryId,
        client: Ipv4Addr,
        transport: Transport,
        bytes: &[u8],
        now: Timestamp,
    ) -> Vec<Output> {
        let Ok(msg) = Message::decode(bytes) else {
            return match Message::formerr(bytes) {
                Some(formerr) => vec![Output::Reply {
                    id,
                    bytes: formerr.encode(),
                }],
                None => vec![Output::Drop { id }],
            };
        };
        if msg.header.response {
            return vec![Output::Drop { id }];
        }
        let refused = if msg.header.opcode != OPCODE_QUERY {
            Some(rcode::NOTIMP)
        } else if msg.questions.len() != 1 {
            Some(rcode::FORMERR)
        } else if !matches!(msg.questions[0].qclass, CLASS_IN | CLASS_ANY) {
            Some(rcode::REFUSED)
        } else {
            None
        };
        if let Some(code) = refused {
            let reply = Message::reply_to(&msg, code);
            return vec![encode_reply(id, &msg, reply, transport)];
        }
        if let Some(local) = self.local_answer(&msg) {
            return vec![encode_reply(id, &msg, local, transport)];
        }
        let question = msg.questions[0].clone();
        if self.policy.decide(&question.name, question.qtype, client) == Verdict::Block {
            let blocked = Message::reply_to(&msg, rcode::NXDOMAIN);
            return vec![
                Output::Event(Event::Blocked {
                    name: question.name,
                    client,
                }),
                encode_reply(id, &msg, blocked, transport),
            ];
        }
        let key = cache_key(&msg);
        if let Some(entry) = self.cache.lookup(&key, now) {
            let mut reply = Message::reply_to(&msg, entry.rcode);
            reply.header.authentic_data = entry.authentic_data && wants_ad(&msg);
            reply.answers = entry.answers;
            reply.authorities = entry.authorities;
            return vec![encode_reply(id, &msg, reply, transport)];
        }
        self.forward(id, client, transport, msg, now)
    }

    /// Send the client's question to an upstream and remember the query.
    fn forward(
        &mut self,
        id: QueryId,
        client: Ipv4Addr,
        transport: Transport,
        msg: Message,
        now: Timestamp,
    ) -> Vec<Output> {
        if self.config.upstreams.is_empty() {
            let mut outputs = Vec::new();
            if !self.no_upstreams_told {
                self.no_upstreams_told = true;
                outputs.push(Output::Event(Event::NoUpstreams));
            }
            let servfail = Message::reply_to(&msg, rcode::SERVFAIL);
            outputs.push(encode_reply(id, &msg, servfail, transport));
            return outputs;
        }
        if self.pending.len() >= MAX_PENDING {
            let servfail = Message::reply_to(&msg, rcode::SERVFAIL);
            return vec![encode_reply(id, &msg, servfail, transport)];
        }
        let Some(upstream) = self.pick_upstream(now, None) else {
            let servfail = Message::reply_to(&msg, rcode::SERVFAIL);
            return vec![encode_reply(id, &msg, servfail, transport)];
        };
        let pending = Pending {
            client: id,
            client_addr: client,
            transport,
            query: msg,
            upstream,
            upstream_transport: Transport::Udp,
            deadline: now + UPSTREAM_TIMEOUT,
            attempts: 1,
        };
        vec![self.send_upstream(pending)]
    }

    /// Build the upstream query for `pending`, file it under a fresh id, and hand back the
    /// forward.
    fn send_upstream(&mut self, pending: Pending) -> Output {
        let uid = self.fresh_id();
        self.send_upstream_as(uid, pending)
    }

    /// [`Forwarder::send_upstream`] with the id chosen by the caller.
    fn send_upstream_as(&mut self, uid: u16, pending: Pending) -> Output {
        let question = pending.query.questions[0].clone();
        let dnssec_ok = pending.query.edns().is_some_and(|edns| edns.dnssec_ok);
        let upstream_query = Message {
            header: Header {
                id: uid,
                recursion_desired: true,
                checking_disabled: pending.query.header.checking_disabled,
                ..Header::default()
            },
            questions: vec![question],
            additionals: vec![opt_record(dnssec_ok)],
            ..Message::default()
        };
        let output = Output::Forward {
            upstream: pending.upstream,
            transport: pending.upstream_transport,
            bytes: upstream_query.encode(),
        };
        self.pending.insert(uid, pending);
        output
    }

    fn upstream_reply(
        &mut self,
        upstream: Ipv4Addr,
        transport: Transport,
        bytes: &[u8],
        now: Timestamp,
    ) -> Vec<Output> {
        let Ok(msg) = Message::decode(bytes) else {
            return Vec::new();
        };
        let uid = msg.header.id;
        let matches = self.pending.get(&uid).is_some_and(|pending| {
            pending.upstream == upstream
                && pending.upstream_transport == transport
                && msg.header.response
                && msg.questions.len() == 1
                && msg.questions[0] == pending.query.questions[0]
        });
        if !matches {
            return Vec::new();
        }
        let Some(mut pending) = self.pending.remove(&uid) else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        if self.down.remove(&upstream).is_some() {
            outputs.push(Output::Event(Event::UpstreamUp(upstream)));
        }
        if msg.header.truncated && transport == Transport::Udp {
            pending.upstream_transport = Transport::Tcp;
            pending.deadline = now + UPSTREAM_TIMEOUT;
            outputs.push(self.send_upstream_as(uid, pending));
            return outputs;
        }
        // An error from one upstream is that upstream's failure, not the name's: while another
        // upstream has not been asked, it is asked next. The answer is relayed only when every
        // one has failed. An answer is not a silence, so nothing is marked down.
        let failed_answer = matches!(
            msg.header.rcode,
            rcode::FORMERR | rcode::NOTIMP | rcode::REFUSED | rcode::SERVFAIL
        );
        let attempts_allowed = usize::from(MAX_ATTEMPTS).min(self.config.upstreams.len());
        if failed_answer
            && usize::from(pending.attempts) < attempts_allowed
            && let Some(next) = self.pick_upstream(now, Some(upstream))
        {
            pending.upstream = next;
            pending.upstream_transport = Transport::Udp;
            pending.deadline = now + UPSTREAM_TIMEOUT;
            pending.attempts += 1;
            outputs.push(self.send_upstream(pending));
            return outputs;
        }
        let question = &pending.query.questions[0];
        if let Some(addr) = self.rebinding_address(&msg) {
            outputs.push(Output::Event(Event::RebindDropped {
                name: question.name.clone(),
                addr,
                client: pending.client_addr,
            }));
            let refused = Message::reply_to(&pending.query, rcode::REFUSED);
            outputs.push(encode_reply(
                pending.client,
                &pending.query,
                refused,
                pending.transport,
            ));
            return outputs;
        }
        self.cache.store(cache_key(&pending.query), &msg, now);
        let mut reply = Message::reply_to(&pending.query, msg.header.rcode);
        reply.header.authentic_data = msg.header.authentic_data && wants_ad(&pending.query);
        reply.header.truncated = msg.header.truncated;
        reply.answers = msg.answers;
        reply.authorities = msg.authorities;
        outputs.push(encode_reply(
            pending.client,
            &pending.query,
            reply,
            pending.transport,
        ));
        outputs
    }

    /// Every pending query past its deadline: its upstream goes down (unless the wait was for a
    /// TCP retry, which the upstream had already answered over UDP), and it moves to the next
    /// upstream or fails.
    fn timeout(&mut self, now: Timestamp) -> Vec<Output> {
        let expired: Vec<u16> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(uid, _)| *uid)
            .collect();
        let mut outputs = Vec::new();
        for uid in expired {
            let Some(mut pending) = self.pending.remove(&uid) else {
                continue;
            };
            let failed = pending.upstream;
            let silent = pending.upstream_transport == Transport::Udp;
            if silent && self.down.insert(failed, now + UPSTREAM_DOWN_HOLD).is_none() {
                outputs.push(Output::Event(Event::UpstreamDown(failed)));
            }
            let next = if pending.attempts < MAX_ATTEMPTS {
                self.pick_upstream(now, Some(failed))
            } else {
                None
            };
            match next {
                Some(upstream) => {
                    pending.upstream = upstream;
                    pending.upstream_transport = Transport::Udp;
                    pending.deadline = now + UPSTREAM_TIMEOUT;
                    pending.attempts += 1;
                    outputs.push(self.send_upstream(pending));
                }
                None => outputs.push(servfail(&pending)),
            }
        }
        outputs
    }

    fn configure(&mut self, config: Config) -> Vec<Output> {
        let mut outputs = vec![Output::Event(Event::Configured {
            upstreams: config.upstreams.len(),
            local: config.local.len(),
        })];
        self.down
            .retain(|upstream, _| config.upstreams.contains(upstream));
        let orphaned: Vec<u16> = self
            .pending
            .iter()
            .filter(|(_, pending)| !config.upstreams.contains(&pending.upstream))
            .map(|(uid, _)| *uid)
            .collect();
        for uid in orphaned {
            if let Some(pending) = self.pending.remove(&uid) {
                outputs.push(servfail(&pending));
            }
        }
        self.no_upstreams_told = config.upstreams.is_empty();
        if config.upstreams.is_empty() {
            outputs.push(Output::Event(Event::NoUpstreams));
        }
        if config.cache_capacity != self.config.cache_capacity {
            self.cache.set_capacity(config.cache_capacity);
        }
        self.config = config;
        outputs
    }

    /// The next upstream in turn that is not marked down, skipping `except`; when all are down,
    /// the next one anyway. `None` when nothing but `except` is left, or there is none at all.
    fn pick_upstream(&mut self, now: Timestamp, except: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let n = self.config.upstreams.len();
        if n == 0 {
            return None;
        }
        let candidates = (0..n)
            .map(|i| (self.cursor + i) % n)
            .filter(|index| Some(self.config.upstreams[*index]) != except);
        let mut fallback = None;
        for index in candidates {
            let upstream = self.config.upstreams[index];
            if !self.is_down(upstream, now) {
                self.cursor = index + 1;
                return Some(upstream);
            }
            fallback.get_or_insert(index);
        }
        let index = fallback?;
        self.cursor = index + 1;
        Some(self.config.upstreams[index])
    }

    fn is_down(&self, upstream: Ipv4Addr, now: Timestamp) -> bool {
        self.down.get(&upstream).is_some_and(|until| *until > now)
    }

    /// The first address in `msg`'s answers that a public name must not resolve to, unless the
    /// question's name is on the allow list.
    fn rebinding_address(&self, msg: &Message) -> Option<IpAddr> {
        let question = &msg.questions[0];
        if self
            .config
            .rebind_allow
            .iter()
            .any(|allowed| question.name.ends_with(allowed))
        {
            return None;
        }
        msg.answers.iter().find_map(|record| match record.rdata {
            RData::A(addr) if self.is_internal_v4(addr) => Some(IpAddr::V4(addr)),
            RData::Aaaa(addr) if self.is_internal_v6(addr) => Some(IpAddr::V6(addr)),
            _ => None,
        })
    }

    /// RFC 1918, the shared space of RFC 6598 (`100.64.0.0/10`, the address a home behind
    /// carrier NAT sits at), link-local, loopback, `0.0.0.0/8`, the broadcast address, a LAN
    /// subnet (whatever it is numbered from) or one of the router's own addresses.
    fn is_internal_v4(&self, addr: Ipv4Addr) -> bool {
        let [a, b, _, _] = addr.octets();
        addr.is_private()
            || (a == 100 && (64..=127).contains(&b))
            || addr.is_link_local()
            || addr.is_loopback()
            || a == 0
            || addr.is_broadcast()
            || self
                .config
                .lan_subnets
                .iter()
                .any(|subnet| subnet.contains(&addr))
            || self.config.router_addrs.contains(&addr)
    }

    /// ULA, link-local, loopback, or an IPv4-mapped address that [`Forwarder::is_internal_v4`]
    /// rejects.
    fn is_internal_v6(&self, addr: Ipv6Addr) -> bool {
        addr.is_unique_local()
            || addr.is_unicast_link_local()
            || addr.is_loopback()
            || addr.is_unspecified()
            || addr
                .to_ipv4_mapped()
                .is_some_and(|mapped| self.is_internal_v4(mapped))
    }

    /// A random 16-bit id not in use (xorshift; the seed is the driver's randomness).
    fn fresh_id(&mut self) -> u16 {
        loop {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            let id = u16::try_from(self.rng & 0xffff).unwrap_or(1);
            if !self.pending.contains_key(&id) {
                return id;
            }
        }
    }

    /// The authoritative answer when the question falls in the local zone or a LAN's reverse
    /// zone; `None` when it is for the upstreams.
    fn local_answer(&self, msg: &Message) -> Option<Message> {
        let question = &msg.questions[0];
        if let Some(addr) = reverse_addr(&question.name) {
            let subnet = self
                .config
                .lan_subnets
                .iter()
                .find(|subnet| subnet.contains(&addr))?;
            let zone = reverse_zone(*subnet);
            let mut reply = Message::reply_to(msg, rcode::NOERROR);
            reply.header.authoritative = true;
            match (self.name_for(addr), question.qtype) {
                (Some(name), rtype::PTR | rtype::ANY) => reply.answers.push(Record {
                    name: question.name.clone(),
                    rtype: rtype::PTR,
                    class: CLASS_IN,
                    ttl: LOCAL_TTL,
                    rdata: RData::Ptr(name),
                }),
                (Some(_), _) => reply.authorities.push(self.soa(&zone)),
                (None, _) => {
                    reply.header.rcode = rcode::NXDOMAIN;
                    reply.authorities.push(self.soa(&zone));
                }
            }
            return Some(reply);
        }
        if !question.name.ends_with(&self.config.domain) {
            return None;
        }
        let mut reply = Message::reply_to(msg, rcode::NOERROR);
        reply.header.authoritative = true;
        let is_apex = question.name == self.config.domain;
        let addrs = self.addrs_for(&question.name);
        if !is_apex && addrs.is_empty() {
            reply.header.rcode = rcode::NXDOMAIN;
            reply.authorities.push(self.soa(&self.config.domain));
            return Some(reply);
        }
        match question.qtype {
            rtype::A | rtype::ANY if !addrs.is_empty() => {
                for addr in addrs {
                    reply.answers.push(Record {
                        name: question.name.clone(),
                        rtype: rtype::A,
                        class: CLASS_IN,
                        ttl: LOCAL_TTL,
                        rdata: RData::A(addr),
                    });
                }
            }
            rtype::SOA if is_apex => reply.answers.push(self.soa(&self.config.domain)),
            _ => reply.authorities.push(self.soa(&self.config.domain)),
        }
        Some(reply)
    }

    /// The addresses `name` resolves to locally: the router's, or the first local record's.
    fn addrs_for(&self, name: &Name) -> Vec<Ipv4Addr> {
        if self.config.router_name.as_ref() == Some(name) {
            return self.config.router_addrs.clone();
        }
        self.config
            .local
            .iter()
            .find(|record| &record.name == name)
            .map(|record| vec![record.addr])
            .unwrap_or_default()
    }

    /// The name `addr` resolves to locally.
    fn name_for(&self, addr: Ipv4Addr) -> Option<Name> {
        if self.config.router_addrs.contains(&addr) {
            return self.config.router_name.clone();
        }
        self.config
            .local
            .iter()
            .find(|record| record.addr == addr)
            .map(|record| record.name.clone())
    }

    /// The SOA of a local zone, as its negative answers carry it.
    fn soa(&self, zone: &Name) -> Record {
        let mname = self
            .config
            .router_name
            .clone()
            .unwrap_or_else(|| self.config.domain.clone());
        let rname = "hostmaster"
            .parse::<Name>()
            .and_then(|host| host.join(&self.config.domain))
            .unwrap_or_else(|_| self.config.domain.clone());
        Record {
            name: zone.clone(),
            rtype: rtype::SOA,
            class: CLASS_IN,
            ttl: LOCAL_NEGATIVE_TTL,
            rdata: RData::Soa {
                mname,
                rname,
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: LOCAL_NEGATIVE_TTL,
            },
        }
    }
}

/// The cache key of a client's query: its question and its DNSSEC bits, since a signed answer
/// is not an unsigned one and a CD=1 answer is not for everyone (RFC 4035 §3.2.2, §4.6).
fn cache_key(query: &Message) -> Key {
    let question = &query.questions[0];
    Key {
        name: question.name.clone(),
        qtype: question.qtype,
        dnssec_ok: query.edns().is_some_and(|edns| edns.dnssec_ok),
        checking_disabled: query.header.checking_disabled,
    }
}

/// Whether the client asked for the AD bit: DO or AD set in its query (RFC 6840 §5.7).
fn wants_ad(query: &Message) -> bool {
    query.header.authentic_data || query.edns().is_some_and(|edns| edns.dnssec_ok)
}

/// SERVFAIL to the client of a query no upstream answered.
fn servfail(pending: &Pending) -> Output {
    let reply = Message::reply_to(&pending.query, rcode::SERVFAIL);
    encode_reply(pending.client, &pending.query, reply, pending.transport)
}

/// The reply for `query` as bytes for the client: RA set, our OPT when the client sent one,
/// truncated to its UDP buffer or whole over TCP.
fn encode_reply(id: QueryId, query: &Message, mut reply: Message, transport: Transport) -> Output {
    reply.header.recursion_available = true;
    if let Some(edns) = query.edns() {
        reply.additionals.push(opt_record(edns.dnssec_ok));
    }
    let bytes = match transport {
        Transport::Udp => reply.encode_within(query.max_udp_payload()),
        Transport::Tcp => reply.encode(),
    };
    Output::Reply { id, bytes }
}

/// Our OPT record: the payload size we take, the client's DO bit.
fn opt_record(dnssec_ok: bool) -> Record {
    Record {
        name: Name::root(),
        rtype: rtype::OPT,
        class: EDNS_UDP_PAYLOAD,
        ttl: if dnssec_ok { 0x8000 } else { 0 },
        rdata: RData::Opt(Edns {
            udp_payload: EDNS_UDP_PAYLOAD,
            extended_rcode: 0,
            version: 0,
            dnssec_ok,
            options: Vec::new(),
        }),
    }
}

/// The `in-addr.arpa` zone covering `subnet`: the first whole octets of its prefix (a /24 is
/// `1.168.192.in-addr.arpa`, a /20 is `168.192.in-addr.arpa`).
fn reverse_zone(subnet: Ipv4Net) -> Name {
    let octets = usize::from(subnet.prefix_len() / 8).min(3);
    let full = reverse_name(subnet.network());
    let labels = full.labels();
    Name::from_labels(labels[4 - octets..].to_vec()).unwrap_or(full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{CLASS_IN, Edns, Header, Question, rcode, rtype};

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn config() -> Config {
        Config {
            upstreams: vec![ip("203.0.113.1")],
            domain: name("home.arpa"),
            router_name: Some(name("openfeo.home.arpa")),
            router_addrs: vec![ip("192.168.1.1")],
            lan_subnets: vec!["192.168.1.0/24".parse().unwrap()],
            local: vec![
                LocalRecord {
                    name: name("nas.home.arpa"),
                    addr: ip("192.168.1.10"),
                },
                LocalRecord {
                    name: name("pc.home.arpa"),
                    addr: ip("192.168.1.120"),
                },
            ],
            rebind_allow: vec![name("allowed.isp.example")],
            cache_capacity: 64,
        }
    }

    /// A plain query, id 7, RD set.
    fn q(qname: &str, qtype: u16) -> Vec<u8> {
        Message {
            header: Header {
                id: 7,
                recursion_desired: true,
                ..Header::default()
            },
            questions: vec![Question {
                name: name(qname),
                qtype,
                qclass: CLASS_IN,
            }],
            ..Message::default()
        }
        .encode()
    }

    /// A query with an OPT record.
    fn q_edns(qname: &str, qtype: u16, payload: u16, dnssec_ok: bool) -> Vec<u8> {
        let mut m = Message::decode(&q(qname, qtype)).unwrap();
        m.additionals.push(Record {
            name: Name::root(),
            rtype: rtype::OPT,
            class: payload,
            ttl: 0,
            rdata: RData::Opt(Edns {
                udp_payload: payload,
                extended_rcode: 0,
                version: 0,
                dnssec_ok,
                options: vec![],
            }),
        });
        m.encode()
    }

    fn client(id: QueryId, transport: Transport, bytes: Vec<u8>) -> Input {
        Input::Query {
            id,
            client: ip("192.168.1.50"),
            transport,
            bytes,
        }
    }

    /// The one reply among the outputs, decoded.
    fn reply(outputs: &[Output]) -> Message {
        let replies: Vec<&Vec<u8>> = outputs
            .iter()
            .filter_map(|o| match o {
                Output::Reply { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect();
        assert_eq!(replies.len(), 1, "one reply expected in {outputs:?}");
        Message::decode(replies[0]).unwrap()
    }

    fn forwards(outputs: &[Output]) -> Vec<(Ipv4Addr, Transport, Message)> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::Forward {
                    upstream,
                    transport,
                    bytes,
                } => Some((*upstream, *transport, Message::decode(bytes).unwrap())),
                _ => None,
            })
            .collect()
    }

    fn a(owner: &str, ttl: u32, addr: &str) -> Record {
        Record {
            name: name(owner),
            rtype: rtype::A,
            class: CLASS_IN,
            ttl,
            rdata: RData::A(ip(addr)),
        }
    }

    fn txt(owner: &str, ttl: u32, len: usize) -> Record {
        Record {
            name: name(owner),
            rtype: rtype::TXT,
            class: CLASS_IN,
            ttl,
            rdata: RData::Txt(vec![vec![b'x'; len]]),
        }
    }

    fn cname(owner: &str, ttl: u32, target: &str) -> Record {
        Record {
            name: name(owner),
            rtype: rtype::CNAME,
            class: CLASS_IN,
            ttl,
            rdata: RData::Cname(name(target)),
        }
    }

    fn aaaa(owner: &str, ttl: u32, addr: &str) -> Record {
        Record {
            name: name(owner),
            rtype: rtype::AAAA,
            class: CLASS_IN,
            ttl,
            rdata: RData::Aaaa(addr.parse().unwrap()),
        }
    }

    /// An upstream's answer to the forwarded query `fwd`: its id, the records, an OPT when the
    /// query carried one.
    fn upstream_answer(fwd: &Message, records: &[Record]) -> Vec<u8> {
        let mut m = Message::reply_to(fwd, rcode::NOERROR);
        m.header.recursion_available = true;
        m.answers = records.to_vec();
        if let Some(edns) = fwd.edns() {
            m.additionals.push(Record {
                name: Name::root(),
                rtype: rtype::OPT,
                class: edns.udp_payload,
                ttl: 0,
                rdata: RData::Opt(Edns {
                    options: vec![],
                    ..edns.clone()
                }),
            });
        }
        m.encode()
    }

    #[test]
    fn local_names_answer_authoritatively_from_reservations_leases_and_the_router() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(client(1, Transport::Udp, q("NAS.home.arpa", rtype::A)), 0);
        let r = reply(&out);
        assert_eq!(
            (
                r.header.id,
                r.header.response,
                r.header.authoritative,
                r.header.recursion_available,
                r.header.rcode
            ),
            (7, true, true, true, rcode::NOERROR)
        );
        assert_eq!(
            r.answers,
            vec![Record {
                name: name("nas.home.arpa"),
                rtype: rtype::A,
                class: CLASS_IN,
                ttl: LOCAL_TTL,
                rdata: RData::A(ip("192.168.1.10")),
            }]
        );
        assert_eq!(forwards(&out), Vec::new());
        assert_eq!(
            reply(&f.handle(
                client(2, Transport::Udp, q("openfeo.home.arpa", rtype::A)),
                0
            ))
            .answers[0]
                .rdata,
            RData::A(ip("192.168.1.1"))
        );
        let ptr = reply(&f.handle(
            client(
                3,
                Transport::Udp,
                q("10.1.168.192.in-addr.arpa", rtype::PTR),
            ),
            0,
        ));
        assert_eq!(ptr.answers[0].rdata, RData::Ptr(name("nas.home.arpa")));
    }

    #[test]
    fn home_arpa_and_lan_reverse_zones_never_go_upstream() {
        let mut f = Forwarder::new(config(), 1);
        let nx = reply(&f.handle(
            client(1, Transport::Udp, q("printer.home.arpa", rtype::A)),
            0,
        ));
        assert_eq!(
            (nx.header.rcode, nx.header.authoritative),
            (rcode::NXDOMAIN, true)
        );
        assert!(
            matches!(nx.authorities[0].rdata, RData::Soa { ref mname, minimum, .. } if *mname == name("openfeo.home.arpa") && minimum == LOCAL_NEGATIVE_TTL)
        );
        let nodata = reply(&f.handle(
            client(2, Transport::Udp, q("nas.home.arpa", rtype::AAAA)),
            0,
        ));
        assert_eq!(
            (
                nodata.header.rcode,
                nodata.answers.len(),
                nodata.authorities.len()
            ),
            (rcode::NOERROR, 0, 1)
        );
        let rev = reply(&f.handle(
            client(
                3,
                Transport::Udp,
                q("200.1.168.192.in-addr.arpa", rtype::PTR),
            ),
            0,
        ));
        assert_eq!(rev.header.rcode, rcode::NXDOMAIN);
        assert_eq!(rev.authorities[0].name, name("1.168.192.in-addr.arpa"));
        assert_eq!(f.pending(), 0, "nothing was forwarded");
        let out = f.handle(
            client(4, Transport::Udp, q("5.5.0.10.in-addr.arpa", rtype::PTR)),
            0,
        );
        assert_eq!(
            forwards(&out).len(),
            1,
            "a reverse name outside our subnets is forwarded"
        );
    }

    #[test]
    fn odd_queries_are_answered_with_an_error_and_never_forwarded() {
        let mut f = Forwarder::new(config(), 1);
        let at = |f: &mut Forwarder, bytes: Vec<u8>| f.handle(client(9, Transport::Tcp, bytes), 0);
        assert_eq!(
            at(&mut f, vec![0; 5]),
            vec![Output::Drop { id: 9 }],
            "no header, no reply: the client is dropped"
        );
        let mut cut = q("x.example", rtype::A);
        cut.truncate(14);
        assert_eq!(reply(&at(&mut f, cut)).header.rcode, rcode::FORMERR);
        let mut two = Message::decode(&q("x.example", rtype::A)).unwrap();
        two.questions.push(two.questions[0].clone());
        assert_eq!(
            reply(&at(&mut f, two.encode())).header.rcode,
            rcode::FORMERR
        );
        let mut none = Message::decode(&q("x.example", rtype::A)).unwrap();
        none.questions.clear();
        assert_eq!(
            reply(&at(&mut f, none.encode())).header.rcode,
            rcode::FORMERR
        );
        let mut update = Message::decode(&q("x.example", rtype::A)).unwrap();
        update.header.opcode = 5;
        assert_eq!(
            reply(&at(&mut f, update.encode())).header.rcode,
            rcode::NOTIMP
        );
        let mut chaos = Message::decode(&q("version.bind", rtype::TXT)).unwrap();
        chaos.questions[0].qclass = 3;
        assert_eq!(
            reply(&at(&mut f, chaos.encode())).header.rcode,
            rcode::REFUSED
        );
        let mut response = Message::decode(&q("x.example", rtype::A)).unwrap();
        response.header.response = true;
        assert_eq!(at(&mut f, response.encode()), vec![Output::Drop { id: 9 }]);
        assert_eq!(
            at(&mut f, vec![0xff; 65_535]).len(),
            1,
            "a giant TCP message gets one FORMERR"
        );
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn remote_names_are_forwarded_with_edns_and_cached_on_the_way_back() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert_eq!((upstream, transport), (ip("203.0.113.1"), Transport::Udp));
        assert_ne!(fwd.header.id, 7, "a fresh id");
        assert_eq!(fwd.edns().map(|e| e.udp_payload), Some(EDNS_UDP_PAYLOAD));
        assert!(fwd.header.recursion_desired);
        assert_eq!(f.next_timeout(), Some(UPSTREAM_TIMEOUT));
        let out = f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]),
            },
            100,
        );
        let r = reply(&out);
        assert_eq!(
            (
                r.header.id,
                r.header.rcode,
                r.header.authoritative,
                r.header.recursion_available
            ),
            (7, rcode::NOERROR, false, true)
        );
        assert_eq!(r.answers[0].rdata, RData::A(ip("198.51.100.10")));
        assert!(
            r.edns().is_none(),
            "the client sent no OPT, so it gets none"
        );
        let out = f.handle(
            client(2, Transport::Udp, q("WWW.isp.example", rtype::A)),
            10_100,
        );
        assert!(forwards(&out).is_empty(), "served from the cache");
        assert_eq!(reply(&out).answers[0].ttl, 50);
        assert_eq!(f.cache_stats().hits, 1);
    }

    #[test]
    fn clients_with_edns_get_an_opt_back_and_udp_replies_fit_their_buffer() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(
            client(
                1,
                Transport::Udp,
                q_edns("big.isp.example", rtype::TXT, 512, true),
            ),
            0,
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert!(fwd.edns().unwrap().dnssec_ok, "DO passes through");
        let big = upstream_answer(
            &fwd,
            &[
                txt("big.isp.example", 60, 250),
                txt("big.isp.example", 60, 250),
                txt("big.isp.example", 60, 250),
            ],
        );
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: big,
            },
            50,
        ));
        assert!(r.header.truncated && r.edns().map(|e| e.udp_payload) == Some(EDNS_UDP_PAYLOAD));
        // The same DO bit: the cache keeps signed and unsigned answers apart.
        let out = f.handle(
            client(
                2,
                Transport::Tcp,
                q_edns("big.isp.example", rtype::TXT, 512, true),
            ),
            60,
        );
        assert_eq!(
            reply(&out).answers.len(),
            3,
            "over TCP the cached answer is whole"
        );
    }

    #[test]
    fn configure_switches_upstreams_and_local_names_live_and_keeps_the_cache() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]),
            },
            10,
        );
        let mut changed = config();
        changed.upstreams = vec![ip("9.9.9.9")];
        changed.local.push(LocalRecord {
            name: name("tv.home.arpa"),
            addr: ip("192.168.1.130"),
        });
        let out = f.handle(Input::Configure(changed), 20);
        assert_eq!(
            out,
            vec![Output::Event(Event::Configured {
                upstreams: 1,
                local: 3
            })]
        );
        assert!(
            forwards(&f.handle(
                client(2, Transport::Udp, q("www.isp.example", rtype::A)),
                30
            ))
            .is_empty(),
            "the cache survives"
        );
        assert_eq!(
            forwards(&f.handle(client(3, Transport::Udp, q("other.example", rtype::A)), 40))[0].0,
            ip("9.9.9.9")
        );
        assert_eq!(
            reply(&f.handle(client(4, Transport::Udp, q("tv.home.arpa", rtype::A)), 50)).answers[0]
                .rdata,
            RData::A(ip("192.168.1.130"))
        );
    }

    #[test]
    fn a_silent_upstream_is_retried_on_the_next_and_marked_down() {
        let mut cfg = config();
        cfg.upstreams = vec![ip("203.0.113.99"), ip("203.0.113.1")];
        let mut f = Forwarder::new(cfg, 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        assert_eq!(forwards(&out)[0].0, ip("203.0.113.99"));
        let out = f.handle(Input::Timeout, UPSTREAM_TIMEOUT);
        assert!(out.contains(&Output::Event(Event::UpstreamDown(ip("203.0.113.99")))));
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert_eq!(upstream, ip("203.0.113.1"));
        assert_eq!(
            reply(&f.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]),
                },
                2_100,
            ))
            .header
            .rcode,
            rcode::NOERROR
        );
        let out = f.handle(
            client(2, Transport::Udp, q("other.example", rtype::A)),
            3_000,
        );
        assert_eq!(
            forwards(&out)[0].0,
            ip("203.0.113.1"),
            "the down server is skipped"
        );
        let out = f.handle(
            client(3, Transport::Udp, q("third.example", rtype::A)),
            3_000 + UPSTREAM_DOWN_HOLD,
        );
        assert_eq!(
            forwards(&out)[0].0,
            ip("203.0.113.99"),
            "and tried again after the hold"
        );
    }

    #[test]
    fn when_every_attempt_times_out_the_client_gets_servfail() {
        let mut f = Forwarder::new(config(), 1);
        f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let out = f.handle(Input::Timeout, UPSTREAM_TIMEOUT);
        assert_eq!(
            reply(&out).header.rcode,
            rcode::SERVFAIL,
            "one upstream, no second attempt possible"
        );
        assert_eq!(f.pending(), 0);
        assert_eq!(f.next_timeout(), None);
    }

    #[test]
    fn truncated_udp_replies_are_fetched_again_over_tcp() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(
            client(1, Transport::Tcp, q("big.isp.example", rtype::TXT)),
            0,
        );
        let (upstream, _, fwd) = forwards(&out).remove(0);
        let mut tc = Message::decode(&upstream_answer(&fwd, &[])).unwrap();
        tc.header.truncated = true;
        let out = f.handle(
            Input::UpstreamReply {
                upstream,
                transport: Transport::Udp,
                bytes: tc.encode(),
            },
            10,
        );
        let (upstream2, transport2, fwd2) = forwards(&out).remove(0);
        assert_eq!((upstream2, transport2), (upstream, Transport::Tcp));
        assert!(out.iter().all(|o| !matches!(o, Output::Reply { .. })));
        let full = upstream_answer(
            &fwd2,
            &[
                txt("big.isp.example", 60, 250),
                txt("big.isp.example", 60, 250),
                txt("big.isp.example", 60, 250),
            ],
        );
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport: Transport::Tcp,
                bytes: full,
            },
            20,
        ));
        assert_eq!((r.header.truncated, r.answers.len()), (false, 3));
    }

    #[test]
    fn rebinding_through_a_cname_is_dropped_and_allowed_names_cover_subdomains() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(
            client(1, Transport::Udp, q("evil.isp.example", rtype::A)),
            0,
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let chain = upstream_answer(
            &fwd,
            &[
                cname("evil.isp.example", 60, "target.isp.example"),
                a("target.isp.example", 60, "192.168.1.5"),
            ],
        );
        let out = f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: chain,
            },
            10,
        );
        assert_eq!(reply(&out).header.rcode, rcode::REFUSED);
        assert!(out.contains(&Output::Event(Event::RebindDropped {
            name: name("evil.isp.example"),
            addr: ip("192.168.1.5").into(),
            client: ip("192.168.1.50"),
        })));
        assert_eq!(f.cache_stats().stores, 0);
        for (qname, addr) in [
            ("router.isp.example", "192.168.1.1"),
            ("ll.isp.example", "169.254.3.4"),
            ("lo.isp.example", "127.0.0.9"),
        ] {
            let out = f.handle(client(2, Transport::Udp, q(qname, rtype::A)), 20);
            let (upstream, transport, fwd) = forwards(&out).remove(0);
            assert_eq!(
                reply(&f.handle(
                    Input::UpstreamReply {
                        upstream,
                        transport,
                        bytes: upstream_answer(&fwd, &[a(qname, 60, addr)]),
                    },
                    30,
                ))
                .header
                .rcode,
                rcode::REFUSED,
                "{qname}"
            );
        }
        let out = f.handle(
            client(3, Transport::Udp, q("dev.allowed.isp.example", rtype::A)),
            40,
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: upstream_answer(&fwd, &[a("dev.allowed.isp.example", 60, "192.168.1.6")]),
            },
            50,
        ));
        assert_eq!(
            (r.header.rcode, r.answers[0].rdata.clone()),
            (rcode::NOERROR, RData::A(ip("192.168.1.6")))
        );
        let out = f.handle(
            client(4, Transport::Udp, q("v6.isp.example", rtype::AAAA)),
            60,
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert_eq!(
            reply(&f.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: upstream_answer(&fwd, &[aaaa("v6.isp.example", 60, "fd00::1")]),
                },
                70,
            ))
            .header
            .rcode,
            rcode::REFUSED,
            "ULA"
        );
    }

    #[test]
    fn replies_that_do_not_match_the_pending_query_are_ignored() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let spoofed_source = f.handle(
            Input::UpstreamReply {
                upstream: ip("203.0.113.66"),
                transport,
                bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "6.6.6.6")]),
            },
            10,
        );
        assert_eq!(spoofed_source, Vec::new());
        let mut other_q = Message::decode(&upstream_answer(
            &fwd,
            &[a("www.isp.example", 60, "6.6.6.6")],
        ))
        .unwrap();
        other_q.questions[0].name = name("www.other.example");
        assert_eq!(
            f.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: other_q.encode(),
                },
                11,
            ),
            Vec::new()
        );
        let mut unknown_id = Message::decode(&upstream_answer(&fwd, &[])).unwrap();
        unknown_id.header.id ^= 0x5555;
        assert_eq!(
            f.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: unknown_id.encode(),
                },
                12,
            ),
            Vec::new()
        );
        assert_eq!(f.pending(), 1, "the real reply is still awaited");
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]),
            },
            13,
        ));
        assert_eq!(r.answers[0].rdata, RData::A(ip("198.51.100.10")));
    }

    #[test]
    fn without_upstreams_remote_names_fail_fast_and_local_names_still_resolve() {
        let mut cfg = config();
        cfg.upstreams = Vec::new();
        let mut f = Forwarder::new(cfg, 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL);
        assert!(out.contains(&Output::Event(Event::NoUpstreams)));
        assert_eq!(f.next_timeout(), None, "nothing to wait for");
        let out = f.handle(client(2, Transport::Udp, q("other.example", rtype::A)), 1);
        assert!(
            !out.contains(&Output::Event(Event::NoUpstreams)),
            "announced once"
        );
        assert_eq!(
            reply(&f.handle(client(3, Transport::Udp, q("nas.home.arpa", rtype::A)), 2))
                .header
                .rcode,
            rcode::NOERROR
        );
        let out = f.handle(Input::Configure(config()), 3);
        assert_eq!(
            out,
            vec![Output::Event(Event::Configured {
                upstreams: 1,
                local: 2,
            })]
        );
    }

    #[test]
    fn pending_queries_to_a_removed_upstream_get_servfail() {
        let mut f = Forwarder::new(config(), 1);
        f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let mut cfg = config();
        cfg.upstreams = vec![ip("9.9.9.9")];
        let out = f.handle(Input::Configure(cfg), 1);
        assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL);
        assert_eq!(f.pending(), 0);
    }

    /// An RRSIG as an opaque record (type 46).
    fn rrsig(owner: &str, ttl: u32) -> Record {
        Record {
            name: name(owner),
            rtype: 46,
            class: CLASS_IN,
            ttl,
            rdata: RData::Other(vec![0; 18]),
        }
    }

    /// A query with the AD bit set and no OPT: a stub asking for the AD bit back.
    fn q_ad(qname: &str, qtype: u16) -> Vec<u8> {
        let mut msg = Message::decode(&q(qname, qtype)).unwrap();
        msg.header.authentic_data = true;
        msg.encode()
    }

    /// A query with CD set and no OPT.
    fn q_cd(qname: &str, qtype: u16) -> Vec<u8> {
        let mut msg = Message::decode(&q(qname, qtype)).unwrap();
        msg.header.checking_disabled = true;
        msg.encode()
    }

    /// Review finding: the cache must keep DO and CD apart, or a validating stub is served an
    /// unsigned answer another client cached and a CD=1 client's answer reaches everyone; the
    /// upstream's AD bit reaches the clients that asked (DO or AD set) and no other.
    #[test]
    fn dnssec_bits_partition_the_cache_and_ad_follows_the_upstream() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let mut unsigned = Message::decode(&upstream_answer(
            &fwd,
            &[a("www.isp.example", 60, "198.51.100.10")],
        ))
        .unwrap();
        unsigned.header.authentic_data = true;
        let plain = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: unsigned.encode(),
            },
            10,
        ));
        assert!(
            !plain.header.authentic_data,
            "a client that set neither DO nor AD is not told AD"
        );
        let out = f.handle(
            client(
                2,
                Transport::Udp,
                q_edns("www.isp.example", rtype::A, 1232, true),
            ),
            20,
        );
        assert_eq!(
            forwards(&out).len(),
            1,
            "a DO client must not be served the unsigned answer from the cache: {out:?}"
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert!(fwd.edns().is_some_and(|edns| edns.dnssec_ok));
        let mut signed = Message::decode(&upstream_answer(
            &fwd,
            &[
                a("www.isp.example", 60, "198.51.100.10"),
                rrsig("www.isp.example", 60),
            ],
        ))
        .unwrap();
        signed.header.authentic_data = true;
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: signed.encode(),
            },
            30,
        ));
        assert_eq!((r.answers.len(), r.header.authentic_data), (2, true));
        let r = reply(&f.handle(
            client(
                3,
                Transport::Udp,
                q_edns("www.isp.example", rtype::A, 1232, true),
            ),
            40,
        ));
        assert_eq!(
            (r.answers.len(), r.header.authentic_data),
            (2, true),
            "the second DO client is served the signed answer from the cache"
        );
        let r = reply(&f.handle(
            client(4, Transport::Udp, q_ad("www.isp.example", rtype::A)),
            50,
        ));
        assert_eq!(
            (r.answers.len(), r.header.authentic_data),
            (1, true),
            "a client that set AD gets the cached plain answer with AD"
        );
        let out = f.handle(
            client(5, Transport::Udp, q_cd("cd.isp.example", rtype::A)),
            60,
        );
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert!(fwd.header.checking_disabled);
        reply(&f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: upstream_answer(&fwd, &[a("cd.isp.example", 60, "6.6.6.6")]),
            },
            70,
        ));
        let out = f.handle(client(6, Transport::Udp, q("cd.isp.example", rtype::A)), 80);
        assert_eq!(
            forwards(&out).len(),
            1,
            "a CD=0 client is not served a CD=1 client's answer: {out:?}"
        );
    }

    #[test]
    fn rebinding_covers_shared_space_broadcast_lan_subnets_and_the_wan_address() {
        let mut cfg = config();
        // A LAN numbered outside RFC 1918, and the WAN address as the reconciler supplies it.
        cfg.lan_subnets.push("198.18.0.0/15".parse().unwrap());
        cfg.router_addrs.push(ip("203.0.113.10"));
        let mut f = Forwarder::new(cfg, 1);
        let cases = [
            ("cgnat.isp.example", "100.64.1.2"),
            ("bcast.isp.example", "255.255.255.255"),
            ("lan.isp.example", "198.18.0.9"),
            ("wan.isp.example", "203.0.113.10"),
        ];
        for (id, (qname, addr)) in cases.into_iter().enumerate() {
            let id = QueryId::try_from(id).unwrap() + 1;
            let out = f.handle(client(id, Transport::Udp, q(qname, rtype::A)), 0);
            let (upstream, transport, fwd) = forwards(&out).remove(0);
            let r = reply(&f.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: upstream_answer(&fwd, &[a(qname, 60, addr)]),
                },
                1,
            ));
            assert_eq!(r.header.rcode, rcode::REFUSED, "{qname}");
        }
    }

    #[test]
    fn an_upstream_error_fails_over_to_the_next_before_the_client_hears_it() {
        let mut cfg = config();
        cfg.upstreams = vec![ip("203.0.113.1"), ip("203.0.113.2")];
        let mut f = Forwarder::new(cfg, 1);
        let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let out = f.handle(
            Input::UpstreamReply {
                upstream,
                transport,
                bytes: Message::reply_to(&fwd, rcode::REFUSED).encode(),
            },
            10,
        );
        assert!(
            !out.iter().any(|o| matches!(o, Output::Reply { .. })),
            "{out:?}"
        );
        assert!(
            !out.contains(&Output::Event(Event::UpstreamDown(upstream))),
            "an answer is not a silence"
        );
        let (second, transport, fwd) = forwards(&out).remove(0);
        assert_eq!(second, ip("203.0.113.2"));
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream: second,
                transport,
                bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]),
            },
            20,
        ));
        assert_eq!(r.header.rcode, rcode::NOERROR);
        // Every upstream failing: the last answer is relayed.
        let out = f.handle(
            client(2, Transport::Udp, q("nope.isp.example", rtype::A)),
            30,
        );
        let (u1, t1, f1) = forwards(&out).remove(0);
        let out = f.handle(
            Input::UpstreamReply {
                upstream: u1,
                transport: t1,
                bytes: Message::reply_to(&f1, rcode::SERVFAIL).encode(),
            },
            31,
        );
        let (u2, t2, f2) = forwards(&out).remove(0);
        let r = reply(&f.handle(
            Input::UpstreamReply {
                upstream: u2,
                transport: t2,
                bytes: Message::reply_to(&f2, rcode::SERVFAIL).encode(),
            },
            32,
        ));
        assert_eq!(r.header.rcode, rcode::SERVFAIL);
    }

    #[test]
    fn a_tcp_retry_that_times_out_marks_nothing_down() {
        let mut f = Forwarder::new(config(), 1);
        let out = f.handle(
            client(1, Transport::Tcp, q("big.isp.example", rtype::TXT)),
            0,
        );
        let (upstream, _, fwd) = forwards(&out).remove(0);
        let mut tc = Message::decode(&upstream_answer(&fwd, &[])).unwrap();
        tc.header.truncated = true;
        f.handle(
            Input::UpstreamReply {
                upstream,
                transport: Transport::Udp,
                bytes: tc.encode(),
            },
            10,
        );
        let out = f.handle(Input::Timeout, 10 + UPSTREAM_TIMEOUT);
        assert!(
            !out.contains(&Output::Event(Event::UpstreamDown(upstream))),
            "{out:?}"
        );
        assert_eq!(
            reply(&out).header.rcode,
            rcode::SERVFAIL,
            "one upstream: nothing else to try"
        );
    }

    #[test]
    fn queries_the_core_will_never_answer_are_dropped_explicitly() {
        let mut f = Forwarder::new(config(), 1);
        let mut response = Message::decode(&q("www.isp.example", rtype::A)).unwrap();
        response.header.response = true;
        assert_eq!(
            f.handle(client(7, Transport::Udp, response.encode()), 0),
            vec![Output::Drop { id: 7 }]
        );
        assert_eq!(
            f.handle(client(8, Transport::Udp, vec![1, 2, 3]), 0),
            vec![Output::Drop { id: 8 }],
            "no header at all"
        );
    }

    /// Pins, unless one fails: then it is a finding and a fix in this task.
    #[test]
    fn apex_and_any_queries_are_answered_locally_and_full_queues_servfail() {
        let mut f = Forwarder::new(config(), 1);
        let r = reply(&f.handle(client(1, Transport::Udp, q("home.arpa", rtype::SOA)), 0));
        assert_eq!(
            (r.header.authoritative, r.answers.len(), r.answers[0].rtype),
            (true, 1, rtype::SOA)
        );
        let r = reply(&f.handle(client(2, Transport::Udp, q("home.arpa", rtype::NS)), 0));
        assert_eq!(
            (r.header.rcode, r.answers.len(), r.authorities[0].rtype),
            (rcode::NOERROR, 0, rtype::SOA),
            "NODATA with the SOA"
        );
        let r = reply(&f.handle(client(3, Transport::Udp, q("nas.home.arpa", rtype::ANY)), 0));
        assert_eq!(r.answers[0].rdata, RData::A(ip("192.168.1.10")));
        let mut any_class = Message::decode(&q("nas.home.arpa", rtype::A)).unwrap();
        any_class.questions[0].qclass = CLASS_ANY;
        assert_eq!(
            reply(&f.handle(client(4, Transport::Udp, any_class.encode()), 0)).answers[0].rdata,
            RData::A(ip("192.168.1.10"))
        );
        for i in 0..MAX_PENDING {
            let id = 100 + QueryId::try_from(i).unwrap();
            f.handle(
                client(
                    id,
                    Transport::Udp,
                    q(&format!("h{i}.isp.example"), rtype::A),
                ),
                1,
            );
        }
        assert_eq!(
            reply(&f.handle(
                client(9_999, Transport::Udp, q("one-more.isp.example", rtype::A)),
                2
            ))
            .header
            .rcode,
            rcode::SERVFAIL
        );
        let out = f.handle(
            Input::Configure(Config {
                upstreams: vec![],
                ..config()
            }),
            3,
        );
        assert_eq!(
            out.iter()
                .filter(|o| matches!(o, Output::Reply { .. }))
                .count(),
            MAX_PENDING,
            "every pending query gets SERVFAIL"
        );
    }
}
