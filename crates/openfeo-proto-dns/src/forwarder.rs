// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The forwarder's state machine (SPEC §7.7, sans-IO per §6.3): a client query runs through
//! validation, the local zone, the policy slot, the cache and the upstreams; what comes back
//! is checked for rebinding and cached. `Forwarder::handle(Input, now) -> Vec<Output>`; the
//! driver in `openfeo-net` moves the bytes and keeps time.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

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
    /// Reverse zones the forwarder is authoritative for.
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
    transport: Transport,
    /// The client's query, for the reply's header and the OPT decision.
    query: Message,
    upstream: Ipv4Addr,
    upstream_transport: Transport,
    deadline: Timestamp,
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
            Input::Timeout => Vec::new(),
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
            return Message::formerr(bytes)
                .map(|formerr| {
                    vec![Output::Reply {
                        id,
                        bytes: formerr.encode(),
                    }]
                })
                .unwrap_or_default();
        };
        if msg.header.response {
            return Vec::new();
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
        let key = Key {
            name: question.name.clone(),
            qtype: question.qtype,
        };
        if let Some(entry) = self.cache.lookup(&key, now) {
            let mut reply = Message::reply_to(&msg, entry.rcode);
            reply.answers = entry.answers;
            reply.authorities = entry.authorities;
            return vec![encode_reply(id, &msg, reply, transport)];
        }
        self.forward(id, transport, msg, now)
    }

    /// Send the client's question to an upstream and remember the query.
    fn forward(
        &mut self,
        id: QueryId,
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
        let upstream = self.pick_upstream(now);
        let pending = Pending {
            client: id,
            transport,
            query: msg,
            upstream,
            upstream_transport: Transport::Udp,
            deadline: now + UPSTREAM_TIMEOUT,
        };
        vec![self.send_upstream(pending)]
    }

    /// Build the upstream query for `pending`, file it under a fresh id, and hand back the
    /// forward.
    fn send_upstream(&mut self, pending: Pending) -> Output {
        let uid = self.fresh_id();
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
        let Some(pending) = self.pending.remove(&msg.header.id) else {
            return Vec::new();
        };
        let _ = (upstream, transport);
        let question = &pending.query.questions[0];
        let key = Key {
            name: question.name.clone(),
            qtype: question.qtype,
        };
        self.cache.store(key, &msg, now);
        let mut reply = Message::reply_to(&pending.query, msg.header.rcode);
        reply.answers = msg.answers;
        reply.authorities = msg.authorities;
        vec![encode_reply(
            pending.client,
            &pending.query,
            reply,
            pending.transport,
        )]
    }

    fn configure(&mut self, config: Config) -> Vec<Output> {
        let mut outputs = vec![Output::Event(Event::Configured {
            upstreams: config.upstreams.len(),
            local: config.local.len(),
        })];
        self.down
            .retain(|upstream, _| config.upstreams.contains(upstream));
        self.no_upstreams_told = config.upstreams.is_empty();
        if config.upstreams.is_empty() {
            outputs.push(Output::Event(Event::NoUpstreams));
        }
        self.config = config;
        outputs
    }

    /// The next upstream in turn that is not marked down; when all are, the next one anyway,
    /// its mark cleared.
    fn pick_upstream(&mut self, now: Timestamp) -> Ipv4Addr {
        let n = self.config.upstreams.len();
        for i in 0..n {
            let index = (self.cursor + i) % n;
            let upstream = self.config.upstreams[index];
            if !self.is_down(upstream, now) {
                self.cursor = index + 1;
                return upstream;
            }
        }
        let index = self.cursor % n;
        let upstream = self.config.upstreams[index];
        self.down.remove(&upstream);
        self.cursor = index + 1;
        upstream
    }

    fn is_down(&self, upstream: Ipv4Addr, now: Timestamp) -> bool {
        self.down.get(&upstream).is_some_and(|until| *until > now)
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
        assert_eq!(at(&mut f, vec![0; 5]), Vec::new(), "no header, no reply");
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
        assert_eq!(at(&mut f, response.encode()), Vec::new());
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
        let out = f.handle(
            client(
                2,
                Transport::Tcp,
                q_edns("big.isp.example", rtype::TXT, 512, false),
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
}
