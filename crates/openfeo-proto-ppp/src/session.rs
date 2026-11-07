// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! One PPP session over a PPPoE session (RFC 1661 §3): the phases Dead, Establish (LCP),
//! Authenticate (PAP or CHAP as LCP settled), Network (IPCP and IPV6CP together) and
//! Terminate, the LCP echo keepalive, Protocol-Reject for what we do not speak, and one
//! `Down` with a reason when it ends. A core: frames in, frames and events out.

use std::fmt;

use crate::Timestamp;
use crate::frame::{CHAP, IPCP, IPV6CP, LCP, PAP, Packet, code};
use crate::fsm::{Action, Event, Fsm, State};
use crate::ipcp::{Ipcp, Ipv4Up};
use crate::ipv6cp::{Ipv6Up, Ipv6cp};
use crate::lcp::{AuthProto, Keepalive, Lcp};
use crate::{chap, pap};

/// What one WAN's session is.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub username: String,
    pub password: Vec<u8>,
    /// The PPP payload the port carries: 1500 with RFC 4638, else 1492.
    pub mru: u16,
    /// The stable-privacy secret, behind the IPV6CP identifier.
    pub secret: [u8; 16],
    pub wan: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("mru", &self.mru)
            .field("secret", &"<redacted>")
            .field("wan", &self.wan)
            .finish()
    }
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// The PPPoE session exists: bring PPP up.
    Start,
    /// A frame from the unit or the channel.
    Frame { protocol: u16, payload: Vec<u8> },
    /// The timer of [`Session::next_timeout`] fired.
    Timeout,
    /// End the session in order: Terminate-Request, then `Down`.
    Stop,
    /// The port lost carrier or the PPPoE session was torn down: `Down` at once.
    CarrierLost,
}

/// What the session wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send this PPP frame (the driver picks the descriptor by protocol class).
    Send {
        protocol: u16,
        payload: Vec<u8>,
    },
    /// Tell the kernel the MRU LCP settled.
    Mru(u16),
    LcpUp {
        mru: u16,
        auth: Option<AuthProto>,
    },
    /// Authenticated, by `"pap"` or `"chap"`.
    AuthOk(&'static str),
    Ipv4Up(Ipv4Up),
    Ipv4Down,
    Ipv6Up(Ipv6Up),
    Ipv6Down,
    /// The session is over; nothing is sent until the next `Start`.
    Down {
        reason: Reason,
        uptime_ms: u64,
    },
    Note(Note),
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    KeepaliveLost,
    TerminatedByPeer,
    AuthFailed(String),
    NoNetworkProtocol,
    AuthProtocolUnsupported,
    LcpFailed,
    CarrierLost,
    Stopped,
}

/// Console-worthy events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// A frame of a protocol we do not speak was Protocol-Rejected.
    ProtocolRejected(u16),
    /// The peer rejected one of our network protocols.
    NcpRejected(u16),
    /// A frame was dropped, and why.
    Ignored(&'static str),
}

/// RFC 1661 §3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Dead,
    Establish,
    Authenticate,
    Network,
    Terminate,
}

/// Where one network control protocol stands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Ncp {
    up: bool,
    failed: bool,
}

/// One PPP session.
#[derive(Debug, Clone)]
pub struct Session {
    config: Config,
    seed: u64,
    phase: Phase,
    lcp: Fsm<Lcp>,
    ipcp: Fsm<Ipcp>,
    ipv6cp: Fsm<Ipv6cp>,
    keepalive: Keepalive,
    pap: Option<pap::Client>,
    chap: Option<chap::Client>,
    authenticated: bool,
    lcp_up_at: Option<Timestamp>,
    ipv4: Ncp,
    ipv6: Ncp,
    stopping: bool,
    reject_id: u8,
}

impl Session {
    /// A session in `Dead`; `seed` feeds the identifiers and magic numbers.
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Session {
        let mut session = Session {
            lcp: Fsm::new(Lcp::new(config.mru, seed), seed),
            ipcp: Fsm::new(Ipcp::new(), seed >> 8),
            ipv6cp: Fsm::new(Ipv6cp::new(&config.secret, &config.wan), seed >> 16),
            config,
            seed,
            phase: Phase::Dead,
            keepalive: Keepalive::new(),
            pap: None,
            chap: None,
            authenticated: false,
            lcp_up_at: None,
            ipv4: Ncp::default(),
            ipv6: Ncp::default(),
            stopping: false,
            reject_id: 0,
        };
        session.reset();
        session
    }

    /// Feed one input at `now`.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Start => {
                if self.phase == Phase::Dead {
                    self.reset();
                    self.phase = Phase::Establish;
                    self.lcp_event(Event::Open, now, &mut out);
                    self.lcp_event(Event::Up, now, &mut out);
                }
            }
            Input::Frame { protocol, payload } => {
                if self.phase != Phase::Dead {
                    self.frame(protocol, &payload, now, &mut out);
                }
            }
            Input::Timeout => {
                if self.phase != Phase::Dead {
                    self.timeouts(now, &mut out);
                }
            }
            Input::Stop => {
                if self.phase != Phase::Dead {
                    self.stopping = true;
                    self.phase = Phase::Terminate;
                    self.lcp_event(Event::Close, now, &mut out);
                }
            }
            Input::CarrierLost => {
                if self.phase != Phase::Dead {
                    self.finish(Reason::CarrierLost, now, &mut out);
                }
            }
        }
        out
    }

    /// When to feed [`Input::Timeout`]; `None` while nothing is pending.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        if self.phase == Phase::Dead {
            return None;
        }
        [
            self.lcp.next_timeout(),
            self.ipcp.next_timeout(),
            self.ipv6cp.next_timeout(),
            self.keepalive.next_timeout(),
            self.pap.as_ref().and_then(pap::Client::next_timeout),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    // --- lifecycle --------------------------------------------------------------------------

    /// Back to the beginning: fresh automata, fresh magic, nothing up.
    fn reset(&mut self) {
        self.phase = Phase::Dead;
        self.lcp = Fsm::new(Lcp::new(self.config.mru, self.seed), self.seed);
        self.ipcp = Fsm::new(Ipcp::new(), self.seed >> 8);
        self.ipv6cp = Fsm::new(
            Ipv6cp::new(&self.config.secret, &self.config.wan),
            self.seed >> 16,
        );
        self.keepalive = Keepalive::new();
        self.pap = None;
        self.chap = None;
        self.authenticated = false;
        self.lcp_up_at = None;
        self.ipv4 = Ncp::default();
        self.ipv6 = Ncp::default();
        self.stopping = false;
        // The next session's magic and identifiers differ from this one's.
        self.seed = self
            .seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(1);
    }

    /// The session is over for `reason`: whatever was up goes down, `Down` is said once, and
    /// everything is reset for the next `Start`.
    fn finish(&mut self, reason: Reason, now: Timestamp, out: &mut Vec<Output>) {
        if self.phase == Phase::Dead {
            return;
        }
        self.networks_down(out);
        let uptime_ms = self.lcp_up_at.map_or(0, |at| now.saturating_sub(at));
        out.push(Output::Down { reason, uptime_ms });
        self.reset();
    }

    /// Terminate the link in order (a Terminate-Request goes out), then finish for `reason`.
    fn close_and_finish(&mut self, reason: Reason, now: Timestamp, out: &mut Vec<Output>) {
        self.phase = Phase::Terminate;
        self.lcp_event(Event::Close, now, out);
        self.finish(reason, now, out);
    }

    fn networks_down(&mut self, out: &mut Vec<Output>) {
        if self.ipv4.up {
            self.ipv4.up = false;
            out.push(Output::Ipv4Down);
        }
        if self.ipv6.up {
            self.ipv6.up = false;
            out.push(Output::Ipv6Down);
        }
    }

    // --- LCP --------------------------------------------------------------------------------

    fn lcp_event(&mut self, event: Event, now: Timestamp, out: &mut Vec<Output>) {
        let actions = self.lcp.handle(event, now);
        self.lcp_actions(actions, now, out);
    }

    fn lcp_actions(&mut self, actions: Vec<Action>, now: Timestamp, out: &mut Vec<Output>) {
        for action in actions {
            if self.phase == Phase::Dead {
                return;
            }
            match action {
                Action::Send(packet) => out.push(send(LCP, &packet)),
                Action::ThisLayerUp => self.lcp_up(now, out),
                Action::ThisLayerDown => self.lcp_down(now, out),
                Action::ThisLayerStarted => {}
                Action::ThisLayerFinished => {
                    let reason = if self.stopping {
                        Reason::Stopped
                    } else {
                        Reason::LcpFailed
                    };
                    self.finish(reason, now, out);
                }
                Action::Unknown(packet) => self.lcp_unknown(&packet, now, out),
            }
        }
    }

    fn lcp_up(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let negotiated = self.lcp.options().negotiated();
        self.lcp_up_at = Some(now);
        out.push(Output::Mru(negotiated.mru_ours));
        out.push(Output::LcpUp {
            mru: negotiated.mru_ours,
            auth: negotiated.auth,
        });
        if self.lcp.options().auth_unsupported() {
            self.close_and_finish(Reason::AuthProtocolUnsupported, now, out);
            return;
        }
        self.keepalive.start(now);
        match negotiated.auth {
            Some(AuthProto::Pap) => {
                self.phase = Phase::Authenticate;
                let mut client = pap::Client::new(&self.config.username, &self.config.password);
                let outputs = client.start(now);
                self.pap = Some(client);
                self.pap_outputs(outputs, now, out);
            }
            Some(AuthProto::ChapMd5) => {
                self.phase = Phase::Authenticate;
                self.chap = Some(chap::Client::new(
                    &self.config.username,
                    &self.config.password,
                ));
            }
            Some(AuthProto::Other { .. }) => {
                self.close_and_finish(Reason::AuthProtocolUnsupported, now, out);
            }
            None => self.network(now, out),
        }
    }

    fn lcp_down(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.keepalive.stop();
        self.networks_down(out);
        self.ncp_event(false, Event::Down, now, out);
        self.ncp_event(true, Event::Down, now, out);
    }

    fn lcp_unknown(&mut self, packet: &Packet, now: Timestamp, out: &mut Vec<Output>) {
        match packet.code {
            code::ECHO_REPLY => self.keepalive.reply(packet),
            code::PROTOCOL_REJECT => {
                let rejected = match packet.data.as_slice() {
                    [high, low, ..] => u16::from_be_bytes([*high, *low]),
                    _ => return,
                };
                out.push(Output::Note(Note::NcpRejected(rejected)));
                match rejected {
                    IPCP => {
                        self.ipv4.failed = true;
                        self.ncp_event(false, Event::Close, now, out);
                        if self.ipv4.up {
                            self.ipv4.up = false;
                            out.push(Output::Ipv4Down);
                        }
                    }
                    IPV6CP => {
                        self.ipv6.failed = true;
                        self.ncp_event(true, Event::Close, now, out);
                        if self.ipv6.up {
                            self.ipv6.up = false;
                            out.push(Output::Ipv6Down);
                        }
                    }
                    _ => {}
                }
                self.check_networks(now, out);
            }
            _ => {
                for reply in self.lcp.options_mut().handle_unknown(packet) {
                    out.push(send(LCP, &reply));
                }
            }
        }
    }

    // --- authentication ---------------------------------------------------------------------

    fn pap_outputs(&mut self, outputs: Vec<pap::Output>, now: Timestamp, out: &mut Vec<Output>) {
        for output in outputs {
            match output {
                pap::Output::Send(packet) => out.push(send(PAP, &packet)),
                pap::Output::Ok => {
                    self.authenticated = true;
                    out.push(Output::AuthOk("pap"));
                    self.network(now, out);
                }
                pap::Output::Failed(text) => {
                    self.close_and_finish(Reason::AuthFailed(text), now, out);
                    return;
                }
            }
        }
    }

    fn chap_packet(&mut self, packet: &Packet, now: Timestamp, out: &mut Vec<Output>) {
        let Some(client) = self.chap.as_mut() else {
            out.push(Output::Note(Note::Ignored("CHAP was not negotiated")));
            return;
        };
        for output in client.handle(packet) {
            match output {
                chap::Output::Send(packet) => out.push(send(CHAP, &packet)),
                chap::Output::Ok => {
                    if !self.authenticated {
                        self.authenticated = true;
                        out.push(Output::AuthOk("chap"));
                        self.network(now, out);
                    }
                }
                chap::Output::Rechallenged => {}
                chap::Output::Failed(text) => {
                    self.close_and_finish(Reason::AuthFailed(text), now, out);
                    return;
                }
            }
        }
    }

    // --- network control protocols ----------------------------------------------------------

    /// Authentication is behind us: open both network protocols.
    fn network(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.phase = Phase::Network;
        self.ncp_event(false, Event::Open, now, out);
        self.ncp_event(false, Event::Up, now, out);
        self.ncp_event(true, Event::Open, now, out);
        self.ncp_event(true, Event::Up, now, out);
    }

    fn ncp_event(&mut self, v6: bool, event: Event, now: Timestamp, out: &mut Vec<Output>) {
        let actions = if v6 {
            self.ipv6cp.handle(event, now)
        } else {
            self.ipcp.handle(event, now)
        };
        let protocol = if v6 { IPV6CP } else { IPCP };
        for action in actions {
            if self.phase == Phase::Dead {
                return;
            }
            match action {
                Action::Send(packet) => out.push(send(protocol, &packet)),
                Action::ThisLayerUp => {
                    if v6 {
                        self.ipv6cp.options_mut().acked();
                        if let Some(up) = self.ipv6cp.options().result() {
                            self.ipv6.up = true;
                            out.push(Output::Ipv6Up(up));
                        }
                    } else {
                        self.ipcp.options_mut().acked();
                        if let Some(up) = self.ipcp.options().result() {
                            self.ipv4.up = true;
                            out.push(Output::Ipv4Up(up));
                        }
                    }
                }
                Action::ThisLayerDown => {
                    if v6 && self.ipv6.up {
                        self.ipv6.up = false;
                        out.push(Output::Ipv6Down);
                    } else if !v6 && self.ipv4.up {
                        self.ipv4.up = false;
                        out.push(Output::Ipv4Down);
                    }
                }
                Action::ThisLayerFinished => {
                    if v6 {
                        self.ipv6.failed = true;
                    } else {
                        self.ipv4.failed = true;
                    }
                    self.check_networks(now, out);
                }
                Action::ThisLayerStarted | Action::Unknown(_) => {}
            }
        }
    }

    /// Both network protocols gone is a link with nothing to carry.
    fn check_networks(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        if self.phase == Phase::Network && self.ipv4.failed && self.ipv6.failed {
            self.close_and_finish(Reason::NoNetworkProtocol, now, out);
        }
    }

    // --- frames and timers ------------------------------------------------------------------

    fn frame(&mut self, protocol: u16, payload: &[u8], now: Timestamp, out: &mut Vec<Output>) {
        if !matches!(protocol, LCP | PAP | CHAP | IPCP | IPV6CP) {
            self.protocol_reject(protocol, payload, out);
            return;
        }
        let Ok(packet) = Packet::decode(payload) else {
            out.push(Output::Note(Note::Ignored("undecodable packet")));
            return;
        };
        match protocol {
            LCP => {
                let terminated = packet.code == code::TERMINATE_REQUEST
                    && self.lcp.state() == State::Opened
                    && !self.stopping;
                let actions = self.lcp.handle(Event::Receive(packet), now);
                self.lcp_actions(actions, now, out);
                if terminated {
                    self.finish(Reason::TerminatedByPeer, now, out);
                }
            }
            PAP => {
                if let Some(client) = self.pap.as_mut() {
                    let outputs = client.handle(pap::Input::Packet(packet), now);
                    self.pap_outputs(outputs, now, out);
                } else {
                    out.push(Output::Note(Note::Ignored("PAP was not negotiated")));
                }
            }
            CHAP => self.chap_packet(&packet, now, out),
            IPCP | IPV6CP => {
                if self.phase == Phase::Network {
                    self.ncp_event(protocol == IPV6CP, Event::Receive(packet), now, out);
                } else {
                    out.push(Output::Note(Note::Ignored(
                        "network protocol before its phase",
                    )));
                }
            }
            _ => {}
        }
    }

    /// RFC 1661 §5.7: a frame of a protocol we do not speak, rejected while LCP is open.
    fn protocol_reject(&mut self, protocol: u16, payload: &[u8], out: &mut Vec<Output>) {
        if self.lcp.state() != State::Opened {
            out.push(Output::Note(Note::Ignored(
                "unknown protocol before LCP is up",
            )));
            return;
        }
        self.reject_id = self.reject_id.wrapping_add(1);
        let mut data = protocol.to_be_bytes().to_vec();
        let room = usize::from(self.lcp.options().negotiated().mru_theirs).saturating_sub(8);
        data.extend_from_slice(&payload[..payload.len().min(room)]);
        out.push(send(
            LCP,
            &Packet {
                code: code::PROTOCOL_REJECT,
                id: self.reject_id,
                data,
            },
        ));
        out.push(Output::Note(Note::ProtocolRejected(protocol)));
    }

    fn timeouts(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let due = |at: Option<Timestamp>| at.is_some_and(|at| at <= now);
        if due(self.lcp.next_timeout()) {
            self.lcp_event(Event::Timeout, now, out);
        }
        if self.phase == Phase::Dead {
            return;
        }
        if due(self.ipcp.next_timeout()) {
            self.ncp_event(false, Event::Timeout, now, out);
        }
        if due(self.ipv6cp.next_timeout()) {
            self.ncp_event(true, Event::Timeout, now, out);
        }
        if self.phase == Phase::Dead {
            return;
        }
        if let Some(client) = self.pap.as_mut()
            && due(client.next_timeout())
        {
            let outputs = client.handle(pap::Input::Timeout, now);
            self.pap_outputs(outputs, now, out);
        }
        if self.phase == Phase::Dead {
            return;
        }
        if due(self.keepalive.next_timeout()) {
            if self.lcp.options().echo_rejected() {
                self.keepalive.stop();
                return;
            }
            let magic = self.lcp.options().negotiated().magic_ours;
            match self.keepalive.tick(now, magic) {
                Some(echo) => out.push(send(LCP, &echo)),
                None => {
                    if self.keepalive.lost() {
                        self.close_and_finish(Reason::KeepaliveLost, now, out);
                    }
                }
            }
        }
    }
}

fn send(protocol: u16, packet: &Packet) -> Output {
    Output::Send {
        protocol,
        payload: packet.encode(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::{CHAP, IPCP, IPV6CP, LCP, PAP, Packet, code};
    use crate::fsm::Options;
    use crate::lcp::{AuthProto, ECHO_INTERVAL, Lcp, Opt as LcpOpt};
    use crate::{chap, ipcp, ipv6cp, pap};

    const ISP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const OURS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 100);
    const PEER_IID: u64 = 0x0000_0000_0000_0002;

    fn config() -> Config {
        Config {
            username: "openfeo@isp.example".to_owned(),
            password: b"example-secret".to_vec(),
            mru: 1492,
            secret: [7; 16],
            wan: "wan0".to_owned(),
        }
    }

    fn new_session() -> Session {
        Session::new(config(), 0x5eed)
    }

    /// Every frame sent, decoded into `(protocol, packet)`.
    fn sends(out: &[Output]) -> Vec<(u16, Packet)> {
        out.iter()
            .filter_map(|output| match output {
                Output::Send { protocol, payload } => Some((
                    *protocol,
                    Packet::decode(payload).expect("our own packets decode"),
                )),
                _ => None,
            })
            .collect()
    }

    fn sent(out: &[Output], protocol: u16, packet_code: u8) -> Option<Packet> {
        sends(out)
            .into_iter()
            .find(|(proto, packet)| *proto == protocol && packet.code == packet_code)
            .map(|(_, packet)| packet)
    }

    fn frame(protocol: u16, packet: &Packet) -> Input {
        Input::Frame {
            protocol,
            payload: packet.encode(),
        }
    }

    fn has<F: Fn(&Output) -> bool>(out: &[Output], what: F) -> bool {
        out.iter().any(what)
    }

    fn down_reason(out: &[Output]) -> Option<Reason> {
        out.iter().find_map(|output| match output {
            Output::Down { reason, .. } => Some(reason.clone()),
            _ => None,
        })
    }

    /// Start, ack our LCP request, and send the access concentrator's own (a magic and, when
    /// given, its authentication demand): LCP is then up.
    fn establish(session: &mut Session, auth: Option<AuthProto>, now: &mut u64) -> Vec<Output> {
        let mut all = session.handle(Input::Start, *now);
        let ours = sent(&all, LCP, code::CONFIGURE_REQUEST).expect("our LCP request");
        *now += 10;
        all.extend(session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::CONFIGURE_ACK,
                    id: ours.id,
                    data: ours.data,
                },
            ),
            *now,
        ));
        let mut opts = vec![LcpOpt::Magic(0x0bad_cafe)];
        opts.extend(auth.map(LcpOpt::Auth));
        *now += 10;
        all.extend(session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::CONFIGURE_REQUEST,
                    id: 1,
                    data: Lcp::encode(&opts),
                },
            ),
            *now,
        ));
        all
    }

    /// Challenge, read our Response, say Success.
    fn authenticate_chap(session: &mut Session, now: &mut u64) -> Vec<Output> {
        *now += 10;
        let mut all = session.handle(
            frame(
                CHAP,
                &chap::Message::Challenge {
                    value: vec![0x42; 16],
                    name: b"isp".to_vec(),
                }
                .encode(1),
            ),
            *now,
        );
        let response = sent(&all, CHAP, chap::RESPONSE_CODE).expect("our Response");
        assert_eq!(response.id, 1);
        *now += 10;
        all.extend(session.handle(
            frame(CHAP, &chap::Message::Success(b"ok".to_vec()).encode(1)),
            *now,
        ));
        all
    }

    /// The concentrator's side of IPCP and IPV6CP against what the session asked for.
    fn network(session: &mut Session, now: &mut u64, pending: &[Output]) -> Vec<Output> {
        let mut all = Vec::new();
        let ipcp_request = sent(pending, IPCP, code::CONFIGURE_REQUEST).expect("our IPCP request");
        *now += 10;
        all.extend(session.handle(
            frame(
                IPCP,
                &Packet {
                    code: code::CONFIGURE_NAK,
                    id: ipcp_request.id,
                    data: ipcp::Ipcp::encode(&[
                        ipcp::Opt::Address(OURS),
                        ipcp::Opt::PrimaryDns(ISP),
                        ipcp::Opt::SecondaryDns(Ipv4Addr::UNSPECIFIED),
                    ]),
                },
            ),
            *now,
        ));
        let again = sent(&all, IPCP, code::CONFIGURE_REQUEST).expect("a new IPCP request");
        assert_eq!(
            ipcp::Ipcp::decode(&again.data).unwrap(),
            vec![ipcp::Opt::Address(OURS), ipcp::Opt::PrimaryDns(ISP)]
        );
        *now += 10;
        all.extend(session.handle(
            frame(
                IPCP,
                &Packet {
                    code: code::CONFIGURE_ACK,
                    id: again.id,
                    data: again.data,
                },
            ),
            *now,
        ));
        *now += 10;
        all.extend(session.handle(
            frame(
                IPCP,
                &Packet {
                    code: code::CONFIGURE_REQUEST,
                    id: 1,
                    data: ipcp::Ipcp::encode(&[ipcp::Opt::Address(ISP)]),
                },
            ),
            *now,
        ));
        let v6 = sent(pending, IPV6CP, code::CONFIGURE_REQUEST).expect("our IPV6CP request");
        *now += 10;
        all.extend(session.handle(
            frame(
                IPV6CP,
                &Packet {
                    code: code::CONFIGURE_ACK,
                    id: v6.id,
                    data: v6.data,
                },
            ),
            *now,
        ));
        *now += 10;
        all.extend(session.handle(
            frame(
                IPV6CP,
                &Packet {
                    code: code::CONFIGURE_REQUEST,
                    id: 1,
                    data: ipv6cp::Ipv6cp::encode(&[ipv6cp::Opt::InterfaceId(PEER_IID)]),
                },
            ),
            *now,
        ));
        all
    }

    /// A session with LCP, CHAP, IPCP and IPV6CP up, and the moment LCP came up.
    fn up() -> (Session, u64, u64) {
        let mut session = new_session();
        let mut now = 1_000;
        let out = establish(&mut session, Some(AuthProto::ChapMd5), &mut now);
        assert!(
            has(&out, |o| matches!(
                o,
                Output::LcpUp {
                    mru: 1492,
                    auth: Some(AuthProto::ChapMd5)
                }
            )),
            "{out:?}"
        );
        let lcp_up_at = now;
        let out = authenticate_chap(&mut session, &mut now);
        assert!(has(&out, |o| *o == Output::AuthOk("chap")), "{out:?}");
        assert_eq!(session.phase(), Phase::Network);
        let out = network(&mut session, &mut now, &out);
        assert!(
            has(
                &out,
                |o| matches!(o, Output::Ipv4Up(up) if up.local == OURS && up.peer == Some(ISP) && up.dns == vec![ISP])
            ),
            "{out:?}"
        );
        assert!(
            has(
                &out,
                |o| matches!(o, Output::Ipv6Up(up) if up.peer_iid == PEER_IID)
            ),
            "{out:?}"
        );
        (session, now, lcp_up_at)
    }

    #[test]
    fn a_full_session_comes_up_with_chap_ipcp_and_ipv6cp() {
        let mut session = new_session();
        assert_eq!(session.phase(), Phase::Dead);
        let mut now = 1_000;
        let out = establish(&mut session, Some(AuthProto::ChapMd5), &mut now);
        assert!(has(&out, |o| *o == Output::Mru(1492)), "{out:?}");
        assert_eq!(session.phase(), Phase::Authenticate);
        assert!(
            sent(&out, IPCP, code::CONFIGURE_REQUEST).is_none(),
            "no NCP before authentication"
        );
        let (session, _, _) = up();
        assert!(session.next_timeout().is_some(), "the keepalive is armed");
    }

    #[test]
    fn pap_is_used_when_the_ac_asks_for_it_and_no_auth_goes_straight_to_network() {
        let mut session = new_session();
        let mut now = 0;
        let out = establish(&mut session, Some(AuthProto::Pap), &mut now);
        let request = sent(&out, PAP, pap::REQUEST).expect("a PAP request");
        assert_eq!(
            pap::Message::decode(&request),
            Ok(pap::Message::Request {
                peer_id: b"openfeo@isp.example".to_vec(),
                password: b"example-secret".to_vec(),
            })
        );
        now += 10;
        let out = session.handle(
            frame(PAP, &pap::Message::Ack(Vec::new()).encode(request.id)),
            now,
        );
        assert!(has(&out, |o| *o == Output::AuthOk("pap")), "{out:?}");
        assert!(sent(&out, IPCP, code::CONFIGURE_REQUEST).is_some());
        assert!(sent(&out, IPV6CP, code::CONFIGURE_REQUEST).is_some());

        let mut session = new_session();
        let mut now = 0;
        let out = establish(&mut session, None, &mut now);
        assert_eq!(session.phase(), Phase::Network);
        assert!(
            sent(&out, IPCP, code::CONFIGURE_REQUEST).is_some(),
            "{out:?}"
        );
        assert!(!has(&out, |o| matches!(o, Output::AuthOk(_))));
    }

    #[test]
    fn an_auth_failure_ends_the_session_with_the_message_and_a_terminate() {
        let mut session = new_session();
        let mut now = 0;
        let out = establish(&mut session, Some(AuthProto::Pap), &mut now);
        let request = sent(&out, PAP, pap::REQUEST).unwrap();
        now += 10;
        let out = session.handle(
            frame(
                PAP,
                &pap::Message::Nak(b"Login incorrect".to_vec()).encode(request.id),
            ),
            now,
        );
        assert_eq!(
            down_reason(&out),
            Some(Reason::AuthFailed("Login incorrect".to_owned()))
        );
        assert!(
            sent(&out, LCP, code::TERMINATE_REQUEST).is_some(),
            "{out:?}"
        );
        assert_eq!(session.phase(), Phase::Dead);
    }

    #[test]
    fn a_rechallenge_in_network_phase_keeps_the_ncps_up() {
        let (mut session, mut now, _) = up();
        now += 100;
        let out = session.handle(
            frame(
                CHAP,
                &chap::Message::Challenge {
                    value: vec![0x24; 16],
                    name: b"isp".to_vec(),
                }
                .encode(2),
            ),
            now,
        );
        assert!(sent(&out, CHAP, chap::RESPONSE_CODE).is_some(), "{out:?}");
        assert!(!has(&out, |o| matches!(
            o,
            Output::Ipv4Down | Output::Ipv6Down | Output::Down { .. }
        )));
        assert_eq!(session.phase(), Phase::Network);
        now += 10;
        let out = session.handle(
            frame(CHAP, &chap::Message::Success(Vec::new()).encode(2)),
            now,
        );
        assert!(
            !has(&out, |o| matches!(o, Output::AuthOk(_))),
            "said once: {out:?}"
        );
    }

    #[test]
    fn one_ncp_may_fail_alone_and_both_failing_ends_the_link() {
        let mut session = new_session();
        let mut now = 0;
        let out = establish(&mut session, None, &mut now);
        let v6 = sent(&out, IPV6CP, code::CONFIGURE_REQUEST).unwrap();
        let mut current = sent(&out, IPCP, code::CONFIGURE_REQUEST);
        // IPV6CP Protocol-Rejected: IPv6 is off, the link stands.
        let mut data = IPV6CP.to_be_bytes().to_vec();
        data.extend(v6.encode());
        now += 10;
        let out = session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::PROTOCOL_REJECT,
                    id: 9,
                    data,
                },
            ),
            now,
        );
        assert!(down_reason(&out).is_none(), "{out:?}");
        assert_eq!(session.phase(), Phase::Network);
        // IPCP naked five times with 0.0.0.0: IPv4 fails too, and nothing is left.
        let mut last = Vec::new();
        for _ in 0..5 {
            let request = current.take().expect("an IPCP request to nak");
            now += 10;
            last = session.handle(
                frame(
                    IPCP,
                    &Packet {
                        code: code::CONFIGURE_NAK,
                        id: request.id,
                        data: ipcp::Ipcp::encode(&[ipcp::Opt::Address(Ipv4Addr::UNSPECIFIED)]),
                    },
                ),
                now,
            );
            current = sent(&last, IPCP, code::CONFIGURE_REQUEST);
        }
        assert_eq!(
            down_reason(&last),
            Some(Reason::NoNetworkProtocol),
            "{last:?}"
        );
        assert_eq!(session.phase(), Phase::Dead);
    }

    #[test]
    fn unknown_protocols_are_rejected_and_a_rejected_echo_stops_the_keepalive() {
        let (mut session, mut now, _) = up();
        now += 10;
        let out = session.handle(
            Input::Frame {
                protocol: 0x8099,
                payload: vec![1, 2, 3],
            },
            now,
        );
        let reject = sent(&out, LCP, code::PROTOCOL_REJECT).expect("a Protocol-Reject");
        assert_eq!(&reject.data[..2], &0x8099u16.to_be_bytes());
        assert_eq!(&reject.data[2..], &[1, 2, 3]);
        assert_eq!(session.phase(), Phase::Network);
        // The concentrator cannot echo: the keepalive stops, the link stays.
        now += 10;
        let out = session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::CODE_REJECT,
                    id: 3,
                    data: Packet {
                        code: code::ECHO_REQUEST,
                        id: 1,
                        data: vec![],
                    }
                    .encode(),
                },
            ),
            now,
        );
        assert!(down_reason(&out).is_none(), "{out:?}");
        let mut echoes = 0;
        for _ in 0..6 {
            now += ECHO_INTERVAL;
            let out = session.handle(Input::Timeout, now);
            echoes += sends(&out)
                .iter()
                .filter(|(p, packet)| *p == LCP && packet.code == code::ECHO_REQUEST)
                .count();
            assert!(down_reason(&out).is_none(), "{out:?}");
        }
        assert_eq!(echoes, 0, "no echo after the peer rejected the code");
        assert_eq!(session.phase(), Phase::Network);
    }

    #[test]
    fn three_missed_echoes_end_the_session_with_keepalive_lost() {
        let (mut session, mut now, lcp_up_at) = up();
        let mut echoes = Vec::new();
        let mut down = None;
        for _ in 0..5 {
            now += ECHO_INTERVAL;
            let out = session.handle(Input::Timeout, now);
            echoes.extend(
                sends(&out)
                    .into_iter()
                    .filter(|(p, packet)| *p == LCP && packet.code == code::ECHO_REQUEST),
            );
            if let Some(reason) = down_reason(&out) {
                down = Some((reason, out));
                break;
            }
        }
        assert_eq!(echoes.len(), 3, "three echoes went unanswered");
        let (reason, out) = down.expect("the session went down");
        assert_eq!(reason, Reason::KeepaliveLost);
        assert!(
            has(&out, |o| matches!(o, Output::Ipv4Down))
                && has(&out, |o| matches!(o, Output::Ipv6Down))
        );
        assert!(has(
            &out,
            |o| matches!(o, Output::Down { uptime_ms, .. } if *uptime_ms == now - lcp_up_at)
        ));
        assert_eq!(session.phase(), Phase::Dead);
        assert_eq!(session.next_timeout(), None);
    }

    #[test]
    fn an_answered_echo_keeps_the_session_up() {
        let (mut session, mut now, _) = up();
        for _ in 0..6 {
            now += ECHO_INTERVAL;
            let out = session.handle(Input::Timeout, now);
            let echo = sent(&out, LCP, code::ECHO_REQUEST).expect("an echo each interval");
            now += 5;
            let out = session.handle(
                frame(
                    LCP,
                    &Packet {
                        code: code::ECHO_REPLY,
                        id: echo.id,
                        data: 0x0bad_cafeu32.to_be_bytes().to_vec(),
                    },
                ),
                now,
            );
            assert!(down_reason(&out).is_none());
        }
        assert_eq!(session.phase(), Phase::Network);
        // The peer's echo request is answered too.
        let out = session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::ECHO_REQUEST,
                    id: 77,
                    data: 0x0bad_cafeu32.to_be_bytes().to_vec(),
                },
            ),
            now + 1,
        );
        assert_eq!(sent(&out, LCP, code::ECHO_REPLY).map(|p| p.id), Some(77));
    }

    #[test]
    fn a_terminate_request_from_the_peer_is_acked_and_the_session_is_down() {
        let (mut session, mut now, _) = up();
        now += 10;
        let out = session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::TERMINATE_REQUEST,
                    id: 5,
                    data: b"bye".to_vec(),
                },
            ),
            now,
        );
        assert_eq!(sent(&out, LCP, code::TERMINATE_ACK).map(|p| p.id), Some(5));
        assert_eq!(down_reason(&out), Some(Reason::TerminatedByPeer), "{out:?}");
        assert!(has(&out, |o| matches!(o, Output::Ipv4Down)));
        assert_eq!(session.phase(), Phase::Dead);
    }

    #[test]
    fn stop_sends_two_terminate_requests_then_down() {
        let (mut session, mut now, _) = up();
        now += 10;
        let out = session.handle(Input::Stop, now);
        assert!(
            sent(&out, LCP, code::TERMINATE_REQUEST).is_some(),
            "{out:?}"
        );
        assert!(
            has(&out, |o| matches!(o, Output::Ipv4Down)),
            "the networks go first: {out:?}"
        );
        assert_eq!(session.phase(), Phase::Terminate);
        assert!(
            down_reason(&out).is_none(),
            "not down until the peer answers or the timer runs out"
        );
        let due = session.next_timeout().expect("the restart timer");
        let out = session.handle(Input::Timeout, due);
        assert!(
            sent(&out, LCP, code::TERMINATE_REQUEST).is_some(),
            "the second: {out:?}"
        );
        let due = session.next_timeout().expect("the restart timer again");
        let out = session.handle(Input::Timeout, due);
        assert_eq!(down_reason(&out), Some(Reason::Stopped), "{out:?}");
        assert_eq!(session.phase(), Phase::Dead);
        // A Terminate-Ack ends it at once instead.
        let (mut session, mut now, _) = up();
        now += 10;
        let out = session.handle(Input::Stop, now);
        let request = sent(&out, LCP, code::TERMINATE_REQUEST).unwrap();
        let out = session.handle(
            frame(
                LCP,
                &Packet {
                    code: code::TERMINATE_ACK,
                    id: request.id,
                    data: vec![],
                },
            ),
            now + 5,
        );
        assert_eq!(down_reason(&out), Some(Reason::Stopped), "{out:?}");
    }

    #[test]
    fn carrier_lost_is_down_at_once_and_nothing_is_sent_after_down_until_start() {
        let (mut session, mut now, _) = up();
        now += 10;
        let out = session.handle(Input::CarrierLost, now);
        assert_eq!(down_reason(&out), Some(Reason::CarrierLost));
        assert!(sends(&out).is_empty(), "no frame onto a dead link: {out:?}");
        assert_eq!(session.phase(), Phase::Dead);
        for input in [
            Input::Timeout,
            frame(
                LCP,
                &Packet {
                    code: code::ECHO_REQUEST,
                    id: 1,
                    data: vec![0; 4],
                },
            ),
            Input::Stop,
        ] {
            now += 10;
            let out = session.handle(input, now);
            assert!(out.is_empty(), "dead is dead: {out:?}");
        }
        assert_eq!(session.next_timeout(), None);
        let out = session.handle(Input::Start, now + 10);
        assert!(
            sent(&out, LCP, code::CONFIGURE_REQUEST).is_some(),
            "started again"
        );
    }

    #[test]
    fn uptime_counts_from_lcp_up() {
        let (mut session, now, lcp_up_at) = up();
        let out = session.handle(Input::CarrierLost, now + 5_000);
        assert!(
            has(
                &out,
                |o| matches!(o, Output::Down { uptime_ms, .. } if *uptime_ms == now + 5_000 - lcp_up_at)
            ),
            "{out:?}"
        );
    }
}
