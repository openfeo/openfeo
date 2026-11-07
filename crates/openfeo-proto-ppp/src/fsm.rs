// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The option-negotiation automaton of RFC 1661 §4, once, generic over the options a control
//! protocol negotiates. LCP, IPCP and IPV6CP each give it their options and policy; it gives
//! them the state table, the restart timer and counters, and the packets to send.

use crate::frame::{Error, Packet, code};
use crate::{MS, Timestamp};

/// Configure-Requests sent before giving up (RFC 1661 §4.6).
pub const MAX_CONFIGURE: u32 = 10;
/// Terminate-Requests sent before giving up.
pub const MAX_TERMINATE: u32 = 2;
/// Configure-Naks sent, or received, before the negotiation is judged not to converge.
pub const MAX_FAILURE: u32 = 5;
/// The restart timer.
pub const RESTART_TIMER: Timestamp = 3 * MS;

/// What a protocol makes of the peer's Configure-Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgement<O> {
    /// Every option is acceptable as it stands.
    Ack,
    /// These options are acceptable with the values given here instead.
    Nak(Vec<O>),
    /// These options are not negotiable at all.
    Reject(Vec<O>),
}

/// The options a control protocol negotiates, and its policy about them.
pub trait Options: Clone {
    /// One option.
    type Opt: Clone + PartialEq + core::fmt::Debug;

    /// Decode an option list.
    ///
    /// # Errors
    ///
    /// The protocol's own [`Error`] for a malformed list.
    fn decode(data: &[u8]) -> Result<Vec<Self::Opt>, Error>;
    /// Encode an option list.
    fn encode(opts: &[Self::Opt]) -> Vec<u8>;
    /// Our Configure-Request, as things stand.
    fn ours(&self) -> Vec<Self::Opt>;
    /// Judge the peer's Configure-Request.
    fn judge(&mut self, theirs: &[Self::Opt]) -> Judgement<Self::Opt>;
    /// The peer Naked our request with these suggestions; take what we can. `false` gives up.
    fn naked(&mut self, suggested: &[Self::Opt]) -> bool;
    /// The peer Rejected these of ours; live without them. `false` gives up.
    fn rejected(&mut self, opts: &[Self::Opt]) -> bool;
}

/// What drives the automaton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The lower layer is up (the session exists; LCP is up, for an NCP).
    Up,
    /// The lower layer is down.
    Down,
    /// The administrator wants the layer up.
    Open,
    /// The administrator wants the layer down.
    Close,
    /// The timer of [`Fsm::next_timeout`] fired.
    Timeout,
    /// A packet of this protocol arrived.
    Receive(Packet),
}

/// What the automaton wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(Packet),
    ThisLayerUp,
    ThisLayerDown,
    ThisLayerStarted,
    ThisLayerFinished,
    /// A packet the automaton does not handle itself (echo, discard, a Code-Reject or
    /// Protocol-Reject that does not end the layer): the protocol's to act on.
    Unknown(Packet),
}

/// RFC 1661 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Initial,
    Starting,
    Closed,
    Stopped,
    Closing,
    Stopping,
    RequestSent,
    AckReceived,
    AckSent,
    Opened,
}

/// The automaton for one protocol.
#[derive(Debug, Clone)]
pub struct Fsm<O: Options> {
    options: O,
    state: State,
    /// The restart counter.
    restart: u32,
    timeout: Option<Timestamp>,
    /// The identifier of our outstanding Configure-Request.
    reqid: u8,
    /// The identifier of our last Terminate-Request or Code-Reject.
    otherid: u8,
    /// Configure-Naks we sent this negotiation; past [`MAX_FAILURE`] we Reject instead.
    nak_sent: u32,
    /// Configure-Naks we received this negotiation; at [`MAX_FAILURE`] we give up.
    nak_received: u32,
}

impl<O: Options> Fsm<O> {
    /// An automaton in `Initial`; `seed` picks the first identifier.
    #[must_use]
    pub fn new(options: O, seed: u64) -> Fsm<O> {
        Fsm {
            options,
            state: State::Initial,
            restart: 0,
            timeout: None,
            reqid: u8::try_from(seed & 0xff).unwrap_or(0),
            otherid: u8::try_from((seed >> 8) & 0xff).unwrap_or(0),
            nak_sent: 0,
            nak_received: 0,
        }
    }

    /// Feed one event at `now`.
    pub fn handle(&mut self, event: Event, now: Timestamp) -> Vec<Action> {
        let mut out = Vec::new();
        match event {
            Event::Up => self.up(now, &mut out),
            Event::Down => self.down(&mut out),
            Event::Open => self.open(now, &mut out),
            Event::Close => self.close(now, &mut out),
            Event::Timeout => {
                if self.timeout.is_some_and(|due| due <= now) {
                    self.expire(now, &mut out);
                }
            }
            Event::Receive(packet) => self.receive(packet, now, &mut out),
        }
        out
    }

    /// When to feed [`Event::Timeout`]; `None` while nothing is pending.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.timeout
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The protocol's options as negotiated so far.
    pub fn options(&self) -> &O {
        &self.options
    }

    // --- administrative events ----------------------------------------------------------------

    fn up(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Initial => self.state = State::Closed,
            State::Starting => {
                self.begin();
                self.irc(MAX_CONFIGURE);
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            _ => {}
        }
    }

    fn down(&mut self, out: &mut Vec<Action>) {
        self.timeout = None;
        self.state = match self.state {
            State::Closed | State::Closing => State::Initial,
            State::Stopped => {
                out.push(Action::ThisLayerStarted);
                State::Starting
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                State::Starting
            }
            State::Stopping | State::RequestSent | State::AckReceived | State::AckSent => {
                State::Starting
            }
            State::Initial | State::Starting => self.state,
        };
    }

    fn open(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Initial => {
                out.push(Action::ThisLayerStarted);
                self.state = State::Starting;
            }
            State::Closed | State::Stopped => {
                self.begin();
                self.irc(MAX_CONFIGURE);
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            State::Closing => self.state = State::Stopping,
            _ => {}
        }
    }

    fn close(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Starting => {
                self.tlf(out);
                self.state = State::Initial;
            }
            State::Stopped => self.state = State::Closed,
            State::Stopping => self.state = State::Closing,
            State::RequestSent | State::AckReceived | State::AckSent => {
                self.irc(MAX_TERMINATE);
                self.str_(now, out);
                self.state = State::Closing;
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.irc(MAX_TERMINATE);
                self.str_(now, out);
                self.state = State::Closing;
            }
            State::Initial | State::Closed | State::Closing => {}
        }
    }

    fn expire(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        if self.restart > 0 {
            match self.state {
                State::Closing | State::Stopping => self.str_(now, out),
                State::RequestSent | State::AckReceived => {
                    self.scr(false, now, out);
                    self.state = State::RequestSent;
                }
                State::AckSent => self.scr(false, now, out),
                _ => self.timeout = None,
            }
        } else {
            match self.state {
                State::Closing => {
                    self.tlf(out);
                    self.state = State::Closed;
                }
                State::Stopping | State::RequestSent | State::AckReceived | State::AckSent => {
                    self.tlf(out);
                    self.state = State::Stopped;
                }
                _ => self.timeout = None,
            }
        }
    }

    // --- packets ------------------------------------------------------------------------------

    fn receive(&mut self, packet: Packet, now: Timestamp, out: &mut Vec<Action>) {
        if matches!(self.state, State::Initial | State::Starting) {
            return;
        }
        match packet.code {
            code::CONFIGURE_REQUEST => self.configure_request(&packet, now, out),
            code::CONFIGURE_ACK => {
                if packet.id == self.reqid {
                    self.configure_ack(now, out);
                }
            }
            code::CONFIGURE_NAK | code::CONFIGURE_REJECT => {
                if packet.id == self.reqid {
                    self.configure_nak_or_reject(&packet, now, out);
                }
            }
            code::TERMINATE_REQUEST => self.terminate_request(packet.id, now, out),
            code::TERMINATE_ACK => self.terminate_ack(now, out),
            code::CODE_REJECT => {
                let rejected = packet.data.first().copied().unwrap_or(0);
                if (code::CONFIGURE_REQUEST..=code::TERMINATE_ACK).contains(&rejected) {
                    self.catastrophic(now, out);
                } else {
                    out.push(Action::Unknown(packet));
                }
            }
            code::PROTOCOL_REJECT => out.push(Action::Unknown(packet)),
            code::ECHO_REQUEST | code::ECHO_REPLY | code::DISCARD_REQUEST => {
                if self.state == State::Opened {
                    out.push(Action::Unknown(packet));
                }
            }
            _ => self.scj(&packet, out),
        }
    }

    fn configure_request(&mut self, packet: &Packet, now: Timestamp, out: &mut Vec<Action>) {
        let Ok(theirs) = O::decode(&packet.data) else {
            return;
        };
        let judgement = self.options.judge(&theirs);
        let good = matches!(judgement, Judgement::Ack);
        match self.state {
            State::Closed => Self::sta(packet.id, out),
            State::Stopped => {
                self.begin();
                self.irc(MAX_CONFIGURE);
                self.scr(true, now, out);
                self.answer(packet, judgement, out);
                self.state = if good {
                    State::AckSent
                } else {
                    State::RequestSent
                };
            }
            State::RequestSent => {
                self.answer(packet, judgement, out);
                if good {
                    self.state = State::AckSent;
                }
            }
            State::AckReceived => {
                self.answer(packet, judgement, out);
                if good {
                    self.tlu(out);
                }
            }
            State::AckSent => {
                self.answer(packet, judgement, out);
                if !good {
                    self.state = State::RequestSent;
                }
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.scr(true, now, out);
                self.answer(packet, judgement, out);
                self.state = if good {
                    State::AckSent
                } else {
                    State::RequestSent
                };
            }
            State::Closing | State::Stopping | State::Initial | State::Starting => {}
        }
    }

    fn configure_ack(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Closed | State::Stopped => Self::sta(self.reqid, out),
            State::RequestSent => {
                self.irc(MAX_CONFIGURE);
                self.state = State::AckReceived;
            }
            State::AckReceived => {
                self.scr(false, now, out);
                self.state = State::RequestSent;
            }
            State::AckSent => {
                self.irc(MAX_CONFIGURE);
                self.tlu(out);
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            State::Closing | State::Stopping | State::Initial | State::Starting => {}
        }
    }

    fn configure_nak_or_reject(&mut self, packet: &Packet, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Closed | State::Stopped => {
                Self::sta(packet.id, out);
                return;
            }
            State::Closing | State::Stopping | State::Initial | State::Starting => return,
            _ => {}
        }
        let Ok(theirs) = O::decode(&packet.data) else {
            return;
        };
        let keep_going = if packet.code == code::CONFIGURE_NAK {
            self.nak_received += 1;
            self.nak_received < MAX_FAILURE && self.options.naked(&theirs)
        } else {
            self.options.rejected(&theirs)
        };
        if !keep_going {
            self.catastrophic(now, out);
            return;
        }
        match self.state {
            State::RequestSent | State::AckSent => {
                self.irc(MAX_CONFIGURE);
                self.scr(true, now, out);
            }
            State::AckReceived => {
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            _ => {}
        }
    }

    fn terminate_request(&mut self, id: u8, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Closed | State::Stopped | State::Closing | State::Stopping => Self::sta(id, out),
            State::RequestSent | State::AckReceived | State::AckSent => {
                Self::sta(id, out);
                self.state = State::RequestSent;
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.restart = 0;
                self.timeout = Some(now.saturating_add(RESTART_TIMER));
                Self::sta(id, out);
                self.state = State::Stopping;
            }
            State::Initial | State::Starting => {}
        }
    }

    fn terminate_ack(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Closing => {
                self.tlf(out);
                self.state = State::Closed;
            }
            State::Stopping => {
                self.tlf(out);
                self.state = State::Stopped;
            }
            State::AckReceived => self.state = State::RequestSent,
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.scr(true, now, out);
                self.state = State::RequestSent;
            }
            _ => {}
        }
    }

    /// RXJ−: a rejection the layer cannot live with (RFC 1661 §4.4).
    fn catastrophic(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        match self.state {
            State::Closed | State::Stopped => self.tlf(out),
            State::Closing => {
                self.tlf(out);
                self.state = State::Closed;
            }
            State::Stopping | State::RequestSent | State::AckReceived | State::AckSent => {
                self.tlf(out);
                self.state = State::Stopped;
            }
            State::Opened => {
                out.push(Action::ThisLayerDown);
                self.irc(MAX_TERMINATE);
                self.str_(now, out);
                self.state = State::Stopping;
            }
            State::Initial | State::Starting => {}
        }
    }

    // --- actions ------------------------------------------------------------------------------

    fn irc(&mut self, count: u32) {
        self.restart = count;
    }

    /// A negotiation begins: the Nak counters start over.
    fn begin(&mut self) {
        self.nak_sent = 0;
        self.nak_received = 0;
    }

    fn tlu(&mut self, out: &mut Vec<Action>) {
        self.state = State::Opened;
        self.timeout = None;
        self.begin();
        out.push(Action::ThisLayerUp);
    }

    fn tlf(&mut self, out: &mut Vec<Action>) {
        self.timeout = None;
        out.push(Action::ThisLayerFinished);
    }

    /// Send a Configure-Request: a new identifier for a new request, the same for a
    /// retransmission; the counter goes down and the timer is armed.
    fn scr(&mut self, fresh: bool, now: Timestamp, out: &mut Vec<Action>) {
        if fresh {
            self.reqid = self.reqid.wrapping_add(1);
        }
        out.push(Action::Send(Packet {
            code: code::CONFIGURE_REQUEST,
            id: self.reqid,
            data: O::encode(&self.options.ours()),
        }));
        self.restart = self.restart.saturating_sub(1);
        self.timeout = Some(now.saturating_add(RESTART_TIMER));
    }

    fn str_(&mut self, now: Timestamp, out: &mut Vec<Action>) {
        self.otherid = self.otherid.wrapping_add(1);
        out.push(Action::Send(Packet {
            code: code::TERMINATE_REQUEST,
            id: self.otherid,
            data: Vec::new(),
        }));
        self.restart = self.restart.saturating_sub(1);
        self.timeout = Some(now.saturating_add(RESTART_TIMER));
    }

    fn sta(id: u8, out: &mut Vec<Action>) {
        out.push(Action::Send(Packet {
            code: code::TERMINATE_ACK,
            id,
            data: Vec::new(),
        }));
    }

    /// Ack, Nak or Reject the peer's request; past `MAX_FAILURE` Naks, a Nak becomes a Reject.
    fn answer(&mut self, request: &Packet, judgement: Judgement<O::Opt>, out: &mut Vec<Action>) {
        let (code, data) = match judgement {
            Judgement::Ack => (code::CONFIGURE_ACK, request.data.clone()),
            Judgement::Nak(opts) => {
                self.nak_sent += 1;
                if self.nak_sent > MAX_FAILURE {
                    (code::CONFIGURE_REJECT, O::encode(&opts))
                } else {
                    (code::CONFIGURE_NAK, O::encode(&opts))
                }
            }
            Judgement::Reject(opts) => (code::CONFIGURE_REJECT, O::encode(&opts)),
        };
        out.push(Action::Send(Packet {
            code,
            id: request.id,
            data,
        }));
    }

    fn scj(&mut self, packet: &Packet, out: &mut Vec<Action>) {
        self.otherid = self.otherid.wrapping_add(1);
        out.push(Action::Send(Packet {
            code: code::CODE_REJECT,
            id: self.otherid,
            data: packet.encode(),
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Packet, code, options, put_option};

    /// One u32 option (type 1); the peer's value is fine up to 100, anything above is naked to
    /// 100; an unknown type is rejected; a Nak of ours is taken; a Reject of ours is fatal.
    #[derive(Debug, Clone, PartialEq)]
    struct Toy {
        value: u32,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum ToyOpt {
        Value(u32),
        Other(u8, Vec<u8>),
    }

    impl Options for Toy {
        type Opt = ToyOpt;

        fn decode(data: &[u8]) -> Result<Vec<ToyOpt>, Error> {
            options(data)?
                .into_iter()
                .map(|(kind, data)| match (kind, data) {
                    (1, [a, b, c, d]) => Ok(ToyOpt::Value(u32::from_be_bytes([*a, *b, *c, *d]))),
                    (1, _) => Err(Error::Option { kind: 1 }),
                    (kind, data) => Ok(ToyOpt::Other(kind, data.to_vec())),
                })
                .collect()
        }

        fn encode(opts: &[ToyOpt]) -> Vec<u8> {
            let mut out = Vec::new();
            for opt in opts {
                match opt {
                    ToyOpt::Value(v) => put_option(&mut out, 1, &v.to_be_bytes()),
                    ToyOpt::Other(kind, data) => put_option(&mut out, *kind, data),
                }
            }
            out
        }

        fn ours(&self) -> Vec<ToyOpt> {
            vec![ToyOpt::Value(self.value)]
        }

        fn judge(&mut self, theirs: &[ToyOpt]) -> Judgement<ToyOpt> {
            let rejects: Vec<ToyOpt> = theirs
                .iter()
                .filter(|opt| matches!(opt, ToyOpt::Other(..)))
                .cloned()
                .collect();
            if !rejects.is_empty() {
                return Judgement::Reject(rejects);
            }
            let naks: Vec<ToyOpt> = theirs
                .iter()
                .filter(|opt| matches!(opt, ToyOpt::Value(v) if *v > 100))
                .map(|_| ToyOpt::Value(100))
                .collect();
            if naks.is_empty() {
                Judgement::Ack
            } else {
                Judgement::Nak(naks)
            }
        }

        fn naked(&mut self, suggested: &[ToyOpt]) -> bool {
            for opt in suggested {
                if let ToyOpt::Value(v) = opt {
                    self.value = *v;
                }
            }
            true
        }

        fn rejected(&mut self, _opts: &[ToyOpt]) -> bool {
            false
        }
    }

    fn fsm() -> Fsm<Toy> {
        Fsm::new(Toy { value: 1500 }, 7)
    }

    fn sent(actions: &[Action]) -> Vec<&Packet> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Send(packet) => Some(packet),
                _ => None,
            })
            .collect()
    }

    fn packet(code: u8, id: u8, opts: &[ToyOpt]) -> Packet {
        Packet {
            code,
            id,
            data: Toy::encode(opts),
        }
    }

    /// Open, Up, the peer's request acked, our request acked: Opened.
    fn opened() -> (Fsm<Toy>, u8) {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let actions = fsm.handle(Event::Up, 0);
        let our_id = sent(&actions)[0].id;
        fsm.handle(
            Event::Receive(packet(code::CONFIGURE_REQUEST, 3, &[ToyOpt::Value(5)])),
            10,
        );
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_ACK, our_id, &[ToyOpt::Value(1500)])),
            20,
        );
        assert!(actions.contains(&Action::ThisLayerUp), "{actions:?}");
        assert_eq!(fsm.state(), State::Opened);
        (fsm, our_id)
    }

    #[test]
    fn open_then_up_sends_a_configure_request_and_acks_the_peers() {
        let mut fsm = fsm();
        assert_eq!(fsm.state(), State::Initial);
        let actions = fsm.handle(Event::Open, 0);
        assert_eq!(actions, vec![Action::ThisLayerStarted]);
        assert_eq!(fsm.state(), State::Starting);
        let actions = fsm.handle(Event::Up, 0);
        let request = sent(&actions)[0];
        assert_eq!(request.code, code::CONFIGURE_REQUEST);
        assert_eq!(
            Toy::decode(&request.data).unwrap(),
            vec![ToyOpt::Value(1500)]
        );
        assert_eq!(fsm.state(), State::RequestSent);
        assert_eq!(fsm.next_timeout(), Some(RESTART_TIMER));
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_REQUEST, 3, &[ToyOpt::Value(5)])),
            10,
        );
        let ack = sent(&actions)[0];
        assert_eq!((ack.code, ack.id), (code::CONFIGURE_ACK, 3));
        assert_eq!(Toy::decode(&ack.data).unwrap(), vec![ToyOpt::Value(5)]);
        assert_eq!(fsm.state(), State::AckSent);
    }

    #[test]
    fn both_acks_open_the_layer() {
        let (fsm, _) = opened();
        assert_eq!(fsm.next_timeout(), None, "no timer while Opened");
    }

    #[test]
    fn a_nak_is_applied_and_a_new_request_sent_with_a_new_id() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let actions = fsm.handle(Event::Up, 0);
        let first = sent(&actions)[0].id;
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_NAK, first, &[ToyOpt::Value(100)])),
            10,
        );
        let again = sent(&actions)[0];
        assert_eq!(again.code, code::CONFIGURE_REQUEST);
        assert_ne!(again.id, first, "a new request has a new identifier");
        assert_eq!(Toy::decode(&again.data).unwrap(), vec![ToyOpt::Value(100)]);
        assert_eq!(fsm.options().value, 100);
    }

    #[test]
    fn max_failure_naks_give_up_with_this_layer_finished() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let mut actions = fsm.handle(Event::Up, 0);
        for round in 0..MAX_FAILURE {
            let id = sent(&actions)[0].id;
            actions = fsm.handle(
                Event::Receive(packet(
                    code::CONFIGURE_NAK,
                    id,
                    &[ToyOpt::Value(100 + round)],
                )),
                u64::from(round) * 10,
            );
        }
        assert!(
            actions.contains(&Action::ThisLayerFinished),
            "after {MAX_FAILURE} naks: {actions:?}"
        );
        assert_eq!(fsm.state(), State::Stopped);
        assert!(
            sent(&actions).is_empty(),
            "nothing more is asked: {actions:?}"
        );
    }

    #[test]
    fn a_reject_of_our_only_option_is_fatal() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let actions = fsm.handle(Event::Up, 0);
        let id = sent(&actions)[0].id;
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_REJECT, id, &[ToyOpt::Value(1500)])),
            10,
        );
        assert!(actions.contains(&Action::ThisLayerFinished), "{actions:?}");
        assert_eq!(fsm.state(), State::Stopped);
    }

    #[test]
    fn the_peers_unknown_option_is_rejected_and_its_oversize_value_naked() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        fsm.handle(Event::Up, 0);
        let actions = fsm.handle(
            Event::Receive(packet(
                code::CONFIGURE_REQUEST,
                4,
                &[ToyOpt::Value(5), ToyOpt::Other(9, vec![1])],
            )),
            10,
        );
        let reply = sent(&actions)[0];
        assert_eq!((reply.code, reply.id), (code::CONFIGURE_REJECT, 4));
        assert_eq!(
            Toy::decode(&reply.data).unwrap(),
            vec![ToyOpt::Other(9, vec![1])]
        );
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_REQUEST, 5, &[ToyOpt::Value(500)])),
            11,
        );
        let reply = sent(&actions)[0];
        assert_eq!((reply.code, reply.id), (code::CONFIGURE_NAK, 5));
        assert_eq!(Toy::decode(&reply.data).unwrap(), vec![ToyOpt::Value(100)]);
        assert_eq!(fsm.state(), State::RequestSent);
    }

    #[test]
    fn terminate_request_from_the_peer_is_acked_and_the_layer_goes_down() {
        let (mut fsm, _) = opened();
        let actions = fsm.handle(Event::Receive(packet(code::TERMINATE_REQUEST, 9, &[])), 100);
        let ack = sent(&actions)[0];
        assert_eq!((ack.code, ack.id), (code::TERMINATE_ACK, 9));
        assert!(actions.contains(&Action::ThisLayerDown), "{actions:?}");
        assert_eq!(fsm.state(), State::Stopping);
        let due = fsm
            .next_timeout()
            .expect("the zero restart counter's timer");
        let actions = fsm.handle(Event::Timeout, due);
        assert!(actions.contains(&Action::ThisLayerFinished), "{actions:?}");
        assert_eq!(fsm.state(), State::Stopped);
    }

    #[test]
    fn close_sends_two_terminate_requests_then_finishes() {
        let (mut fsm, _) = opened();
        let actions = fsm.handle(Event::Close, 100);
        assert!(actions.contains(&Action::ThisLayerDown));
        assert_eq!(sent(&actions)[0].code, code::TERMINATE_REQUEST);
        assert_eq!(fsm.state(), State::Closing);
        let actions = fsm.handle(Event::Timeout, 100 + RESTART_TIMER);
        assert_eq!(sent(&actions)[0].code, code::TERMINATE_REQUEST);
        let actions = fsm.handle(Event::Timeout, 100 + 2 * RESTART_TIMER);
        assert!(sent(&actions).is_empty(), "{actions:?}");
        assert!(actions.contains(&Action::ThisLayerFinished));
        assert_eq!(fsm.state(), State::Closed);
        assert_eq!(fsm.next_timeout(), None);
    }

    #[test]
    fn an_old_identifier_is_ignored() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let actions = fsm.handle(Event::Up, 0);
        let id = sent(&actions)[0].id;
        let actions = fsm.handle(
            Event::Receive(packet(code::CONFIGURE_ACK, id.wrapping_add(9), &[])),
            10,
        );
        assert!(actions.is_empty(), "{actions:?}");
        assert_eq!(fsm.state(), State::RequestSent);
    }

    #[test]
    fn restart_timer_retransmits_up_to_max_configure() {
        let mut fsm = fsm();
        fsm.handle(Event::Open, 0);
        let actions = fsm.handle(Event::Up, 0);
        let id = sent(&actions)[0].id;
        let mut now = 0;
        for _ in 1..MAX_CONFIGURE {
            now += RESTART_TIMER;
            assert_eq!(fsm.next_timeout(), Some(now));
            let actions = fsm.handle(Event::Timeout, now);
            let again = sent(&actions)[0];
            assert_eq!((again.code, again.id), (code::CONFIGURE_REQUEST, id));
        }
        now += RESTART_TIMER;
        let actions = fsm.handle(Event::Timeout, now);
        assert!(sent(&actions).is_empty(), "{actions:?}");
        assert!(actions.contains(&Action::ThisLayerFinished));
        assert_eq!(fsm.state(), State::Stopped);
    }

    #[test]
    fn an_unknown_code_is_code_rejected_and_echoes_reach_the_protocol() {
        let (mut fsm, _) = opened();
        let odd = Packet {
            code: 42,
            id: 1,
            data: vec![9],
        };
        let actions = fsm.handle(Event::Receive(odd.clone()), 100);
        let reject = sent(&actions)[0];
        assert_eq!(reject.code, code::CODE_REJECT);
        assert_eq!(reject.data, odd.encode());
        assert_eq!(fsm.state(), State::Opened);
        let echo = Packet {
            code: code::ECHO_REQUEST,
            id: 2,
            data: vec![0, 0, 0, 0],
        };
        let actions = fsm.handle(Event::Receive(echo.clone()), 101);
        assert_eq!(actions, vec![Action::Unknown(echo)]);
    }

    #[test]
    fn a_code_reject_of_a_needed_code_closes_and_of_an_echo_is_surfaced() {
        let (mut fsm, _) = opened();
        let rejected_echo = Packet {
            code: code::CODE_REJECT,
            id: 1,
            data: Packet {
                code: code::ECHO_REQUEST,
                id: 5,
                data: vec![],
            }
            .encode(),
        };
        let actions = fsm.handle(Event::Receive(rejected_echo.clone()), 100);
        assert_eq!(actions, vec![Action::Unknown(rejected_echo)]);
        assert_eq!(fsm.state(), State::Opened);
        let rejected_request = Packet {
            code: code::CODE_REJECT,
            id: 2,
            data: Packet {
                code: code::CONFIGURE_REQUEST,
                id: 1,
                data: vec![],
            }
            .encode(),
        };
        let actions = fsm.handle(Event::Receive(rejected_request), 101);
        assert!(actions.contains(&Action::ThisLayerDown), "{actions:?}");
        assert_eq!(sent(&actions)[0].code, code::TERMINATE_REQUEST);
        assert_eq!(fsm.state(), State::Stopping);
    }
}
