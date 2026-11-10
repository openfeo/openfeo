// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The WebSocket envelope (SPEC §8.3) as a core with no I/O: frames in, messages out. The
//! first frame must authenticate; after that a connection asks things (the driver performs
//! each request, since one may hash a password, and hands the answer back) and subscribes to
//! topics. `state` and `counters` are coalesced: at most one unsent push of each is held, and
//! a newer one replaces it, so a slow reader only ever gets the latest. Events are queued, 256
//! deep; a reader that falls further behind loses the oldest and is told so once.

use std::collections::{BTreeSet, VecDeque};

use openfeo_config::api::{
    ClientMsg, Error, ErrorCode, Request, Response, ServerMsg, Telemetry, client_msg, server_msg,
    telemetry,
};
use openfeo_config::events::Event;
use openfeo_config::state::{Counters, State};
use prost::Message as _;

use crate::limits::{EVENT_BACKLOG, EVENT_QUEUE, MAX_FRAME, MAX_SUBSCRIPTIONS};

/// Close code: no authentication, a bad token, or a session that ended.
pub const CLOSE_UNAUTHENTICATED: u16 = 4401;
/// Close code: a frame larger than [`MAX_FRAME`].
pub const CLOSE_TOO_BIG: u16 = 1009;
/// Close code: a text frame; the envelope is binary.
pub const CLOSE_NOT_BINARY: u16 = 1003;

/// The two things a connection needs answered at once.
pub trait Backend {
    /// Whether `token` names a live session.
    fn authenticate(&mut self, token: &str) -> bool;
    /// The last `n` events, oldest first.
    fn backlog(&mut self, n: u32) -> Vec<Event>;
}

/// What the driver must do next. One or two exist per frame and each is consumed at once, so
/// the message is held inline.
#[derive(Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Out {
    /// Send this message.
    Send(ServerMsg),
    /// Perform this request and hand the result to [`Conn::reply`] under the same id.
    Ask {
        /// The frame's id.
        id: u32,
        /// What was asked.
        request: Request,
    },
    /// Close the socket with this code, after sending what precedes it.
    Close(u16),
}

/// What a connection may subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Topic {
    /// The whole `State`, now and after every change; coalesced.
    State,
    /// `Counters` once a second; coalesced.
    Counters,
    /// Events as they happen; queued.
    Events,
}

impl Topic {
    /// The topic a name means.
    #[must_use]
    pub fn parse(name: &str) -> Option<Topic> {
        match name {
            "state" => Some(Topic::State),
            "counters" => Some(Topic::Counters),
            "events" => Some(Topic::Events),
            _ => None,
        }
    }

    /// The topic's name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Topic::State => "state",
            Topic::Counters => "counters",
            Topic::Events => "events",
        }
    }
}

/// One connection's side of the envelope.
#[derive(Debug, Default)]
pub struct Conn {
    authenticated: bool,
    closed: bool,
    topics: BTreeSet<Topic>,
    replies: VecDeque<ServerMsg>,
    state: Option<State>,
    counters: Option<Counters>,
    events: VecDeque<Event>,
    lost: bool,
}

fn error(id: u32, code: ErrorCode, message: &str) -> ServerMsg {
    ServerMsg {
        id,
        body: Some(server_msg::Body::Error(Error {
            code: code.into(),
            message: message.to_owned(),
            retry_after_secs: 0,
        })),
    }
}

fn ack(id: u32) -> ServerMsg {
    ServerMsg {
        id,
        body: Some(server_msg::Body::Response(Response { body: None })),
    }
}

impl Conn {
    /// A connection that has not authenticated.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the first frame carried a good token.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Whether the connection subscribed to `topic`.
    #[must_use]
    pub fn wants(&self, topic: Topic) -> bool {
        self.topics.contains(&topic)
    }

    fn close(&mut self, code: u16) -> Out {
        self.closed = true;
        Out::Close(code)
    }

    /// A binary frame arrived.
    pub fn on_binary(&mut self, frame: &[u8], backend: &mut dyn Backend) -> Vec<Out> {
        if self.closed {
            return Vec::new();
        }
        if frame.len() > MAX_FRAME {
            return vec![self.close(CLOSE_TOO_BIG)];
        }
        let message = ClientMsg::decode(frame).ok();
        if !self.authenticated {
            return match message {
                Some(ClientMsg {
                    id,
                    body: Some(client_msg::Body::Auth(auth)),
                }) if backend.authenticate(&auth.token) => {
                    self.authenticated = true;
                    vec![Out::Send(ack(id))]
                }
                other => vec![
                    Out::Send(error(
                        other.map_or(0, |message| message.id),
                        ErrorCode::Unauthenticated,
                        "the first frame must be Auth with a live token",
                    )),
                    self.close(CLOSE_UNAUTHENTICATED),
                ],
            };
        }
        let Some(ClientMsg {
            id,
            body: Some(body),
        }) = message
        else {
            return vec![Out::Send(error(
                0,
                ErrorCode::InvalidArgument,
                "not a ClientMsg with a body",
            ))];
        };
        match body {
            // Authenticating again changes nothing.
            client_msg::Body::Auth(_) => vec![Out::Send(ack(id))],
            client_msg::Body::Subscribe(subscribe) => {
                let Some(topic) = Topic::parse(&subscribe.topic) else {
                    return vec![Out::Send(error(id, ErrorCode::NotFound, "no such topic"))];
                };
                if !self.topics.contains(&topic) && self.topics.len() >= MAX_SUBSCRIPTIONS {
                    return vec![Out::Send(error(
                        id,
                        ErrorCode::ResourceExhausted,
                        "too many subscriptions",
                    ))];
                }
                self.topics.insert(topic);
                if topic == Topic::Events && subscribe.backlog > 0 {
                    let wanted = subscribe
                        .backlog
                        .min(u32::try_from(EVENT_BACKLOG).unwrap_or(u32::MAX));
                    for event in backend.backlog(wanted) {
                        self.queue_event(event);
                    }
                }
                vec![Out::Send(ack(id))]
            }
            client_msg::Body::Unsubscribe(unsubscribe) => {
                let Some(topic) = Topic::parse(&unsubscribe.topic) else {
                    return vec![Out::Send(error(id, ErrorCode::NotFound, "no such topic"))];
                };
                self.topics.remove(&topic);
                match topic {
                    Topic::State => self.state = None,
                    Topic::Counters => self.counters = None,
                    Topic::Events => {
                        self.events.clear();
                        self.lost = false;
                    }
                }
                vec![Out::Send(ack(id))]
            }
            client_msg::Body::Request(request) if request.body.is_some() => {
                vec![Out::Ask { id, request }]
            }
            client_msg::Body::Request(_) => vec![Out::Send(error(
                id,
                ErrorCode::InvalidArgument,
                "a Request with no body",
            ))],
        }
    }

    /// A text frame arrived: the envelope is binary.
    pub fn on_text(&mut self) -> Vec<Out> {
        if self.closed {
            return Vec::new();
        }
        vec![self.close(CLOSE_NOT_BINARY)]
    }

    /// The time allowed for the first frame ran out.
    pub fn on_auth_deadline(&mut self) -> Vec<Out> {
        if self.authenticated || self.closed {
            return Vec::new();
        }
        vec![self.close(CLOSE_UNAUTHENTICATED)]
    }

    /// The answer to an [`Out::Ask`], queued ahead of any push.
    pub fn reply(&mut self, id: u32, result: Result<Response, Error>) {
        self.replies.push_back(ServerMsg {
            id,
            body: Some(match result {
                Ok(response) => server_msg::Body::Response(response),
                Err(error) => server_msg::Body::Error(error),
            }),
        });
    }

    /// The latest `State`; replaces one not yet sent. Dropped unless subscribed.
    pub fn push_state(&mut self, state: &State) {
        if self.wants(Topic::State) {
            self.state = Some(state.clone());
        }
    }

    /// The latest `Counters`; replaces one not yet sent. Dropped unless subscribed.
    pub fn push_counters(&mut self, counters: &Counters) {
        if self.wants(Topic::Counters) {
            self.counters = Some(counters.clone());
        }
    }

    /// An event; queued. Dropped unless subscribed.
    pub fn push_event(&mut self, event: &Event) {
        if self.wants(Topic::Events) {
            self.queue_event(event.clone());
        }
    }

    fn queue_event(&mut self, event: Event) {
        if self.events.len() >= EVENT_QUEUE {
            self.events.pop_front();
            self.lost = true;
        }
        self.events.push_back(event);
    }

    /// What the writer sends next: replies first, then word of lost events, then the latest
    /// state and counters, then events in order.
    pub fn next_out(&mut self) -> Option<ServerMsg> {
        if self.closed {
            return None;
        }
        if let Some(reply) = self.replies.pop_front() {
            return Some(reply);
        }
        if self.lost {
            self.lost = false;
            return Some(error(
                0,
                ErrorCode::DataLoss,
                "events were dropped: this reader fell behind",
            ));
        }
        let telemetry = |topic: Topic, body: telemetry::Body| ServerMsg {
            id: 0,
            body: Some(server_msg::Body::Telemetry(Telemetry {
                topic: topic.as_str().to_owned(),
                body: Some(body),
            })),
        };
        if let Some(state) = self.state.take() {
            return Some(telemetry(Topic::State, telemetry::Body::State(state)));
        }
        if let Some(counters) = self.counters.take() {
            return Some(telemetry(
                Topic::Counters,
                telemetry::Body::Counters(counters),
            ));
        }
        self.events.pop_front().map(|event| ServerMsg {
            id: 0,
            body: Some(server_msg::Body::Event(event)),
        })
    }
}

#[cfg(test)]
mod tests {
    use openfeo_config::api::{
        Auth, GetStateRequest, GetStateResponse, Subscribe, Unsubscribe, request, response,
    };

    use super::*;
    use client_msg::Body;

    struct Fake;

    impl Backend for Fake {
        fn authenticate(&mut self, token: &str) -> bool {
            token == "good"
        }

        fn backlog(&mut self, n: u32) -> Vec<Event> {
            let all = [event(1_000), event(1_001), event(1_002)];
            let skip = all.len().saturating_sub(n as usize);
            all[skip..].to_vec()
        }
    }

    fn encode(message: &ClientMsg) -> Vec<u8> {
        message.encode_to_vec()
    }

    fn client(id: u32, body: Body) -> ClientMsg {
        ClientMsg {
            id,
            body: Some(body),
        }
    }

    fn get_state() -> Request {
        Request {
            body: Some(request::Body::GetState(GetStateRequest {})),
        }
    }

    fn state_response() -> Response {
        Response {
            body: Some(response::Body::GetState(GetStateResponse {
                state: Some(State::default()),
            })),
        }
    }

    fn subscribe(topic: &str, backlog: u32) -> Body {
        Body::Subscribe(Subscribe {
            topic: topic.into(),
            backlog,
        })
    }

    fn event(n: u64) -> Event {
        Event {
            uptime_ms: n,
            topic: "health.ok".into(),
            ..Event::default()
        }
    }

    fn error_code_of(message: &ServerMsg) -> Option<ErrorCode> {
        match &message.body {
            Some(server_msg::Body::Error(error)) => Some(error.code()),
            _ => None,
        }
    }

    fn event_number(message: &ServerMsg) -> Option<u64> {
        match &message.body {
            Some(server_msg::Body::Event(event)) => Some(event.uptime_ms),
            _ => None,
        }
    }

    fn pushed_generation(message: &ServerMsg) -> Option<u64> {
        match &message.body {
            Some(server_msg::Body::Telemetry(Telemetry {
                body: Some(telemetry::Body::State(state)),
                ..
            })) => Some(state.generation),
            _ => None,
        }
    }

    fn authed() -> Conn {
        let mut conn = Conn::new();
        let out = conn.on_binary(
            &encode(&client(
                1,
                Body::Auth(Auth {
                    token: "good".into(),
                }),
            )),
            &mut Fake,
        );
        assert_eq!(out, [Out::Send(ack(1))]);
        assert!(conn.authenticated());
        conn
    }

    fn drain(conn: &mut Conn) -> Vec<ServerMsg> {
        std::iter::from_fn(|| conn.next_out()).collect()
    }

    #[test]
    fn the_first_frame_must_be_auth_and_a_bad_token_closes_with_4401() {
        let mut conn = Conn::new();
        let out = conn.on_binary(&encode(&client(1, Body::Request(get_state()))), &mut Fake);
        assert!(matches!(
            &out[..],
            [Out::Send(message), Out::Close(4401)]
                if error_code_of(message) == Some(ErrorCode::Unauthenticated) && message.id == 1
        ));
        assert_eq!(
            conn.on_binary(
                &encode(&client(
                    2,
                    Body::Auth(Auth {
                        token: "good".into()
                    })
                )),
                &mut Fake
            ),
            [],
            "closed is closed"
        );
        let mut conn = Conn::new();
        let out = conn.on_binary(
            &encode(&client(
                1,
                Body::Auth(Auth {
                    token: "bad".into(),
                }),
            )),
            &mut Fake,
        );
        assert!(matches!(&out[..], [Out::Send(_), Out::Close(4401)]));
        let mut conn = Conn::new();
        assert!(matches!(
            &conn.on_binary(b"\xff\xff\xff", &mut Fake)[..],
            [Out::Send(_), Out::Close(4401)]
        ));
        assert_eq!(Conn::new().on_auth_deadline(), [Out::Close(4401)]);
    }

    #[test]
    fn a_request_gets_its_reply_under_its_id() {
        let mut conn = authed();
        let out = conn.on_binary(&encode(&client(7, Body::Request(get_state()))), &mut Fake);
        assert!(
            matches!(&out[..], [Out::Ask { id: 7, .. }]),
            "the driver is asked; nothing is sent yet"
        );
        conn.push_state(&State::default()); // not subscribed: dropped
        conn.reply(7, Ok(state_response()));
        assert!(matches!(
            conn.next_out(),
            Some(ServerMsg {
                id: 7,
                body: Some(server_msg::Body::Response(_))
            })
        ));
        assert_eq!(conn.next_out(), None);
        assert_eq!(
            conn.on_auth_deadline(),
            [],
            "authenticated: the deadline is moot"
        );
    }

    #[test]
    fn only_the_latest_state_is_kept_for_a_slow_reader() {
        let mut conn = authed();
        assert_eq!(
            conn.on_binary(&encode(&client(2, subscribe("state", 0))), &mut Fake),
            [Out::Send(ack(2))]
        );
        for generation in 1..=5 {
            conn.push_state(&State {
                generation,
                ..State::default()
            });
        }
        let sent = conn.next_out().expect("one push");
        assert_eq!(pushed_generation(&sent), Some(5));
        assert_eq!(sent.id, 0);
        assert_eq!(
            conn.next_out(),
            None,
            "the four older ones were replaced, not queued"
        );
    }

    #[test]
    fn events_queue_256_deep_then_say_data_was_lost_once() {
        let mut conn = authed();
        conn.on_binary(&encode(&client(2, subscribe("events", 2))), &mut Fake);
        let backlog: Vec<_> = drain(&mut conn).iter().filter_map(event_number).collect();
        assert_eq!(backlog, [1_001, 1_002], "the last two, oldest first");
        for n in 0..300 {
            conn.push_event(&event(n));
        }
        let after = drain(&mut conn);
        assert_eq!(
            after
                .iter()
                .filter(|m| error_code_of(m) == Some(ErrorCode::DataLoss))
                .count(),
            1
        );
        assert_eq!(
            error_code_of(&after[0]),
            Some(ErrorCode::DataLoss),
            "said first"
        );
        let numbers: Vec<_> = after.iter().filter_map(event_number).collect();
        assert_eq!(numbers.len(), 256);
        assert_eq!(numbers.first(), Some(&44));
        assert_eq!(numbers.last(), Some(&299), "the newest survive");
    }

    #[test]
    fn bad_frames_are_answered_not_fatal_except_the_oversized_and_text() {
        let mut conn = authed();
        assert!(matches!(
            &conn.on_binary(b"\xff\xff\xff", &mut Fake)[..],
            [Out::Send(message)] if error_code_of(message) == Some(ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            &conn.on_binary(&encode(&ClientMsg { id: 4, body: None }), &mut Fake)[..],
            [Out::Send(message)] if error_code_of(message) == Some(ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            &conn.on_binary(&encode(&client(3, subscribe("nope", 0))), &mut Fake)[..],
            [Out::Send(message)] if error_code_of(message) == Some(ErrorCode::NotFound) && message.id == 3
        ));
        assert!(matches!(
            &conn.on_binary(&encode(&client(5, Body::Request(Request { body: None }))), &mut Fake)[..],
            [Out::Send(message)] if error_code_of(message) == Some(ErrorCode::InvalidArgument)
        ));
        assert_eq!(
            conn.on_binary(&vec![0; (1 << 20) + 1], &mut Fake),
            [Out::Close(1009)]
        );
        assert_eq!(authed().on_text(), [Out::Close(1003)]);
    }

    #[test]
    fn unsubscribe_stops_the_pushes() {
        let mut conn = authed();
        for topic in ["state", "counters", "events"] {
            conn.on_binary(&encode(&client(2, subscribe(topic, 0))), &mut Fake);
        }
        conn.on_binary(&encode(&client(2, subscribe("state", 0))), &mut Fake);
        assert!(
            conn.wants(Topic::State) && conn.wants(Topic::Counters) && conn.wants(Topic::Events)
        );
        conn.push_state(&State::default());
        conn.push_counters(&Counters::default());
        conn.push_event(&event(1));
        let out = conn.on_binary(
            &encode(&client(
                9,
                Body::Unsubscribe(Unsubscribe {
                    topic: "state".into(),
                }),
            )),
            &mut Fake,
        );
        assert_eq!(out, [Out::Send(ack(9))]);
        let sent = drain(&mut conn);
        assert_eq!(
            sent.len(),
            2,
            "counters and the event; the unsent state went"
        );
        assert_eq!(pushed_generation(&sent[0]), None);
        conn.push_state(&State::default());
        assert_eq!(conn.next_out(), None);
    }

    #[test]
    fn pushes_to_a_topic_nobody_asked_for_are_dropped() {
        let mut conn = authed();
        conn.push_state(&State::default());
        conn.push_counters(&Counters::default());
        conn.push_event(&event(1));
        assert_eq!(conn.next_out(), None);
        assert_eq!(
            Topic::parse("counters").map(Topic::as_str),
            Some("counters")
        );
    }
}
