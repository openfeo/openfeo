// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The WebSocket (SPEC §8.3): a thin driver over [`Conn`]. It feeds frames in, performs what
//! the connection asks, forwards changes of World, counters and events to the topics the
//! connection wants, and writes what the core says to write. A socket that does not take a
//! frame in time, does not answer two pings, or whose session ends is closed.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, SinkExt as _, StreamExt as _};
use openfeo_config::api::{
    ChangePasswordResponse, ErrorCode, GetStateResponse, LogoutResponse, Request, ServerMsg,
    request, response,
};
use prost::Message as _;
use tokio::sync::broadcast;

use crate::envelope::{Backend, CLOSE_UNAUTHENTICATED, Conn, Out, Topic};
use crate::events::to_pb;
use crate::gate::origin_allowed;
use crate::http::Peer;
use crate::limits::{MAX_FRAME, MAX_SOCKETS};
use crate::server::{ApiError, Shared};
use crate::telemetry::CountersSub;

/// `GET /ws`: the upgrade, for a browser on the router's own origin or for anything that is
/// not a browser, while fewer than [`MAX_SOCKETS`] are open.
pub async fn upgrade(
    State(shared): State<Arc<Shared>>,
    Extension(Peer(peer)): Extension<Peer>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let origin = match headers.get(ORIGIN).map(|value| value.to_str()) {
        Some(Ok(origin)) => Some(origin),
        // An origin that is not text is not ours.
        Some(Err(_)) => return StatusCode::FORBIDDEN.into_response(),
        None => None,
    };
    if !origin_allowed(origin, &shared.names(), &shared.world.borrow()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(slot) = Slot::take(&shared) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| drive(socket, slot, peer.ip()))
}

/// One of the [`MAX_SOCKETS`] places, and the session's count of sockets; both given back
/// when the socket ends, however it ends.
struct Slot {
    shared: Arc<Shared>,
    token: Option<String>,
}

impl Slot {
    fn take(shared: &Arc<Shared>) -> Option<Slot> {
        shared
            .sockets
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |open| {
                (open < MAX_SOCKETS).then_some(open + 1)
            })
            .ok()?;
        Some(Slot {
            shared: shared.clone(),
            token: None,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(token) = &self.token {
            self.shared.socket(token, -1);
        }
        self.shared.sockets.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Backend for Slot {
    fn authenticate(&mut self, token: &str) -> bool {
        let live = self.shared.authenticate(token);
        if live && self.token.is_none() {
            self.shared.socket(token, 1);
            self.token = Some(token.to_owned());
        }
        live
    }

    fn backlog(&mut self, n: u32) -> Vec<openfeo_config::events::Event> {
        self.shared.backlog(n)
    }
}

/// Perform what a connection asked: the same operations HTTP and gRPC call.
pub(crate) async fn perform(
    shared: &Shared,
    from: IpAddr,
    token: &str,
    request: Request,
) -> Result<openfeo_config::api::Response, ApiError> {
    let body = match request.body {
        Some(request::Body::GetState(_)) => response::Body::GetState(GetStateResponse {
            state: Some(shared.state()),
        }),
        Some(request::Body::Logout(_)) => {
            shared.logout(token);
            response::Body::Logout(LogoutResponse {})
        }
        Some(request::Body::ChangePassword(change)) => {
            shared
                .change_password(from, token, change.old_password, change.new_password)
                .await?;
            response::Body::ChangePassword(ChangePasswordResponse {})
        }
        None => {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "a Request with no body",
            ));
        }
    };
    Ok(openfeo_config::api::Response { body: Some(body) })
}

/// Send `message` unless the sink does not take it within `limit`: a reader that has stopped
/// reading is not waited on.
pub(crate) async fn send_in_time<S>(sink: &mut S, message: Message, limit: Duration) -> bool
where
    S: Sink<Message> + Unpin,
{
    matches!(
        tokio::time::timeout(limit, sink.send(message)).await,
        Ok(Ok(()))
    )
}

fn close(code: u16) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: "".into(),
    }))
}

fn frame(message: &ServerMsg) -> Message {
    Message::Binary(message.encode_to_vec().into())
}

/// What the driver follows for the topics its connection wants.
struct Feeds {
    events: broadcast::Receiver<Arc<openfeo_world::Event>>,
    counters: Option<CountersSub>,
    had_state: bool,
}

impl Feeds {
    /// Take up or drop the counters as the connection wants them; true when it has just
    /// subscribed to `state`.
    fn follow(&mut self, conn: &Conn, shared: &Arc<Shared>) -> bool {
        match (conn.wants(Topic::Counters), self.counters.is_some()) {
            (true, false) => self.counters = Some(shared.telemetry.subscribe()),
            (false, true) => self.counters = None,
            _ => {}
        }
        let wants_state = conn.wants(Topic::State);
        let newly = wants_state && !self.had_state;
        self.had_state = wants_state;
        newly
    }
}

async fn next_counters(
    counters: &mut Option<CountersSub>,
) -> Option<openfeo_config::state::Counters> {
    match counters {
        Some(sub) => sub.changed().await,
        None => std::future::pending().await,
    }
}

async fn drive(socket: WebSocket, mut slot: Slot, from: IpAddr) {
    let shared = slot.shared.clone();
    let limits = shared.limits;
    let (mut sink, mut stream): (SplitSink<WebSocket, Message>, SplitStream<WebSocket>) =
        socket.split();
    let mut conn = Conn::new();
    let mut world = shared.world.clone();
    let mut ended = shared.sessions_ended.subscribe();
    let mut feeds = Feeds {
        events: shared.publisher.events(),
        counters: None,
        had_state: false,
    };
    let auth_deadline = tokio::time::sleep(limits.auth_frame);
    tokio::pin!(auth_deadline);
    let mut pings =
        tokio::time::interval_at(tokio::time::Instant::now() + limits.ping, limits.ping);
    let mut unanswered = 0u8;
    loop {
        while let Some(message) = conn.next_out() {
            if !send_in_time(&mut sink, frame(&message), limits.write).await {
                return;
            }
        }
        let outs = tokio::select! {
            received = stream.next() => match received {
                Some(Ok(Message::Binary(bytes))) => {
                    if !conn.wants(Topic::Events) {
                        // Start from now, so a backlog asked for in this frame and the live
                        // events that follow it meet without a gap.
                        feeds.events = shared.publisher.events();
                    }
                    conn.on_binary(&bytes, &mut slot)
                }
                Some(Ok(Message::Text(_))) => conn.on_text(),
                Some(Ok(Message::Pong(_))) => {
                    unanswered = 0;
                    Vec::new()
                }
                Some(Ok(Message::Ping(_))) => Vec::new(),
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
            },
            () = &mut auth_deadline, if !conn.authenticated() => conn.on_auth_deadline(),
            changed = world.changed(), if conn.wants(Topic::State) => {
                if changed.is_err() {
                    return;
                }
                conn.push_state(&shared.state());
                Vec::new()
            }
            event = feeds.events.recv(), if conn.wants(Topic::Events) => {
                match event {
                    Ok(event) => conn.push_event(&to_pb(&event)),
                    Err(broadcast::error::RecvError::Lagged(_)) => conn.events_lost(),
                    Err(broadcast::error::RecvError::Closed) => return,
                }
                Vec::new()
            }
            sample = next_counters(&mut feeds.counters) => {
                match sample {
                    Some(counters) => conn.push_counters(&counters),
                    None => return,
                }
                Vec::new()
            }
            changed = ended.changed() => {
                if changed.is_err() {
                    return;
                }
                if slot.token.as_deref().is_some_and(|token| !shared.session_is_live(token)) {
                    vec![Out::Close(CLOSE_UNAUTHENTICATED)]
                } else {
                    Vec::new()
                }
            }
            _ = pings.tick() => {
                if unanswered >= 2 {
                    return;
                }
                unanswered += 1;
                if !send_in_time(&mut sink, Message::Ping(Vec::new().into()), limits.write).await {
                    return;
                }
                Vec::new()
            }
        };
        if !act(outs, &mut conn, &mut sink, &slot, from).await {
            return;
        }
        // Follow what the connection now wants.
        if feeds.follow(&conn, &shared) {
            // "Now, and after every change": the first push is the state as it stands.
            world.borrow_and_update();
            conn.push_state(&shared.state());
        }
    }
}

/// Do what the core said: send, perform a request and queue its reply, or close. False when
/// the socket is finished.
async fn act(
    outs: Vec<Out>,
    conn: &mut Conn,
    sink: &mut SplitSink<WebSocket, Message>,
    slot: &Slot,
    from: IpAddr,
) -> bool {
    let limit = slot.shared.limits.write;
    for out in outs {
        match out {
            Out::Send(message) => {
                if !send_in_time(sink, frame(&message), limit).await {
                    return false;
                }
            }
            Out::Ask { id, request } => {
                let token = slot.token.clone().unwrap_or_default();
                let result = perform(&slot.shared, from, &token, request).await;
                conn.reply(id, result.map_err(|error| error.to_pb()));
            }
            Out::Close(code) => {
                while let Some(message) = conn.next_out() {
                    if !send_in_time(sink, frame(&message), limit).await {
                        return false;
                    }
                }
                let _ = send_in_time(sink, close(code), limit).await;
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use openfeo_config::api::{ChangePasswordRequest, GetStateRequest, LogoutRequest, server_msg};
    use openfeo_config::state::WanPhase;
    use openfeo_world::EventDraft;

    use super::*;
    use crate::server::Limits;
    use crate::server::tests::PASSWORD;
    use crate::testing::{TestApi, spawn_api_with_limits};

    #[tokio::test]
    async fn a_foreign_origin_is_refused_and_no_origin_is_a_script() {
        let (api, _) = TestApi::with_password(PASSWORD).await;
        assert_eq!(api.ws(Some("https://evil.example")).await.err(), Some(403));
        assert_eq!(
            api.ws(Some("http://openfeo.home.arpa")).await.err(),
            Some(403)
        );
        assert!(api.ws(Some("https://openfeo.home.arpa")).await.is_ok());
        assert!(api.ws(None).await.is_ok());
    }

    #[tokio::test]
    async fn a_socket_that_says_nothing_is_closed_with_4401() {
        let api = spawn_api_with_limits(Limits {
            auth_frame: Duration::from_millis(200),
            ..Limits::default()
        })
        .await;
        let mut ws = api.ws(None).await.unwrap();
        assert_eq!(ws.closed_with().await, Some(4401));
        let mut ws = api.ws(None).await.unwrap();
        ws.send(openfeo_config::api::client_msg::Body::Auth(
            openfeo_config::api::Auth {
                token: "not-a-token".to_owned(),
            },
        ))
        .await;
        assert_eq!(ws.closed_with().await, Some(4401), "a bad token, at once");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            api.shared.sockets.load(Ordering::SeqCst),
            0,
            "both places given back"
        );
    }

    #[tokio::test]
    async fn a_world_change_is_pushed_and_an_event_with_it() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        ws.subscribe("events", 0).await;
        ws.subscribe("state", 0).await;
        assert_eq!(
            ws.next_state().await.wans[0].phase(),
            WanPhase::Up,
            "the state as it stands"
        );
        api.shared.publisher.update(|world| {
            Arc::make_mut(&mut world.dhcp4).remove("wan0");
            world.set_wan_cause("wan0", "lease expired");
        });
        // The new state and the event of the change, in whichever order they are sent.
        let (mut event, mut state) = (None, None);
        while event.is_none() || state.is_none() {
            match ws.msg().await.body {
                Some(server_msg::Body::Event(got)) => event = Some(got),
                Some(server_msg::Body::Telemetry(push)) => {
                    if let Some(openfeo_config::api::telemetry::Body::State(got)) = push.body {
                        state = Some(got);
                    }
                }
                _ => {}
            }
        }
        let (event, state) = (event.unwrap(), state.unwrap());
        assert_eq!(
            (event.topic.as_str(), event.fields["reason"].as_str()),
            ("wan.wan0.down", "lease expired")
        );
        assert!(event.time_unix_ms > 0 && event.uptime_ms > 0);
        assert_eq!(
            (state.wans[0].phase(), state.wans[0].reason.as_str()),
            (WanPhase::Connecting, "lease expired")
        );
    }

    #[tokio::test]
    async fn a_late_subscriber_gets_the_backlog_it_asks_for() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        for n in 0..5 {
            api.shared
                .publisher
                .emit(EventDraft::new("health.ok").with("n", n.to_string()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut ws = api.ws_with(&token).await;
        ws.subscribe("events", 2).await;
        assert_eq!(ws.next_event().await.fields["n"], "3");
        assert_eq!(ws.next_event().await.fields["n"], "4");
        api.shared
            .publisher
            .emit(EventDraft::new("health.ok").with("n", "live"));
        assert_eq!(ws.next_event().await.fields["n"], "live");
    }

    #[tokio::test]
    async fn requests_over_the_socket_and_a_logout_that_closes_it_with_4401() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        let server_msg::Body::Response(reply) =
            ws.ask(request::Body::GetState(GetStateRequest {})).await
        else {
            panic!("a response");
        };
        let Some(response::Body::GetState(reply)) = reply.body else {
            panic!("a state");
        };
        assert_eq!(reply.state.unwrap().wans[0].name, "wan0");
        let reply = ws.ask(request::Body::Logout(LogoutRequest {})).await;
        assert!(
            matches!(reply, server_msg::Body::Response(_)),
            "answered first"
        );
        assert_eq!(ws.closed_with().await, Some(4401));
        assert_eq!(api.get_with("/api/state", &token).await.status, 401);
    }

    #[tokio::test]
    async fn changing_the_password_over_one_socket_closes_the_other() {
        let (api, mine) = TestApi::with_password(PASSWORD).await;
        let other = api
            .shared
            .login("127.0.0.1".parse().unwrap(), PASSWORD.to_owned())
            .await
            .unwrap()
            .token;
        let mut my_socket = api.ws_with(&mine).await;
        let mut other_socket = api.ws_with(&other).await;
        let wrong = my_socket
            .ask(request::Body::ChangePassword(ChangePasswordRequest {
                old_password: "not-the-old-one".to_owned(),
                new_password: "a-new-password".to_owned(),
            }))
            .await;
        assert!(matches!(
            wrong,
            server_msg::Body::Error(error) if error.code() == ErrorCode::InvalidArgument
        ));
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let changed = my_socket
            .ask(request::Body::ChangePassword(ChangePasswordRequest {
                old_password: PASSWORD.to_owned(),
                new_password: "a-new-password".to_owned(),
            }))
            .await;
        assert!(
            matches!(changed, server_msg::Body::Response(_)),
            "{changed:?}"
        );
        assert_eq!(other_socket.closed_with().await, Some(4401));
        let still = my_socket
            .ask(request::Body::GetState(GetStateRequest {}))
            .await;
        assert!(
            matches!(still, server_msg::Body::Response(_)),
            "the caller's stays"
        );
    }

    #[tokio::test]
    async fn counters_are_pushed_each_second_while_subscribed() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        ws.subscribe("counters", 0).await;
        let first = ws.next_counters().await;
        let second = ws.next_counters().await;
        let apart = second.monotonic_ms - first.monotonic_ms;
        assert!((900..=1_500).contains(&apart), "{apart} ms apart");
    }

    #[tokio::test]
    async fn a_seventeenth_socket_gets_503() {
        let (api, _) = TestApi::with_password(PASSWORD).await;
        let mut open = Vec::new();
        for _ in 0..16 {
            open.push(api.ws(None).await.unwrap());
        }
        assert_eq!(api.ws(None).await.err(), Some(503));
        drop(open.pop());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(api.ws(None).await.is_ok(), "a place came free");
    }

    #[tokio::test]
    async fn a_ping_unanswered_twice_closes_the_socket() {
        let api = spawn_api_with_limits(Limits {
            ping: Duration::from_millis(100),
            ..Limits::default()
        })
        .await;
        let token = api
            .shared
            .set_initial_password("127.0.0.1".parse().unwrap(), PASSWORD.to_owned())
            .await
            .unwrap()
            .token;
        // Authenticated, then never read again: the client's pongs are never sent.
        let ws = api.ws_with(&token).await;
        assert_eq!(api.shared.sockets.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(api.shared.sockets.load(Ordering::SeqCst), 0);
        drop(ws);
    }

    /// A sink that never takes anything: a reader that has stopped reading.
    struct Stalled;

    impl Sink<Message> for Stalled {
        type Error = std::convert::Infallible;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_that_stops_reading_is_closed_not_waited_on() {
        let started = tokio::time::Instant::now();
        let sent = send_in_time(
            &mut Stalled,
            Message::Binary(vec![0; 16].into()),
            Duration::from_secs(10),
        )
        .await;
        assert!(!sent, "the driver gives up, and gives its slot back");
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        let mut taken = futures::sink::drain().sink_map_err(|never| match never {});
        assert!(
            send_in_time(
                &mut taken,
                Message::Binary(vec![0; 16].into()),
                Duration::from_secs(10)
            )
            .await
        );
    }
}
