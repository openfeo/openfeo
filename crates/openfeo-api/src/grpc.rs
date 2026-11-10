// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! gRPC (SPEC §8.3), for scripts and tooling: the same operations as the WebSocket and the
//! plain HTTP calls, on the same listener, told apart by `content-type: application/grpc`.
//! Every call but `Login` and `SetInitialPassword` needs `authorization: Bearer <token>`.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use openfeo_config::api::{
    ChangePasswordRequest, ChangePasswordResponse, ErrorCode, GetStateRequest, GetStateResponse,
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, ServerMsg,
    SetInitialPasswordRequest, SetInitialPasswordResponse, SubscribeRequest, SubscribeResponse,
    server_msg, subscribe_response, telemetry,
};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::envelope::{Conn, Topic};
use crate::events::to_pb;
use crate::http::Peer;
use crate::limits::EVENT_BACKLOG;
use crate::pb::auth_service_server::AuthService;
use crate::pb::state_service_server::StateService;
use crate::server::{ApiError, Shared};
use crate::ws::Slot;

/// Both services over the shared state.
#[derive(Debug, Clone)]
pub struct Grpc {
    shared: Arc<Shared>,
}

impl Grpc {
    /// The services over `shared`.
    #[must_use]
    pub fn new(shared: Arc<Shared>) -> Self {
        Grpc { shared }
    }
}

fn status(error: &ApiError) -> Status {
    let code = match error.code {
        ErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        ErrorCode::Unauthenticated => tonic::Code::Unauthenticated,
        ErrorCode::FailedPrecondition => tonic::Code::FailedPrecondition,
        ErrorCode::NotFound => tonic::Code::NotFound,
        ErrorCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        ErrorCode::DataLoss => tonic::Code::DataLoss,
        ErrorCode::Unavailable => tonic::Code::Unavailable,
        ErrorCode::Unspecified | ErrorCode::Internal => tonic::Code::Internal,
    };
    let mut status = Status::new(code, error.message.clone());
    if error.retry_after_secs > 0
        && let Ok(value) = error.retry_after_secs.to_string().parse()
    {
        status.metadata_mut().insert("retry-after", value);
    }
    status
}

/// The address the call came from, as the listener attached it. Without one the call is
/// refused: the backoff would otherwise put every caller in one bucket.
fn from<T>(request: &Request<T>) -> Result<IpAddr, Status> {
    request
        .extensions()
        .get::<Peer>()
        .map(|peer| peer.0.ip())
        .ok_or_else(|| Status::internal("the call carries no peer address"))
}

/// The call's token, if it names a live session.
fn token<T>(shared: &Shared, request: &Request<T>) -> Result<String, Status> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| shared.authenticate(token))
        .map(str::to_owned)
        .ok_or_else(|| Status::unauthenticated("log in first"))
}

#[tonic::async_trait]
impl AuthService for Grpc {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let from = from(&request)?;
        let session = self
            .shared
            .login(from, request.into_inner().password)
            .await
            .map_err(|error| status(&error))?;
        Ok(Response::new(LoginResponse {
            session: Some(session),
        }))
    }

    async fn set_initial_password(
        &self,
        request: Request<SetInitialPasswordRequest>,
    ) -> Result<Response<SetInitialPasswordResponse>, Status> {
        let from = from(&request)?;
        let session = self
            .shared
            .set_initial_password(from, request.into_inner().password)
            .await
            .map_err(|error| status(&error))?;
        Ok(Response::new(SetInitialPasswordResponse {
            session: Some(session),
        }))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let token = token(&self.shared, &request)?;
        self.shared.logout(&token);
        Ok(Response::new(LogoutResponse {}))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let token = token(&self.shared, &request)?;
        let from = from(&request)?;
        let change = request.into_inner();
        self.shared
            .change_password(from, &token, change.old_password, change.new_password)
            .await
            .map_err(|error| status(&error))?;
        Ok(Response::new(ChangePasswordResponse {}))
    }
}

/// What a push becomes on the stream; word of lost events ends it, so the caller subscribes
/// again and takes a backlog.
fn stream_item(message: ServerMsg) -> Option<Result<SubscribeResponse, Status>> {
    let body = match message.body? {
        server_msg::Body::Event(event) => subscribe_response::Body::Event(event),
        server_msg::Body::Telemetry(push) => match push.body? {
            telemetry::Body::State(state) => subscribe_response::Body::State(state),
            telemetry::Body::Counters(counters) => subscribe_response::Body::Counters(counters),
        },
        server_msg::Body::Error(error) => {
            return Some(Err(Status::data_loss(error.message)));
        }
        server_msg::Body::Response(_) => return None,
    };
    Some(Ok(SubscribeResponse { body: Some(body) }))
}

async fn feed(
    slot: Slot,
    topics: Vec<Topic>,
    backlog: u32,
    tx: mpsc::Sender<Result<SubscribeResponse, Status>>,
) {
    // The stream holds a place among the sockets and counts as its session's activity, as a
    // WebSocket does, until this task ends.
    let shared = slot.shared.clone();
    let token = slot.token.clone().unwrap_or_default();
    let mut conn = Conn::subscribed(&topics);
    let mut world = shared.world.clone();
    let mut ended = shared.sessions_ended.subscribe();
    // A logout that landed between the token check and this subscription would otherwise go
    // unseen until the next one.
    if !shared.session_is_live(&token) {
        let _ = tx
            .send(Err(Status::unauthenticated("the session ended")))
            .await;
        return;
    }
    let mut events = shared.publisher.events();
    let mut counters = conn
        .wants(Topic::Counters)
        .then(|| shared.telemetry.subscribe());
    if conn.wants(Topic::Events) {
        for event in shared.backlog(backlog.min(u32::try_from(EVENT_BACKLOG).unwrap_or(u32::MAX))) {
            conn.push_event(&event);
        }
    }
    world.borrow_and_update();
    conn.push_state(&shared.state());
    loop {
        while let Some(message) = conn.next_out() {
            let Some(item) = stream_item(message) else {
                continue;
            };
            let last = item.is_err();
            if tx.send(item).await.is_err() || last {
                return;
            }
        }
        tokio::select! {
            () = tx.closed() => return,
            changed = world.changed(), if conn.wants(Topic::State) => {
                if changed.is_err() {
                    return;
                }
                conn.push_state(&shared.state());
            }
            event = events.recv(), if conn.wants(Topic::Events) => match event {
                Ok(event) => conn.push_event(&to_pb(&event)),
                Err(broadcast::error::RecvError::Lagged(_)) => conn.events_lost(),
                Err(broadcast::error::RecvError::Closed) => return,
            },
            sample = async {
                match counters.as_mut() {
                    Some(sub) => sub.changed().await,
                    None => std::future::pending().await,
                }
            } => match sample {
                Some(sample) => conn.push_counters(&sample),
                None => return,
            },
            changed = ended.changed() => {
                if changed.is_err() || !shared.session_is_live(&token) {
                    let _ = tx.send(Err(Status::unauthenticated("the session ended"))).await;
                    return;
                }
            }
        }
    }
}

#[tonic::async_trait]
impl StateService for Grpc {
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<SubscribeResponse, Status>> + Send>>;

    async fn get_state(
        &self,
        request: Request<GetStateRequest>,
    ) -> Result<Response<GetStateResponse>, Status> {
        token(&self.shared, &request)?;
        Ok(Response::new(GetStateResponse {
            state: Some(self.shared.state()),
        }))
    }

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let token = token(&self.shared, &request)?;
        let request = request.into_inner();
        let topics = request
            .topics
            .iter()
            .map(|name| Topic::parse(name).ok_or_else(|| Status::not_found("no such topic")))
            .collect::<Result<Vec<_>, _>>()?;
        // One pending item per topic and a little slack; a slow reader holds the feed here,
        // and what it misses meanwhile is coalesced where it comes from.
        let (tx, rx) = mpsc::channel(8);
        let slot = Slot::authenticated(&self.shared, &token)
            .ok_or_else(|| Status::resource_exhausted("too many open streams and sockets"))?;
        tokio::spawn(feed(slot, topics, request.backlog, tx));
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use futures::StreamExt as _;
    use openfeo_config::api::{GetStateRequest, request, response, server_msg};
    use openfeo_world::EventDraft;

    use super::*;
    use crate::pb::auth_service_client::AuthServiceClient;
    use crate::pb::state_service_client::StateServiceClient;
    use crate::server::tests::PASSWORD;
    use crate::testing::{TestApi, with_token};

    #[tokio::test]
    async fn state_is_the_same_over_grpc_the_websocket_and_json() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut client = StateServiceClient::new(api.channel().await);
        let over_grpc = client
            .get_state(with_token(GetStateRequest {}, &token))
            .await
            .unwrap()
            .into_inner()
            .state
            .unwrap();
        let mut ws = api.ws_with(&token).await;
        let server_msg::Body::Response(reply) =
            ws.ask(request::Body::GetState(GetStateRequest {})).await
        else {
            panic!("a response");
        };
        let Some(response::Body::GetState(reply)) = reply.body else {
            panic!("a state");
        };
        let over_ws = reply.state.unwrap();
        let over_json: GetStateResponse =
            api.get_with("/api/state?format=json", &token).await.json();
        let over_json = over_json.state.unwrap();
        // Everything but the uptime, which moves between three calls.
        for other in [&over_ws, &over_json] {
            assert_eq!(over_grpc.generation, other.generation);
            assert_eq!(over_grpc.wans, other.wans);
            assert_eq!(over_grpc.lans, other.lans);
            assert_eq!(over_grpc.ports, other.ports);
            assert_eq!(over_grpc.addresses, other.addresses);
        }
        assert_eq!(over_grpc.wans[0].ipv4, "203.0.113.100/24");
    }

    #[tokio::test]
    async fn grpc_refuses_without_a_token_and_streams_with_one() {
        let (api, _) = TestApi::with_password(PASSWORD).await;
        let channel = api.channel().await;
        let mut state = StateServiceClient::new(channel.clone());
        let refused = state
            .get_state(with_token(GetStateRequest {}, ""))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Unauthenticated);
        let mut auth = AuthServiceClient::new(channel);
        let wrong = auth
            .login(LoginRequest {
                password: "wrong-password-1".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(wrong.code(), tonic::Code::Unauthenticated);
        let waiting = auth
            .login(LoginRequest {
                password: PASSWORD.to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(waiting.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            waiting
                .metadata()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        // The same source as over plain HTTP: the peer's address reached the gRPC call.
        let held = api
            .post_json("/api/login", &serde_json::json!({ "password": PASSWORD }))
            .await;
        assert_eq!(held.status, 429, "one backoff source across transports");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let token = auth
            .login(LoginRequest {
                password: PASSWORD.to_owned(),
            })
            .await
            .unwrap()
            .into_inner()
            .session
            .unwrap()
            .token;
        let mut stream = state
            .subscribe(with_token(
                SubscribeRequest {
                    topics: vec!["state".to_owned(), "events".to_owned()],
                    backlog: 0,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let first = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            first.body,
            Some(subscribe_response::Body::State(_))
        ));
        api.shared.publisher.emit(EventDraft::new("health.ok"));
        let second = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            second.body,
            Some(subscribe_response::Body::Event(event)) if event.topic == "health.ok"
        ));
        let unknown = state
            .subscribe(with_token(
                SubscribeRequest {
                    topics: vec!["nope".to_owned()],
                    backlog: 0,
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(unknown.code(), tonic::Code::NotFound);
        assert_eq!(
            api.shared.sockets.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an open stream holds a place, as a socket does"
        );
        auth.logout(with_token(LogoutRequest {}, &token))
            .await
            .unwrap();
        let ended = stream.next().await.unwrap().unwrap_err();
        assert_eq!(
            ended.code(),
            tonic::Code::Unauthenticated,
            "the stream ends with the session"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            api.shared.sockets.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "and gives it back"
        );
    }

    #[tokio::test]
    async fn a_foreign_authority_is_refused_over_grpc_too() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let addr = api.https;
        let channel = tonic::transport::Endpoint::from_static("http://evil.example")
            .connect_with_connector(tower::service_fn(move |_: hyper::Uri| async move {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                let tls = tokio_rustls::TlsConnector::from(crate::testing::client_config(&[b"h2"]))
                    .connect(
                        rustls::pki_types::ServerName::try_from(crate::testing::HOST).unwrap(),
                        stream,
                    )
                    .await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }))
            .await
            .unwrap();
        let refused = StateServiceClient::new(channel)
            .get_state(with_token(GetStateRequest {}, &token))
            .await
            .unwrap_err();
        assert_ne!(refused.code(), tonic::Code::Ok);
        assert!(
            refused.message().contains("421") || refused.code() == tonic::Code::Unknown,
            "{refused:?}"
        );
    }
}
