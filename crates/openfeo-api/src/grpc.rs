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
    ApplyConfigRequest, ApplyConfigResponse, ChangePasswordRequest, ChangePasswordResponse,
    ConfirmConfigRequest, ConfirmConfigResponse, ErrorCode, GetConfigRequest, GetConfigResponse,
    GetStateRequest, GetStateResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse,
    RevertConfigRequest, RevertConfigResponse, ServerMsg, SetInitialPasswordRequest,
    SetInitialPasswordResponse, SubscribeRequest, SubscribeResponse, ValidateConfigRequest,
    ValidateConfigResponse, server_msg, subscribe_response, telemetry,
};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::envelope::{Conn, Topic};
use crate::events::to_pb;
use crate::http::{Arrival, Local, Peer};
use crate::keeper::Why;
use crate::limits::EVENT_BACKLOG;
use crate::pb::auth_service_server::AuthService;
use crate::pb::config_service_server::ConfigService;
use crate::pb::state_service_server::StateService;
use crate::server::{ApiError, Shared};
use crate::ws::Slot;

/// The services over the shared state.
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

/// Both ends of the connection the call came over, as the listener attached them.
fn arrival<T>(request: &Request<T>) -> Result<Arrival, Status> {
    let peer = request
        .extensions()
        .get::<Peer>()
        .copied()
        .ok_or_else(|| Status::internal("the call carries no peer address"))?;
    Ok(Arrival::of(
        peer,
        request.extensions().get::<Local>().copied(),
    ))
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
impl ConfigService for Grpc {
    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        token(&self.shared, &request)?;
        Ok(Response::new(self.shared.config_view().await))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        token(&self.shared, &request)?;
        let at = arrival(&request)?;
        let Some(config) = request.into_inner().config else {
            return Err(Status::invalid_argument("a validation with no config"));
        };
        Ok(Response::new(self.shared.validate_config(config, at).await))
    }

    async fn apply_config(
        &self,
        request: Request<ApplyConfigRequest>,
    ) -> Result<Response<ApplyConfigResponse>, Status> {
        token(&self.shared, &request)?;
        self.shared
            .apply_config(request.into_inner())
            .await
            .map(Response::new)
            .map_err(|error| status(&error))
    }

    async fn confirm_config(
        &self,
        request: Request<ConfirmConfigRequest>,
    ) -> Result<Response<ConfirmConfigResponse>, Status> {
        token(&self.shared, &request)?;
        self.shared
            .confirm_config()
            .await
            .map_err(|error| status(&error))?;
        Ok(Response::new(ConfirmConfigResponse {}))
    }

    async fn revert_config(
        &self,
        request: Request<RevertConfigRequest>,
    ) -> Result<Response<RevertConfigResponse>, Status> {
        token(&self.shared, &request)?;
        self.shared
            .revert_config(Why::Asked)
            .await
            .map_err(|error| status(&error))?;
        Ok(Response::new(RevertConfigResponse {}))
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

    use openfeo_config::api::{
        ApplyConfigRequest, ConfirmConfigRequest, GetConfigRequest, RevertConfigRequest,
        ValidateConfigRequest,
    };
    use openfeo_config::state::ConfigEffectKind;
    use openfeo_config::{Config, secrets};

    use crate::pb::config_service_client::ConfigServiceClient;

    /// What a socket was answered, or the error it was sent.
    async fn asked(
        ws: &mut crate::testing::Ws,
        body: request::Body,
    ) -> Result<response::Body, openfeo_config::api::Error> {
        match ws.ask(body).await {
            server_msg::Body::Response(openfeo_config::api::Response { body: Some(body) }) => {
                Ok(body)
            }
            server_msg::Body::Error(error) => Err(error),
            other => panic!("a response or an error, not {other:?}"),
        }
    }

    /// The config as the socket reads it, and its tag.
    async fn read(ws: &mut crate::testing::Ws) -> (Config, String) {
        let Ok(response::Body::GetConfig(GetConfigResponse {
            config: Some(config),
            tag,
            ..
        })) = asked(ws, request::Body::GetConfig(GetConfigRequest {})).await
        else {
            panic!("the config");
        };
        (config, tag)
    }

    /// `config` with `lan0` at `192.168.2.1/24` and everything in it moved along.
    fn moved(mut config: Config) -> Config {
        let lan = &mut config.lans[0];
        "192.168.2.1/24".clone_into(&mut lan.ipv4);
        if let Some(dhcp) = &mut lan.dhcp {
            dhcp.range = vec!["192.168.2.100".to_owned(), "192.168.2.200".to_owned()];
            for lease in &mut dhcp.r#static {
                lease.ip = lease.ip.replace("192.168.1.", "192.168.2.");
            }
        }
        if let Some(firewall) = &mut config.firewall {
            for forward in &mut firewall.port_forwards {
                forward.to = forward.to.replace("192.168.1.", "192.168.2.");
            }
        }
        config
    }

    #[tokio::test]
    async fn a_config_is_read_without_its_secrets_over_the_socket_and_over_grpc() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        let (over_ws, tag) = read(&mut ws).await;
        let mut client = ConfigServiceClient::new(api.channel().await);
        let over_grpc = client
            .get_config(with_token(GetConfigRequest {}, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(over_grpc.config.as_ref(), Some(&over_ws));
        assert_eq!(over_grpc.tag, tag);
        assert_eq!(over_grpc.confirm_secs, 120);
        // A password is set, and it is not in what is read.
        let running = api.shared.world.borrow().config.clone();
        let hash = running.admin.as_ref().unwrap().password_hash.clone();
        assert!(hash.starts_with("$argon2id$"));
        assert_eq!(over_ws.admin.as_ref().unwrap().password_hash, "");
        assert_eq!(over_ws, secrets::redact(&running));
        assert_eq!(tag, secrets::tag(&running));
    }

    #[tokio::test]
    async fn validate_says_the_effects_and_the_caller() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        // The test's connection arrives at 127.0.0.1: let the World hold that on lan0's bridge,
        // so the router can tell which LAN is asking.
        api.shared.publisher.update(|world| {
            let mut addresses = (*world.addresses).clone();
            addresses.insert(openfeo_world::AddrFact {
                ifname: "br-lan0".to_owned(),
                net: "127.0.0.1/8".parse().unwrap(),
                peer: None,
                deprecated: false,
            });
            world.addresses = Arc::new(addresses);
        });
        let mut ws = api.ws_with(&token).await;
        let (config, _) = read(&mut ws).await;
        let Ok(response::Body::ValidateConfig(over_ws)) = asked(
            &mut ws,
            request::Body::ValidateConfig(ValidateConfigRequest {
                config: Some(moved(config.clone())),
            }),
        )
        .await
        else {
            panic!("a validation");
        };
        assert_eq!(over_ws.violations, Vec::new());
        assert_eq!(over_ws.effects.len(), 1);
        assert_eq!(over_ws.effects[0].subject, "lan0");
        assert_eq!(over_ws.effects[0].kind(), ConfigEffectKind::LanAddressMoves);
        let caller = over_ws.caller.clone().expect("the caller");
        assert_eq!(caller.lan, "lan0");
        assert!(caller.lan_changes);
        assert!(
            !caller.connection_drops,
            "it arrived at an address that is not the LAN's own"
        );
        assert_eq!(caller.router_after, "192.168.2.1");
        // The same over gRPC, and nothing was changed by asking.
        let mut client = ConfigServiceClient::new(api.channel().await);
        let over_grpc = client
            .validate_config(with_token(
                ValidateConfigRequest {
                    config: Some(moved(config.clone())),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(over_grpc, over_ws);
        assert_eq!(read(&mut ws).await.0, config);
        assert_eq!(api.shared.world.borrow().pending, None);
    }

    #[tokio::test]
    async fn validate_of_a_bad_config_says_only_what_is_wrong() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        let (mut config, _) = read(&mut ws).await;
        config.lans[0].ipv4 = "192.168.2.1/24".to_owned();
        let Ok(response::Body::ValidateConfig(said)) = asked(
            &mut ws,
            request::Body::ValidateConfig(ValidateConfigRequest {
                config: Some(config),
            }),
        )
        .await
        else {
            panic!("a validation");
        };
        assert!(said.violations.len() >= 2, "{:?}", said.violations);
        assert!(
            said.violations
                .iter()
                .any(|violation| violation.path.starts_with("lans[0].dhcp")),
            "{:?}",
            said.violations
        );
        assert_eq!(said.effects, Vec::new());
        assert_eq!(said.caller, None);
        // No config at all is the request's fault.
        let error = asked(
            &mut ws,
            request::Body::ValidateConfig(ValidateConfigRequest { config: None }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn an_apply_over_the_socket_is_confirmed_over_grpc() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        let (config, tag) = read(&mut ws).await;
        let Ok(response::Body::ApplyConfig(applied)) = asked(
            &mut ws,
            request::Body::ApplyConfig(ApplyConfigRequest {
                config: Some(moved(config.clone())),
                tag: tag.clone(),
                immediate: false,
                timeout_secs: 0,
            }),
        )
        .await
        else {
            panic!("applied");
        };
        assert_ne!(applied.tag, tag);
        assert!(api.shared.world.borrow().pending.is_some());
        // A second one waits, over either transport.
        let error = asked(
            &mut ws,
            request::Body::ApplyConfig(ApplyConfigRequest {
                config: Some(config.clone()),
                tag: applied.tag.clone(),
                immediate: true,
                timeout_secs: 0,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        let mut client = ConfigServiceClient::new(api.channel().await);
        client
            .confirm_config(with_token(ConfirmConfigRequest {}, &token))
            .await
            .unwrap();
        assert_eq!(api.shared.world.borrow().pending, None);
        assert_eq!(
            read(&mut ws).await,
            (moved(config.clone()), applied.tag.clone())
        );
        // Nothing left to revert, said as the precondition it is on both.
        let status = client
            .revert_config(with_token(RevertConfigRequest {}, &token))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        let error = asked(&mut ws, request::Body::RevertConfig(RevertConfigRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        // Applied over gRPC, reverted over the socket.
        let back = client
            .apply_config(with_token(
                ApplyConfigRequest {
                    config: Some(config.clone()),
                    tag: applied.tag,
                    immediate: false,
                    timeout_secs: 30,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(back.tag, tag);
        assert!(matches!(
            asked(&mut ws, request::Body::RevertConfig(RevertConfigRequest {})).await,
            Ok(response::Body::RevertConfig(_))
        ));
        assert_eq!(read(&mut ws).await.0, moved(config));
        // A stale tag is a precondition too; a bad window is the request's fault.
        let status = client
            .apply_config(with_token(
                ApplyConfigRequest {
                    config: Some(Config::default()),
                    tag,
                    immediate: false,
                    timeout_secs: 0,
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn the_state_pushed_to_a_subscriber_carries_the_pending_change_and_then_does_not() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut ws = api.ws_with(&token).await;
        let (config, tag) = read(&mut ws).await;
        let mut watcher = api.ws_with(&token).await;
        watcher.subscribe("state", 0).await;
        let first = watcher.next_state().await;
        assert_eq!(first.system.unwrap().pending_config, None);
        asked(
            &mut ws,
            request::Body::ApplyConfig(ApplyConfigRequest {
                config: Some(moved(config)),
                tag,
                immediate: false,
                timeout_secs: 45,
            }),
        )
        .await
        .unwrap();
        let pending = loop {
            if let Some(pending) = watcher.next_state().await.system.unwrap().pending_config {
                break pending;
            }
        };
        assert_eq!(pending.window_secs, 45);
        assert_eq!(
            pending.reverts_uptime_ms - pending.applied_uptime_ms,
            45_000
        );
        assert_eq!(pending.effects.len(), 1);
        assert_eq!(pending.effects[0].kind(), ConfigEffectKind::LanAddressMoves);
        asked(
            &mut ws,
            request::Body::ConfirmConfig(ConfirmConfigRequest {}),
        )
        .await
        .unwrap();
        loop {
            if watcher
                .next_state()
                .await
                .system
                .unwrap()
                .pending_config
                .is_none()
            {
                break;
            }
        }
    }

    #[tokio::test]
    async fn the_config_calls_need_a_session() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut client = ConfigServiceClient::new(api.channel().await);
        assert_eq!(
            client
                .get_config(GetConfigRequest {})
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        for code in [
            client
                .validate_config(with_token(ValidateConfigRequest::default(), "not-a-token"))
                .await
                .unwrap_err()
                .code(),
            client
                .apply_config(ApplyConfigRequest::default())
                .await
                .unwrap_err()
                .code(),
            client
                .confirm_config(ConfirmConfigRequest {})
                .await
                .unwrap_err()
                .code(),
            client
                .revert_config(RevertConfigRequest {})
                .await
                .unwrap_err()
                .code(),
        ] {
            assert_eq!(code, tonic::Code::Unauthenticated);
        }
        // A socket that has not said who it is gets no answer to a request: it is closed.
        let mut ws = api.ws(None).await.unwrap();
        ws.send(openfeo_config::api::client_msg::Body::Request(
            openfeo_config::api::Request {
                body: Some(request::Body::GetConfig(GetConfigRequest {})),
            },
        ))
        .await;
        assert_eq!(
            ws.closed_with().await,
            Some(crate::envelope::CLOSE_UNAUTHENTICATED)
        );
        // With a session it answers.
        let mut ws = api.ws_with(&token).await;
        assert_eq!(read(&mut ws).await.1.len(), 32);
    }

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
