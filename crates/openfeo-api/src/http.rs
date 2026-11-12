// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The plain HTTP calls (SPEC §8.3) and the page where the panel will be. Bodies are protobuf,
//! or the canonical JSON mapping when the request asks (`?format=json` on a GET, a JSON
//! `content-type` on a POST). Every answer carries the same locked-down headers, and a request
//! that does not call the router by its own name is answered 421 before anything else.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, RawQuery, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, HOST, ORIGIN, REFERRER_POLICY, RETRY_AFTER, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use openfeo_config::api::{
    ErrorCode, GetStateResponse, LoginRequest, LoginResponse, SetInitialPasswordRequest,
    SetInitialPasswordResponse,
};
use prost::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::gate::{host_allowed, origin_allowed};
use crate::limits::MAX_BODY;
use crate::server::{ApiError, Shared};

/// The address a connection came from, attached to each of its requests by the listener.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

const PROTOBUF: &str = "application/x-protobuf";
const JSON: &str = "application/json";
/// Own origin only: no inline script, no `eval`, nothing framed or fetched from elsewhere.
const CSP: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// How a call's bodies are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Protobuf,
    Json,
}

fn wire(headers: &HeaderMap, query: Option<&str>) -> Wire {
    let json_body = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(JSON));
    let json_asked = query.is_some_and(|query| query.split('&').any(|pair| pair == "format=json"));
    if json_body || json_asked {
        Wire::Json
    } else {
        Wire::Protobuf
    }
}

fn encode<T: Message + Serialize>(wire: Wire, message: &T) -> (&'static str, Vec<u8>) {
    match wire {
        Wire::Protobuf => (PROTOBUF, message.encode_to_vec()),
        // A generated message always serialises; an empty body would be the worst case.
        Wire::Json => (JSON, serde_json::to_vec(message).unwrap_or_default()),
    }
}

fn decode<T: Message + Default + DeserializeOwned>(wire: Wire, body: &[u8]) -> Result<T, ApiError> {
    let decoded = match wire {
        Wire::Protobuf => T::decode(body).ok(),
        Wire::Json => serde_json::from_slice(body).ok(),
    };
    decoded.ok_or_else(|| ApiError::new(ErrorCode::InvalidArgument, "the body does not parse"))
}

/// The HTTP status for an error code.
#[must_use]
pub fn status_of(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorCode::FailedPrecondition => StatusCode::CONFLICT,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unspecified | ErrorCode::DataLoss | ErrorCode::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn answer<T: Message + Serialize>(wire: Wire, status: StatusCode, message: &T) -> Response {
    let (content_type, body) = encode(wire, message);
    (status, [(CONTENT_TYPE, content_type)], body).into_response()
}

fn refuse(wire: Wire, error: &ApiError) -> Response {
    let mut response = answer(wire, status_of(error.code), &error.to_pb());
    if error.code == ErrorCode::ResourceExhausted
        && let Ok(value) = HeaderValue::from_str(&error.retry_after_secs.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// The bearer token of a request, if it carries one.
#[must_use]
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

async fn status(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    answer(
        wire(&headers, query.as_deref()),
        StatusCode::OK,
        &shared.status(),
    )
}

async fn set_password(
    State(shared): State<Arc<Shared>>,
    Extension(Peer(peer)): Extension<Peer>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let wire = wire(&headers, query.as_deref());
    let request: SetInitialPasswordRequest = match decode(wire, &body) {
        Ok(request) => request,
        Err(error) => return refuse(wire, &error),
    };
    match shared
        .set_initial_password(peer.ip(), request.password)
        .await
    {
        Ok(session) => answer(
            wire,
            StatusCode::OK,
            &SetInitialPasswordResponse {
                session: Some(session),
            },
        ),
        Err(error) => refuse(wire, &error),
    }
}

async fn login(
    State(shared): State<Arc<Shared>>,
    Extension(Peer(peer)): Extension<Peer>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let wire = wire(&headers, query.as_deref());
    let request: LoginRequest = match decode(wire, &body) {
        Ok(request) => request,
        Err(error) => return refuse(wire, &error),
    };
    match shared.login(peer.ip(), request.password).await {
        Ok(session) => answer(
            wire,
            StatusCode::OK,
            &LoginResponse {
                session: Some(session),
            },
        ),
        Err(error) => refuse(wire, &error),
    }
}

async fn get_state(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let wire = wire(&headers, query.as_deref());
    if !bearer(&headers).is_some_and(|token| shared.authenticate(token)) {
        return refuse(
            wire,
            &ApiError::new(ErrorCode::Unauthenticated, "log in first"),
        );
    }
    answer(
        wire,
        StatusCode::OK,
        &GetStateResponse {
            state: Some(shared.state()),
        },
    )
}

async fn no_such_call(headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    refuse(
        wire(&headers, query.as_deref()),
        &ApiError::new(ErrorCode::NotFound, "no such call"),
    )
}

/// The panel (SPEC §8.4): every path that is not the API's is one of its files or its page.
async fn panel(method: Method, uri: axum::http::Uri, headers: HeaderMap) -> Response {
    crate::assets::serve(crate::assets::PANEL, &method, uri.path(), &headers)
}

fn is_grpc(request: &Request) -> bool {
    request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
}

/// One of the plain HTTP calls under `/api`, as opposed to a gRPC call, the WebSocket or the
/// panel's files.
fn is_plain_call(request: &Request) -> bool {
    request.uri().path().starts_with("/api") && !is_grpc(request)
}

/// Around every request: the host check first (SPEC §9), and the same headers on every answer.
async fn guard(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(axum::http::uri::Authority::as_str)
        });
    let ours = host.is_some_and(|host| host_allowed(host, &shared.names(), &shared.world.borrow()));
    // A body announced as too large is refused on its announced length, before any of it is
    // read; one that does not say is cut off by the limit as it arrives.
    let too_large = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_BODY as u64);
    // A browser says where a request comes from. One from another site is refused, and a POST
    // must be in a form no page can send without asking first (a plain form post or a
    // `text/plain` body needs no preflight): while no password is set, a page a LAN user
    // happens to open must not be able to set one.
    let foreign = request.headers().get(ORIGIN).is_some_and(|origin| {
        !origin.to_str().is_ok_and(|origin| {
            origin_allowed(Some(origin), &shared.names(), &shared.world.borrow())
        })
    });
    let untyped = is_plain_call(&request)
        && request.method() == Method::POST
        && !request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with(JSON) || value.starts_with(PROTOBUF));
    let mut response = if !ours {
        StatusCode::MISDIRECTED_REQUEST.into_response()
    } else if foreign {
        StatusCode::FORBIDDEN.into_response()
    } else if untyped {
        StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()
    } else if too_large {
        // The unread body cannot be skipped, so the connection ends with the answer.
        (StatusCode::PAYLOAD_TOO_LARGE, [(CONNECTION, "close")]).into_response()
    } else if is_plain_call(&request) {
        // A plain call is over quickly or not at all: a body that trickles in does not hold
        // the request open. (The WebSocket and gRPC streams live as long as they are used.)
        match tokio::time::timeout(shared.limits.request, next.run(request)).await {
            Ok(response) => response,
            Err(_) => (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response(),
        }
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// The routes of M4 part 1a's plain HTTP side, over `shared`. The caller adds the WebSocket
/// and gRPC, then [`finish`]es the router.
pub fn routes() -> Router<Arc<Shared>> {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/password", post(set_password))
        .route("/api/login", post(login))
        .route("/api/state", get(get_state))
        .route("/api/{*call}", any(no_such_call))
        .route("/api", any(no_such_call))
        .fallback(panel)
}

/// Close the router over `shared`: the body limit, the host check and the headers apply to
/// every route in it.
pub fn finish(router: Router<Arc<Shared>>, shared: Arc<Shared>) -> Router {
    router
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(shared.clone(), guard))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openfeo_config::admin::ConfigState;
    use openfeo_config::api::{Error, GetStatusResponse};
    use openfeo_config::state::WanPhase;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::server::Limits;
    use crate::server::tests::{PASSWORD, problem};
    use crate::testing::{TestApi, spawn_api, spawn_api_full, spawn_api_with_limits};

    #[tokio::test]
    async fn the_security_headers_are_on_a_panel_file_too() {
        let api = spawn_api(ConfigState::Loaded).await;
        for path in ["/", "/some/route/of/the/panel"] {
            let page = api.get(path).await;
            assert_eq!(page.status, 200, "{path}");
            for header in [
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
            ] {
                assert!(page.header(header).is_some(), "{path}: no {header}");
            }
        }
        // A file under assets/ that the binary does not hold is not the page.
        assert_eq!(api.get("/assets/nothing.js").await.status, 404);
    }

    #[tokio::test]
    async fn a_router_with_no_password_answers_only_status_and_the_first_password() {
        let api = spawn_api(ConfigState::Loaded).await;
        let status: GetStatusResponse = api.get("/api/status?format=json").await.json();
        assert!(status.needs_password && !status.config_refused);
        assert_eq!(status.hostname, "openfeo");
        assert_eq!(status.tls_fingerprint.len(), 95);
        assert_eq!(api.get("/api/state").await.status, 401);
        assert_eq!(
            api.post_json("/api/login", &json!({"password": PASSWORD}))
                .await
                .status,
            401
        );
        let set = api
            .post_json("/api/password", &json!({"password": PASSWORD}))
            .await;
        assert_eq!(set.status, 200);
        let session: SetInitialPasswordResponse = set.json();
        let token = session.session.unwrap().token;
        assert_eq!(api.get_with("/api/state", &token).await.status, 200);
        assert_eq!(
            api.post_json("/api/password", &json!({"password": "another-password"}))
                .await
                .status,
            409
        );
        assert!(
            std::fs::read_to_string(&api.config_path)
                .unwrap()
                .contains("password_hash = \"$argon2id$")
        );
    }

    #[tokio::test]
    async fn two_first_passwords_at_once_over_http_and_exactly_one_wins() {
        let api = spawn_api(ConfigState::Loaded).await;
        let (first, second) = (
            json!({"password": "first-password-a"}),
            json!({"password": "first-password-b"}),
        );
        let (a, b) = tokio::join!(
            api.post_json("/api/password", &first),
            api.post_json("/api/password", &second)
        );
        let mut statuses = [a.status, b.status];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409]);
        let winner = if a.status == 200 {
            "first-password-a"
        } else {
            "first-password-b"
        };
        assert_eq!(
            api.post_json("/api/login", &json!({"password": winner}))
                .await
                .status,
            200
        );
    }

    #[tokio::test]
    async fn a_wrong_password_is_401_and_the_next_try_is_429_with_retry_after() {
        let (api, _) = TestApi::with_password(PASSWORD).await;
        let wrong = api
            .post_json("/api/login", &json!({"password": "wrong-password-1"}))
            .await;
        assert_eq!(wrong.status, 401);
        assert_eq!(wrong.json::<Error>().retry_after_secs, 1);
        let waiting = api
            .post_json("/api/login", &json!({"password": PASSWORD}))
            .await;
        assert_eq!(waiting.status, 429);
        assert_eq!(waiting.header("retry-after"), Some("1"));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let right = api
            .post_json("/api/login", &json!({"password": PASSWORD}))
            .await;
        assert_eq!(right.status, 200);
        assert_eq!(
            right.json::<LoginResponse>().session.unwrap().token.len(),
            43
        );
    }

    #[tokio::test]
    async fn a_foreign_host_is_misdirected_and_every_answer_is_locked_down() {
        let api = spawn_api(ConfigState::Loaded).await;
        let foreign = api
            .send(
                true,
                "GET",
                "/api/status",
                &[("host", "evil.example")],
                Vec::new(),
            )
            .await;
        assert_eq!(foreign.status, 421);
        assert_eq!(
            foreign.header("x-frame-options"),
            Some("DENY"),
            "even a refusal"
        );
        let ok = api.get("/").await;
        assert_eq!(ok.status, 200);
        assert!(
            ok.header("content-security-policy")
                .unwrap()
                .contains("default-src 'self'")
        );
        assert_eq!(ok.header("x-frame-options"), Some("DENY"));
        assert_eq!(ok.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(ok.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(ok.header("access-control-allow-origin"), None);
        assert_eq!(ok.header("strict-transport-security"), None);
        assert!(
            ok.text()
                .contains("The panel was not built into this binary")
        );
        assert_eq!(
            api.get("/some/panel/route").await.status,
            200,
            "the panel's own routes"
        );
        assert_eq!(api.get("/api/nope").await.status, 404);
        assert_eq!(
            api.send(true, "DELETE", "/", &[], Vec::new()).await.status,
            405
        );
        let redirect = api
            .send(false, "GET", "/anything?x=1", &[], Vec::new())
            .await;
        assert_eq!(redirect.status, 308);
        assert_eq!(
            redirect.header("location"),
            Some("https://openfeo.home.arpa/anything?x=1")
        );
        let foreign = api
            .send(false, "GET", "/", &[("host", "evil.example")], Vec::new())
            .await;
        assert_eq!(foreign.status, 421);
        assert_eq!(foreign.header("location"), None);
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_before_it_is_read() {
        let api = spawn_api(ConfigState::Loaded).await;
        // Only the head is sent: the answer must not wait for ten megabytes that never come.
        let mut tls = api.tls(&[b"http/1.1"]).await;
        tls.write_all(
            b"POST /api/login HTTP/1.1\r\nhost: openfeo.home.arpa\r\ncontent-type: application/json\r\ncontent-length: 10485760\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut head))
            .await
            .expect("answered without the body")
            .unwrap();
        assert_eq!(&head, b"HTTP/1.1 413");
        assert_eq!(
            api.post_json("/api/password", &json!({"password": "x".repeat(300)}))
                .await
                .status,
            400
        );
        let not_utf8 = api
            .send(
                true,
                "POST",
                "/api/login",
                &[("content-type", "application/json")],
                vec![0xff, 0xfe],
            )
            .await;
        assert_eq!(not_utf8.status, 400);
        let not_protobuf = api
            .send(
                true,
                "POST",
                "/api/login",
                &[("content-type", "application/x-protobuf")],
                vec![0xff, 0xff, 0xff],
            )
            .await;
        assert_eq!(not_protobuf.status, 400);
    }

    #[tokio::test]
    async fn a_handshake_that_never_finishes_is_dropped_and_frees_its_slot() {
        let api = spawn_api_with_limits(Limits {
            handshake: Duration::from_millis(200),
            connections: 2,
            ..Limits::default()
        })
        .await;
        let idle = [
            TcpStream::connect(api.https).await.unwrap(),
            TcpStream::connect(api.https).await.unwrap(),
        ];
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            api.get("/api/status").await.status,
            200,
            "the two stalled connections were dropped"
        );
        drop(idle);
    }

    #[tokio::test]
    async fn a_client_that_finishes_tls_and_says_nothing_is_dropped_and_frees_its_slot() {
        let api = spawn_api_with_limits(Limits {
            handshake: Duration::from_millis(200),
            connections: 2,
            ..Limits::default()
        })
        .await;
        let mut silent = [api.tls(&[b"http/1.1"]).await, api.tls(&[b"h2"]).await];
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            api.get("/api/status").await.status,
            200,
            "both silent connections were dropped"
        );
        for tls in &mut silent {
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut byte))
                .await
                .expect("closed");
            assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        }
    }

    #[tokio::test]
    async fn an_http2_connection_that_goes_quiet_is_closed() {
        let api = spawn_api_with_limits(Limits {
            idle: Duration::from_millis(300),
            connections: 1,
            ..Limits::default()
        })
        .await;
        let mut tls = api.tls(&[b"h2"]).await;
        // The preface and an empty SETTINGS frame: a connection, and then nothing more.
        tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        let mut sink = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut sink)).await;
        assert!(ended.is_ok(), "still open after 3 s");
        assert_eq!(
            api.get("/api/status").await.status,
            200,
            "its one place came free"
        );
    }

    #[tokio::test]
    async fn a_body_that_never_finishes_is_answered_408() {
        let api = spawn_api_with_limits(Limits {
            request: Duration::from_millis(300),
            ..Limits::default()
        })
        .await;
        let mut tls = api.tls(&[b"http/1.1"]).await;
        tls.write_all(
            b"POST /api/login HTTP/1.1\r\nhost: openfeo.home.arpa\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{",
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut head))
            .await
            .expect("answered though the body never came")
            .unwrap();
        assert_eq!(&head, b"HTTP/1.1 408");
    }

    #[tokio::test]
    async fn one_source_cannot_take_every_connection() {
        let api = spawn_api_with_limits(Limits {
            per_source: 2,
            ..Limits::default()
        })
        .await;
        // Two connections held open by sockets that are doing something.
        let held = [api.ws(None).await.unwrap(), api.ws(None).await.unwrap()];
        let third = TcpStream::connect(api.https).await.unwrap();
        let mut third = third;
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), third.read(&mut byte))
            .await
            .expect("the third is closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        drop(held);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(api.get("/api/status").await.status, 200, "places came free");
    }

    #[tokio::test]
    async fn a_page_on_another_site_cannot_set_the_first_password() {
        let api = spawn_api(ConfigState::Loaded).await;
        let protobuf = SetInitialPasswordRequest {
            password: "someone-elses-password".to_owned(),
        }
        .encode_to_vec();
        // What a page can send with no preflight: a simple content type.
        for content_type in [
            None,
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
        ] {
            let headers: Vec<(&str, &str)> = content_type
                .map(|value| ("content-type", value))
                .into_iter()
                .collect();
            let reply = api
                .send(true, "POST", "/api/password", &headers, protobuf.clone())
                .await;
            assert_eq!(reply.status, 415, "{content_type:?}");
        }
        // And what it sends when it does ask: its own origin.
        let foreign = api
            .send(
                true,
                "POST",
                "/api/password",
                &[
                    ("content-type", "application/json"),
                    ("origin", "https://evil.example"),
                ],
                br#"{"password":"someone-elses-password"}"#.to_vec(),
            )
            .await;
        assert_eq!(foreign.status, 403);
        let read = api
            .send(
                true,
                "GET",
                "/api/status",
                &[("origin", "https://evil.example")],
                Vec::new(),
            )
            .await;
        assert_eq!(read.status, 403);
        assert!(api.shared.status().needs_password, "nothing was set");
        let own = api
            .send(
                true,
                "POST",
                "/api/password",
                &[
                    ("content-type", "application/x-protobuf"),
                    ("origin", "https://openfeo.home.arpa"),
                ],
                SetInitialPasswordRequest {
                    password: PASSWORD.to_owned(),
                }
                .encode_to_vec(),
            )
            .await;
        assert_eq!(own.status, 200, "the panel's own origin, in protobuf");
    }

    #[tokio::test]
    async fn a_client_the_gate_refuses_is_dropped_before_tls() {
        let api = spawn_api_full(
            ConfigState::Loaded,
            Limits::default(),
            std::sync::Arc::new(crate::gate::client_admitted),
        )
        .await;
        let mut stream = TcpStream::connect(api.https).await.unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .expect("closed at once");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "loopback is not a private LAN: {read:?}"
        );
    }

    #[tokio::test]
    async fn a_config_file_that_cannot_be_read_offers_no_first_password_over_http() {
        let api = spawn_api(ConfigState::Refused {
            problem: problem("not TOML"),
            readable: false,
        })
        .await;
        let status: GetStatusResponse = api.get("/api/status?format=json").await.json();
        assert!(!status.needs_password && status.config_refused);
        assert_eq!(
            api.post_json("/api/password", &json!({"password": PASSWORD}))
                .await
                .status,
            409
        );
    }

    #[tokio::test]
    async fn state_as_json_and_as_protobuf_are_the_same_state() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let as_json: GetStateResponse = api.get_with("/api/state?format=json", &token).await.json();
        let reply = api.get_with("/api/state", &token).await;
        assert_eq!(reply.header("content-type"), Some("application/x-protobuf"));
        let as_protobuf = GetStateResponse::decode(reply.body.as_ref()).unwrap();
        let (json, protobuf) = (as_json.state.unwrap(), as_protobuf.state.unwrap());
        assert_eq!(json.wans, protobuf.wans);
        assert_eq!(json.lans, protobuf.lans);
        assert_eq!(json.wans[0].phase(), WanPhase::Up);
        assert_eq!(json.wans[0].ipv4, "203.0.113.100/24");
        assert_eq!(json.system.unwrap().tls_fingerprint.len(), 95);
        assert_eq!(api.get_with("/api/state", "not-a-token").await.status, 401);
    }

    #[tokio::test]
    async fn the_certificate_is_kept_and_presented_again_after_a_restart() {
        let api = spawn_api(ConfigState::Loaded).await;
        let first: GetStatusResponse = api.get("/api/status?format=json").await.json();
        assert!(api.tls_dir.join("key.pem").exists());
        let (der, _, meta) = crate::cert::load(&api.tls_dir).unwrap().unwrap();
        assert_eq!(crate::cert::fingerprint(&der), first.tls_fingerprint);
        assert_eq!(meta.names, ["openfeo", "openfeo.home.arpa"]);
    }

    /// The API follows a config that changes while it runs: the router renamed is issued a
    /// certificate for its new names (with the key it had) and answers to them at once.
    #[tokio::test]
    async fn a_renamed_router_is_reissued_a_certificate_and_takes_its_new_name() {
        let api = spawn_api(ConfigState::Loaded).await;
        let first: GetStatusResponse = api.get("/api/status?format=json").await.json();
        let key = std::fs::read(api.tls_dir.join("key.pem")).unwrap();
        assert_eq!(api.shared.names().fqdn, "openfeo.home.arpa");
        let mut fingerprint = api.shared.fingerprint.subscribe();
        api.shared.publisher.update(|world| {
            let mut config = (*world.config).clone();
            config.system.get_or_insert_with(Default::default).hostname = "edge".to_owned();
            world.config = std::sync::Arc::new(config);
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fingerprint.wait_for(|now| *now != first.tls_fingerprint),
        )
        .await
        .expect("the certificate was looked at again when the World changed")
        .unwrap();
        let (der, _, meta) = crate::cert::load(&api.tls_dir).unwrap().unwrap();
        assert_eq!(meta.names, ["edge", "edge.home.arpa"]);
        assert_eq!(
            crate::cert::fingerprint(&der),
            *api.shared.fingerprint.borrow()
        );
        assert_eq!(
            std::fs::read(api.tls_dir.join("key.pem")).unwrap(),
            key,
            "reissued with its key"
        );
        // Which hosts pass follows too.
        let names = api.shared.names();
        assert_eq!(
            (names.hostname.as_str(), names.fqdn.as_str()),
            ("edge", "edge.home.arpa")
        );
        let world = api.shared.world.borrow().clone();
        assert!(crate::gate::host_allowed("edge.home.arpa", &names, &world));
        assert!(!crate::gate::host_allowed(
            "openfeo.home.arpa",
            &names,
            &world
        ));
    }
}
