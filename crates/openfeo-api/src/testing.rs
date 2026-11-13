// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Test support: the API bound to loopback over a fixture World, and a small HTTPS client that
//! trusts any certificate and calls the router by its name.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper_util::rt::TokioIo;
use openfeo_config::admin::ConfigState;
use openfeo_reconcile::fixtures;
use openfeo_runtime::Publisher;
use openfeo_world::health::HealthView;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::listener::Server;
use crate::server::tests::NoCounters;
use crate::server::{Limits, Shared};
use crate::{Admit, ApiDeps, Listen};

pub(crate) const HOST: &str = "openfeo.home.arpa";

/// Trusts whatever the server presents: the router's certificate is self-signed.
#[derive(Debug)]
struct AnyCertificate;

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS client config that trusts anything and offers these ALPN protocols.
pub(crate) fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

/// What came back.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl Reply {
    pub(crate) fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("{err}: {:?}", String::from_utf8_lossy(&self.body)))
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// The API on loopback.
pub(crate) struct TestApi {
    pub(crate) shared: Arc<Shared>,
    pub(crate) https: SocketAddr,
    pub(crate) http: SocketAddr,
    pub(crate) config_path: PathBuf,
    pub(crate) tls_dir: PathBuf,
    _dir: tempfile::TempDir,
    _health: watch::Sender<HealthView>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn anyone() -> Admit {
    Arc::new(|_, _| true)
}

pub(crate) async fn spawn_api(config_state: ConfigState) -> TestApi {
    spawn_api_full(config_state, Limits::default(), anyone()).await
}

pub(crate) async fn spawn_api_with_limits(limits: Limits) -> TestApi {
    spawn_api_full(ConfigState::Loaded, limits, anyone()).await
}

pub(crate) async fn spawn_api_full(
    config_state: ConfigState,
    limits: Limits,
    admit: Admit,
) -> TestApi {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "# the lab's\nconfig_version = 1\n").unwrap();
    let tls_dir = dir.path().join("tls");
    let mut world = fixtures::dhcp_world();
    // The WAN port has carrier, so the fixture's lease makes wan0 up.
    let p0 = Arc::make_mut(&mut world.links).get_mut("p0").unwrap();
    p0.up = true;
    p0.carrier = true;
    let (publisher, world) =
        Publisher::with_derive(world, Box::new(openfeo_reconcile::derive::derive));
    let publisher = Arc::new(publisher);
    publisher.update(|_| {});
    let (health_tx, health) = watch::channel(HealthView {
        healthy: true,
        unhealthy: Vec::new(),
    });
    let server = Server::bind(ApiDeps {
        world,
        publisher,
        health,
        counters: Arc::new(NoCounters),
        config_path: config_path.clone(),
        tls_dir: tls_dir.clone(),
        config_state,
        version: "0.4.0-test".to_owned(),
        build_epoch: 1_794_000_000,
        listen: Listen {
            https: "127.0.0.1:0".parse().unwrap(),
            http: "127.0.0.1:0".parse().unwrap(),
            admit,
        },
        limits,
        extra_host: None,
        confirm_secs: crate::keeper::DEFAULT_WINDOW_SECS,
    })
    .await
    .unwrap();
    let (shared, https, http) = (
        server.shared.clone(),
        server.https_addr().unwrap(),
        server.http_addr().unwrap(),
    );
    let task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    TestApi {
        shared,
        https,
        http,
        config_path,
        tls_dir,
        _dir: dir,
        _health: health_tx,
        task,
    }
}

impl TestApi {
    /// The API with the test password already set; the token of the client that set it.
    pub(crate) async fn with_password(password: &str) -> (TestApi, String) {
        let api = spawn_api(ConfigState::Loaded).await;
        let session = api
            .shared
            .set_initial_password("127.0.0.1".parse().unwrap(), password.to_owned())
            .await
            .unwrap();
        (api, session.token)
    }

    pub(crate) async fn tls(&self, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        let stream = TcpStream::connect(self.https).await.unwrap();
        TlsConnector::from(client_config(alpn))
            .connect(ServerName::try_from(HOST).unwrap(), stream)
            .await
            .unwrap()
    }

    /// One request over a fresh connection.
    pub(crate) async fn send(
        &self,
        tls: bool,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Reply {
        let mut request = hyper::Request::builder().method(method).uri(path);
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            request = request.header("host", HOST);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(Bytes::from(body))).unwrap();
        let response = if tls {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(self.tls(&[b"http/1.1"]).await))
                    .await
                    .unwrap();
            tokio::spawn(connection);
            sender.send_request(request).await.unwrap()
        } else {
            let stream = TcpStream::connect(self.http).await.unwrap();
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
            tokio::spawn(connection);
            sender.send_request(request).await.unwrap()
        };
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }

    pub(crate) async fn get(&self, path: &str) -> Reply {
        self.send(true, "GET", path, &[], Vec::new()).await
    }

    pub(crate) async fn get_with(&self, path: &str, token: &str) -> Reply {
        let bearer = format!("Bearer {token}");
        self.send(true, "GET", path, &[("authorization", &bearer)], Vec::new())
            .await
    }

    pub(crate) async fn post_json(&self, path: &str, json: &serde_json::Value) -> Reply {
        self.send(
            true,
            "POST",
            path,
            &[("content-type", "application/json")],
            serde_json::to_vec(json).unwrap(),
        )
        .await
    }
}

/// A WebSocket client speaking the envelope.
pub(crate) struct Ws {
    socket: tokio_tungstenite::WebSocketStream<TlsStream<TcpStream>>,
    next_id: u32,
}

/// What arrived on a socket.
#[derive(Debug)]
pub(crate) enum Got {
    Msg(Box<openfeo_config::api::ServerMsg>),
    Closed(Option<u16>),
}

impl TestApi {
    /// Open `/ws`; `Err` is the HTTP status of a refused upgrade.
    pub(crate) async fn ws(&self, origin: Option<&str>) -> Result<Ws, u16> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        let mut request = format!("wss://{HOST}/ws").into_client_request().unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("origin", origin.parse().unwrap());
        }
        match tokio_tungstenite::client_async(request, self.tls(&[b"http/1.1"]).await).await {
            Ok((socket, _)) => Ok(Ws { socket, next_id: 1 }),
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                Err(response.status().as_u16())
            }
            Err(other) => panic!("{other}"),
        }
    }

    /// A socket that has authenticated with `token`.
    pub(crate) async fn ws_with(&self, token: &str) -> Ws {
        let mut ws = self.ws(None).await.unwrap();
        ws.auth(token).await;
        ws
    }

    /// A gRPC channel to the API over TLS and HTTP/2.
    #[cfg(feature = "client")]
    pub(crate) async fn channel(&self) -> tonic::transport::Channel {
        let addr = self.https;
        tonic::transport::Endpoint::from_static("http://openfeo.home.arpa")
            .connect_with_connector(tower::service_fn(move |_: hyper::Uri| async move {
                let stream = TcpStream::connect(addr).await?;
                let tls = TlsConnector::from(client_config(&[b"h2"]))
                    .connect(ServerName::try_from(HOST).unwrap(), stream)
                    .await?;
                Ok::<_, std::io::Error>(TokioIo::new(tls))
            }))
            .await
            .unwrap()
    }
}

/// A gRPC request carrying `token`.
#[cfg(feature = "client")]
pub(crate) fn with_token<T>(message: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if !token.is_empty() {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    request
}

impl Ws {
    pub(crate) async fn send(&mut self, body: openfeo_config::api::client_msg::Body) -> u32 {
        use futures::SinkExt as _;
        use prost::Message as _;
        let id = self.next_id;
        self.next_id += 1;
        let message = openfeo_config::api::ClientMsg {
            id,
            body: Some(body),
        };
        self.socket
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                message.encode_to_vec().into(),
            ))
            .await
            .unwrap();
        id
    }

    /// The next envelope message or the close, within five seconds.
    pub(crate) async fn got(&mut self) -> Got {
        use futures::StreamExt as _;
        use prost::Message as _;
        use tokio_tungstenite::tungstenite::Message;
        loop {
            let next = tokio::time::timeout(std::time::Duration::from_secs(5), self.socket.next())
                .await
                .expect("something within 5 s");
            match next {
                Some(Ok(Message::Binary(bytes))) => {
                    return Got::Msg(Box::new(
                        openfeo_config::api::ServerMsg::decode(bytes.as_ref()).unwrap(),
                    ));
                }
                Some(Ok(Message::Close(frame))) => {
                    return Got::Closed(frame.map(|frame| u16::from(frame.code)));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Got::Closed(None),
            }
        }
    }

    pub(crate) async fn msg(&mut self) -> openfeo_config::api::ServerMsg {
        match self.got().await {
            Got::Msg(message) => *message,
            Got::Closed(code) => panic!("closed with {code:?}"),
        }
    }

    /// Read until the socket closes; the close code.
    pub(crate) async fn closed_with(&mut self) -> Option<u16> {
        loop {
            if let Got::Closed(code) = self.got().await {
                return code;
            }
        }
    }

    pub(crate) async fn auth(&mut self, token: &str) {
        use openfeo_config::api::{Auth, client_msg::Body, server_msg};
        let id = self
            .send(Body::Auth(Auth {
                token: token.to_owned(),
            }))
            .await;
        let ack = self.msg().await;
        assert_eq!(ack.id, id);
        assert!(
            matches!(ack.body, Some(server_msg::Body::Response(_))),
            "{ack:?}"
        );
    }

    pub(crate) async fn subscribe(&mut self, topic: &str, backlog: u32) {
        use openfeo_config::api::{Subscribe, client_msg::Body};
        let id = self
            .send(Body::Subscribe(Subscribe {
                topic: topic.to_owned(),
                backlog,
            }))
            .await;
        // Pushes for other topics may arrive before the acknowledgement.
        loop {
            if self.msg().await.id == id {
                return;
            }
        }
    }

    /// The reply to `request`, skipping pushes.
    pub(crate) async fn ask(
        &mut self,
        request: openfeo_config::api::request::Body,
    ) -> openfeo_config::api::server_msg::Body {
        use openfeo_config::api::{Request, client_msg::Body};
        let id = self
            .send(Body::Request(Request {
                body: Some(request),
            }))
            .await;
        loop {
            let message = self.msg().await;
            if message.id == id {
                return message.body.unwrap();
            }
        }
    }

    pub(crate) async fn next_state(&mut self) -> openfeo_config::state::State {
        use openfeo_config::api::{Telemetry, server_msg, telemetry};
        loop {
            if let Some(server_msg::Body::Telemetry(Telemetry {
                body: Some(telemetry::Body::State(state)),
                ..
            })) = self.msg().await.body
            {
                return state;
            }
        }
    }

    pub(crate) async fn next_counters(&mut self) -> openfeo_config::state::Counters {
        use openfeo_config::api::{Telemetry, server_msg, telemetry};
        loop {
            if let Some(server_msg::Body::Telemetry(Telemetry {
                body: Some(telemetry::Body::Counters(counters)),
                ..
            })) = self.msg().await.body
            {
                return counters;
            }
        }
    }

    pub(crate) async fn next_event(&mut self) -> openfeo_config::events::Event {
        use openfeo_config::api::server_msg;
        loop {
            if let Some(server_msg::Body::Event(event)) = self.msg().await.body {
                return event;
            }
        }
    }
}
