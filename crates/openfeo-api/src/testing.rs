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
