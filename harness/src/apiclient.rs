// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The API's clients for the scenarios (SPEC §8.3, §11): plain HTTP calls, the WebSocket
//! envelope and gRPC, each made from inside a namespace (a LAN host's, or the ISP's to prove
//! nothing answers there). Every call runs on a thread that has entered the namespace, on a
//! runtime of its own, so the sockets are that namespace's. The router's certificate is
//! self-signed: these clients trust whatever is presented and hand it back for the scenario
//! to judge.

#![allow(unsafe_code)] // setns(2) on the calling thread, as `lanclient` does

use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use nix::sched::{CloneFlags, setns};
use openfeo_api::pb::state_service_client::StateServiceClient;
use openfeo_config::api::{
    Auth, ClientMsg, GetStateRequest, Request, ServerMsg, Subscribe, client_msg, request,
    server_msg, telemetry,
};
use openfeo_config::events::Event;
use openfeo_config::state::{Counters, State};
use prost::Message as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite;

use crate::netns::NetNs;

/// How long any one connect, handshake or read may take.
const STEP: Duration = Duration::from_secs(10);

/// Trusts whatever the server presents: the scenario compares the fingerprint itself.
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

fn tls_config(alpn: &[u8]) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

async fn within<T, E>(what: &str, future: impl Future<Output = Result<T, E>>) -> Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    tokio::time::timeout(STEP, future)
        .await
        .map_err(|_| anyhow!("{what}: nothing within {} s", STEP.as_secs()))?
        .with_context(|| what.to_owned())
}

/// One HTTP answer.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The headers, names in lower case.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// The certificate the server presented, DER, when the call was over TLS.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl Reply {
    /// A header's value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body as text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON.
    ///
    /// # Errors
    ///
    /// When it does not parse as `T`.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).with_context(|| format!("not JSON: {}", self.text()))
    }
}

/// The router's API as one namespace sees it.
#[derive(Debug, Clone)]
pub struct Api {
    ns: PathBuf,
    /// The router's address and HTTPS port.
    https: SocketAddr,
    /// The name the router is called by (`Host`, SNI, `:authority`).
    host: String,
}

impl Api {
    /// The API at `https` as a client in `ns` reaches it, calling the router `host`.
    #[must_use]
    pub fn on(ns: &NetNs, https: SocketAddr, host: &str) -> Api {
        Api {
            ns: ns.path(),
            https,
            host: host.to_owned(),
        }
    }

    /// The same API called by another name or address literal.
    #[must_use]
    pub fn as_host(&self, host: &str) -> Api {
        Api {
            host: host.to_owned(),
            ..self.clone()
        }
    }

    /// Run `work` on a fresh thread inside the namespace, on a runtime of its own.
    fn inside<T, F, Fut>(&self, work: F) -> Result<T>
    where
        T: Send,
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T>>,
    {
        let ns = File::open(&self.ns).with_context(|| format!("open {}", self.ns.display()))?;
        std::thread::scope(|scope| {
            scope
                .spawn(move || -> Result<T> {
                    setns(&ns, CloneFlags::CLONE_NEWNET).context("setns")?;
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("runtime")?
                        .block_on(work())
                })
                .join()
                .map_err(|_| anyhow!("the API client thread panicked"))?
        })
    }

    async fn tls(&self, alpn: &[u8]) -> Result<TlsStream<TcpStream>> {
        let stream = within("connect", TcpStream::connect(self.https)).await?;
        // SNI must be a name; an address literal gets the router's default name.
        let sni = if self.host.parse::<std::net::IpAddr>().is_ok() || self.host.starts_with('[') {
            "openfeo".to_owned()
        } else {
            self.host.clone()
        };
        let name = ServerName::try_from(sni).context("server name")?;
        within(
            "tls handshake",
            TlsConnector::from(tls_config(alpn)?).connect(name, stream),
        )
        .await
    }

    /// Whether a TCP connection to the router's address on `port` is accepted within
    /// `timeout`, from inside the namespace.
    ///
    /// # Errors
    ///
    /// When the namespace cannot be entered.
    pub fn connects(&self, port: u16, timeout: Duration) -> Result<bool> {
        let target = SocketAddr::new(self.https.ip(), port);
        self.inside(|| async move {
            Ok(matches!(
                tokio::time::timeout(timeout, TcpStream::connect(target)).await,
                Ok(Ok(_))
            ))
        })
    }

    /// One request on a fresh connection: over TLS to the HTTPS port, or in the clear to port
    /// 80. `Host` is this client's name for the router unless `headers` gives one.
    ///
    /// # Errors
    ///
    /// When the namespace cannot be entered, nothing answers in time, or the exchange fails.
    pub fn request(
        &self,
        tls: bool,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Reply> {
        self.inside(|| async move {
            let mut request = hyper::Request::builder().method(method).uri(path);
            if !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("host"))
            {
                request = request.header("host", self.host.as_str());
            }
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let request = request.body(Full::new(Bytes::copy_from_slice(body)))?;
            let (response, peer_cert_der) = if tls {
                let stream = self.tls(b"http/1.1").await?;
                let cert = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|cert| cert.to_vec());
                let (mut sender, connection) = within(
                    "http handshake",
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)),
                )
                .await?;
                tokio::spawn(connection);
                (within("request", sender.send_request(request)).await?, cert)
            } else {
                let plain = SocketAddr::new(self.https.ip(), 80);
                let stream = within("connect", TcpStream::connect(plain)).await?;
                let (mut sender, connection) = within(
                    "http handshake",
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)),
                )
                .await?;
                tokio::spawn(connection);
                (within("request", sender.send_request(request)).await?, None)
            };
            let (parts, body) = response.into_parts();
            let body = within("body", body.collect()).await?.to_bytes().to_vec();
            Ok(Reply {
                status: parts.status.as_u16(),
                headers: parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect(),
                body,
                peer_cert_der,
            })
        })
    }

    /// `GET path` over HTTPS, with a bearer token when given.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request).
    pub fn get(&self, path: &str, token: Option<&str>) -> Result<Reply> {
        let bearer = token.map(|token| format!("Bearer {token}"));
        let headers: Vec<(&str, &str)> = bearer
            .iter()
            .map(|bearer| ("authorization", bearer.as_str()))
            .collect();
        self.request(true, "GET", path, &headers, &[])
    }

    /// `POST path` over HTTPS with a JSON body.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request).
    pub fn post(&self, path: &str, json: &serde_json::Value) -> Result<Reply> {
        self.request(
            true,
            "POST",
            path,
            &[("content-type", "application/json")],
            &serde_json::to_vec(json)?,
        )
    }

    fn token_of(reply: &Reply, what: &str) -> Result<String> {
        if reply.status != 200 {
            bail!("{what}: {} {}", reply.status, reply.text());
        }
        let json: serde_json::Value = reply.json()?;
        json["session"]["token"]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("{what}: no token in {}", reply.text()))
    }

    /// Set the first password; the token of the session it opens.
    ///
    /// # Errors
    ///
    /// When the call fails or is refused.
    pub fn claim(&self, password: &str) -> Result<String> {
        let reply = self.post(
            "/api/password",
            &serde_json::json!({ "password": password }),
        )?;
        Self::token_of(&reply, "set the first password")
    }

    /// Log in; the token.
    ///
    /// # Errors
    ///
    /// When the call fails or is refused.
    pub fn login(&self, password: &str) -> Result<String> {
        let reply = self.post("/api/login", &serde_json::json!({ "password": password }))?;
        Self::token_of(&reply, "log in")
    }

    /// The state over gRPC.
    ///
    /// # Errors
    ///
    /// When the channel cannot be opened or the call is refused.
    pub fn grpc_state(&self, token: &str) -> Result<State> {
        self.inside(|| async move {
            let this = self.clone();
            let endpoint =
                tonic::transport::Endpoint::from_shared(format!("http://{}", self.host))?;
            let channel = within(
                "grpc connect",
                endpoint.connect_with_connector(tower::service_fn(move |_: hyper::Uri| {
                    let this = this.clone();
                    async move {
                        this.tls(b"h2")
                            .await
                            .map(TokioIo::new)
                            .map_err(|err| std::io::Error::other(format!("{err:#}")))
                    }
                })),
            )
            .await?;
            let mut request = tonic::Request::new(GetStateRequest {});
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse()?);
            let reply = within(
                "GetState",
                StateServiceClient::new(channel).get_state(request),
            )
            .await?;
            reply.into_inner().state.context("no state in the reply")
        })
    }

    /// Open `/ws`, with this `Origin` if any. `Ok(Err(status))` is a refused upgrade.
    ///
    /// # Errors
    ///
    /// When the namespace cannot be entered or the connection fails before the upgrade is
    /// answered.
    pub fn ws(&self, origin: Option<&str>) -> Result<Result<Ws, u16>> {
        let ns = File::open(&self.ns).with_context(|| format!("open {}", self.ns.display()))?;
        let (this, origin) = (self.clone(), origin.map(str::to_owned));
        let (opened_tx, opened_rx) = channel::<Result<Result<(), u16>>>();
        let (got_tx, got_rx) = channel::<Got>();
        let (send_tx, send_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let run = || -> Result<()> {
                setns(&ns, CloneFlags::CLONE_NEWNET).context("setns")?;
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("runtime")?
                    .block_on(socket(this, origin, &opened_tx, got_tx, send_rx))
            };
            if let Err(err) = run() {
                let _ = opened_tx.send(Err(err));
            }
        });
        match opened_rx.recv_timeout(STEP * 3) {
            Ok(Ok(Ok(()))) => Ok(Ok(Ws {
                got: got_rx,
                send: send_tx,
                next_id: 1,
            })),
            Ok(Ok(Err(status))) => Ok(Err(status)),
            Ok(Err(err)) => Err(err),
            Err(_) => bail!("the WebSocket did not open in time"),
        }
    }

    /// A socket that has authenticated with `token`.
    ///
    /// # Errors
    ///
    /// When it cannot be opened or the token is refused.
    pub fn ws_with(&self, token: &str) -> Result<Ws> {
        let mut ws = self
            .ws(None)?
            .map_err(|status| anyhow!("the upgrade was refused with {status}"))?;
        let id = ws.send(client_msg::Body::Auth(Auth {
            token: token.to_owned(),
        }))?;
        let ack = ws.msg(STEP)?;
        anyhow::ensure!(
            ack.id == id && matches!(ack.body, Some(server_msg::Body::Response(_))),
            "authentication was not acknowledged: {ack:?}"
        );
        Ok(ws)
    }
}

/// What arrived on a socket.
#[derive(Debug)]
enum Got {
    Msg(Box<ServerMsg>),
    Closed(Option<u16>),
}

/// The socket's thread: open it, then carry frames both ways until it closes.
async fn socket(
    api: Api,
    origin: Option<String>,
    opened: &Sender<Result<Result<(), u16>>>,
    got: Sender<Got>,
    mut send: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    use tungstenite::client::IntoClientRequest as _;
    let mut request = format!("wss://{}/ws", api.host).into_client_request()?;
    if let Some(origin) = origin {
        request.headers_mut().insert("origin", origin.parse()?);
    }
    let stream = api.tls(b"http/1.1").await?;
    let mut ws =
        match tokio::time::timeout(STEP, tokio_tungstenite::client_async(request, stream)).await {
            Ok(Ok((ws, _))) => ws,
            Ok(Err(tungstenite::Error::Http(response))) => {
                let _ = opened.send(Ok(Err(response.status().as_u16())));
                return Ok(());
            }
            Ok(Err(err)) => bail!("websocket handshake: {err}"),
            Err(_) => bail!("websocket handshake: nothing within {} s", STEP.as_secs()),
        };
    let _ = opened.send(Ok(Ok(())));
    loop {
        tokio::select! {
            frame = send.recv() => match frame {
                Some(frame) => {
                    if ws.send(tungstenite::Message::Binary(frame.into())).await.is_err() {
                        let _ = got.send(Got::Closed(None));
                        return Ok(());
                    }
                }
                // The scenario dropped its handle.
                None => return Ok(()),
            },
            received = ws.next() => match received {
                Some(Ok(tungstenite::Message::Binary(bytes))) => {
                    if let Ok(message) = ServerMsg::decode(bytes.as_ref())
                        && got.send(Got::Msg(Box::new(message))).is_err()
                    {
                        return Ok(());
                    }
                }
                Some(Ok(tungstenite::Message::Close(frame))) => {
                    let _ = got.send(Got::Closed(frame.map(|frame| u16::from(frame.code))));
                    return Ok(());
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    let _ = got.send(Got::Closed(None));
                    return Ok(());
                }
            },
        }
    }
}

/// An open WebSocket speaking the envelope; dropping it closes the connection.
#[derive(Debug)]
pub struct Ws {
    got: Receiver<Got>,
    send: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    next_id: u32,
}

impl Ws {
    /// Send one frame; its id.
    ///
    /// # Errors
    ///
    /// When the socket's thread is gone.
    pub fn send(&mut self, body: client_msg::Body) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = ClientMsg {
            id,
            body: Some(body),
        }
        .encode_to_vec();
        self.send
            .send(frame)
            .map_err(|_| anyhow!("the socket is closed"))?;
        Ok(id)
    }

    fn got(&mut self, timeout: Duration) -> Result<Got> {
        match self.got.recv_timeout(timeout) {
            Ok(got) => Ok(got),
            Err(RecvTimeoutError::Timeout) => {
                bail!("nothing arrived on the socket within {timeout:?}")
            }
            Err(RecvTimeoutError::Disconnected) => Ok(Got::Closed(None)),
        }
    }

    /// The next message.
    ///
    /// # Errors
    ///
    /// When none arrives in time or the socket closes first.
    pub fn msg(&mut self, timeout: Duration) -> Result<ServerMsg> {
        match self.got(timeout)? {
            Got::Msg(message) => Ok(*message),
            Got::Closed(code) => bail!("the socket closed ({code:?})"),
        }
    }

    /// Subscribe to `topic` and wait for the acknowledgement; pushes that arrive first are
    /// discarded.
    ///
    /// # Errors
    ///
    /// When the acknowledgement does not come.
    pub fn subscribe(&mut self, topic: &str, backlog: u32) -> Result<()> {
        let id = self.send(client_msg::Body::Subscribe(Subscribe {
            topic: topic.to_owned(),
            backlog,
        }))?;
        loop {
            if self.msg(STEP)?.id == id {
                return Ok(());
            }
        }
    }

    /// Send a request and wait for its reply, discarding pushes that arrive first.
    ///
    /// # Errors
    ///
    /// When no reply comes.
    pub fn ask(&mut self, body: request::Body) -> Result<server_msg::Body> {
        let id = self.send(client_msg::Body::Request(Request { body: Some(body) }))?;
        loop {
            let message = self.msg(STEP)?;
            if message.id == id {
                return message.body.context("a reply with no body");
            }
        }
    }

    /// Ask for the state over the socket.
    ///
    /// # Errors
    ///
    /// When no state comes back.
    pub fn request_state(&mut self) -> Result<State> {
        let id = self.send(client_msg::Body::Request(Request {
            body: Some(request::Body::GetState(GetStateRequest {})),
        }))?;
        loop {
            let message = self.msg(STEP)?;
            if message.id != id {
                continue;
            }
            let Some(server_msg::Body::Response(response)) = message.body else {
                bail!("not a response: {message:?}");
            };
            let Some(openfeo_config::api::response::Body::GetState(reply)) = response.body else {
                bail!("not a state: {response:?}");
            };
            return reply.state.context("no state in the reply");
        }
    }

    /// Read until `pick` finds what it wants, within `timeout` in all.
    fn until<T>(
        &mut self,
        timeout: Duration,
        what: &str,
        mut pick: impl FnMut(ServerMsg) -> Option<T>,
    ) -> Result<T> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(!left.is_zero(), "no {what} within {timeout:?}");
            if let Some(found) = pick(
                self.msg(left)
                    .with_context(|| format!("waiting for {what}"))?,
            ) {
                return Ok(found);
            }
        }
    }

    /// The next `State` push that satisfies `wanted`.
    ///
    /// # Errors
    ///
    /// When none arrives in time.
    pub fn state_where(
        &mut self,
        timeout: Duration,
        wanted: impl Fn(&State) -> bool,
    ) -> Result<State> {
        self.until(timeout, "state", |message| match message.body {
            Some(server_msg::Body::Telemetry(push)) => match push.body {
                Some(telemetry::Body::State(state)) if wanted(&state) => Some(state),
                _ => None,
            },
            _ => None,
        })
    }

    /// The next event whose topic is `topic`.
    ///
    /// # Errors
    ///
    /// When none arrives in time.
    pub fn event(&mut self, timeout: Duration, topic: &str) -> Result<Event> {
        self.until(timeout, topic, |message| match message.body {
            Some(server_msg::Body::Event(event)) if event.topic == topic => Some(event),
            _ => None,
        })
    }

    /// The next `Counters` push.
    ///
    /// # Errors
    ///
    /// When none arrives in time.
    pub fn counters(&mut self, timeout: Duration) -> Result<Counters> {
        self.until(timeout, "counters", |message| match message.body {
            Some(server_msg::Body::Telemetry(push)) => match push.body {
                Some(telemetry::Body::Counters(counters)) => Some(counters),
                _ => None,
            },
            _ => None,
        })
    }

    /// Read until the socket closes; its close code.
    ///
    /// # Errors
    ///
    /// When it is still open after `timeout`.
    pub fn closed_with(&mut self, timeout: Duration) -> Result<Option<u16>> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(
                !left.is_zero(),
                "the socket is still open after {timeout:?}"
            );
            if let Got::Closed(code) = self.got(left)? {
                return Ok(code);
            }
        }
    }
}
