// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The listener (SPEC §8.3, §9): TCP 443 for everything and TCP 80 to send a browser there.
//! A connection is taken only from a client the gate admits, must finish its TLS handshake
//! and send its request in good time, and is one of a bounded number. The certificate is held
//! where each handshake reads it, so a reissue takes effect without a restart.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::Extension;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{HOST, LOCATION};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use openfeo_runtime::supervise::TaskError;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::auth::Source;
use crate::cert::{self, Action, CertError, CertMeta, Clock};
use crate::gate::{host_allowed, https_authority};
use crate::http::{Local, Peer};
use crate::limits::MAX_STREAMS;
use crate::server::Shared;
use crate::watched::Watched;
use crate::{Admit, ApiDeps};

/// How often lapsed sessions are dropped.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// How often the certificate is looked at when nothing else prompts it.
const CERT_CHECK_EVERY: Duration = Duration::from_hours(24);

/// The certificate being presented, swapped when it is reissued.
#[derive(Debug)]
struct Presented(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for Presented {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.0
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
    }
}

fn certified(cert_der: &[u8], key_pem: &str) -> Result<CertifiedKey, CertError> {
    let key =
        rcgen::KeyPair::from_pem(key_pem).map_err(|err| CertError::Generate(err.to_string()))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|err| CertError::Generate(err.to_string()))?;
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(cert_der.to_vec())],
        key,
    ))
}

/// The certificate's home and what is known of the one held.
struct Tls {
    dir: PathBuf,
    build_epoch: u64,
    presented: Arc<Presented>,
    held: std::sync::Mutex<Option<(String, CertMeta)>>,
}

impl Tls {
    fn clock(&self, shared: &Shared) -> Clock {
        Clock {
            now_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(self.build_epoch, |since| since.as_secs()),
            synced: shared.world.borrow().time.synced,
            build_epoch: self.build_epoch,
        }
    }

    /// Issue or reissue if the names, the clock or the calendar call for it, keep the result
    /// on disk, present it and tell `shared` its fingerprint.
    fn ensure(&self, shared: &Shared) -> Result<(), CertError> {
        let names = cert::names(shared.world.borrow().config.system.as_ref());
        let clock = self.clock(shared);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let action = cert::decide(held.as_ref().map(|(_, meta)| meta), &names, &clock);
        let key = match action {
            Action::Keep => return Ok(()),
            Action::Issue => None,
            Action::Reissue(_) => held.as_ref().map(|(key, _)| key.clone()),
        };
        let issued = cert::issue(key.as_deref(), &names, &clock)?;
        if let Err(err) = cert::store(&self.dir, &issued) {
            // Served from memory all the same; the next start issues again.
            warn!("tls: cannot keep the certificate: {err}");
        }
        *self
            .presented
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner) =
            Arc::new(certified(&issued.cert_der, &issued.key_pem)?);
        match action {
            Action::Reissue(why) => info!("{}", cert::line_reissued(why, &issued.meta)),
            Action::Issue | Action::Keep => info!("{}", cert::line_issued(&issued.meta)),
        }
        info!("{}", cert::line_fingerprint(&issued.cert_der));
        shared
            .fingerprint
            .send_replace(cert::fingerprint(&issued.cert_der));
        *held = Some((issued.key_pem, issued.meta));
        Ok(())
    }
}

/// The API, bound and ready to [`serve`](Self::serve).
pub struct Server {
    /// What every transport shares.
    pub shared: Arc<Shared>,
    https: TcpListener,
    http: TcpListener,
    admit: Admit,
    tls: Arc<Tls>,
    acceptor: TlsAcceptor,
    router: Router,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").finish_non_exhaustive()
    }
}

/// `api: listening on :443 and :80`.
#[must_use]
pub fn line_listening(https: u16, http: u16) -> String {
    format!("api: listening on :{https} and :{http}")
}

impl Server {
    /// Bind both ports, load or issue the certificate, and build the routes.
    ///
    /// # Errors
    ///
    /// When a port cannot be bound or the certificate cannot be made.
    pub async fn bind(deps: ApiDeps) -> Result<Self, TaskError> {
        let https = TcpListener::bind(deps.listen.https).await?;
        let http = TcpListener::bind(deps.listen.http).await?;
        let shared = Shared::new(crate::server::SharedParts {
            world: deps.world,
            publisher: deps.publisher,
            health: deps.health,
            telemetry: crate::telemetry::Telemetry::new(deps.counters),
            config_path: deps.config_path,
            config_state: deps.config_state,
            version: deps.version,
            limits: deps.limits,
            extra_host: deps.extra_host,
            default_window_secs: deps.confirm_secs,
        });
        let loaded = cert::load(&deps.tls_dir).unwrap_or_else(|err| {
            warn!("tls: {err}; issuing a new certificate");
            None
        });
        // A placeholder never presented: `ensure` below issues when nothing was loaded.
        let (first, held) = if let Some((der, key, meta)) = loaded {
            shared.fingerprint.send_replace(cert::fingerprint(&der));
            info!("{}", cert::line_fingerprint(&der));
            (certified(&der, &key)?, Some((key, meta)))
        } else {
            let clock = Clock {
                now_unix: deps.build_epoch,
                synced: false,
                build_epoch: deps.build_epoch,
            };
            let issued = cert::issue(None, &["openfeo".to_owned()], &clock)?;
            (certified(&issued.cert_der, &issued.key_pem)?, None)
        };
        let tls = Arc::new(Tls {
            dir: deps.tls_dir,
            build_epoch: deps.build_epoch,
            presented: Arc::new(Presented(RwLock::new(Arc::new(first)))),
            held: std::sync::Mutex::new(held),
        });
        tls.ensure(&shared)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(tls.presented.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let router = crate::http::finish(crate::routes(&shared), shared.clone());
        Ok(Server {
            shared,
            https,
            http,
            admit: deps.listen.admit,
            tls,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            router,
        })
    }

    /// Where HTTPS is bound.
    ///
    /// # Errors
    ///
    /// When the socket has no local address.
    pub fn https_addr(&self) -> std::io::Result<SocketAddr> {
        self.https.local_addr()
    }

    /// Where the port 80 redirect is bound.
    ///
    /// # Errors
    ///
    /// When the socket has no local address.
    pub fn http_addr(&self) -> std::io::Result<SocketAddr> {
        self.http.local_addr()
    }

    /// Serve until a listener fails. Dropping the future stops every task it started.
    ///
    /// # Errors
    ///
    /// When a listener cannot accept any more.
    pub async fn serve(self) -> Result<(), TaskError> {
        info!(
            "{}",
            line_listening(self.https_addr()?.port(), self.http_addr()?.port())
        );
        let mut tasks: JoinSet<Result<(), TaskError>> = JoinSet::new();
        let places = Places {
            all: Arc::new(Semaphore::new(self.shared.limits.connections)),
            per_source: Arc::new(PerSource::default()),
        };
        // The recorder is listening before anything below can say something: an event of the
        // API's own start is in the backlog.
        let events = self.shared.publisher.events();
        tasks.spawn(remember_events(self.shared.clone(), events));
        self.shared.settle_at_start();
        tasks.spawn(crate::config::keep_window(self.shared.clone()));
        tasks.spawn({
            let telemetry = self.shared.telemetry.clone();
            async move {
                telemetry.run().await;
                Ok(())
            }
        });
        tasks.spawn(sweep(self.shared.clone()));
        tasks.spawn(watch_certificate(self.shared.clone(), self.tls.clone()));
        tasks.spawn(accept_http(
            self.http,
            self.shared.clone(),
            self.admit.clone(),
            places.clone(),
        ));
        tasks.spawn(accept_https(
            self.https,
            self.shared.clone(),
            self.admit,
            places,
            self.acceptor,
            self.router,
        ));
        // The first task to end is the reason the API stops; the rest go with the set.
        match tasks.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(err)) => Err(err.into()),
            None => Ok(()),
        }
    }
}

/// Keep the recent events for later subscribers.
async fn remember_events(
    shared: Arc<Shared>,
    mut events: broadcast::Receiver<Arc<openfeo_world::Event>>,
) -> Result<(), TaskError> {
    loop {
        match events.recv().await {
            Ok(event) => shared.remember(event),
            // Fell behind: the events between are lost to the backlog, nothing more.
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return Err("the publisher is gone".into()),
        }
    }
}

async fn sweep(shared: Arc<Shared>) -> Result<(), TaskError> {
    let mut ticks = tokio::time::interval(SWEEP_EVERY);
    loop {
        ticks.tick().await;
        shared.sweep();
    }
}

/// Look at the certificate again whenever the World changes (the names, the clock syncing)
/// and once a day.
async fn watch_certificate(shared: Arc<Shared>, tls: Arc<Tls>) -> Result<(), TaskError> {
    let mut world = shared.world.clone();
    let mut daily = tokio::time::interval(CERT_CHECK_EVERY);
    loop {
        tokio::select! {
            changed = world.changed() => changed.map_err(|_| "the publisher is gone")?,
            _ = daily.tick() => {}
        }
        if let Err(err) = tls.ensure(&shared) {
            warn!("tls: {err}");
        }
    }
}

/// The peer as the rest of the API should see it: an IPv4 client of the dual-stack listener
/// arrives as `::ffff:a.b.c.d` and is the IPv4 address `a.b.c.d` to the gate, the backoff
/// table and the console alike.
fn canonical(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(peer, |v4| SocketAddr::new(v4.into(), v6.port())),
        SocketAddr::V4(_) => peer,
    }
}

/// How many connections each source holds now.
#[derive(Debug, Default)]
struct PerSource(std::sync::Mutex<BTreeMap<Source, usize>>);

/// One connection's places: one of all of them, and one of its source's. Both are given back
/// when the connection ends, however it ends.
struct Place {
    _permit: tokio::sync::OwnedSemaphorePermit,
    per_source: Arc<PerSource>,
    source: Source,
}

impl PerSource {
    /// Count one more for `source` unless it already holds `limit`.
    fn take(self: &Arc<Self>, source: Source, limit: usize) -> bool {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(source).or_insert(0);
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut held = self
            .per_source
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

/// The limits on connections: all of them, and each source's share.
#[derive(Clone)]
struct Places {
    all: Arc<Semaphore>,
    per_source: Arc<PerSource>,
}

/// Take the next connection the gate admits and that fits under the limits.
async fn accept(
    listener: &TcpListener,
    shared: &Shared,
    admit: &Admit,
    places: &Places,
) -> Result<(TcpStream, SocketAddr, Place), TaskError> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // Out of descriptors, or a connection reset before it was taken: not fatal.
                debug!("api: accept: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let peer = canonical(peer);
        if !admit(&shared.world.borrow(), peer) {
            debug!("api: {peer} is not on a private LAN; dropped");
            continue;
        }
        let Ok(permit) = places.all.clone().try_acquire_owned() else {
            debug!("api: too many connections; {peer} dropped");
            continue;
        };
        let source = Source::of(peer.ip());
        if !places.per_source.take(source, shared.limits.per_source) {
            debug!("api: too many connections from {peer}; dropped");
            continue;
        }
        let place = Place {
            _permit: permit,
            per_source: places.per_source.clone(),
            source,
        };
        return Ok((stream, peer, place));
    }
}

async fn accept_https(
    listener: TcpListener,
    shared: Arc<Shared>,
    admit: Admit,
    places: Places,
    acceptor: TlsAcceptor,
    router: Router,
) -> Result<(), TaskError> {
    loop {
        let (stream, peer, place) = accept(&listener, &shared, &admit, &places).await?;
        let (acceptor, limit, idle) = (
            acceptor.clone(),
            shared.limits.handshake,
            shared.limits.idle,
        );
        // Where the connection arrived, as canonical as where it came from. A socket that
        // cannot say is gone already; the peer's own address then stands in and names no LAN.
        let local = stream.local_addr().map_or(peer, canonical);
        let service = TowerToHyperService::new(
            router
                .clone()
                .layer(Extension(Peer(peer)))
                .layer(Extension(Local(local))),
        );
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(limit, acceptor.accept(stream)).await else {
                debug!("api: {peer} did not finish its handshake");
                return;
            };
            // The handshake is not the end of it: the first bytes of a request are due as
            // promptly, and a connection may never go quiet for long. HTTP/2's keep-alive
            // (and the WebSocket's pings) keep a healthy long-lived one talking.
            // The place travels with the I/O: an upgrade to a WebSocket hands the I/O to
            // another task, and the connection must go on counting for as long as it exists.
            let tls = Watched::new(tls, limit, idle, place);
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(limit);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(Some(idle / 3))
                .keep_alive_timeout(idle / 3)
                .max_concurrent_streams(MAX_STREAMS);
            if let Err(err) = builder
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await
            {
                debug!("api: {peer}: {err}");
            }
        });
    }
}

/// Port 80: send a request for one of the router's own names to the same host over HTTPS.
fn redirect(request: &Request<Incoming>, shared: &Shared) -> Response<Full<Bytes>> {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| host_allowed(host, &shared.names(), &shared.world.borrow()))
        .and_then(https_authority);
    let mut response = Response::new(Full::new(Bytes::new()));
    match host {
        Some(host) => {
            let path = request
                .uri()
                .path_and_query()
                .map_or("/", hyper::http::uri::PathAndQuery::as_str);
            *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
            if let Ok(location) = format!("https://{host}{path}").parse() {
                response.headers_mut().insert(LOCATION, location);
            }
        }
        None => *response.status_mut() = StatusCode::MISDIRECTED_REQUEST,
    }
    response
}

async fn accept_http(
    listener: TcpListener,
    shared: Arc<Shared>,
    admit: Admit,
    places: Places,
) -> Result<(), TaskError> {
    loop {
        let (stream, peer, place) = accept(&listener, &shared, &admit, &places).await?;
        let (shared, limit) = (shared.clone(), shared.limits.handshake);
        tokio::spawn(async move {
            let stream = Watched::new(stream, limit, limit, place);
            let service = service_fn(move |request: Request<Incoming>| {
                let response = redirect(&request, &shared);
                async move { Ok::<_, std::convert::Infallible>(response) }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limit)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!("api: {peer}: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv4_client_of_the_dual_stack_listener_is_seen_as_ipv4() {
        let mapped: SocketAddr = "[::ffff:192.168.1.2]:50000".parse().unwrap();
        assert_eq!(canonical(mapped), "192.168.1.2:50000".parse().unwrap());
        assert_eq!(
            crate::server::line_password_set(canonical(mapped).ip()),
            "admin: password set from 192.168.1.2"
        );
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::23".parse().unwrap(),
            50_000,
            0,
            10,
        ));
        assert_eq!(canonical(scoped), scoped, "an IPv6 client keeps its scope");
        let plain: SocketAddr = "192.168.1.2:50000".parse().unwrap();
        assert_eq!(canonical(plain), plain);
    }

    #[test]
    fn the_console_line_is_the_contract() {
        assert_eq!(line_listening(443, 80), "api: listening on :443 and :80");
    }
}
