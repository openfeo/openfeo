// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What every transport shares (SPEC §8.3, §9): the sessions, the backoff table, the recent
//! events, and the operations themselves. HTTP, the WebSocket and gRPC each decode a request,
//! call one of these, and encode the answer; none of them holds policy of its own.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openfeo_config::Admin;
use openfeo_config::admin::{ConfigState, write_password_hash};
use openfeo_config::api::{ErrorCode, GetStatusResponse, Session};
use openfeo_config::state::State;
use openfeo_reconcile::state::{SystemFacts, state};
use openfeo_runtime::clock::boot_ms;
use openfeo_runtime::{Publisher, WorldRx};
use openfeo_world::health::HealthView;
use tokio::sync::watch;
use tracing::{error, info};

use crate::auth::password::check_policy;
use crate::auth::{Backoff, Sessions, Source, Verifier};
use crate::events::Recent;
use crate::gate::Names;
use crate::limits::{
    AUTH_FRAME_TIMEOUT, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_SOURCE, PING_INTERVAL, REQUEST_TIMEOUT, SESSION_IDLE_MS,
};
use crate::telemetry::Telemetry;

/// A change in the offset between the wall clock and the boot clock larger than this is the
/// wall clock stepping, not the jitter of reading two clocks.
const WALL_STEP_MS: u64 = 1_000;

/// The limits a test may shorten; the router runs with the defaults (`limits`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// A connection must finish its TLS handshake, and then send a request head, within this.
    pub handshake: Duration,
    /// Connections open at once.
    pub connections: usize,
    /// A WebSocket's first frame must arrive within this.
    pub auth_frame: Duration,
    /// A WebSocket that does not take a frame within this is closed.
    pub write: Duration,
    /// How often the server pings an open WebSocket; two unanswered close it.
    pub ping: Duration,
    /// Connections open at once from one source (an IPv4 address or an IPv6 /64).
    pub per_source: usize,
    /// A connection that sends nothing for this long is closed. Long-lived ones are kept
    /// talking by the WebSocket's pings and HTTP/2's keep-alive, both well inside it.
    pub idle: Duration,
    /// A plain HTTP call must be complete, body and all, within this.
    pub request: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            handshake: HANDSHAKE_TIMEOUT,
            connections: MAX_CONNECTIONS,
            auth_frame: AUTH_FRAME_TIMEOUT,
            write: Duration::from_secs(10),
            ping: PING_INTERVAL,
            per_source: MAX_CONNECTIONS_PER_SOURCE,
            idle: IDLE_TIMEOUT,
            request: REQUEST_TIMEOUT,
        }
    }
}

/// An operation refused, in terms every transport can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// gRPC's code name.
    pub code: ErrorCode,
    /// One sentence for a person.
    pub message: String,
    /// With `ResourceExhausted` after a wrong password: how long to wait.
    pub retry_after_secs: u32,
}

impl ApiError {
    /// An error with no wait.
    #[must_use]
    pub fn new(code: ErrorCode, message: &str) -> Self {
        ApiError {
            code,
            message: message.to_owned(),
            retry_after_secs: 0,
        }
    }

    /// The error as the wire carries it.
    #[must_use]
    pub fn to_pb(&self) -> openfeo_config::api::Error {
        openfeo_config::api::Error {
            code: self.code.into(),
            message: self.message.clone(),
            retry_after_secs: self.retry_after_secs,
        }
    }
}

/// `admin: password set from 192.168.1.23`.
#[must_use]
pub fn line_password_set(from: IpAddr) -> String {
    format!("admin: password set from {from}")
}

/// `admin: password changed from 192.168.1.23`.
#[must_use]
pub fn line_password_changed(from: IpAddr) -> String {
    format!("admin: password changed from {from}")
}

/// `admin: login from 192.168.1.23`.
#[must_use]
pub fn line_login(from: IpAddr) -> String {
    format!("admin: login from {from}")
}

/// `admin: login refused from 192.168.1.23 (wait 4 s)`.
#[must_use]
pub fn line_login_refused(from: IpAddr, wait_ms: u64) -> String {
    format!(
        "admin: login refused from {from} (wait {} s)",
        wait_secs(wait_ms)
    )
}

/// A wait in whole seconds, rounded up: what `Retry-After` carries.
fn wait_secs(wait_ms: u64) -> u32 {
    u32::try_from(wait_ms.div_ceil(1000)).unwrap_or(u32::MAX)
}

/// A password being checked for a source. If the check is given up before it is judged (the
/// client went away and its request was dropped), the source is freed to try again.
struct Attempt<'a> {
    backoff: &'a Mutex<Backoff>,
    source: Source,
    judged: bool,
}

impl Attempt<'_> {
    fn judge(mut self) {
        self.judged = true;
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.judged {
            lock(self.backoff).abandon(self.source);
        }
    }
}

/// The state every transport shares.
pub struct Shared {
    /// The World.
    pub world: WorldRx,
    /// Its publisher: a new password goes into the running config through it.
    pub publisher: Arc<Publisher>,
    /// The heartbeat's latest view of health.
    pub health: watch::Receiver<HealthView>,
    /// The counters.
    pub telemetry: Arc<Telemetry>,
    /// `/state/config.toml`.
    pub config_path: PathBuf,
    /// How the running config came to be.
    pub config_state: ConfigState,
    /// The binary's version.
    pub version: String,
    /// The limits in force.
    pub limits: Limits,
    /// SHA-256 of the certificate being presented.
    pub fingerprint: watch::Sender<String>,
    /// Bumped whenever sessions end (logout, a password change, a sweep): every open socket
    /// then asks whether its own is still live.
    pub sessions_ended: watch::Sender<u64>,
    /// Sockets open now.
    pub sockets: AtomicUsize,
    /// See [`wall_offset_ms`](Self::wall_offset_ms).
    wall_offset: AtomicU64,
    sessions: Mutex<Sessions>,
    backoff: Mutex<Backoff>,
    recent: Mutex<Recent>,
    verifier: Verifier,
    extra_host: Option<String>,
    /// One password change at a time: the check for "no password yet" and the write are one
    /// step.
    password: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What [`Shared::new`] is given.
pub struct SharedParts {
    /// The World.
    pub world: WorldRx,
    /// Its publisher.
    pub publisher: Arc<Publisher>,
    /// The heartbeat's view.
    pub health: watch::Receiver<HealthView>,
    /// The counters.
    pub telemetry: Arc<Telemetry>,
    /// `/state/config.toml`.
    pub config_path: PathBuf,
    /// How the running config came to be.
    pub config_state: ConfigState,
    /// The binary's version.
    pub version: String,
    /// The limits in force.
    pub limits: Limits,
    /// One more host taken as the router's own; see [`ApiDeps::extra_host`](crate::ApiDeps).
    pub extra_host: Option<String>,
}

impl Shared {
    /// The shared state, with no sessions and nobody waiting.
    #[must_use]
    pub fn new(parts: SharedParts) -> Arc<Self> {
        Arc::new(Shared {
            world: parts.world,
            publisher: parts.publisher,
            health: parts.health,
            telemetry: parts.telemetry,
            config_path: parts.config_path,
            config_state: parts.config_state,
            version: parts.version,
            extra_host: parts.extra_host,
            limits: parts.limits,
            fingerprint: watch::Sender::new(String::new()),
            sessions_ended: watch::Sender::new(0),
            sockets: AtomicUsize::new(0),
            wall_offset: AtomicU64::new(0),
            sessions: Mutex::new(Sessions::new()),
            backoff: Mutex::new(Backoff::new()),
            recent: Mutex::new(Recent::default()),
            verifier: Verifier::new(),
            password: tokio::sync::Mutex::new(()),
        })
    }

    /// The router's two names, from the running config.
    #[must_use]
    pub fn names(&self) -> Names {
        Names::of(self.world.borrow().config.system.as_ref()).with_extra(self.extra_host.as_deref())
    }

    fn hash(&self) -> String {
        self.world
            .borrow()
            .config
            .admin
            .as_ref()
            .map(|admin| admin.password_hash.clone())
            .unwrap_or_default()
    }

    /// Whether the config file is there but cannot be read: no password can be set over it.
    fn config_unreadable(&self) -> bool {
        matches!(
            self.config_state,
            ConfigState::Refused {
                readable: false,
                ..
            }
        )
    }

    /// What anyone on the LAN may know before logging in.
    #[must_use]
    pub fn status(&self) -> GetStatusResponse {
        let names = self.names();
        let domain = names
            .fqdn
            .strip_prefix(&format!("{}.", names.hostname))
            .unwrap_or_default()
            .to_owned();
        GetStatusResponse {
            hostname: names.hostname,
            domain,
            needs_password: self.hash().is_empty() && !self.config_unreadable(),
            config_refused: matches!(self.config_state, ConfigState::Refused { .. }),
            tls_fingerprint: self.fingerprint.borrow().clone(),
            config_unreadable: self.config_unreadable(),
        }
    }

    fn session(&self) -> Result<Session, ApiError> {
        let token = lock(&self.sessions).issue(boot_ms()).map_err(|err| {
            error!("admin: cannot issue a session: {err}");
            ApiError::new(ErrorCode::Internal, "a session could not be issued")
        })?;
        Ok(Session {
            token,
            idle_secs: u32::try_from(SESSION_IDLE_MS / 1000).unwrap_or(u32::MAX),
        })
    }

    /// Hash `password`, write it into the config file and the running config.
    async fn store_password(&self, password: String) -> Result<(), ApiError> {
        check_policy(&password)
            .map_err(|err| ApiError::new(ErrorCode::InvalidArgument, &err.to_string()))?;
        let hash = self.verifier.hash(password).await.map_err(|err| {
            error!("admin: cannot hash the password: {err}");
            ApiError::new(ErrorCode::Internal, "the password could not be hashed")
        })?;
        let (path, ports) = (self.config_path.clone(), self.world.borrow().ports.clone());
        let written = {
            let hash = hash.clone();
            tokio::task::spawn_blocking(move || write_password_hash(&path, &hash, &ports)).await
        };
        match written {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("admin: cannot write the password to the config file: {err}");
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "the password could not be written to the config file",
                ));
            }
            Err(err) => {
                error!("admin: the config write did not finish: {err}");
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "the password could not be written to the config file",
                ));
            }
        }
        self.publisher.update(|world| {
            Arc::make_mut(&mut world.config).admin = Some(Admin {
                password_hash: hash,
            });
        });
        Ok(())
    }

    /// Set the first password (SPEC §9): once, from any admitted client, while none is set;
    /// that client is logged in.
    ///
    /// # Errors
    ///
    /// `FailedPrecondition` when a password is set or the config file cannot be read,
    /// `InvalidArgument` when the password is too short or long, `Internal` when it cannot be
    /// stored.
    pub async fn set_initial_password(
        &self,
        from: IpAddr,
        password: String,
    ) -> Result<Session, ApiError> {
        let _one_at_a_time = self.password.lock().await;
        if self.config_unreadable() {
            return Err(ApiError::new(
                ErrorCode::FailedPrecondition,
                "the config file cannot be read, so no password can be set",
            ));
        }
        if !self.hash().is_empty() {
            return Err(ApiError::new(
                ErrorCode::FailedPrecondition,
                "a password is already set",
            ));
        }
        self.store_password(password).await?;
        info!("{}", line_password_set(from));
        self.session()
    }

    /// Check `password` for `from` under the backoff: `Ok` when it is right.
    async fn check_password(&self, from: IpAddr, password: String) -> Result<(), ApiError> {
        let hash = self.hash();
        if hash.is_empty() {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "no password is set",
            ));
        }
        let source = Source::of(from);
        // Checking for a wait and claiming the attempt are one step: a burst sent at once is
        // one attempt, and the rest are told to wait without a hash being computed.
        if let Err(waiting) = lock(&self.backoff).begin(source, boot_ms()) {
            return Err(ApiError {
                code: ErrorCode::ResourceExhausted,
                message: format!("wait {} s before trying again", wait_secs(waiting)),
                retry_after_secs: wait_secs(waiting),
            });
        }
        let attempt = Attempt {
            backoff: &self.backoff,
            source,
            judged: false,
        };
        let right = self.verifier.verify(password, hash).await;
        attempt.judge();
        if right {
            lock(&self.backoff).succeeded(source);
            Ok(())
        } else {
            let wait = lock(&self.backoff).failed(source, boot_ms());
            info!("{}", line_login_refused(from, wait));
            Err(ApiError {
                code: ErrorCode::Unauthenticated,
                message: "wrong password".to_owned(),
                retry_after_secs: wait_secs(wait),
            })
        }
    }

    /// Log in.
    ///
    /// # Errors
    ///
    /// `Unauthenticated` for a wrong password (or when none is set), `ResourceExhausted` while
    /// the source must wait.
    pub async fn login(&self, from: IpAddr, password: String) -> Result<Session, ApiError> {
        self.check_password(from, password).await?;
        info!("{}", line_login(from));
        self.session()
    }

    /// Whether `token` names a live session; a yes counts as activity.
    #[must_use]
    pub fn authenticate(&self, token: &str) -> bool {
        lock(&self.sessions).check(token, boot_ms())
    }

    /// Whether `token` still names a session, without counting as activity.
    #[must_use]
    pub fn session_is_live(&self, token: &str) -> bool {
        lock(&self.sessions).is_live(token)
    }

    /// A WebSocket of the session opened (`+1`) or closed (`-1`).
    pub fn socket(&self, token: &str, delta: i32) {
        lock(&self.sessions).connected(token, delta, boot_ms());
    }

    fn sessions_changed(&self) {
        self.sessions_ended.send_modify(|count| *count += 1);
    }

    /// End the session `token` names.
    pub fn logout(&self, token: &str) {
        if lock(&self.sessions).revoke(token) {
            self.sessions_changed();
        }
    }

    /// Change the password: the old one is checked under the same backoff as a login, and
    /// every session but `token`'s ends.
    ///
    /// # Errors
    ///
    /// As [`login`](Self::login) for the old password and
    /// [`set_initial_password`](Self::set_initial_password) for the new one.
    pub async fn change_password(
        &self,
        from: IpAddr,
        token: &str,
        old: String,
        new: String,
    ) -> Result<(), ApiError> {
        let _one_at_a_time = self.password.lock().await;
        check_policy(&new)
            .map_err(|err| ApiError::new(ErrorCode::InvalidArgument, &err.to_string()))?;
        self.check_password(from, old).await.map_err(|mut err| {
            // The caller is logged in; it is the old password that is wrong.
            if err.code == ErrorCode::Unauthenticated {
                err.code = ErrorCode::InvalidArgument;
                "the old password is wrong".clone_into(&mut err.message);
            }
            err
        })?;
        self.store_password(new).await?;
        info!("{}", line_password_changed(from));
        if lock(&self.sessions).revoke_others(token) > 0 {
            self.sessions_changed();
        }
        Ok(())
    }

    /// Drop the sessions that have lapsed.
    pub fn sweep(&self) {
        if lock(&self.sessions).sweep(boot_ms()) > 0 {
            self.sessions_changed();
        }
    }

    /// The snapshot of the router now.
    #[must_use]
    pub fn state(&self) -> State {
        let boot = boot_ms();
        let now_unix_ms = self.wall_offset_ms(boot).saturating_add(boot);
        let system = SystemFacts {
            version: self.version.clone(),
            uptime_secs: boot / 1000,
            boot_ms: boot,
            now_unix_ms,
            health: self.health.borrow().clone(),
            tls_fingerprint: self.fingerprint.borrow().clone(),
            config_problem: match &self.config_state {
                ConfigState::Refused { problem, .. } => Some(problem.clone()),
                ConfigState::Loaded | ConfigState::FirstBoot => None,
            },
        };
        state(&self.world.borrow(), &system)
    }

    /// The wall clock minus the boot clock, in milliseconds. The two are read a moment apart,
    /// so the difference jitters; it is held steady and moved only when the wall clock steps
    /// (SNTP), so that a time derived from it (when a WAN came up) is the same in every
    /// snapshot.
    fn wall_offset_ms(&self, boot: u64) -> u64 {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        let fresh = wall.saturating_sub(boot);
        let held = self.wall_offset.load(Ordering::Relaxed);
        if held.abs_diff(fresh) > WALL_STEP_MS {
            self.wall_offset.store(fresh, Ordering::Relaxed);
            fresh
        } else {
            held
        }
    }

    /// Remember an event for later subscribers.
    pub fn remember(&self, event: Arc<openfeo_world::Event>) {
        lock(&self.recent).push(event);
    }

    /// The last `n` events, oldest first, as the wire carries them.
    #[must_use]
    pub fn backlog(&self, n: u32) -> Vec<openfeo_config::events::Event> {
        lock(&self.recent)
            .last(n as usize)
            .iter()
            .map(|event| crate::events::to_pb(event))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use openfeo_config::state::{ConfigProblem, Counters};
    use openfeo_reconcile::fixtures;

    use super::*;
    use crate::telemetry::CounterSource;

    pub(crate) const PASSWORD: &str = "lab-admin-password";

    pub(crate) struct NoCounters;

    impl CounterSource for NoCounters {
        fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>> {
            Box::pin(async {
                Some(Counters {
                    monotonic_ms: boot_ms(),
                    ..Counters::default()
                })
            })
        }
    }

    /// Shared state over `fixtures::dhcp_world()`, with a small valid config file in a temp
    /// directory (returned so it outlives the test).
    pub(crate) fn shared(
        config_state: ConfigState,
        limits: Limits,
    ) -> (Arc<Shared>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "# the lab's\nconfig_version = 1\n").unwrap();
        let (publisher, world) = Publisher::with_derive(
            fixtures::dhcp_world(),
            Box::new(openfeo_reconcile::derive::derive),
        );
        let (_health_tx, health) = watch::channel(HealthView {
            healthy: true,
            unhealthy: Vec::new(),
        });
        let shared = Shared::new(SharedParts {
            world,
            publisher: Arc::new(publisher),
            health,
            telemetry: Telemetry::new(Arc::new(NoCounters)),
            config_path,
            config_state,
            version: "0.4.0-test".to_owned(),
            limits,
            extra_host: None,
        });
        shared.fingerprint.send_replace("AB:CD".to_owned());
        (shared, dir)
    }

    pub(crate) fn problem(reason: &str) -> ConfigProblem {
        ConfigProblem {
            reason: reason.to_owned(),
            violations: Vec::new(),
        }
    }

    fn lan() -> IpAddr {
        "192.168.1.23".parse().unwrap()
    }

    #[tokio::test]
    async fn the_first_password_is_set_once_and_logs_that_client_in() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        let status = shared.status();
        assert!(status.needs_password && !status.config_refused);
        assert_eq!(
            (status.hostname.as_str(), status.domain.as_str()),
            ("openfeo", "home.arpa")
        );
        assert_eq!(
            shared
                .login(lan(), PASSWORD.to_owned())
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthenticated,
            "nothing to log in with yet"
        );
        assert_eq!(
            shared
                .set_initial_password(lan(), "short".to_owned())
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let session = shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap();
        assert_eq!(session.idle_secs, 1_800);
        assert!(shared.authenticate(&session.token));
        assert!(!shared.status().needs_password);
        assert_eq!(
            shared
                .set_initial_password(lan(), "another-password".to_owned())
                .await
                .unwrap_err()
                .code,
            ErrorCode::FailedPrecondition
        );
        let file = std::fs::read_to_string(&shared.config_path).unwrap();
        assert!(file.starts_with("# the lab's\nconfig_version = 1\n"));
        assert!(file.contains("password_hash = \"$argon2id$"));
        assert!(
            shared
                .publisher
                .current()
                .config
                .admin
                .as_ref()
                .is_some_and(|admin| admin.password_hash.starts_with("$argon2id$"))
        );
    }

    #[tokio::test]
    async fn two_first_passwords_at_once_and_exactly_one_wins() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        let (a, b) = tokio::join!(
            shared.set_initial_password(lan(), "first-password-a".to_owned()),
            shared.set_initial_password(lan(), "first-password-b".to_owned())
        );
        assert_eq!(
            u8::from(a.is_ok()) + u8::from(b.is_ok()),
            1,
            "exactly one wins: {a:?} {b:?}"
        );
        let winner = if a.is_ok() {
            "first-password-a"
        } else {
            "first-password-b"
        };
        assert!(shared.login(lan(), winner.to_owned()).await.is_ok());
        // And the file holds the winner's hash, not the loser's and not a mixture.
        let file = std::fs::read_to_string(&shared.config_path).unwrap();
        let openfeo_config::admin::Salvage::Hash(hash) =
            openfeo_config::admin::salvage_password_hash(&file)
        else {
            panic!("no hash in {file}");
        };
        assert!(crate::auth::password::verify(winner, &hash));
        assert_eq!(file.matches("password_hash").count(), 1);
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_then_made_to_wait() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap();
        let wrong = shared
            .login(lan(), "wrong-password-1".to_owned())
            .await
            .unwrap_err();
        assert_eq!(
            (wrong.code, wrong.retry_after_secs),
            (ErrorCode::Unauthenticated, 1)
        );
        let waiting = shared.login(lan(), PASSWORD.to_owned()).await.unwrap_err();
        assert_eq!(
            (waiting.code, waiting.retry_after_secs),
            (ErrorCode::ResourceExhausted, 1),
            "even the right password waits"
        );
        let elsewhere: IpAddr = "192.168.1.99".parse().unwrap();
        assert!(
            shared.login(elsewhere, PASSWORD.to_owned()).await.is_ok(),
            "another source is not held up"
        );
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        assert!(shared.login(lan(), PASSWORD.to_owned()).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_of_wrong_passwords_is_one_attempt_and_the_rest_wait() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap();
        let burst = (0..20).map(|n| {
            let shared = shared.clone();
            tokio::spawn(async move { shared.login(lan(), format!("wrong-password-{n:02}")).await })
        });
        let mut codes = Vec::new();
        for attempt in burst.collect::<Vec<_>>() {
            codes.push(attempt.await.unwrap().unwrap_err().code);
        }
        let judged = codes
            .iter()
            .filter(|code| **code == ErrorCode::Unauthenticated)
            .count();
        let held = codes
            .iter()
            .filter(|code| **code == ErrorCode::ResourceExhausted)
            .count();
        assert_eq!(
            (judged, held),
            (1, 19),
            "one password was checked; the rest were told to wait"
        );
        // The owner, elsewhere on the LAN, is not behind a queue of them.
        let elsewhere: IpAddr = "192.168.1.99".parse().unwrap();
        let started = std::time::Instant::now();
        assert!(shared.login(elsewhere, PASSWORD.to_owned()).await.is_ok());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn an_attempt_given_up_does_not_hold_its_source() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap();
        // Dropped before it is judged, as when the client goes away mid-request.
        let attempt = shared.login(lan(), "wrong-password-1".to_owned());
        drop(tokio::time::timeout(Duration::from_millis(1), attempt).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(shared.login(lan(), PASSWORD.to_owned()).await.is_ok());
    }

    #[tokio::test]
    async fn changing_the_password_ends_other_sessions_and_keeps_the_callers() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        let mine = shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap()
            .token;
        let other = shared
            .login(lan(), PASSWORD.to_owned())
            .await
            .unwrap()
            .token;
        let ended = shared.sessions_ended.subscribe();
        let wrong_old = shared
            .change_password(
                lan(),
                &mine,
                "not-the-old-one".to_owned(),
                "a-new-password".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(wrong_old.code, ErrorCode::InvalidArgument);
        assert!(shared.authenticate(&other), "nothing changed yet");
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        shared
            .change_password(
                lan(),
                &mine,
                PASSWORD.to_owned(),
                "a-new-password".to_owned(),
            )
            .await
            .unwrap();
        assert!(shared.authenticate(&mine));
        assert!(!shared.authenticate(&other));
        assert!(
            ended.has_changed().unwrap(),
            "open sockets are told to check"
        );
        assert!(
            shared
                .login(lan(), "a-new-password".to_owned())
                .await
                .is_ok()
        );
        let old = shared.login(lan(), PASSWORD.to_owned()).await.unwrap_err();
        assert_eq!(old.code, ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn logout_ends_the_session() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        let token = shared
            .set_initial_password(lan(), PASSWORD.to_owned())
            .await
            .unwrap()
            .token;
        shared.logout(&token);
        assert!(!shared.authenticate(&token));
        assert!(!shared.session_is_live(&token));
    }

    #[tokio::test]
    async fn a_config_file_that_cannot_be_read_offers_no_first_password() {
        let (shared, _dir) = shared(
            ConfigState::Refused {
                problem: problem("not TOML"),
                readable: false,
            },
            Limits::default(),
        );
        let status = shared.status();
        assert!(!status.needs_password && status.config_refused);
        assert_eq!(
            shared
                .set_initial_password(lan(), PASSWORD.to_owned())
                .await
                .unwrap_err()
                .code,
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            shared
                .state()
                .system
                .unwrap()
                .config_problem
                .unwrap()
                .reason,
            "not TOML"
        );
    }

    #[test]
    fn status_says_when_the_config_cannot_be_read() {
        // The panel shows a screen of its own for a file nobody can log in over, and must tell
        // it from a refused file whose password still works before anyone types one.
        let (unreadable, _dir) = shared(
            ConfigState::Refused {
                problem: problem("not TOML"),
                readable: false,
            },
            Limits::default(),
        );
        let status = unreadable.status();
        assert!(status.config_unreadable && status.config_refused && !status.needs_password);
        let (refused, _dir) = shared(
            ConfigState::Refused {
                problem: problem("invalid (1 errors)"),
                readable: true,
            },
            Limits::default(),
        );
        assert!(!refused.status().config_unreadable && refused.status().config_refused);
        let (loaded, _dir) = shared(ConfigState::Loaded, Limits::default());
        assert!(!loaded.status().config_unreadable);
        let (first_boot, _dir) = shared(ConfigState::FirstBoot, Limits::default());
        assert!(!first_boot.status().config_unreadable);
    }

    #[tokio::test]
    async fn a_refused_config_that_parses_and_has_no_password_may_be_given_one() {
        let (shared, _dir) = shared(
            ConfigState::Refused {
                problem: problem("invalid (1 errors)"),
                readable: true,
            },
            Limits::default(),
        );
        let status = shared.status();
        assert!(status.needs_password && status.config_refused);
        assert!(
            shared
                .set_initial_password(lan(), PASSWORD.to_owned())
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_admin_lines_are_the_contract() {
        assert_eq!(
            line_password_set(lan()),
            "admin: password set from 192.168.1.23"
        );
        assert_eq!(
            line_password_changed(lan()),
            "admin: password changed from 192.168.1.23"
        );
        assert_eq!(line_login(lan()), "admin: login from 192.168.1.23");
        assert_eq!(
            line_login_refused(lan(), 4_000),
            "admin: login refused from 192.168.1.23 (wait 4 s)"
        );
        assert_eq!(
            line_login_refused(lan(), 300_000),
            "admin: login refused from 192.168.1.23 (wait 300 s)"
        );
    }

    #[tokio::test]
    async fn a_time_derived_from_the_two_clocks_is_the_same_in_every_snapshot() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        shared.publisher.update(|_| {});
        let first = shared.state().wans[0].phase_since_unix_ms;
        assert!(first.is_some_and(|since| since > 1_600_000_000_000));
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_micros(300)).await;
            assert_eq!(shared.state().wans[0].phase_since_unix_ms, first);
        }
    }

    #[tokio::test]
    async fn the_state_is_the_worlds_with_the_systems_facts() {
        let (shared, _dir) = shared(ConfigState::Loaded, Limits::default());
        let state = shared.state();
        let system = state.system.unwrap();
        assert_eq!(system.version, "0.4.0-test");
        assert_eq!(system.tls_fingerprint, "AB:CD");
        assert!(system.healthy);
        assert_eq!(state.wans[0].name, "wan0");
    }
}
