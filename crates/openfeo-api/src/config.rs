// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The keeper of the config at work (SPEC §5.5): what [`crate::keeper::Keeper`] decides is done
//! here. A change is written beside the config as pending, published into the World, and
//! promoted only when it is confirmed; a revert, asked for or because the window ran out,
//! publishes the confirmed config again. Publishing is one swap of `world.config`: every task
//! follows the World (SPEC §6.3), so applying, confirming and reverting have no code path of
//! their own below this.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use openfeo_config::api::{
    ApplyConfigRequest, ApplyConfigResponse, ErrorCode, GetConfigResponse, ValidateConfigResponse,
};
use openfeo_config::state::ConfigViolation;
use openfeo_config::{Config, file, secrets};
use openfeo_runtime::clock::boot_ms;
use openfeo_runtime::supervise::TaskError;
use openfeo_world::{Effect, EventDraft, PendingFact};
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::gate;
use crate::http::Arrival;
use crate::keeper::{Keeper, Refusal, Why};
use crate::server::{ApiError, Shared};

/// How many violations a refused apply names in its error; the rest are counted.
const VIOLATIONS_NAMED: usize = 5;

/// `config: applied; confirm within 120 s`.
#[must_use]
pub fn line_applied(window_secs: u32) -> String {
    format!("config: applied; confirm within {window_secs} s")
}

/// `config: applied immediately`.
#[must_use]
pub fn line_applied_immediately() -> String {
    "config: applied immediately".to_owned()
}

/// `config: effect lan0 address moves`.
#[must_use]
pub fn line_effect(effect: &Effect) -> String {
    format!("config: effect {} {}", effect.subject, effect.kind.what())
}

/// `config: confirmed`.
#[must_use]
pub fn line_confirmed() -> String {
    "config: confirmed".to_owned()
}

/// `config: reverted (asked)`, `config: reverted (not confirmed in 120 s)`, or
/// `config: reverted (the API restarted before it was confirmed)`.
#[must_use]
pub fn line_reverted(why: Why, window_secs: u32) -> String {
    match why {
        Why::Asked => "config: reverted (asked)".to_owned(),
        Why::TimedOut => format!("config: reverted (not confirmed in {window_secs} s)"),
        Why::Restarted => "config: reverted (the API restarted before it was confirmed)".to_owned(),
    }
}

/// The `why` of a `config.reverted` event.
fn why_field(why: Why) -> &'static str {
    match why {
        Why::Asked => "asked",
        Why::TimedOut => "timeout",
        Why::Restarted => "restart",
    }
}

/// `config: an unconfirmed change was discarded`.
#[must_use]
pub fn line_discarded() -> String {
    "config: an unconfirmed change was discarded".to_owned()
}

/// What the keeper refused, as the API says it.
fn refused(refusal: &Refusal) -> ApiError {
    match refusal {
        Refusal::Invalid(violations) => {
            let named: Vec<String> = violations
                .iter()
                .take(VIOLATIONS_NAMED)
                .map(|violation| format!("{}: {}", violation.path, violation.message))
                .collect();
            let more = violations.len().saturating_sub(VIOLATIONS_NAMED);
            let rest = if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            };
            let text = format!(
                "the config has {} violation{}: {}{rest}",
                violations.len(),
                if violations.len() == 1 { "" } else { "s" },
                named.join("; ")
            );
            ApiError::new(ErrorCode::InvalidArgument, &text)
        }
        Refusal::Window => ApiError::new(
            ErrorCode::InvalidArgument,
            "the window must be 10 to 600 s, or 0 for the router's default",
        ),
        Refusal::StaleTag => ApiError::new(
            ErrorCode::FailedPrecondition,
            "the config has changed since it was read; read it again",
        ),
        Refusal::ChangePending => ApiError::new(
            ErrorCode::FailedPrecondition,
            "a change of config is pending; confirm or revert it first",
        ),
        Refusal::NothingPending => ApiError::new(
            ErrorCode::FailedPrecondition,
            "no change of config is pending",
        ),
        Refusal::FileRefused => ApiError::new(
            ErrorCode::FailedPrecondition,
            "the router refused its config file and runs on defaults; mend or remove the file first",
        ),
    }
}

fn not_written(what: &str, err: &dyn std::fmt::Display) -> ApiError {
    error!("config: cannot write {what}: {err}");
    ApiError::new(ErrorCode::Internal, "the config could not be written")
}

/// Where the first `config.toml` the router wrote over is kept.
fn original_path(config_path: &Path) -> PathBuf {
    let mut name = config_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".orig");
    config_path.with_file_name(name)
}

/// Before `config.toml` is written over: when somebody wrote notes in it, keep it beside
/// itself, once. A rendering has no comments, so a `#` anywhere in the text is taken for one
/// (a `#` inside a value keeps a file that held no notes, which loses nothing). Layout alone is
/// not kept: the router's own file, after a password was set in it, is laid out a little
/// differently from a fresh rendering and is nobody's hand-written file.
fn keep_original(config_path: &Path) -> io::Result<()> {
    let original = original_path(config_path);
    if original.exists() {
        return Ok(());
    }
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !text.contains('#') {
        return Ok(());
    }
    file::write_whole(&original, &text).map_err(io::Error::other)
}

/// Sync the directory `path` is in: a rename or a removal there is on the disk when this
/// returns, not at the filesystem's next commit some seconds later.
fn sync_dir_of(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

/// The pending config becomes `config.toml`: written whole from `text`, what the keeper
/// holds, and not renamed from the pending file, so that a confirm cut off after this (or
/// asked again) finds nothing it cannot do twice. The pending file is removed afterwards; one
/// that will not go is discarded at the next start, holding what `config.toml` now does.
fn promote(config_path: &Path, text: &str) -> io::Result<()> {
    keep_original(config_path)?;
    file::write_whole(config_path, text).map_err(io::Error::other)?;
    if let Err(err) = remove_pending(config_path) {
        warn!(
            "config: cannot remove {}: {err}",
            file::pending_path(config_path).display()
        );
    }
    Ok(())
}

/// Remove the pending file for good: the directory is synced, so a power cut straight
/// afterwards does not bring the file back to be discarded at the next start. `false` when
/// there was none.
fn remove_pending(config_path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(file::pending_path(config_path)) {
        Ok(()) => sync_dir_of(config_path).map(|()| true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Run a change of config to its end, whoever is waiting for it. A caller that goes away
/// mid-flight (a gRPC call reset or past its deadline drops the handler's future) must not
/// leave the file written and the keeper and the World as they were: the change runs as a
/// task of its own and the caller only waits for it.
async fn whole<T: Send + 'static>(
    what: &'static str,
    work: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> Result<T, ApiError> {
    match tokio::spawn(work).await {
        Ok(done) => done,
        Err(err) => {
            warn!("config: {what} did not finish: {err}");
            Err(ApiError::new(
                ErrorCode::Internal,
                "the change of config did not finish",
            ))
        }
    }
}

/// Run file work off the async threads and say what went wrong.
async fn off_thread(
    what: &'static str,
    work: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> Result<(), ApiError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(not_written(what, &err)),
        Err(err) => Err(not_written(what, &err)),
    }
}

impl Shared {
    /// The running config as the API hands it out: without its secrets, with its tag and the
    /// window an apply is given when it names none.
    pub async fn config_view(&self) -> GetConfigResponse {
        let keeper = self.keeper.lock().await;
        GetConfigResponse {
            config: Some(secrets::redact(keeper.running())),
            tag: secrets::tag(keeper.running()),
            confirm_secs: keeper.default_window_secs(),
        }
    }

    /// Look at a proposal without applying it: the proposal with the running secrets carried
    /// in and what applying it would do, or what is wrong with it.
    ///
    /// # Errors
    ///
    /// The violations.
    pub async fn check_config(
        &self,
        proposed: Config,
    ) -> Result<(Config, Vec<Effect>), Vec<ConfigViolation>> {
        let ports = self.world.borrow().ports.clone();
        let keeper = self.keeper.lock().await;
        keeper
            .check(proposed, &ports)
            .map_err(|refusal| match refusal {
                Refusal::Invalid(violations) => violations
                    .into_iter()
                    .map(|violation| ConfigViolation {
                        path: violation.path,
                        code: violation.code.to_string(),
                        message: violation.message,
                    })
                    .collect(),
                // `check` refuses for nothing else.
                _ => Vec::new(),
            })
    }

    /// What applying `proposed` would mean, for the router and for whoever asks from `at`
    /// (SPEC §8.3): what is wrong with it and nothing more, or what it interrupts and whether
    /// it moves the caller. Changes nothing.
    pub async fn validate_config(&self, proposed: Config, at: Arrival) -> ValidateConfigResponse {
        match self.check_config(proposed).await {
            Err(violations) => ValidateConfigResponse {
                violations,
                effects: Vec::new(),
                caller: None,
            },
            Ok((config, effects)) => {
                let world = self.world.borrow().clone();
                let lan = gate::caller_lan(&world, at.peer, at.local);
                ValidateConfigResponse {
                    violations: Vec::new(),
                    effects: effects
                        .iter()
                        .map(openfeo_reconcile::state::effect_pb)
                        .collect(),
                    caller: Some(gate::caller(
                        &world.config,
                        &config,
                        lan.as_deref(),
                        at.local,
                    )),
                }
            }
        }
    }

    /// Apply a config (SPEC §5.5): pending until it is confirmed, or at once when the request
    /// says `immediate`. The file is written before anything is taken or published, so a write
    /// that fails changes nothing.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for a config that breaks a rule (the text names up to five) or a
    /// window out of range; `FailedPrecondition` for a stale tag, a change already pending or
    /// a router running over a refused file; `Internal` when the file cannot be written.
    pub async fn apply_config(
        self: &Arc<Self>,
        request: ApplyConfigRequest,
    ) -> Result<ApplyConfigResponse, ApiError> {
        let this = Arc::clone(self);
        whole("the apply", async move { this.apply_whole(request).await }).await
    }

    /// The apply itself, from the keeper's lock to the event.
    async fn apply_whole(
        &self,
        request: ApplyConfigRequest,
    ) -> Result<ApplyConfigResponse, ApiError> {
        let Some(proposed) = request.config else {
            return Err(ApiError::new(
                ErrorCode::InvalidArgument,
                "an apply with no config",
            ));
        };
        let ports = self.world.borrow().ports.clone();
        let mut keeper = self.keeper.lock().await;
        let accepted = keeper
            .accept(
                proposed,
                &request.tag,
                request.immediate,
                request.timeout_secs,
                &ports,
                boot_ms(),
            )
            .map_err(|refusal| refused(&refusal))?;
        let text = file::render(accepted.config())
            .map_err(|err| not_written("the config as text", &err))?;
        let config_path = self.config_path.clone();
        if accepted.pending().is_some() {
            off_thread("config.pending.toml", move || {
                file::write_whole(&file::pending_path(&config_path), &text)
                    .map_err(io::Error::other)
            })
            .await?;
        } else {
            off_thread("config.toml", move || {
                keep_original(&config_path)?;
                file::write_whole(&config_path, &text).map_err(io::Error::other)
            })
            .await?;
        }
        let tag = secrets::tag(accepted.config());
        let (config, pending) = (accepted.config().clone(), accepted.pending().cloned());
        let effects = accepted.effects().to_vec();
        keeper.commit(accepted);
        // Said before it is published, so that on the console the change comes first and
        // what it sets off (a task stopped, an address moved) follows it.
        let applied = pending
            .as_ref()
            .map_or_else(line_applied_immediately, |fact| {
                line_applied(fact.window_secs)
            });
        info!("{applied}");
        for effect in &effects {
            info!("{}", line_effect(effect));
        }
        self.publish(config, pending.clone());
        let (mode, window_secs) = if let Some(fact) = &pending {
            self.start_window(fact.window_secs);
            ("pending", fact.window_secs)
        } else {
            ("immediate", 0)
        };
        self.publisher.emit(
            EventDraft::new("config.applied")
                .with("mode", mode)
                .with("effects", effects.len().to_string())
                .with("window_secs", window_secs.to_string()),
        );
        Ok(ApplyConfigResponse { tag })
    }

    /// Confirm the pending change: its file becomes `config.toml`.
    ///
    /// # Errors
    ///
    /// `FailedPrecondition` when nothing is pending; `Internal` when the file cannot be
    /// promoted (the change is then still pending).
    pub async fn confirm_config(self: &Arc<Self>) -> Result<(), ApiError> {
        let this = Arc::clone(self);
        whole("the confirm", async move { this.confirm_whole().await }).await
    }

    /// The confirm itself.
    async fn confirm_whole(&self) -> Result<(), ApiError> {
        let mut keeper = self.keeper.lock().await;
        if keeper.pending().is_none() {
            return Err(refused(&Refusal::NothingPending));
        }
        let text = file::render(keeper.running())
            .map_err(|err| not_written("the config as text", &err))?;
        let config_path = self.config_path.clone();
        off_thread("config.toml", move || promote(&config_path, &text)).await?;
        let config = keeper.confirm().map_err(|refusal| refused(&refusal))?;
        info!("{}", line_confirmed());
        self.publish(config, None);
        self.window.send_replace(None);
        self.publisher.emit(EventDraft::new("config.confirmed"));
        Ok(())
    }

    /// Revert the pending change: the confirmed config is published again.
    ///
    /// # Errors
    ///
    /// `FailedPrecondition` when nothing is pending.
    pub async fn revert_config(self: &Arc<Self>, why: Why) -> Result<(), ApiError> {
        let this = Arc::clone(self);
        whole("the revert", async move {
            let mut keeper = this.keeper.lock().await;
            this.revert_held(&mut keeper, why).await
        })
        .await
    }

    /// The revert, by whoever holds the keeper.
    async fn revert_held(&self, keeper: &mut Keeper, why: Why) -> Result<(), ApiError> {
        let window_secs = keeper.pending().map_or(0, |fact| fact.window_secs);
        let config = keeper.revert().map_err(|refusal| refused(&refusal))?;
        // As an apply: the line first, then what going back sets off.
        info!("{}", line_reverted(why, window_secs));
        self.publish(config, None);
        self.window.send_replace(None);
        let config_path = self.config_path.clone();
        // The config is already back; a pending file that will not go is discarded at the
        // next start, as any other.
        let _ = off_thread("config.pending.toml (removing it)", move || {
            remove_pending(&config_path).map(|_| ())
        })
        .await;
        self.publisher
            .emit(EventDraft::new("config.reverted").with("why", why_field(why)));
        Ok(())
    }

    /// At the start of the API: a pending file left by a router that stopped before its change
    /// was confirmed is deleted and never applied (SPEC §5.5), and that is said.
    pub fn discard_pending(&self) {
        let pending_path = file::pending_path(&self.config_path);
        match std::fs::remove_file(&pending_path) {
            Ok(()) => {
                // Gone for this run whatever the sync says; unsynced, a power cut in the next
                // seconds has it discarded once more.
                if let Err(err) = sync_dir_of(&pending_path) {
                    warn!(
                        "config: cannot sync the removal of {}: {err}",
                        pending_path.display()
                    );
                }
                info!("{}", line_discarded());
                self.publisher.emit(EventDraft::new("config.discarded"));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => warn!("config: cannot remove {}: {err}", pending_path.display()),
        }
    }

    /// At the start of the API task (SPEC §5.5): nobody is keeping a window. A change the
    /// World still calls pending was applied by an API task that has since been restarted,
    /// with its timer and every session that could have confirmed it: the router goes back
    /// to the confirmed config now. With nothing pending in the World, a pending file is what
    /// an earlier run of the router left ([`Shared::discard_pending`]).
    pub fn settle_at_start(&self) {
        let orphan = self.world.borrow().pending.clone();
        let Some(fact) = orphan else {
            self.discard_pending();
            return;
        };
        info!("{}", line_reverted(Why::Restarted, fact.window_secs));
        self.publish(fact.confirmed.clone(), None);
        if let Err(err) = remove_pending(&self.config_path) {
            warn!(
                "config: cannot remove {}: {err}",
                file::pending_path(&self.config_path).display()
            );
        }
        self.publisher
            .emit(EventDraft::new("config.reverted").with("why", why_field(Why::Restarted)));
    }

    /// One swap of the World's config, and of what is pending with it.
    fn publish(&self, config: Arc<Config>, pending: Option<PendingFact>) {
        let pending = pending.map(Arc::new);
        self.publisher.update(|world| {
            world.config = config;
            world.pending = pending;
        });
    }

    /// Start the window of the change just applied: [`keep_window`] reverts it when it ends.
    fn start_window(&self, window_secs: u32) {
        let turn = self.window_turn.fetch_add(1, Ordering::Relaxed) + 1;
        let ends = Instant::now() + Duration::from_secs(u64::from(window_secs));
        self.window.send_replace(Some((turn, ends)));
    }

    /// The window that began as `turn` has run out: revert, unless that change was settled
    /// (and perhaps another applied) in the meantime.
    async fn window_ran_out(&self, turn: u64) {
        let mut keeper = self.keeper.lock().await;
        let current = self.window.borrow().map(|(turn, _)| turn);
        if current == Some(turn) {
            // Nothing pending by now is nothing to do.
            let _ = self.revert_held(&mut keeper, Why::TimedOut).await;
        }
    }
}

/// The window's timer: while a change is pending, wait for its window to end and revert it.
/// It counts on tokio's monotonic clock and needs nobody to be connected.
///
/// # Errors
///
/// Never in practice: only if the shared state is gone.
pub async fn keep_window(shared: Arc<Shared>) -> Result<(), TaskError> {
    let mut window = shared.window.subscribe();
    loop {
        let current = *window.borrow_and_update();
        match current {
            None => window
                .changed()
                .await
                .map_err(|_| "the API's state is gone")?,
            Some((turn, ends)) => {
                tokio::select! {
                    () = tokio::time::sleep_until(ends) => shared.window_ran_out(turn).await,
                    changed = window.changed() => changed.map_err(|_| "the API's state is gone")?,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use openfeo_config::admin::ConfigState;
    use openfeo_config::api::ApplyConfigRequest;
    use openfeo_config::{StaticLease, file, wan};
    use openfeo_reconcile::fixtures;
    use openfeo_runtime::Publisher;
    use openfeo_world::health::HealthView;
    use tokio::sync::watch;

    use super::*;
    use crate::server::tests::{NoCounters, PASSWORD};
    use crate::server::{Limits, SharedParts};
    use crate::telemetry::Telemetry;

    struct Rig {
        shared: Arc<Shared>,
        dir: tempfile::TempDir,
        events: tokio::sync::broadcast::Receiver<Arc<openfeo_world::Event>>,
    }

    impl Rig {
        /// Shared state over `world`, whose config is on disk as the router renders it, with
        /// `window_secs` as the default window. The window's task is not running.
        fn over(world: openfeo_world::World, state: ConfigState, window_secs: u32) -> Rig {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("config.toml");
            std::fs::write(&config_path, file::render(&world.config).unwrap()).unwrap();
            let (publisher, world) =
                Publisher::with_derive(world, Box::new(openfeo_reconcile::derive::derive));
            let publisher = Arc::new(publisher);
            let events = publisher.events();
            let (_health_tx, health) = watch::channel(HealthView {
                healthy: true,
                unhealthy: Vec::new(),
            });
            let shared = Shared::new(SharedParts {
                world,
                publisher,
                health,
                telemetry: Telemetry::new(Arc::new(NoCounters)),
                config_path,
                config_state: state,
                version: "0.4.0-test".to_owned(),
                limits: Limits::default(),
                extra_host: None,
                default_window_secs: window_secs,
            });
            Rig {
                shared,
                dir,
                events,
            }
        }

        fn new(window_secs: u32) -> Rig {
            Rig::over(fixtures::dhcp_world(), ConfigState::Loaded, window_secs)
        }

        /// The shared state a restarted API task builds: new, over the same World and the
        /// same files.
        fn restarted(&self) -> Arc<Shared> {
            let (_health_tx, health) = watch::channel(HealthView {
                healthy: true,
                unhealthy: Vec::new(),
            });
            Shared::new(SharedParts {
                world: self.shared.world.clone(),
                publisher: self.shared.publisher.clone(),
                health,
                telemetry: Telemetry::new(Arc::new(NoCounters)),
                config_path: self.config_path(),
                config_state: ConfigState::Loaded,
                version: "0.4.0-test".to_owned(),
                limits: Limits::default(),
                extra_host: None,
                default_window_secs: 120,
            })
        }

        fn config_path(&self) -> std::path::PathBuf {
            self.dir.path().join("config.toml")
        }

        fn pending_path(&self) -> std::path::PathBuf {
            self.dir.path().join("config.pending.toml")
        }

        fn on_disk(&self) -> Config {
            file::parse(&std::fs::read_to_string(self.config_path()).unwrap()).unwrap()
        }

        fn running(&self) -> Config {
            (*self.shared.world.borrow().config).clone()
        }

        /// Apply `proposed` as the API would send it: without secrets, with the tag it was
        /// read under.
        async fn apply(
            &self,
            proposed: &Config,
            immediate: bool,
            timeout_secs: u32,
        ) -> Result<ApplyConfigResponse, ApiError> {
            let tag = self.shared.config_view().await.tag;
            self.shared
                .apply_config(ApplyConfigRequest {
                    config: Some(secrets::redact(proposed)),
                    tag,
                    immediate,
                    timeout_secs,
                })
                .await
        }

        /// The topics (and the fields) of every event since the last look.
        fn topics(&mut self) -> Vec<String> {
            let mut seen = Vec::new();
            while let Ok(event) = self.events.try_recv() {
                let fields: Vec<String> = event
                    .fields
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect();
                seen.push(
                    format!("{} {}", event.topic, fields.join(" "))
                        .trim()
                        .to_owned(),
                );
            }
            seen
        }
    }

    fn dhcp() -> Config {
        (*fixtures::dhcp_world().config).clone()
    }

    /// The supervisor restarts the API task while a change is pending. The task that kept
    /// the window is gone, and every session with it: the new one goes back to the confirmed
    /// config at once and says that, not that it found something to discard.
    #[tokio::test]
    async fn an_api_restarted_inside_the_window_goes_back_to_the_confirmed_config() {
        let mut rig = Rig::new(120);
        let before = rig.shared.config_view().await.tag;
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        assert!(rig.shared.world.borrow().pending.is_some());
        assert_eq!(rig.running().lans[0].ipv4, "192.168.2.1/24");
        rig.topics();
        let second = rig.restarted();
        second.settle_at_start();
        assert_eq!(rig.running().lans[0].ipv4, "192.168.1.1/24");
        assert_eq!(rig.on_disk().lans[0].ipv4, "192.168.1.1/24");
        assert!(rig.shared.world.borrow().pending.is_none());
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.topics(), ["config.reverted why=restart"]);
        // It keeps the confirmed config: the tag is the one from before the change, and an
        // apply over it is taken.
        assert_eq!(second.config_view().await.tag, before);
        second
            .apply_config(ApplyConfigRequest {
                config: Some(secrets::redact(&with_reservation(dhcp()))),
                tag: before,
                immediate: true,
                timeout_secs: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            rig.on_disk().lans[0].dhcp.as_ref().unwrap().r#static.len(),
            2
        );
    }

    /// Wait, on the runtime, for `settled` to hold; two seconds is for ever here.
    async fn eventually(what: &str, settled: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !settled() {
            assert!(Instant::now() < deadline, "never: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Whoever asked for an apply goes away while its file is being written: a gRPC call
    /// reset in flight drops the handler's future. What was begun is finished, so the file
    /// and the running config never part.
    #[tokio::test]
    async fn an_apply_whose_caller_goes_away_is_finished_whole() {
        let rig = Rig::new(120);
        let request = ApplyConfigRequest {
            config: Some(secrets::redact(&with_reservation(dhcp()))),
            tag: rig.shared.config_view().await.tag,
            immediate: true,
            timeout_secs: 0,
        };
        // Polled once and dropped, while the keeper is busy so that it cannot be done by then.
        let busy = rig.shared.keeper.lock().await;
        let cut = tokio::time::timeout(Duration::ZERO, rig.shared.apply_config(request)).await;
        assert!(cut.is_err(), "the apply finished at its first poll");
        drop(busy);
        eventually("the file written", || {
            rig.on_disk().lans[0].dhcp.as_ref().unwrap().r#static.len() == 2
        })
        .await;
        eventually("the config the file holds running", || {
            rig.running().lans[0].dhcp.as_ref().unwrap().r#static.len() == 2
        })
        .await;
    }

    /// The same for a confirm: the file promoted and the keeper still waiting would have the
    /// timer take the change back while the disk keeps it for the next boot.
    #[tokio::test]
    async fn a_confirm_whose_caller_goes_away_is_finished_whole() {
        let rig = Rig::new(120);
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        let busy = rig.shared.keeper.lock().await;
        let cut = tokio::time::timeout(Duration::ZERO, rig.shared.confirm_config()).await;
        assert!(cut.is_err(), "the confirm finished at its first poll");
        drop(busy);
        eventually("the file promoted", || {
            rig.on_disk().lans[0].ipv4 == "192.168.2.1/24"
        })
        .await;
        eventually("nothing pending", || {
            rig.shared.world.borrow().pending.is_none()
        })
        .await;
        assert_eq!(rig.running().lans[0].ipv4, "192.168.2.1/24");
        assert!(!rig.pending_path().exists());
        // Settled: a second confirm is told there is nothing to confirm.
        let err = rig.shared.confirm_config().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// A confirm cut off after its file work, however that came about (the rename done, the
    /// directory's sync refused), is not stuck: asked again, it finishes.
    #[tokio::test]
    async fn a_confirm_can_be_asked_again_after_its_file_was_promoted() {
        let rig = Rig::new(120);
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        std::fs::rename(rig.pending_path(), rig.config_path()).unwrap();
        rig.shared.confirm_config().await.unwrap();
        assert_eq!(rig.on_disk().lans[0].ipv4, "192.168.2.1/24");
        assert_eq!(rig.running().lans[0].ipv4, "192.168.2.1/24");
        assert!(rig.shared.world.borrow().pending.is_none());
    }

    /// With nothing pending in the World a start is what it was: a pending file is a change
    /// some earlier run of the router never confirmed.
    #[tokio::test]
    async fn a_start_with_nothing_pending_discards_a_pending_file() {
        let mut rig = Rig::new(120);
        std::fs::write(rig.pending_path(), file::render(&moved(dhcp())).unwrap()).unwrap();
        rig.shared.settle_at_start();
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.running().lans[0].ipv4, "192.168.1.1/24");
        assert_eq!(rig.topics(), ["config.discarded"]);
    }

    /// `config` with a reservation more on `lan0`.
    fn with_reservation(mut config: Config) -> Config {
        config.lans[0]
            .dhcp
            .as_mut()
            .unwrap()
            .r#static
            .push(StaticLease {
                mac: "02:00:00:00:00:77".to_owned(),
                ip: "192.168.1.77".to_owned(),
                hostname: "printer".to_owned(),
                client_id: String::new(),
            });
        config
    }

    /// `config` with `lan0` at `192.168.2.1/24` and everything in it moved along.
    fn moved(mut config: Config) -> Config {
        let lan = &mut config.lans[0];
        lan.ipv4 = "192.168.2.1/24".to_owned();
        let dhcp = lan.dhcp.as_mut().unwrap();
        dhcp.range = vec!["192.168.2.100".to_owned(), "192.168.2.200".to_owned()];
        for lease in &mut dhcp.r#static {
            lease.ip = lease.ip.replace("192.168.1.", "192.168.2.");
        }
        if let Some(firewall) = &mut config.firewall {
            for forward in &mut firewall.port_forwards {
                forward.to = forward.to.replace("192.168.1.", "192.168.2.");
            }
        }
        config
    }

    #[tokio::test]
    async fn the_view_is_the_running_config_without_its_secrets() {
        let rig = Rig::new(120);
        rig.shared
            .set_initial_password("192.168.1.23".parse().unwrap(), PASSWORD.to_owned())
            .await
            .unwrap();
        let view = rig.shared.config_view().await;
        let config = view.config.unwrap();
        assert_eq!(config.admin.unwrap().password_hash, "");
        assert_eq!(config.lans, dhcp().lans);
        assert_eq!(view.tag, secrets::tag(&dhcp()));
        assert_eq!(view.confirm_secs, 120);
    }

    #[tokio::test]
    async fn an_apply_writes_the_pending_file_and_publishes_the_config() {
        let mut rig = Rig::new(120);
        let before = std::fs::read_to_string(rig.config_path()).unwrap();
        let answer = rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        assert_eq!(answer.tag, secrets::tag(&moved(dhcp())));
        assert_eq!(
            std::fs::read_to_string(rig.config_path()).unwrap(),
            before,
            "config.toml is not touched until the change is confirmed"
        );
        let pending = file::parse(&std::fs::read_to_string(rig.pending_path()).unwrap()).unwrap();
        assert_eq!(pending, moved(dhcp()));
        assert_eq!(rig.running(), moved(dhcp()));
        let fact = rig.shared.world.borrow().pending.clone().expect("pending");
        assert_eq!(fact.window_secs, 120);
        assert_eq!(fact.reverts_boot_ms - fact.applied_boot_ms, 120_000);
        assert_eq!(
            fact.lans.iter().map(String::as_str).collect::<Vec<_>>(),
            ["lan0"]
        );
        assert_eq!(
            rig.topics(),
            ["config.applied effects=1 mode=pending window_secs=120"]
        );
        // The view follows.
        let view = rig.shared.config_view().await;
        assert_eq!(view.tag, answer.tag);
        assert_eq!(view.config.unwrap().lans[0].ipv4, "192.168.2.1/24");
    }

    #[tokio::test]
    async fn a_confirm_promotes_the_file() {
        let mut rig = Rig::new(120);
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        rig.topics();
        rig.shared.confirm_config().await.unwrap();
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.on_disk(), moved(dhcp()));
        assert_eq!(rig.running(), moved(dhcp()));
        assert_eq!(rig.shared.world.borrow().pending, None);
        assert_eq!(rig.topics(), ["config.confirmed"]);
        // Nothing left to confirm or revert.
        let err = rig.shared.confirm_config().await.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let err = rig.shared.revert_config(Why::Asked).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    #[tokio::test]
    async fn a_revert_republishes_the_old_config_and_deletes_the_file() {
        let mut rig = Rig::new(120);
        let before = std::fs::read_to_string(rig.config_path()).unwrap();
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        rig.topics();
        rig.shared.revert_config(Why::Asked).await.unwrap();
        assert!(!rig.pending_path().exists());
        assert_eq!(std::fs::read_to_string(rig.config_path()).unwrap(), before);
        assert_eq!(rig.running(), dhcp());
        assert_eq!(rig.shared.world.borrow().pending, None);
        assert_eq!(rig.topics(), ["config.reverted why=asked"]);
        // The old tag is back: what was edited before the change still applies.
        assert_eq!(rig.shared.config_view().await.tag, secrets::tag(&dhcp()));
    }

    /// Nobody is connected when the window ends (the apply's own connection went with the
    /// address it moved): the revert needs no client.
    #[tokio::test]
    async fn the_window_runs_out_with_nobody_listening() {
        let mut rig = Rig::new(1);
        let window = tokio::spawn(keep_window(rig.shared.clone()));
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        assert_eq!(rig.running(), moved(dhcp()));
        // The event is the last thing a revert does: wait for it, however loaded the host.
        let mut seen = rig.topics();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !seen
            .iter()
            .any(|topic| topic.starts_with("config.reverted"))
        {
            assert!(
                Instant::now() < deadline,
                "the window never ran out: {seen:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
            seen.extend(rig.topics());
        }
        assert_eq!(
            seen,
            [
                "config.applied effects=1 mode=pending window_secs=1",
                "config.reverted why=timeout"
            ]
        );
        assert_eq!(rig.running(), dhcp());
        assert_eq!(rig.shared.world.borrow().pending, None);
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.on_disk(), dhcp());
        // And the next change gets its own window.
        rig.apply(&with_reservation(dhcp()), false, 0)
            .await
            .unwrap();
        assert_eq!(rig.running(), with_reservation(dhcp()));
        let deadline = Instant::now() + Duration::from_secs(20);
        while rig.running() != dhcp() {
            assert!(Instant::now() < deadline, "the second window never ran out");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        window.abort();
    }

    #[tokio::test]
    async fn a_confirm_just_before_the_window_ends_stands() {
        // Three seconds of window: the confirm has two to spare on a loaded host, and the
        // look afterwards is a second past where the window would have ended.
        let mut rig = Rig::new(3);
        let window = tokio::spawn(keep_window(rig.shared.clone()));
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        rig.shared.confirm_config().await.unwrap();
        tokio::time::sleep(Duration::from_millis(3_000)).await;
        assert_eq!(rig.running(), moved(dhcp()));
        assert_eq!(rig.on_disk(), moved(dhcp()));
        assert_eq!(
            rig.topics(),
            [
                "config.applied effects=1 mode=pending window_secs=3",
                "config.confirmed"
            ]
        );
        window.abort();
    }

    #[tokio::test]
    async fn an_immediate_apply_writes_the_config_file_and_no_pending_one() {
        let mut rig = Rig::new(120);
        rig.apply(&with_reservation(dhcp()), true, 0).await.unwrap();
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.on_disk(), with_reservation(dhcp()));
        assert_eq!(rig.running(), with_reservation(dhcp()));
        assert_eq!(rig.shared.world.borrow().pending, None);
        assert_eq!(
            rig.topics(),
            ["config.applied effects=1 mode=immediate window_secs=0"]
        );
        let err = rig.shared.revert_config(Why::Asked).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    #[tokio::test]
    async fn an_apply_whose_file_cannot_be_written_changes_nothing() {
        let mut rig = Rig::new(120);
        // Where the pending file goes there is a directory with something in it: the rename
        // cannot replace it, whoever runs the test.
        std::fs::create_dir(rig.pending_path()).unwrap();
        std::fs::write(rig.pending_path().join("keep"), "kept").unwrap();
        let tag = rig.shared.config_view().await.tag;
        let err = rig.apply(&moved(dhcp()), false, 0).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(rig.running(), dhcp());
        assert_eq!(rig.shared.world.borrow().pending, None);
        assert_eq!(rig.shared.config_view().await.tag, tag);
        assert_eq!(rig.topics(), Vec::<String>::new());
        // The keeper took nothing: with the way clear the same apply goes through.
        std::fs::remove_dir_all(rig.pending_path()).unwrap();
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
    }

    #[tokio::test]
    async fn a_refused_apply_names_its_violations_and_changes_nothing() {
        let mut rig = Rig::new(120);
        let mut bad = dhcp();
        let dhcp_table = bad.lans[0].dhcp.as_mut().unwrap();
        dhcp_table.r#static.clear();
        for n in 0..6 {
            dhcp_table.r#static.push(StaticLease {
                mac: format!("not-a-mac-{n}"),
                ip: format!("192.168.1.{}", 20 + n),
                hostname: String::new(),
                client_id: String::new(),
            });
        }
        let err = rig.apply(&bad, false, 0).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(
            err.message.starts_with("the config has 6 violations: "),
            "{}",
            err.message
        );
        assert!(err.message.ends_with("; and 1 more"), "{}", err.message);
        assert_eq!(
            err.message.matches("lans[0].dhcp.static[").count(),
            5,
            "{}",
            err.message
        );
        assert_eq!(rig.running(), dhcp());
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.topics(), Vec::<String>::new());
        // One violation is said without a count of the rest.
        let mut one = dhcp();
        one.lans[0].ipv4 = "not-an-address".to_owned();
        let err = rig.apply(&one, false, 0).await.unwrap_err();
        assert!(
            err.message.starts_with("the config has "),
            "{}",
            err.message
        );
        assert!(!err.message.contains(" more"), "{}", err.message);
        // And the check says the same things, each on its own.
        let violations = rig.shared.check_config(bad).await.unwrap_err();
        assert_eq!(violations.len(), 6);
        assert_eq!(violations[0].path, "lans[0].dhcp.static[0].mac");
        assert_eq!(violations[0].code, "invalid_mac");
    }

    #[tokio::test]
    async fn the_other_refusals_have_their_codes() {
        let rig = Rig::new(120);
        // No config at all.
        let err = rig
            .shared
            .apply_config(ApplyConfigRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        // A stale tag.
        let err = rig
            .shared
            .apply_config(ApplyConfigRequest {
                config: Some(moved(dhcp())),
                tag: "0".repeat(32),
                immediate: false,
                timeout_secs: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("changed"), "{}", err.message);
        // A window out of range.
        let err = rig.apply(&moved(dhcp()), false, 9).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("10 to 600"), "{}", err.message);
        // A router on defaults over a file it refused.
        let refused = Rig::over(
            fixtures::dhcp_world(),
            ConfigState::Refused {
                problem: crate::server::tests::problem("config.toml: unknown key"),
                readable: true,
            },
            120,
        );
        let err = refused.apply(&moved(dhcp()), true, 0).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("refused"), "{}", err.message);
        assert!(refused.shared.check_config(moved(dhcp())).await.is_ok());
    }

    #[tokio::test]
    async fn a_second_apply_and_a_password_change_wait_for_the_first() {
        let rig = Rig::new(120);
        let from: IpAddr = "192.168.1.23".parse().unwrap();
        let session = rig
            .shared
            .set_initial_password(from, PASSWORD.to_owned())
            .await
            .unwrap();
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        let err = rig
            .apply(&moved(with_reservation(dhcp())), false, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let err = rig
            .apply(&moved(with_reservation(dhcp())), true, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let err = rig
            .shared
            .change_password(
                from,
                &session.token,
                PASSWORD.to_owned(),
                "another-admin-password".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("pending"), "{}", err.message);
        // The old password still logs in: nothing was changed.
        rig.shared.login(from, PASSWORD.to_owned()).await.unwrap();
        // Settled, both go through.
        rig.shared.confirm_config().await.unwrap();
        rig.apply(&moved(with_reservation(dhcp())), false, 0)
            .await
            .unwrap();
        rig.shared.revert_config(Why::Asked).await.unwrap();
        rig.shared
            .change_password(
                from,
                &session.token,
                PASSWORD.to_owned(),
                "another-admin-password".to_owned(),
            )
            .await
            .unwrap();
    }

    /// The keeper holds its own copies of the config; a password set or changed has to reach
    /// them, or the next apply would write the old hash back.
    #[tokio::test]
    async fn a_password_set_or_changed_is_in_the_next_config_written() {
        let rig = Rig::new(120);
        let from: IpAddr = "192.168.1.23".parse().unwrap();
        let session = rig
            .shared
            .set_initial_password(from, PASSWORD.to_owned())
            .await
            .unwrap();
        let first = rig.on_disk().admin.unwrap().password_hash;
        assert!(first.starts_with("$argon2id$"), "{first}");
        rig.apply(&with_reservation(dhcp()), true, 0).await.unwrap();
        assert_eq!(rig.on_disk().admin.unwrap().password_hash, first);
        // A file the router rendered and then set the password in is still the router's own:
        // nothing of it is kept aside as somebody's hand-written file.
        assert!(!rig.dir.path().join("config.toml.orig").exists());
        assert_eq!(rig.running().admin.unwrap().password_hash, first);
        rig.shared
            .change_password(
                from,
                &session.token,
                PASSWORD.to_owned(),
                "another-admin-password".to_owned(),
            )
            .await
            .unwrap();
        let second = rig.on_disk().admin.unwrap().password_hash;
        assert_ne!(second, first);
        // Pending and then reverted, pending and then confirmed: the new hash every time.
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        let pending = file::parse(&std::fs::read_to_string(rig.pending_path()).unwrap()).unwrap();
        assert_eq!(pending.admin.unwrap().password_hash, second);
        rig.shared.revert_config(Why::Asked).await.unwrap();
        assert_eq!(rig.running().admin.unwrap().password_hash, second);
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        rig.shared.confirm_config().await.unwrap();
        assert_eq!(rig.on_disk().admin.unwrap().password_hash, second);
        rig.shared
            .login(from, "another-admin-password".to_owned())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_hand_written_file_is_kept_beside_the_first_apply_over_it() {
        let rig = Rig::new(120);
        let orig = rig.dir.path().join("config.toml.orig");
        // The router's own rendering is not kept: there is nothing in it to lose.
        rig.apply(&with_reservation(dhcp()), true, 0).await.unwrap();
        assert!(!orig.exists());
        // Nor is one somebody only laid out differently.
        let spaced = file::render(&with_reservation(dhcp()))
            .unwrap()
            .replace("\n[", "\n\n\n[");
        std::fs::write(rig.config_path(), &spaced).unwrap();
        rig.apply(&dhcp(), true, 0).await.unwrap();
        assert!(!orig.exists());
        rig.apply(&with_reservation(dhcp()), true, 0).await.unwrap();
        // A file somebody wrote, with their notes in it.
        let by_hand = format!(
            "# the fibre line: leave the VLAN tag alone\n{}",
            file::render(&with_reservation(dhcp())).unwrap()
        );
        std::fs::write(rig.config_path(), &by_hand).unwrap();
        rig.apply(&dhcp(), true, 0).await.unwrap();
        assert_eq!(std::fs::read_to_string(&orig).unwrap(), by_hand);
        assert_eq!(rig.on_disk(), dhcp());
        // Kept once: a later apply over another hand-edited file leaves the first copy.
        std::fs::write(rig.config_path(), "# later notes\nconfig_version = 1\n").unwrap();
        rig.apply(&moved(dhcp()), false, 0).await.unwrap();
        rig.shared.confirm_config().await.unwrap();
        assert_eq!(std::fs::read_to_string(&orig).unwrap(), by_hand);
        assert_eq!(rig.on_disk(), moved(dhcp()));
    }

    #[tokio::test]
    async fn a_pending_file_found_at_start_is_discarded_and_said() {
        let mut rig = Rig::new(120);
        // Nothing there: nothing said.
        rig.shared.discard_pending();
        assert_eq!(rig.topics(), Vec::<String>::new());
        std::fs::write(rig.pending_path(), file::render(&moved(dhcp())).unwrap()).unwrap();
        rig.shared.discard_pending();
        assert!(!rig.pending_path().exists());
        assert_eq!(rig.running(), dhcp(), "it is never applied");
        assert_eq!(rig.topics(), ["config.discarded"]);
    }

    #[test]
    fn the_config_lines_are_the_contract() {
        assert_eq!(line_applied(120), "config: applied; confirm within 120 s");
        assert_eq!(line_applied_immediately(), "config: applied immediately");
        assert_eq!(
            line_effect(&Effect {
                subject: "lan0".to_owned(),
                kind: openfeo_world::EffectKind::LanAddressMoves,
            }),
            "config: effect lan0 address moves"
        );
        assert_eq!(
            line_effect(&Effect {
                subject: "wan0".to_owned(),
                kind: openfeo_world::EffectKind::WanReconnects,
            }),
            "config: effect wan0 reconnects"
        );
        assert_eq!(line_confirmed(), "config: confirmed");
        assert_eq!(line_reverted(Why::Asked, 120), "config: reverted (asked)");
        assert_eq!(
            line_reverted(Why::TimedOut, 120),
            "config: reverted (not confirmed in 120 s)"
        );
        assert_eq!(
            line_discarded(),
            "config: an unconfirmed change was discarded"
        );
    }

    #[tokio::test]
    async fn no_line_and_no_error_carries_a_secret() {
        let world = fixtures::pppoe_world();
        let rig = Rig::over(world.clone(), ConfigState::Loaded, 120);
        let from: IpAddr = "192.168.1.23".parse().unwrap();
        rig.shared
            .set_initial_password(from, PASSWORD.to_owned())
            .await
            .unwrap();
        let hash = rig.on_disk().admin.unwrap().password_hash;
        let secrets_held = ["example-secret".to_owned(), hash];
        let console = Arc::new(openfeo_runtime::log::Ring::new(256 * 1024));
        let _guard = tracing::subscriber::set_default(openfeo_runtime::log::subscriber(
            "openfeo",
            console.clone(),
            Some(Box::new(std::io::sink())),
        ));
        // A valid apply, typing a new PPPoE password; then confirmed; then an invalid one.
        let mut typed = with_reservation((*world.config).clone());
        let Some(wan::Kind::Pppoe(account)) = &mut typed.wans[0].kind else {
            panic!("the fixture's WAN is PPPoE");
        };
        account.password = "freshly-typed-secret".to_owned();
        let tag = rig.shared.config_view().await.tag;
        rig.shared
            .apply_config(ApplyConfigRequest {
                config: Some(typed.clone()),
                tag,
                immediate: false,
                timeout_secs: 0,
            })
            .await
            .unwrap();
        rig.shared.confirm_config().await.unwrap();
        let mut bad = typed;
        bad.lans[0].ipv4 = "not-an-address".to_owned();
        let tag = rig.shared.config_view().await.tag;
        let err = rig
            .shared
            .apply_config(ApplyConfigRequest {
                config: Some(bad.clone()),
                tag,
                immediate: false,
                timeout_secs: 0,
            })
            .await
            .unwrap_err();
        let violations = rig.shared.check_config(bad).await.unwrap_err();
        let mut said = console.tail(256);
        said.push(format!("{err:?}"));
        said.push(err.message.clone());
        said.push(format!("{violations:?}"));
        said.push(format!("{:?}", rig.shared.config_view().await));
        assert!(
            said.iter().any(|line| line.contains("config: applied")),
            "{said:?}"
        );
        for secret in secrets_held
            .iter()
            .chain([&"freshly-typed-secret".to_owned()])
        {
            for line in &said {
                assert!(!line.contains(secret.as_str()), "{line}");
            }
        }
        // The new password did reach the file, which is where it belongs.
        let Some(wan::Kind::Pppoe(account)) = &rig.on_disk().wans[0].kind else {
            panic!("still PPPoE");
        };
        assert_eq!(account.password, "freshly-typed-secret");
    }
}
