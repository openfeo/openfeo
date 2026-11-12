// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A small in-house task supervisor (SPEC §6.3): plain tokio tasks, restarted with backoff when
//! they fail or panic; 3 restarts within 10 minutes marks the task dead in the health tracker,
//! which stops the heartbeat and lets the watchdog reboot the box (SPEC §5.3).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info};

use crate::HealthTracker;

/// Why a supervised task stopped.
pub type TaskError = Box<dyn std::error::Error + Send + Sync>;
/// A boxed supervised task, for factories that cannot name their future type.
pub type BoxedTask = Pin<Box<dyn Future<Output = Result<(), TaskError>> + Send>>;
/// Restarts allowed within [`WINDOW`] before a task is declared dead.
pub const MAX_RESTARTS: usize = 3;
/// The restart-counting window.
pub const WINDOW: Duration = Duration::from_secs(600);
/// Delay before the first restart; doubles each time up to [`MAX_BACKOFF`].
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// The longest delay between restarts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How long a task asked to stop is given before it is dropped (SPEC §6.3).
pub const STOP_GRACE: Duration = Duration::from_secs(3);

/// What a stoppable task is handed: whether it has been asked to stop.
#[derive(Debug, Clone)]
pub struct Stop(watch::Receiver<bool>);

impl Stop {
    /// Returns once a stop has been asked for: at once if it already was. A task whose handle
    /// is gone has been asked.
    pub async fn requested(&mut self) {
        // The only error is the sender dropped, which is the handle dropped.
        let _ = self.0.wait_for(|asked| *asked).await;
    }

    /// Whether a stop has been asked for.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        *self.0.borrow()
    }
}

/// A task that can be asked to stop: see [`Supervisor::spawn_stoppable`]. Dropping the handle
/// ends the task at once, without the grace.
#[derive(Debug)]
pub struct Stoppable {
    ask: watch::Sender<bool>,
    supervising: Option<JoinHandle<()>>,
}

impl Stoppable {
    /// Ask the task to stop and wait until it is gone: it has [`STOP_GRACE`] to return and is
    /// dropped when it does not. It is not restarted and nothing is reported to health.
    pub async fn stop(mut self) {
        // Nobody listening means the task is already over.
        let _ = self.ask.send(true);
        if let Some(supervising) = self.supervising.take() {
            let _ = supervising.await;
        }
    }
}

impl Drop for Stoppable {
    fn drop(&mut self) {
        if let Some(supervising) = &self.supervising {
            supervising.abort();
        }
    }
}

/// A running task that is aborted when this is dropped, so that it cannot outlive whoever
/// supervises it.
struct Running(JoinHandle<Result<(), TaskError>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The restarts of one task within [`WINDOW`].
#[derive(Default)]
struct Restarts(VecDeque<Instant>);

impl Restarts {
    /// Count a restart at `now`; `false` when the budget is spent.
    fn allow(&mut self, now: Instant) -> bool {
        while self
            .0
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            self.0.pop_front();
        }
        if self.0.len() >= MAX_RESTARTS {
            return false;
        }
        self.0.push_back(now);
        true
    }
}

/// Spawns tasks and keeps them running.
#[derive(Debug, Clone)]
pub struct Supervisor {
    health: HealthTracker,
}

impl Supervisor {
    /// A supervisor reporting dead tasks to `health`.
    #[must_use]
    pub fn new(health: HealthTracker) -> Self {
        Supervisor { health }
    }

    /// Run `factory()` as a task; when it returns `Err` or panics, start a fresh one after a
    /// backoff of 1 s doubling to 30 s. A task that returns `Ok` is finished and not restarted.
    /// After [`MAX_RESTARTS`] restarts within [`WINDOW`] the task is dead: reported to health and
    /// left stopped.
    pub fn spawn<F, Fut>(&self, name: impl Into<String>, factory: F) -> JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let health = self.health.clone();
        let name = name.into();
        tokio::spawn(async move {
            let mut restarts = Restarts::default();
            let mut backoff = INITIAL_BACKOFF;
            loop {
                match tokio::spawn(factory()).await {
                    Ok(Ok(())) => {
                        debug!("task {name} finished");
                        return;
                    }
                    Ok(Err(err)) => error!("task {name} failed: {err}"),
                    Err(join) => error!("task {name} panicked: {join}"),
                }
                if !restarts.allow(Instant::now()) {
                    health.task_dead(&name);
                    error!(
                        "task {name} dead after {MAX_RESTARTS} restarts in {}s; heartbeat withheld",
                        WINDOW.as_secs()
                    );
                    return;
                }
                info!("task {name} restart in {}s", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        })
    }

    /// As [`spawn`](Self::spawn), for a task that can be asked to stop. `factory` hands each
    /// run the [`Stop`] to watch. Once a stop is asked the task is given [`STOP_GRACE`] to
    /// return and is dropped when it does not; it is never restarted after that, a wait before
    /// a restart ends at once, and however the task ended nothing is reported to health.
    pub fn spawn_stoppable<F, Fut>(&self, name: impl Into<String>, factory: F) -> Stoppable
    where
        F: Fn(Stop) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let health = self.health.clone();
        let name = name.into();
        let (ask, asked) = watch::channel(false);
        let mut stop = Stop(asked);
        let supervising = tokio::spawn(async move {
            let mut restarts = Restarts::default();
            let mut backoff = INITIAL_BACKOFF;
            loop {
                let mut running = Running(tokio::spawn(factory(stop.clone())));
                let outcome = tokio::select! {
                    outcome = &mut running.0 => outcome,
                    () = stop.requested() => {
                        if tokio::time::timeout(STOP_GRACE, &mut running.0).await.is_err() {
                            info!("task {name} did not stop in {}s; dropped", STOP_GRACE.as_secs());
                            running.0.abort();
                            let _ = (&mut running.0).await;
                        }
                        debug!("task {name} stopped");
                        return;
                    }
                };
                if stop.is_requested() {
                    debug!("task {name} stopped");
                    return;
                }
                match outcome {
                    Ok(Ok(())) => {
                        debug!("task {name} finished");
                        return;
                    }
                    Ok(Err(err)) => error!("task {name} failed: {err}"),
                    Err(join) => error!("task {name} panicked: {join}"),
                }
                if !restarts.allow(Instant::now()) {
                    health.task_dead(&name);
                    error!(
                        "task {name} dead after {MAX_RESTARTS} restarts in {}s; heartbeat withheld",
                        WINDOW.as_secs()
                    );
                    return;
                }
                info!("task {name} restart in {}s", backoff.as_secs());
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = stop.requested() => {
                        debug!("task {name} stopped");
                        return;
                    }
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        });
        Stoppable {
            ask,
            supervising: Some(supervising),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn failing_until(ok_after: usize) -> (Arc<AtomicUsize>, impl Fn() -> BoxedTask) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let factory = move || -> BoxedTask {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move {
                if n <= ok_after {
                    Err(format!("attempt {n} failed").into())
                } else {
                    std::future::pending::<()>().await;
                    Ok(())
                }
            })
        };
        (attempts, factory)
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_restarts_with_doubling_backoff() {
        let health = HealthTracker::new();
        let supervisor = Supervisor::new(health.clone());
        let (attempts, factory) = failing_until(2);
        let _handle = supervisor.spawn("t", factory);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "first attempt at t=0");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "restart after 1 s");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "second backoff is 2 s");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 3, "restart after 2 s more");
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            3,
            "third attempt runs forever"
        );
        assert!(health.is_healthy(std::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_takes_owned_names() {
        let health = HealthTracker::new();
        let supervisor = Supervisor::new(health.clone());
        let (_, factory) = failing_until(usize::MAX);
        let handle = supervisor.spawn(format!("dhcp4-{}", "wan0"), factory);
        handle.await.unwrap();
        let report = health.report(std::time::Instant::now());
        assert_eq!(report.dead_tasks, vec!["dhcp4-wan0".to_owned()]);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_gives_up_after_three_restarts() {
        let health = HealthTracker::new();
        let supervisor = Supervisor::new(health.clone());
        let (attempts, factory) = failing_until(usize::MAX);
        let handle = supervisor.spawn("t", factory);
        handle.await.unwrap();
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            4,
            "initial run plus 3 restarts"
        );
        let report = health.report(std::time::Instant::now());
        assert_eq!(report.dead_tasks, vec!["t".to_owned()]);
        assert!(!report.is_healthy());
    }

    /// A stoppable factory that counts its starts and runs `body` with the task's [`Stop`] and
    /// the number of the start.
    fn counting<F, Fut>(body: F) -> (Arc<AtomicUsize>, impl Fn(Stop) -> BoxedTask)
    where
        F: Fn(Stop, usize) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let starts = Arc::new(AtomicUsize::new(0));
        let counter = starts.clone();
        let body = Arc::new(body);
        let factory = move |stop: Stop| -> BoxedTask {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let body = body.clone();
            Box::pin(async move { body(stop, n).await })
        };
        (starts, factory)
    }

    /// Says when it was dropped: a task that holds one is gone once the flag is set.
    struct Gone(Arc<AtomicBool>);

    impl Drop for Gone {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn rig() -> (HealthTracker, Supervisor) {
        let health = HealthTracker::new();
        let supervisor = Supervisor::new(health.clone());
        (health, supervisor)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_task_ends_and_is_not_restarted() {
        let (health, supervisor) = rig();
        let (starts, factory) = counting(|mut stop, _| async move {
            stop.requested().await;
            Ok(())
        });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        handle.stop().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "a stopped task stays stopped"
        );
        assert_eq!(
            health.report(std::time::Instant::now()).dead_tasks,
            Vec::<String>::new()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_that_ignores_stop_is_dropped_after_the_grace() {
        let (_health, supervisor) = rig();
        let gone = Arc::new(AtomicBool::new(false));
        let flag = gone.clone();
        let (_, factory) = counting(move |_stop, _| {
            let held = Gone(flag.clone());
            async move {
                let _held = held;
                std::future::pending::<()>().await;
                Ok(())
            }
        });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let asked = Instant::now();
        handle.stop().await;
        let took = asked.elapsed();
        assert!(took >= STOP_GRACE, "dropped after only {took:?}");
        assert!(took < STOP_GRACE + Duration::from_secs(1), "took {took:?}");
        assert!(
            gone.load(Ordering::SeqCst),
            "the task is gone by the time stop returns"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_waiting_out_its_backoff_stops_at_once() {
        let (health, supervisor) = rig();
        let (starts, factory) = counting(|_stop, _| async { Err("no".into()) });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 1, "failed once, waiting 1 s");
        let asked = Instant::now();
        handle.stop().await;
        assert!(
            asked.elapsed() < Duration::from_millis(1),
            "{:?}",
            asked.elapsed()
        );
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            health.report(std::time::Instant::now()).dead_tasks,
            Vec::<String>::new()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_is_not_a_death() {
        let (health, supervisor) = rig();
        // Three failures already in the window: one more unasked would be the task's death.
        let (starts, factory) = counting(|mut stop, n| async move {
            if n <= MAX_RESTARTS {
                return Err(format!("attempt {n} failed").into());
            }
            stop.requested().await;
            Err("went badly on the way out".into())
        });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(starts.load(Ordering::SeqCst), MAX_RESTARTS + 1);
        handle.stop().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(starts.load(Ordering::SeqCst), MAX_RESTARTS + 1);
        let report = health.report(std::time::Instant::now());
        assert!(report.dead_tasks.is_empty(), "{:?}", report.dead_tasks);
    }

    #[tokio::test(start_paused = true)]
    async fn a_task_that_fails_unasked_is_still_restarted() {
        let (_health, supervisor) = rig();
        let (starts, factory) = counting(|_stop, n| async move {
            if n == 1 {
                return Err("first".into());
            }
            std::future::pending::<()>().await;
            Ok(())
        });
        let _handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(starts.load(Ordering::SeqCst), 2, "restarted after 1 s");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stoppable_task_that_keeps_failing_is_declared_dead() {
        let (health, supervisor) = rig();
        let (starts, factory) = counting(|_stop, _| async { Err("no".into()) });
        let _handle = supervisor.spawn_stoppable("dhcp4-wan0", factory);
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert_eq!(starts.load(Ordering::SeqCst), MAX_RESTARTS + 1);
        let report = health.report(std::time::Instant::now());
        assert_eq!(report.dead_tasks, vec!["dhcp4-wan0".to_owned()]);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_handle_ends_the_task() {
        let (_health, supervisor) = rig();
        let gone = Arc::new(AtomicBool::new(false));
        let flag = gone.clone();
        let (_, factory) = counting(move |_stop, _| {
            let held = Gone(flag.clone());
            async move {
                let _held = held;
                std::future::pending::<()>().await;
                Ok(())
            }
        });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!gone.load(Ordering::SeqCst));
        drop(handle);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(gone.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_already_asked_is_seen_at_once_by_a_late_listener() {
        let (_health, supervisor) = rig();
        let (starts, factory) = counting(|mut stop, _| async move {
            // Busy for a while before it first looks.
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(stop.is_requested());
            stop.requested().await;
            Ok(())
        });
        let handle = supervisor.spawn_stoppable("t", factory);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let asked = Instant::now();
        handle.stop().await;
        assert!(
            asked.elapsed() <= Duration::from_secs(1),
            "{:?}",
            asked.elapsed()
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}
