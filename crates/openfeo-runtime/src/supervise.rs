// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A small in-house task supervisor (SPEC §6.3): plain tokio tasks, restarted with backoff when
//! they fail or panic; 3 restarts within 10 minutes marks the task dead in the health tracker,
//! which stops the heartbeat and lets the watchdog reboot the box (SPEC §5.3).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

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
    pub fn spawn<F, Fut>(&self, name: &'static str, factory: F) -> JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let health = self.health.clone();
        tokio::spawn(async move {
            let mut restarts: VecDeque<Instant> = VecDeque::new();
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
                let now = Instant::now();
                while restarts
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= WINDOW)
                {
                    restarts.pop_front();
                }
                if restarts.len() >= MAX_RESTARTS {
                    health.task_dead(name);
                    error!(
                        "task {name} dead after {MAX_RESTARTS} restarts in {}s; heartbeat withheld",
                        WINDOW.as_secs()
                    );
                    return;
                }
                restarts.push_back(now);
                info!("task {name} restart in {}s", backoff.as_secs());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
}
