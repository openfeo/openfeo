// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Live health (SPEC §5.3): appliers mark themselves in flight around every apply and report
//! their status; the supervisor reports dead tasks; the heartbeat task asks
//! [`HealthTracker::is_healthy`] every 5 s. An apply in flight for 30 s is wedged, and wedged
//! means no heartbeat, which is how a hung applier reaches the watchdog.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use openfeo_world::health::{HealthReport, Status, Subsystem};

/// An apply in flight for this long is wedged (SPEC §5.3).
pub const WEDGE_AFTER: Duration = Duration::from_secs(30);

/// Shared, cloneable health state.
#[derive(Debug, Clone, Default)]
pub struct HealthTracker(Arc<Mutex<Inner>>);

#[derive(Debug, Default)]
struct Inner {
    subsystems: BTreeMap<Subsystem, Status>,
    dead_tasks: Vec<String>,
    in_flight: BTreeMap<Subsystem, Instant>,
}

impl HealthTracker {
    /// Everything unknown, nothing in flight: healthy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record the outcome of a subsystem's latest apply.
    pub fn set(&self, subsystem: Subsystem, status: Status) {
        self.lock().subsystems.insert(subsystem, status);
    }

    /// Mark `subsystem` as applying now; drop the guard when the apply returns.
    #[must_use = "dropping the guard ends the in-flight window"]
    pub fn begin(&self, subsystem: Subsystem) -> InFlight {
        self.lock().in_flight.insert(subsystem, Instant::now());
        InFlight {
            tracker: self.clone(),
            subsystem,
        }
    }

    /// A supervised task exceeded its restart budget.
    pub fn task_dead(&self, name: &str) {
        let mut inner = self.lock();
        if !inner.dead_tasks.iter().any(|n| n == name) {
            inner.dead_tasks.push(name.to_owned());
        }
    }

    /// The picture at `now`: an apply in flight for [`WEDGE_AFTER`] or longer is wedged.
    #[must_use]
    pub fn report(&self, now: Instant) -> HealthReport {
        let inner = self.lock();
        HealthReport {
            subsystems: inner.subsystems.clone(),
            dead_tasks: inner.dead_tasks.clone(),
            wedged: inner
                .in_flight
                .iter()
                .filter(|(_, started)| now.saturating_duration_since(**started) >= WEDGE_AFTER)
                .map(|(subsystem, _)| *subsystem)
                .collect(),
        }
    }

    /// Whether PID 1 should be heartbeated at `now`.
    #[must_use]
    pub fn is_healthy(&self, now: Instant) -> bool {
        self.report(now).is_healthy()
    }
}

/// An apply in progress; dropping it ends the in-flight window.
#[derive(Debug)]
pub struct InFlight {
    tracker: HealthTracker,
    subsystem: Subsystem,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.tracker.lock().in_flight.remove(&self.subsystem);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_world::health::{Status, Subsystem};
    use std::time::Duration;

    #[test]
    fn in_flight_apply_over_30s_is_wedged() {
        let health = HealthTracker::new();
        let t0 = Instant::now();
        let guard = health.begin(Subsystem::Links);
        assert!(health.is_healthy(t0 + Duration::from_secs(29)));
        let report = health.report(t0 + WEDGE_AFTER + Duration::from_secs(1));
        assert_eq!(report.wedged, vec![Subsystem::Links]);
        assert!(!report.is_healthy());
        drop(guard);
        assert!(health.is_healthy(t0 + Duration::from_secs(600)));
    }

    #[test]
    fn degraded_is_still_healthy() {
        let health = HealthTracker::new();
        health.set(Subsystem::Routing, Status::Degraded("EEXIST".into()));
        let now = Instant::now();
        assert!(health.is_healthy(now));
        assert_eq!(
            health.report(now).subsystems[&Subsystem::Routing],
            Status::Degraded("EEXIST".into())
        );
        health.set(Subsystem::Routing, Status::Ok);
        assert_eq!(
            health.report(now).subsystems[&Subsystem::Routing],
            Status::Ok
        );
    }

    #[test]
    fn dead_task_is_unhealthy() {
        let health = HealthTracker::new();
        health.task_dead("apply-links");
        let now = Instant::now();
        assert!(!health.is_healthy(now));
        assert_eq!(
            health.report(now).dead_tasks,
            vec!["apply-links".to_owned()]
        );
    }
}
