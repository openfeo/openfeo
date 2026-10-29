// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The child's liveness as PID 1 sees it (SPEC §5.3): a heartbeat within the last 20 s.

use std::time::{Duration, Instant};

/// PID 1 pets the watchdog only while a heartbeat arrived within this window.
pub const GRACE: Duration = Duration::from_secs(20);

/// Time of the last heartbeat. Boot and every child spawn count as one, so a fresh child has
/// [`GRACE`] to start heartbeating before PID 1 stops petting.
#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    last: Instant,
}

impl Heartbeat {
    /// Start the window at `now`.
    #[must_use]
    pub const fn new(now: Instant) -> Self {
        Self { last: now }
    }

    /// A heartbeat arrived at `now`.
    pub fn record(&mut self, now: Instant) {
        self.last = now;
    }

    /// Whether a heartbeat arrived less than [`GRACE`] ago.
    #[must_use]
    pub fn healthy(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) < GRACE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_healthy_within_grace() {
        let t0 = Instant::now();
        let hb = Heartbeat::new(t0);
        assert!(hb.healthy(t0 + Duration::from_secs(19)));
        assert!(!hb.healthy(t0 + Duration::from_secs(20)));
    }

    #[test]
    fn heartbeat_record_extends() {
        let t0 = Instant::now();
        let mut hb = Heartbeat::new(t0);
        hb.record(t0 + Duration::from_secs(15));
        assert!(hb.healthy(t0 + Duration::from_secs(34)));
    }
}
