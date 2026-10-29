// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Child restart policy (SPEC §5.3): exponential backoff, and after three restarts within ten
//! minutes PID 1 gives up and lets the watchdog reboot the box.

use std::time::{Duration, Instant};

/// A restart counts against the limit for this long.
pub const WINDOW: Duration = Duration::from_secs(600);
/// Restarts allowed within [`WINDOW`] before giving up.
pub const MAX_RESTARTS: usize = 3;
/// Upper bound on the backoff delay.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// What PID 1 does after the child exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Spawn the child again after this delay.
    RestartAfter(Duration),
    /// Stop restarting and stop petting the watchdog.
    GiveUp,
}

/// Sliding-window restart counter.
#[derive(Debug, Default)]
pub struct RestartPolicy {
    restarts: Vec<Instant>,
}

impl RestartPolicy {
    /// Record a child exit at `now` and decide what to do about it. The delay doubles with each
    /// restart in the window (1 s, 2 s, 4 s, capped at [`MAX_DELAY`]).
    pub fn on_exit(&mut self, now: Instant) -> Decision {
        self.restarts
            .retain(|t| now.saturating_duration_since(*t) < WINDOW);
        let n = self.restarts.len();
        if n >= MAX_RESTARTS {
            return Decision::GiveUp;
        }
        self.restarts.push(now);
        Decision::RestartAfter(Duration::from_secs(1u64 << n).min(MAX_DELAY))
    }

    /// Restarts recorded in the current window, including the one just decided.
    #[must_use]
    pub fn restarts_in_window(&self) -> usize {
        self.restarts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_then_give_up() {
        let t0 = Instant::now();
        let mut p = RestartPolicy::default();
        assert_eq!(
            p.on_exit(t0),
            Decision::RestartAfter(Duration::from_secs(1))
        );
        assert_eq!(p.restarts_in_window(), 1);
        assert_eq!(
            p.on_exit(t0 + Duration::from_secs(10)),
            Decision::RestartAfter(Duration::from_secs(2))
        );
        assert_eq!(
            p.on_exit(t0 + Duration::from_secs(20)),
            Decision::RestartAfter(Duration::from_secs(4))
        );
        assert_eq!(p.on_exit(t0 + Duration::from_secs(30)), Decision::GiveUp);
    }

    #[test]
    fn window_forgets_old_restarts() {
        let t0 = Instant::now();
        let mut p = RestartPolicy::default();
        for i in 0..3 {
            p.on_exit(t0 + Duration::from_secs(i));
        }
        // 603 s after t0 the youngest restart (t0 + 2 s) is 601 s old: all three have aged out.
        assert_eq!(
            p.on_exit(t0 + Duration::from_secs(603)),
            Decision::RestartAfter(Duration::from_secs(1))
        );
    }
}
