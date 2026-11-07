// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The process's monotonic clock (SPEC §7.3; ADR-0009): the one `Instant` every task counts
//! from, so a moment in a fact (a lease's `obtained_ms`, a deprecation's deadline) means the
//! same thing to the task that wrote it and the task that reads it, and a wall-clock step after
//! SNTP moves no lifetime.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

static START: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since the first call in this process.
#[must_use]
pub fn uptime_ms() -> u64 {
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The `Instant` at `ms` on this clock, for a timer.
#[must_use]
pub fn instant_at(ms: u64) -> Instant {
    START
        .get_or_init(Instant::now)
        .checked_add(Duration::from_millis(ms))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(u64::from(u32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_never_goes_back_and_its_instants_match() {
        let first = uptime_ms();
        std::thread::sleep(Duration::from_millis(5));
        let second = uptime_ms();
        assert!(second >= first + 5, "{first} -> {second}");
        let at = instant_at(second);
        let now = Instant::now();
        assert!(now >= at || at.duration_since(now) < Duration::from_millis(2));
        assert!(instant_at(0) <= Instant::now());
    }
}
