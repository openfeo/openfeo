// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The clock the SNTP driver reads and moves (SPEC §7.10), behind a trait: the box's own through
//! `adjtimex`, and a recording one for the sandbox, where the process may not touch the clock
//! and the scenarios want to see the decisions.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openfeo_proto_sntp::Now;
use tokio::time::Instant;

use crate::sys;

/// Reads the time and moves the clock. Clones share the clock, so the listener tasks can read
/// what the driver steers.
pub trait Clock: Clone + Send + Sync + 'static {
    fn now(&self) -> Now;
    /// Jump by `ns` nanoseconds.
    ///
    /// # Errors
    ///
    /// When the kernel refuses (no `CAP_SYS_TIME`).
    fn step(&self, ns: i64) -> io::Result<()>;
    /// Let the kernel slew `ns` nanoseconds away.
    ///
    /// # Errors
    ///
    /// When the kernel refuses (no `CAP_SYS_TIME`).
    fn slew(&self, ns: i64) -> io::Result<()>;
}

/// The box's clock: `tokio::time::Instant` for `mono_ms` since the driver started, `SystemTime`
/// for `unix_ns`, `adjtimex` for the rest.
#[derive(Debug, Clone)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    #[must_use]
    pub fn new() -> SystemClock {
        SystemClock {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Now {
        Now {
            mono_ms: millis(self.start),
            unix_ns: unix_nanos(),
        }
    }

    fn step(&self, ns: i64) -> io::Result<()> {
        sys::adjtimex_step(ns)
    }

    fn slew(&self, ns: i64) -> io::Result<()> {
        sys::adjtimex_slew(ns)
    }
}

/// A clock for the sandbox: real monotonic time, Unix time shifted by every step and slew it was
/// given (the kernel would, over time), and a record of the decisions. Clones share one record.
#[derive(Debug, Clone)]
pub struct Recording {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    start: Instant,
    shift_ns: i64,
    steps: Vec<i64>,
    slews: Vec<i64>,
}

impl Recording {
    #[must_use]
    pub fn new() -> Recording {
        Recording {
            inner: Arc::new(Mutex::new(Inner {
                start: Instant::now(),
                shift_ns: 0,
                steps: Vec::new(),
                slews: Vec::new(),
            })),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut inner)
    }

    /// Every step so far, in order.
    #[must_use]
    pub fn steps(&self) -> Vec<i64> {
        self.with(|inner| inner.steps.clone())
    }

    /// Every slew so far, in order.
    #[must_use]
    pub fn slews(&self) -> Vec<i64> {
        self.with(|inner| inner.slews.clone())
    }

    /// How far the recorded clock is from the real one.
    #[must_use]
    pub fn shift_ns(&self) -> i64 {
        self.with(|inner| inner.shift_ns)
    }
}

impl Default for Recording {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for Recording {
    fn now(&self) -> Now {
        self.with(|inner| Now {
            mono_ms: millis(inner.start),
            unix_ns: unix_nanos().saturating_add(inner.shift_ns),
        })
    }

    fn step(&self, ns: i64) -> io::Result<()> {
        self.with(|inner| {
            inner.shift_ns = inner.shift_ns.saturating_add(ns);
            inner.steps.push(ns);
        });
        Ok(())
    }

    fn slew(&self, ns: i64) -> io::Result<()> {
        self.with(|inner| {
            inner.shift_ns = inner.shift_ns.saturating_add(ns);
            inner.slews.push(ns);
        });
        Ok(())
    }
}

/// Whole milliseconds since `start`.
fn millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Nanoseconds since the Unix epoch; a clock before 1970 reads as 0.
fn unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_nanos()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_proto_sntp::timestamp::NANOS_PER_SEC;

    #[test]
    fn the_recording_clock_shifts_by_every_step_and_slew_and_remembers_them() {
        let clock = Recording::new();
        let before = clock.now();
        clock.step(7_200 * NANOS_PER_SEC).unwrap();
        clock.slew(-200_000_000).unwrap();
        let after = clock.now();
        assert_eq!(
            (clock.steps(), clock.slews()),
            (vec![7_200 * NANOS_PER_SEC], vec![-200_000_000])
        );
        assert_eq!(clock.shift_ns(), 7_200 * NANOS_PER_SEC - 200_000_000);
        assert!(after.unix_ns - before.unix_ns >= clock.shift_ns());
        assert!(after.mono_ms >= before.mono_ms);
        let shared = clock.clone();
        shared.step(1).unwrap();
        assert_eq!(clock.steps().len(), 2, "clones share one record");
    }
}
