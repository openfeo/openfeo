// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The clock floor (SPEC §7.10): a board without an RTC starts in 1970, and nothing the box does
//! before SNTP answers (TLS, DNS TTLs, lease expiry) should run before the day it was built.
//! PID 1 raises such a clock to the build timestamp; the SNTP client later refuses to go below
//! it (ADR-0016).

use openfeo_proto_sntp::iso8601;

use crate::log::Log;
use crate::sys;

/// What PID 1 does with the clock it finds: `Some(build_epoch)` to set when the clock is earlier
/// than the build (a board without an RTC starts in 1970), `None` to leave it. A build epoch of
/// 0 (a bare `cargo build`) is no floor at all.
#[must_use]
pub fn floor_decision(now_unix_secs: u64, build_epoch: u64) -> Option<u64> {
    (build_epoch != 0 && now_unix_secs < build_epoch).then_some(build_epoch)
}

/// Apply [`floor_decision`] to the wall clock and say what happened: `time floor {iso} (build);
/// clock was {iso}` when the clock was raised, `time clock {iso} (at or after the build)` when
/// it was left, `time floor unknown (dev build)` for a build without an epoch.
pub fn floor(build_epoch: u64, log: &Log) {
    if build_epoch == 0 {
        log.warn("time floor unknown (dev build)");
        return;
    }
    let now = match sys::clock_realtime() {
        Ok(now) => now.as_secs(),
        Err(err) => {
            log.warn(&format!("time: cannot read the clock: {err}"));
            return;
        }
    };
    let Some(floor) = floor_decision(now, build_epoch) else {
        log.info(&format!(
            "time clock {} (at or after the build)",
            iso8601(i64::try_from(now).unwrap_or(i64::MAX))
        ));
        return;
    };
    match sys::set_clock_realtime(floor) {
        Ok(()) => log.info(&format!(
            "time floor {} (build); clock was {}",
            iso8601(i64::try_from(floor).unwrap_or(i64::MAX)),
            iso8601(i64::try_from(now).unwrap_or(i64::MAX))
        )),
        Err(err) => log.warn(&format!("time: cannot raise the clock to the build: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clock_before_the_build_is_raised_to_it_and_a_later_one_is_left() {
        assert_eq!(floor_decision(3, 1_793_448_000), Some(1_793_448_000));
        assert_eq!(floor_decision(1_793_448_000, 1_793_448_000), None);
        assert_eq!(floor_decision(1_800_000_000, 1_793_448_000), None);
        assert_eq!(floor_decision(3, 0), None, "a dev build has no floor");
    }
}
