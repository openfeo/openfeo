// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! How the clock should move for a measured offset (ADR-0016): the first sync steps unless the
//! clock is already close, afterwards offsets under half a second slew and larger ones step. The
//! decision knows nothing of where the offset came from, so a second time source (GPS with a
//! PPS line) can feed it later.

/// The kernel's single-shot slew bound, and ours: under it we slew, from it we step.
pub const STEP_THRESHOLD_NS: i64 = 500_000_000;
/// At the first sync a clock this close is slewed rather than stepped (an RTC box is usually
/// here).
pub const FIRST_STEP_THRESHOLD_NS: i64 = 128_000_000;

/// How the clock should move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Jump by this many nanoseconds.
    Step(i64),
    /// Let the kernel slew this many nanoseconds away.
    Slew(i64),
    /// Nothing to do.
    Hold,
}

/// The decision for `offset_ns` (positive: the clock is behind), given whether the clock was
/// synced before. `Hold` only for an offset of exactly zero.
#[must_use]
pub fn decide(offset_ns: i64, synced_before: bool) -> Decision {
    let threshold = if synced_before {
        STEP_THRESHOLD_NS
    } else {
        FIRST_STEP_THRESHOLD_NS
    };
    match offset_ns {
        0 => Decision::Hold,
        ns if ns.abs() >= threshold => Decision::Step(ns),
        ns => Decision::Slew(ns),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_sync_steps_unless_the_clock_is_already_close() {
        assert_eq!(
            decide(7_200_000_000_000, false),
            Decision::Step(7_200_000_000_000)
        );
        assert_eq!(decide(-128_000_000, false), Decision::Step(-128_000_000));
        assert_eq!(decide(127_999_999, false), Decision::Slew(127_999_999));
        assert_eq!(decide(0, false), Decision::Hold);
    }

    #[test]
    fn after_the_first_sync_small_offsets_slew_and_large_ones_step() {
        assert_eq!(decide(200_000_000, true), Decision::Slew(200_000_000));
        assert_eq!(decide(-499_999_999, true), Decision::Slew(-499_999_999));
        assert_eq!(decide(500_000_000, true), Decision::Step(500_000_000));
        assert_eq!(decide(-3_000_000_000, true), Decision::Step(-3_000_000_000));
    }
}
