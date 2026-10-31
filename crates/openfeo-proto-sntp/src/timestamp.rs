// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! NTP's 64-bit timestamps (seconds since 1900 and a 32-bit fraction, RFC 5905 §6), the
//! driver's two clocks, and the console's way of writing times.

/// Seconds from the NTP epoch (1900-01-01) to the Unix epoch (1970-01-01).
pub const UNIX_OFFSET_SECS: u64 = 2_208_988_800;
pub const NANOS_PER_SEC: i64 = 1_000_000_000;
/// The 32-bit seconds field wraps every 2^32 seconds (2036 is the first time).
const ERA_SECS: i64 = 1 << 32;

/// The driver's two clocks at one instant: a monotonic one for timers (milliseconds since the
/// driver started) and the wall clock for timestamps (nanoseconds since the Unix epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub mono_ms: u64,
    pub unix_ns: i64,
}

/// RFC 5905 64-bit timestamp: seconds since 1900 in the high word, a 32-bit fraction in the low.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    /// The timestamp of `ns` nanoseconds since the Unix epoch; the seconds wrap into the era.
    #[must_use]
    pub fn from_unix_nanos(ns: i64) -> NtpTimestamp {
        let secs = ns.div_euclid(NANOS_PER_SEC);
        let nanos = ns.rem_euclid(NANOS_PER_SEC);
        let ntp_secs =
            (secs + i64::try_from(UNIX_OFFSET_SECS).unwrap_or(i64::MAX)).rem_euclid(ERA_SECS);
        let fraction = (nanos << 32) / NANOS_PER_SEC;
        NtpTimestamp(
            (u64::try_from(ntp_secs).unwrap_or(0) << 32) | u64::try_from(fraction).unwrap_or(0),
        )
    }

    /// Nanoseconds since the Unix epoch, in the era that puts the instant within 2^31 seconds
    /// (68 years) of `pivot_unix_secs` (RFC 4330 §3: the build time is the pivot).
    #[must_use]
    pub fn to_unix_nanos(self, pivot_unix_secs: u64) -> i64 {
        let ntp_secs = i64::try_from(self.0 >> 32).unwrap_or(0);
        let pivot_ntp = i64::try_from(pivot_unix_secs).unwrap_or(0)
            + i64::try_from(UNIX_OFFSET_SECS).unwrap_or(0);
        // The signed distance from the pivot within one era, in [-2^31, 2^31).
        let mut delta = (ntp_secs - pivot_ntp).rem_euclid(ERA_SECS);
        if delta >= ERA_SECS / 2 {
            delta -= ERA_SECS;
        }
        let unix_secs = i64::try_from(pivot_unix_secs).unwrap_or(0) + delta;
        let fraction = i64::try_from(self.0 & 0xffff_ffff).unwrap_or(0);
        // Round the fraction to the nearest nanosecond.
        let nanos = ((fraction * NANOS_PER_SEC) + (1 << 31)) >> 32;
        unix_secs * NANOS_PER_SEC + nanos
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Seconds since the Unix epoch as `2026-10-31T12:00:00Z` (civil-from-days, no calendar crate).
#[must_use]
pub fn iso8601(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Signed nanoseconds as `+7200.012s`, to the millisecond, towards zero.
#[must_use]
pub fn signed_secs(ns: i64) -> String {
    let sign = if ns < 0 { '-' } else { '+' };
    let millis = ns.unsigned_abs() / 1_000_000;
    format!("{sign}{}.{:03}s", millis / 1000, millis % 1000)
}

/// An NTP short (16.16 seconds, root delay and dispersion) as nanoseconds.
#[must_use]
pub fn short_to_nanos(short: u32) -> i64 {
    (i64::from(short) * NANOS_PER_SEC) >> 16
}

/// Nanoseconds as an NTP short, saturating at its maximum; negative values are zero.
#[must_use]
pub fn nanos_to_short(ns: i64) -> u32 {
    let units = (i128::from(ns.max(0)) << 16) / i128::from(NANOS_PER_SEC);
    u32::try_from(units).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_and_ntp_timestamps_convert_both_ways_with_the_era_pivot() {
        let pivot = 1_793_448_000; // 2026-10-31
        let t = NtpTimestamp::from_unix_nanos(1_793_448_000_500_000_000);
        assert_eq!(t.0 >> 32, 1_793_448_000 + UNIX_OFFSET_SECS);
        assert_eq!(t.0 & 0xffff_ffff, 0x8000_0000, "half a second");
        assert_eq!(t.to_unix_nanos(pivot), 1_793_448_000_500_000_000);
        // 2037: past the 2036 rollover of the 32-bit seconds, still within 68 years of the pivot.
        let in_2037 = 2_114_380_800_000_000_000i64;
        assert_eq!(
            NtpTimestamp::from_unix_nanos(in_2037).to_unix_nanos(pivot),
            in_2037
        );
        // 1990: before the pivot, also within 68 years.
        let in_1990 = 631_152_000_000_000_000i64;
        assert_eq!(
            NtpTimestamp::from_unix_nanos(in_1990).to_unix_nanos(pivot),
            in_1990
        );
        assert!(NtpTimestamp::default().is_zero());
    }

    #[test]
    fn iso8601_and_signed_seconds_print_as_the_console_shows_them() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_793_448_000), "2026-10-31T12:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(signed_secs(7_200_012_000_000), "+7200.012s");
        assert_eq!(signed_secs(-2_500_000), "-0.002s");
        assert_eq!(signed_secs(0), "+0.000s");
        assert_eq!(short_to_nanos(0x0001_8000), 1_500_000_000);
        assert_eq!(nanos_to_short(1_500_000_000), 0x0001_8000);
        assert_eq!(nanos_to_short(i64::MAX), u32::MAX);
    }
}
