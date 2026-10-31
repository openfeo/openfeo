// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Console lines a LAN or a WAN outage can provoke at packet rate (a DHCP pool exhausted, an
//! address conflict, a rebinding answer dropped, a forward that cannot leave) are limited to one
//! per window, the rest counted and reported with the next one.

use std::time::Duration;

use tokio::time::Instant;

/// The window of [`Throttle`] for every noisy line.
pub const NOISY_WINDOW: Duration = Duration::from_secs(10);

/// One line per window; the lines held back are counted and reported with the next one.
#[derive(Debug)]
pub struct Throttle {
    window: Duration,
    last: Option<Instant>,
    held: u32,
}

impl Throttle {
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Throttle {
            window,
            last: None,
            held: 0,
        }
    }

    /// `Some(held)` when a line may go out, with the number held back since the last one;
    /// `None` to hold this one.
    pub fn admit(&mut self, now: Instant) -> Option<u32> {
        match self.last {
            Some(last) if now < last + self.window => {
                self.held = self.held.saturating_add(1);
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.held))
            }
        }
    }

    /// `line` as it should go out, with the count of the lines held back since the last one
    /// when there were any; `None` to hold this one.
    pub fn line(&mut self, now: Instant, line: &str) -> Option<String> {
        match self.admit(now)? {
            0 => Some(line.to_owned()),
            held => Some(format!(
                "{line} (and {held} more such lines in the last {}s)",
                self.window.as_secs()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding (part 3a): lines a LAN can provoke at packet rate (`pool exhausted`,
    /// `conflict`) are throttled: one per window, then a count of what was held back.
    #[test]
    fn noisy_lines_are_throttled_to_one_per_window_with_a_count() {
        let t0 = Instant::now();
        let mut throttle = Throttle::new(Duration::from_secs(10));
        assert_eq!(throttle.admit(t0), Some(0), "the first line passes");
        assert_eq!(throttle.admit(t0 + Duration::from_secs(1)), None);
        assert_eq!(throttle.admit(t0 + Duration::from_secs(2)), None);
        assert_eq!(
            throttle.admit(t0 + Duration::from_secs(10)),
            Some(2),
            "the window ends: pass, with the two held back"
        );
        assert_eq!(throttle.admit(t0 + Duration::from_secs(25)), Some(0));
    }

    /// Review finding (part 3b): the drivers' own failure lines take the same path; the line
    /// that passes carries the count of the ones held back.
    #[test]
    fn a_line_carries_the_held_count_once_the_window_ends() {
        let t0 = Instant::now();
        let mut throttle = Throttle::new(Duration::from_secs(10));
        assert_eq!(
            throttle.line(t0, "dns forward to 9.9.9.9 failed: Network is unreachable"),
            Some("dns forward to 9.9.9.9 failed: Network is unreachable".to_owned())
        );
        assert_eq!(
            throttle.line(t0 + Duration::from_secs(1), "dns forward failed"),
            None
        );
        assert_eq!(
            throttle.line(t0 + Duration::from_secs(2), "dns forward failed"),
            None
        );
        assert_eq!(
            throttle.line(t0 + Duration::from_secs(10), "dns forward failed"),
            Some("dns forward failed (and 2 more such lines in the last 10s)".to_owned())
        );
    }
}
