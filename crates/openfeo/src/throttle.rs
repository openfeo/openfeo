// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Console lines the LAN can provoke at packet rate (a DHCP pool exhausted, an address
//! conflict, a rebinding answer dropped) are limited to one per window, the rest counted.

use std::time::Duration;

use tokio::time::Instant;

/// The window of [`Throttle`] for every noisy line.
pub(crate) const NOISY_WINDOW: Duration = Duration::from_secs(10);

/// One line per window; the lines held back are counted and reported with the next one.
#[derive(Debug)]
pub(crate) struct Throttle {
    window: Duration,
    last: Option<Instant>,
    held: u32,
}

impl Throttle {
    pub(crate) fn new(window: Duration) -> Self {
        Throttle {
            window,
            last: None,
            held: 0,
        }
    }

    /// `Some(held)` when a line may go out, with the number held back since the last one;
    /// `None` to hold this one.
    pub(crate) fn admit(&mut self, now: Instant) -> Option<u32> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding: lines a LAN can provoke at packet rate (`pool exhausted`, `conflict`)
    /// are throttled: one per window, then a count of what was held back.
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
}
