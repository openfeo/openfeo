// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `/dev/watchdog0` with a 60 s timeout (SPEC §5.3), or a software stand-in that makes PID 1
//! reboot itself where no watchdog device exists.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::time::{Duration, Instant};

/// The device node.
pub const DEVICE: &str = "/dev/watchdog0";
/// Its sysfs attributes (`CONFIG_WATCHDOG_SYSFS`): `identity`, `timeout`, …
pub const SYSFS: &str = "/sys/class/watchdog/watchdog0";
/// Timeout asked of the driver (clamped by the driver to its maximum).
pub const TIMEOUT_SECS: u32 = 60;
/// How often PID 1 pets while the child is healthy.
pub const PET_INTERVAL: Duration = Duration::from_secs(5);

/// Hardware watchdog, or PID 1's own deadline when there is none.
#[derive(Debug)]
pub enum Watchdog {
    /// `/dev/watchdog0` is open and armed (and, with `WATCHDOG_NOWAYOUT`, cannot be disarmed).
    Hardware {
        /// The open device.
        dev: File,
        /// Timeout in force: ours if the driver accepted it, else what the driver reports
        /// (0 when it reports nothing).
        timeout: u32,
        /// The driver's name for the device (`i6300ESB timer`, `iTCO_wdt`, …).
        identity: String,
    },
    /// No device: PID 1 reboots when `timeout` passes without a pet.
    Software {
        /// Last pet (or boot).
        last_pet: Instant,
        /// Deadline length.
        timeout: Duration,
    },
}

impl Watchdog {
    /// The software stand-in, deadline [`TIMEOUT_SECS`] from `now`.
    #[must_use]
    pub fn software(now: Instant) -> Self {
        Self::Software {
            last_pet: now,
            timeout: Duration::from_secs(u64::from(TIMEOUT_SECS)),
        }
    }

    /// Open and arm [`DEVICE`]; fall back to software when it is absent.
    #[must_use]
    pub fn open(now: Instant) -> Self {
        let Ok(dev) = OpenOptions::new().write(true).open(DEVICE) else {
            return Self::software(now);
        };
        let timeout = crate::sys::wdt_set_timeout(&dev, TIMEOUT_SECS)
            .ok()
            .or_else(|| sysfs_attr("timeout")?.parse().ok())
            .unwrap_or(0);
        let identity = sysfs_attr("identity").unwrap_or_else(|| "unknown".to_owned());
        Self::Hardware {
            dev,
            timeout,
            identity,
        }
    }

    /// Pet.
    ///
    /// # Errors
    ///
    /// The driver's errno (hardware only).
    pub fn pet(&mut self, now: Instant) -> io::Result<()> {
        match self {
            Self::Hardware { dev, .. } => crate::sys::wdt_keepalive(dev),
            Self::Software { last_pet, .. } => {
                *last_pet = now;
                Ok(())
            }
        }
    }

    /// Software only: the deadline has passed and PID 1 must reboot. Hardware never "expires"
    /// from PID 1's point of view; the chip resets the machine.
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        match self {
            Self::Hardware { .. } => false,
            Self::Software { last_pet, timeout } => {
                now.saturating_duration_since(*last_pet) >= *timeout
            }
        }
    }

    /// For the `watchdog …` log line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Hardware {
                timeout, identity, ..
            } => format!("{DEVICE} timeout={timeout}s identity=\"{identity}\""),
            Self::Software { timeout, .. } => {
                format!("none, software fallback timeout={}s", timeout.as_secs())
            }
        }
    }
}

fn sysfs_attr(name: &str) -> Option<String> {
    fs::read_to_string(format!("{SYSFS}/{name}"))
        .ok()
        .map(|s| s.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_watchdog_expires_after_timeout_without_pets() {
        let t0 = Instant::now();
        let mut wd = Watchdog::software(t0);
        assert!(!wd.expired(t0 + Duration::from_secs(59)));
        assert!(wd.expired(t0 + Duration::from_secs(60)));
        wd.pet(t0 + Duration::from_secs(30)).unwrap();
        assert!(!wd.expired(t0 + Duration::from_secs(89)));
    }

    #[test]
    fn describe_hardware_includes_identity() {
        let wd = Watchdog::Hardware {
            dev: File::open("/dev/null").unwrap(),
            timeout: 60,
            identity: "i6300ESB timer".to_owned(),
        };
        assert_eq!(
            wd.describe(),
            "/dev/watchdog0 timeout=60s identity=\"i6300ESB timer\""
        );
    }

    #[test]
    fn describe_software() {
        let wd = Watchdog::software(Instant::now());
        assert_eq!(wd.describe(), "none, software fallback timeout=60s");
    }
}
