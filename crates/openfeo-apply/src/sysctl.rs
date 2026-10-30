// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The sysctl applier: reads every desired key and writes the ones that differ. Best-effort: a
//! key that cannot be written (an interface that does not exist yet) is reported at the end,
//! after every other key was dealt with, so `ip_forward` is never held hostage by one bridge.

use openfeo_platform::sysctl;
use openfeo_reconcile::sysctl::DesiredSysctl;

use crate::{ApplyError, Report};

/// Makes the kernel parameters match [`DesiredSysctl`].
#[derive(Debug, Default)]
pub struct SysctlApplier;

impl SysctlApplier {
    /// A fresh applier (it keeps no state: the kernel is the state).
    #[must_use]
    pub fn new() -> Self {
        SysctlApplier
    }

    /// One pass: compare each key, write when different, count the writes.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Io`] naming the first key that could not be read or written, after every
    /// other key was attempted.
    pub fn apply(&mut self, desired: &DesiredSysctl) -> Result<Report, ApplyError> {
        let mut ops = 0;
        let mut first_error = None;
        for (key, value) in &desired.entries {
            let result = match sysctl::read(key) {
                Ok(current) if current == *value => continue,
                Ok(_) => sysctl::write(key, value),
                Err(err) => Err(err),
            };
            match result {
                Ok(()) => {
                    tracing::info!("sysctl {key}={value}");
                    ops += 1;
                }
                Err(err) => {
                    tracing::warn!("sysctl {key}={value}: {err}");
                    if first_error.is_none() {
                        first_error = Some(ApplyError::Io {
                            path: key.clone(),
                            source: err,
                        });
                    }
                }
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(Report { ops }),
        }
    }
}
