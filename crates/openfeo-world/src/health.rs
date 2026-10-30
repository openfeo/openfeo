// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Health as a value (SPEC §5.3): per-subsystem status, dead supervised tasks and wedged appliers.
//! The child heartbeats only while [`HealthReport::is_healthy`]; `Degraded` (an apply that is
//! failing and being retried) is still healthy, because the watchdog is for hangs, not for an
//! ISP that rejects a route.

use std::collections::BTreeMap;
use std::fmt;

/// A part of the control plane that reports health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subsystem {
    /// The rtnetlink monitor.
    Netlink,
    /// The links applier (bridges, enslavement, up/down).
    Links,
    /// The routing applier (addresses, routes).
    Routing,
    /// Configuration loading.
    Config,
    /// The task supervisor itself.
    Supervisor,
}

impl Subsystem {
    /// The lowercase name used in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Subsystem::Netlink => "netlink",
            Subsystem::Links => "links",
            Subsystem::Routing => "routing",
            Subsystem::Config => "config",
            Subsystem::Supervisor => "supervisor",
        }
    }
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a subsystem is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Last apply succeeded.
    Ok,
    /// Last apply failed and is being retried; the text is the error.
    Degraded(String),
}

/// The whole picture at one instant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthReport {
    /// Per-subsystem status.
    pub subsystems: BTreeMap<Subsystem, Status>,
    /// Supervised tasks that exceeded their restart budget.
    pub dead_tasks: Vec<String>,
    /// Appliers whose current apply has run for too long.
    pub wedged: Vec<Subsystem>,
}

impl HealthReport {
    /// Heartbeat-worthy: no dead task and nothing wedged (SPEC §5.3).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.dead_tasks.is_empty() && self.wedged.is_empty()
    }

    /// Why [`is_healthy`](Self::is_healthy) is false, for the log; `None` when healthy.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.dead_tasks.is_empty() {
            parts.push(format!("dead tasks: {}", self.dead_tasks.join(", ")));
        }
        if !self.wedged.is_empty() {
            let names: Vec<&str> = self.wedged.iter().map(|s| s.as_str()).collect();
            parts.push(format!("wedged: {}", names.join(", ")));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_is_unhealthy_only_for_dead_or_wedged() {
        let mut report = HealthReport::default();
        assert!(report.is_healthy());
        assert_eq!(report.reason(), None);
        report
            .subsystems
            .insert(Subsystem::Routing, Status::Degraded("EEXIST".into()));
        assert!(report.is_healthy(), "degraded is not unhealthy");
        report.dead_tasks.push("apply-links".into());
        assert!(!report.is_healthy());
        assert_eq!(report.reason().unwrap(), "dead tasks: apply-links");
        report.dead_tasks.clear();
        report.wedged.push(Subsystem::Links);
        assert!(!report.is_healthy());
        assert_eq!(report.reason().unwrap(), "wedged: links");
        assert_eq!(Subsystem::Netlink.to_string(), "netlink");
    }
}
