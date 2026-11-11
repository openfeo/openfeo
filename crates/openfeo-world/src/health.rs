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
    /// The nft applier (the firewall and NAT ruleset).
    Nft,
    /// The sysctl applier (forwarding levers).
    Sysctl,
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
            Subsystem::Nft => "nft",
            Subsystem::Sysctl => "sysctl",
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

/// Health as the API reports it (SPEC §10): stricter than what keeps the watchdog petted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthView {
    /// No subsystem degraded or wedged and no task dead.
    pub healthy: bool,
    /// The subsystems and tasks that are, by name, sorted.
    pub unhealthy: Vec<String>,
}

impl HealthReport {
    /// The API's view: a degraded subsystem is unhealthy here though the heartbeat goes on.
    #[must_use]
    pub fn view(&self) -> HealthView {
        let mut unhealthy: Vec<String> = self
            .subsystems
            .iter()
            .filter(|(_, status)| matches!(status, Status::Degraded(_)))
            .map(|(subsystem, _)| subsystem.as_str().to_owned())
            .chain(
                self.wedged
                    .iter()
                    .map(|subsystem| subsystem.as_str().to_owned()),
            )
            .chain(self.dead_tasks.iter().cloned())
            .collect();
        unhealthy.sort();
        unhealthy.dedup();
        HealthView {
            healthy: unhealthy.is_empty(),
            unhealthy,
        }
    }

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

    fn report(degraded: &[Subsystem], dead: &[&str]) -> HealthReport {
        HealthReport {
            subsystems: degraded
                .iter()
                .map(|subsystem| (*subsystem, Status::Degraded("it failed".to_owned())))
                .chain([(Subsystem::Links, Status::Ok)])
                .collect(),
            dead_tasks: dead.iter().map(|name| (*name).to_owned()).collect(),
            wedged: Vec::new(),
        }
    }

    #[test]
    fn a_degraded_subsystem_is_unhealthy_to_the_api_though_the_watchdog_is_still_petted() {
        let degraded = report(&[Subsystem::Nft], &[]);
        assert!(
            degraded.is_healthy(),
            "the watchdog's question is unchanged"
        );
        assert_eq!(
            degraded.view(),
            HealthView {
                healthy: false,
                unhealthy: vec!["nft".to_owned()]
            }
        );
        assert_eq!(
            report(&[Subsystem::Nft], &["dns"]).view().unhealthy,
            ["dns", "nft"]
        );
        assert_eq!(
            report(&[], &[]).view(),
            HealthView {
                healthy: true,
                unhealthy: vec![]
            }
        );
        let wedged = HealthReport {
            wedged: vec![Subsystem::Routing],
            ..HealthReport::default()
        };
        assert_eq!(wedged.view().unhealthy, ["routing"]);
    }

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
        assert_eq!(Subsystem::Nft.to_string(), "nft");
        assert_eq!(Subsystem::Sysctl.to_string(), "sysctl");
    }
}
