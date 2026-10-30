// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Appliers (SPEC §6.2): diff a reconciler's desired state against the netlink monitor's cache
//! and issue the netlink operations that close the gap. Appliers own only what they tag: bridges
//! named `br-*`, ports enslaved to them, global-scope addresses on the interfaces OpenFeO manages,
//! and routes with `RTPROT_OPENFEO`. Kernel-originated state and anything on other interfaces is
//! never touched. The nft applier replaces `table inet openfeo` through libnftables; the sysctl
//! applier writes the forwarding levers. A failed operation is reported at the end of a
//! best-effort pass; the caller retries with backoff and the next World.

#![forbid(unsafe_code)]

pub mod links;
pub mod nft;
pub mod routing;
pub mod sysctl;

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    /// Netlink operations issued (zero means the kernel already matched).
    pub ops: usize,
}

/// Why a pass stopped early.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The kernel refused an operation.
    #[error("{op}: {source}")]
    Netlink {
        /// The operation, in the words of the log line.
        op: String,
        /// The netlink error.
        #[source]
        source: openfeo_netlink::Error,
    },
    /// An interface the desired state names does not exist (yet).
    #[error("{0}")]
    Unresolvable(String),
    /// libnftables refused the ruleset; the text is its error.
    #[error("nft: {0}")]
    Nft(String),
    /// A kernel parameter could not be read or written.
    #[error("sysctl {path}: {source}")]
    Io {
        /// The key under `/proc/sys`.
        path: String,
        /// The error.
        #[source]
        source: std::io::Error,
    },
}

impl ApplyError {
    fn netlink(op: String, source: openfeo_netlink::Error) -> Self {
        ApplyError::Netlink { op, source }
    }
}

/// The interface index for `name`: from the cache, or by asking the kernel when the interface
/// was created in this very pass and the cache has not caught up.
async fn resolve(
    observed: &openfeo_netlink::Cache,
    nl: &openfeo_netlink::Netlink,
    name: &str,
) -> Result<u32, ApplyError> {
    if let Some(link) = observed.link_by_name(name) {
        return Ok(link.index);
    }
    match nl.link_index(name).await {
        Ok(Some(index)) => Ok(index),
        Ok(None) => Err(ApplyError::Unresolvable(format!(
            "{name}: no such interface yet"
        ))),
        Err(err) => Err(ApplyError::netlink(format!("look up {name}"), err)),
    }
}

/// One best-effort pass: every operation is attempted, tolerated kernel answers (already there,
/// already gone) count as done, and the first real failure is returned at the end, so one refused
/// operation never starves the rest of the subsystem (a LAN stays reachable when another LAN's
/// bridge cannot be created).
#[derive(Debug, Default)]
pub(crate) struct Pass {
    ops: usize,
    first_error: Option<ApplyError>,
}

impl Pass {
    /// Record one operation's outcome. `tolerated` answers are success.
    pub(crate) fn op(
        &mut self,
        op: &str,
        result: Result<(), openfeo_netlink::Error>,
        tolerated: impl Fn(&openfeo_netlink::Error) -> bool,
    ) {
        match result {
            Ok(()) => {
                tracing::info!("{op}");
                self.ops += 1;
            }
            Err(err) if tolerated(&err) => {
                tracing::info!("{op}");
                self.ops += 1;
            }
            Err(err) => {
                tracing::warn!("{op}: {err}");
                self.fail(ApplyError::netlink(op.to_owned(), err));
            }
        }
    }

    /// Record a failure that was not a netlink operation (an interface that cannot be found).
    pub(crate) fn fail(&mut self, err: ApplyError) {
        if self.first_error.is_none() {
            self.first_error = Some(err);
        }
    }

    /// The pass's result: the first failure, or the operation count.
    pub(crate) fn finish(self) -> Result<Report, ApplyError> {
        match self.first_error {
            Some(err) => Err(err),
            None => Ok(Report { ops: self.ops }),
        }
    }
}

/// The interfaces OpenFeO manages, by name: its bridges and its physical ports (SPEC §7).
#[must_use]
pub fn is_managed(ifname: &str) -> bool {
    ifname.starts_with("br-")
        || ifname
            .strip_prefix('p')
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_agree_with_the_netlink_crate() {
        assert_eq!(
            openfeo_reconcile::RTPROT_OPENFEO,
            openfeo_netlink::RTPROT_OPENFEO
        );
        assert_eq!(openfeo_reconcile::TABLE_MAIN, openfeo_netlink::TABLE_MAIN);
    }

    #[test]
    fn managed_interfaces_are_bridges_and_ports() {
        for name in ["br-lan0", "p0", "p12"] {
            assert!(is_managed(name), "{name}");
        }
        for name in ["lo", "eth0", "p", "px", "p1a", "veth0", "ppp-wan0"] {
            assert!(!is_managed(name), "{name}");
        }
    }
}
