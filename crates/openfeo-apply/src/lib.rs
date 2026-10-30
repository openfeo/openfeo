// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Appliers (SPEC §6.2): diff a reconciler's desired state against the netlink monitor's cache
//! and issue the netlink operations that close the gap. Appliers own only what they tag: bridges
//! named `br-*`, ports enslaved to them, global-scope addresses on the interfaces OpenFeO manages,
//! and routes with `RTPROT_OPENFEO`. Kernel-originated state and anything on other interfaces is
//! never touched. A failed operation ends the pass with an error; the caller retries with backoff
//! and the next World.

#![forbid(unsafe_code)]

pub mod links;
pub mod routing;

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
