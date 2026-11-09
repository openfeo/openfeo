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
/// already gone) are success that changed nothing, and the first real failure is returned at the
/// end, so one refused operation never starves the rest of the subsystem (a LAN stays reachable
/// when another LAN's bridge cannot be created).
#[derive(Debug, Default)]
pub(crate) struct Pass {
    ops: usize,
    first_error: Option<ApplyError>,
}

impl Pass {
    /// Record one operation's outcome. `tolerated` answers are success, but the kernel already
    /// matched (a reconcile ran between an add and the kernel's echo of it, say), so they are
    /// neither announced on the console nor counted: the console says what changed.
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
                tracing::debug!("{op}: already so");
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

/// The interfaces OpenFeO manages, by name: its bridges, its physical ports and their VLAN
/// sub-interfaces `pN.V` (SPEC §7.1, ADR-0017), and the PPP netdevs `ppp-<wan>` its links
/// applier renamed from the kernel's `ppp<N>` (ADR-0023): no other name of that shape exists
/// on the appliance.
#[must_use]
pub fn is_managed(ifname: &str) -> bool {
    ifname.starts_with("br-")
        || is_vlan_port_name(ifname)
        || openfeo_config::portname::is_port_name(ifname)
        || is_ppp_name(ifname)
}

/// `ppp-<wan>`: a PPPoE WAN's netdev after the rename.
fn is_ppp_name(ifname: &str) -> bool {
    ifname
        .strip_prefix("ppp-")
        .is_some_and(|rest| !rest.is_empty())
}

/// `p<digits>.<vid>`: a VLAN sub-interface of a port, by the one grammar in
/// `openfeo_config::portname` (so a VLAN id outside 1..=4094, or with a leading zero, is not
/// ours).
#[must_use]
pub fn is_vlan_port_name(ifname: &str) -> bool {
    openfeo_config::portname::parse_port_ref(ifname).is_some_and(|r| r.vlan.is_some())
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
        for name in ["lo", "eth0", "p", "px", "p1a", "veth0"] {
            assert!(!is_managed(name), "{name}");
        }
    }

    /// The kernel's `ppp<N>` is a unit the applier has not renamed yet, or someone else's;
    /// `ppp-<wan>` only ever comes from the rename (ADR-0023).
    #[test]
    fn managed_interfaces_include_renamed_ppp_netdevs() {
        for name in ["ppp-wan0", "ppp-wan1"] {
            assert!(is_managed(name), "{name}");
        }
        for name in ["ppp0", "ppp7", "ppp-", "ppp", "pppoe-wan0"] {
            assert!(!is_managed(name), "{name}");
        }
    }

    #[test]
    fn managed_interfaces_include_vlan_sub_interfaces() {
        for name in ["p0.101", "p12.4094"] {
            assert!(is_managed(name), "{name}");
        }
        for name in ["p0.", "eth0.5", "p1a.5", "p1.5a", "p1.5.6", "p1.0", "p1.4095", "p1.01"] {
            assert!(!is_managed(name), "{name}");
        }
    }

    /// One grammar for port names: what the applier owns is exactly what the config parses.
    #[test]
    fn the_grammar_is_openfeo_configs() {
        for name in ["p0", "p12.101", "p1.4095", "p1.01", "px", "p1.5a", "p1.0"] {
            assert_eq!(
                is_vlan_port_name(name) || openfeo_config::portname::is_port_name(name),
                openfeo_config::portname::parse_port_ref(name).is_some(),
                "{name}"
            );
        }
    }

    /// The messages of every event at `INFO` or above: what the console shows.
    struct Announced(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Announced {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            if *event.metadata().level() <= tracing::Level::INFO {
                let mut message = Message(String::new());
                event.record(&mut message);
                self.0.lock().unwrap().push(message.0);
            }
        }
    }

    /// A tolerated answer (`EEXIST` for an add the kernel already holds, say because a reconcile
    /// ran between the add and the kernel's echo of it) is success, but it changed nothing: it
    /// is not announced on the console and not counted as an operation.
    #[test]
    fn a_tolerated_answer_is_neither_announced_nor_counted() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(Announced(seen.clone())),
        );
        let mut pass = Pass::default();
        pass.op(
            "add route default via 203.0.113.1 dev p0 proto 200 metric 10",
            Ok(()),
            |_| false,
        );
        pass.op(
            "add route 198.51.100.0/24 via 203.0.113.1 dev p0 proto 200 metric 10",
            Err(openfeo_netlink::Error::Closed),
            |_| true,
        );
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["add route default via 203.0.113.1 dev p0 proto 200 metric 10"]
        );
        assert_eq!(pass.finish().unwrap(), Report { ops: 1 });
    }
}
