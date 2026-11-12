// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A change of config that is applied and not yet confirmed (SPEC §5.5), and what a change
//! does. The keeper of the config publishes the fact; the state reports it and the DHCPv4
//! server reads it for the cap on its leases.

use std::collections::BTreeSet;
use std::sync::Arc;

use openfeo_config::Config;

/// What happens to one thing when a config is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectKind {
    /// A WAN that was not there.
    WanAdded,
    /// A WAN that will be gone.
    WanRemoved,
    /// A WAN whose clients are restarted: it drops and comes back.
    WanReconnects,
    /// A LAN that was not there.
    LanAdded,
    /// A LAN that will be gone.
    LanRemoved,
    /// A LAN whose IPv4 address or subnet changes: its devices need new addresses.
    LanAddressMoves,
    /// A LAN that gains a DHCPv4 server.
    LanDhcpStarts,
    /// A LAN that loses its DHCPv4 server.
    LanDhcpStops,
    /// A LAN whose DHCPv4 server is restarted with other settings; leases are kept.
    LanDhcpRestarts,
    /// The router's hostname or domain changes: its certificate is reissued.
    RouterRenamed,
}

impl EffectKind {
    /// The words the console puts after the subject: `wan0 reconnects`.
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            EffectKind::WanAdded | EffectKind::LanAdded => "is added",
            EffectKind::WanRemoved | EffectKind::LanRemoved => "is removed",
            EffectKind::WanReconnects => "reconnects",
            EffectKind::LanAddressMoves => "address moves",
            EffectKind::LanDhcpStarts => "dhcp starts",
            EffectKind::LanDhcpStops => "dhcp stops",
            EffectKind::LanDhcpRestarts => "dhcp restarts",
            EffectKind::RouterRenamed => "is renamed",
        }
    }
}

/// One thing a change of config does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    /// The WAN or LAN by name, or the router's new `<hostname>.<domain>`.
    pub subject: String,
    /// What happens to it.
    pub kind: EffectKind,
}

/// A change that is running and will revert by itself unless it is confirmed.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingFact {
    /// The config it goes back to. The keeper of the config holds it too; it is here for
    /// whoever finds the change pending with nobody keeping its window (the API task was
    /// restarted), who publishes it again.
    pub confirmed: Arc<Config>,
    /// When it was applied, in milliseconds since the kernel booted.
    pub applied_boot_ms: u64,
    /// When it reverts, on the same clock.
    pub reverts_boot_ms: u64,
    /// The window it was given.
    pub window_secs: u32,
    /// What applying it did.
    pub effects: Vec<Effect>,
    /// The LANs it touches: their DHCPv4 servers grant no lease longer than the window.
    pub lans: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_its_words() {
        let words: Vec<&str> = [
            EffectKind::WanAdded,
            EffectKind::WanRemoved,
            EffectKind::WanReconnects,
            EffectKind::LanAdded,
            EffectKind::LanRemoved,
            EffectKind::LanAddressMoves,
            EffectKind::LanDhcpStarts,
            EffectKind::LanDhcpStops,
            EffectKind::LanDhcpRestarts,
            EffectKind::RouterRenamed,
        ]
        .into_iter()
        .map(EffectKind::what)
        .collect();
        assert_eq!(
            words,
            [
                "is added",
                "is removed",
                "reconnects",
                "is added",
                "is removed",
                "address moves",
                "dhcp starts",
                "dhcp stops",
                "dhcp restarts",
                "is renamed",
            ]
        );
    }
}
