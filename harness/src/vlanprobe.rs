// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Can this kernel create 802.1Q VLAN links? The sandboxed VLAN scenarios (ADR-0017) need the
//! `8021q` module, which distribution kernels ship as a module and which a user namespace cannot
//! autoload. A host whose running kernel cannot load it (typically: upgraded on disk, not yet
//! rebooted) answers "Unknown device type" to `ip link add … type vlan`. The probe creates a
//! throwaway veth pair and a VLAN on it and turns that answer into a [`Skip`].

use anyhow::{Context, Result};

use crate::netns;
use crate::nftprobe::running_kernel;
use crate::scenario::Skip;

const BASE: &str = "ofprobe0";
const PEER: &str = "ofprobe1";
const VLAN: &str = "ofprobe0.1";

/// `Ok` when the running kernel creates a VLAN sub-interface; `Err(Skip)` when it cannot load
/// `8021q`; any other error when the probe itself failed (no veth either, say).
///
/// # Errors
///
/// [`Skip`] (inside the `anyhow::Error`) for a kernel without VLAN support; a plain error when the
/// probe could not even create its veth pair (not inside the sandbox, say).
pub fn require_vlan_links() -> Result<()> {
    let _ = netns::ip(&["link", "del", BASE]);
    netns::ip(&["link", "add", BASE, "type", "veth", "peer", "name", PEER])
        .context("veth pair for the vlan probe")?;
    let result = netns::ip(&[
        "link", "add", "link", BASE, "name", VLAN, "type", "vlan", "id", "1",
    ]);
    let _ = netns::ip(&["link", "del", BASE]); // takes the VLAN with it
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            let text = format!("{err:#}");
            if text.contains("Unknown device type") || text.contains("Operation not supported") {
                Err(Skip(format!(
                    "kernel {} cannot create 802.1Q VLAN links ({}); reboot or modprobe 8021q",
                    running_kernel(),
                    text.lines().last().unwrap_or_default().trim()
                ))
                .into())
            } else {
                Err(err).context("vlan probe")
            }
        }
    }
}
