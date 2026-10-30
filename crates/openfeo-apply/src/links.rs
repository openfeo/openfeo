// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The links applier: create the LAN bridges (VLAN filtering on), delete stray `br-*` bridges,
//! set bridge MACs, enslave and release ports, bring ports and bridges up or down. Order inside a
//! pass: bridges, MACs, membership, up/down, so a bridge never comes up with a random MAC and a
//! port is never up without its bridge.

use openfeo_netlink::{Cache, Error as NetlinkError, Link, LinkKind, Netlink};
use openfeo_reconcile::links::DesiredLinks;
use tracing::info;

use crate::{ApplyError, Report, resolve};

/// Makes the kernel's links match [`DesiredLinks`].
#[derive(Debug, Default)]
pub struct LinksApplier;

impl LinksApplier {
    /// A fresh applier (it keeps no state: the cache is the state).
    #[must_use]
    pub fn new() -> Self {
        LinksApplier
    }

    /// One pass. Stops at the first refused operation; operations already issued stay.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Netlink`] when the kernel refuses an operation, [`ApplyError::Unresolvable`]
    /// when a desired bridge cannot be found even by name.
    pub async fn apply(
        &mut self,
        desired: &DesiredLinks,
        observed: &Cache,
        nl: &Netlink,
    ) -> Result<Report, ApplyError> {
        let mut ops = 0;
        ops += bridges(desired, observed, nl).await?;
        ops += bridge_macs(desired, observed, nl).await?;
        ops += membership(desired, observed, nl).await?;
        ops += up_down(desired, observed, nl).await?;
        Ok(Report { ops })
    }
}

/// Treat a tolerated kernel answer (already there, already gone) as success.
fn settle(
    result: Result<(), NetlinkError>,
    tolerated: impl Fn(&NetlinkError) -> bool,
    op: &str,
) -> Result<(), ApplyError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if tolerated(&err) => Ok(()),
        Err(err) => Err(ApplyError::netlink(op.to_owned(), err)),
    }
}

fn is_our_bridge(link: &Link) -> bool {
    link.kind == Some(LinkKind::Bridge) && link.name.starts_with("br-")
}

/// Create missing bridges, delete stray `br-*` bridges.
async fn bridges(
    desired: &DesiredLinks,
    observed: &Cache,
    nl: &Netlink,
) -> Result<usize, ApplyError> {
    let mut ops = 0;
    for (name, bridge) in &desired.bridges {
        if observed.link_by_name(name).is_none() {
            let op = format!("add bridge {name}");
            settle(
                nl.link_add_bridge(name, bridge.vlan_filtering).await,
                NetlinkError::is_exist,
                &op,
            )?;
            info!("{op}");
            ops += 1;
        }
    }
    for link in observed.links.values() {
        if is_our_bridge(link) && !desired.bridges.contains_key(&link.name) {
            let op = format!("del bridge {}", link.name);
            settle(nl.link_del(link.index).await, NetlinkError::is_absent, &op)?;
            info!("{op}");
            ops += 1;
        }
    }
    Ok(ops)
}

/// Bridge MAC = lowest member MAC (SPEC §7.1), set whenever it differs or the bridge is new.
async fn bridge_macs(
    desired: &DesiredLinks,
    observed: &Cache,
    nl: &Netlink,
) -> Result<usize, ApplyError> {
    let mut ops = 0;
    for (name, bridge) in &desired.bridges {
        let Some(mac) = bridge.mac else {
            continue;
        };
        if observed
            .link_by_name(name)
            .is_some_and(|link| link.mac == Some(mac.0))
        {
            continue;
        }
        let index = resolve(observed, nl, name).await?;
        let op = format!("set {name} mac {mac}");
        settle(nl.link_set_mac(index, mac.0).await, |_| false, &op)?;
        info!("{op}");
        ops += 1;
    }
    Ok(ops)
}

/// Enslave ports to their bridge; release ports that sit on one of our bridges without a role.
async fn membership(
    desired: &DesiredLinks,
    observed: &Cache,
    nl: &Netlink,
) -> Result<usize, ApplyError> {
    let mut ops = 0;
    for (port_name, port) in &desired.ports {
        let Some(link) = observed.link_by_name(port_name) else {
            continue;
        };
        if let Some(bridge) = &port.master {
            let master = resolve(observed, nl, bridge).await?;
            if link.master != Some(master) {
                let op = format!("enslave {port_name} -> {bridge}");
                settle(
                    nl.link_set_master(link.index, Some(master)).await,
                    |_| false,
                    &op,
                )?;
                info!("{op}");
                ops += 1;
            }
        } else if let Some(bridge) = link
            .master
            .and_then(|master| observed.links.get(&master))
            .filter(|controller| is_our_bridge(controller))
        {
            let op = format!("release {port_name} from {}", bridge.name);
            settle(nl.link_set_master(link.index, None).await, |_| false, &op)?;
            info!("{op}");
            ops += 1;
        }
    }
    Ok(ops)
}

/// Ports up iff they have a role; bridges up.
async fn up_down(
    desired: &DesiredLinks,
    observed: &Cache,
    nl: &Netlink,
) -> Result<usize, ApplyError> {
    let mut ops = 0;
    for (port_name, port) in &desired.ports {
        let Some(link) = observed.link_by_name(port_name) else {
            continue;
        };
        if link.up != port.up {
            let op = format!("set {port_name} {}", if port.up { "up" } else { "down" });
            settle(nl.link_set_up(link.index, port.up).await, |_| false, &op)?;
            info!("{op}");
            ops += 1;
        }
    }
    for (name, bridge) in &desired.bridges {
        if bridge.up && !observed.link_by_name(name).is_some_and(|link| link.up) {
            let index = resolve(observed, nl, name).await?;
            let op = format!("set {name} up");
            settle(nl.link_set_up(index, true).await, |_| false, &op)?;
            info!("{op}");
            ops += 1;
        }
    }
    Ok(ops)
}
