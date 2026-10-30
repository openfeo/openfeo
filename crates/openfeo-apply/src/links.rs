// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The links applier: create the LAN bridges (VLAN filtering on), delete stray `br-*` bridges,
//! set bridge MACs, enslave and release ports, bring ports and bridges up or down. Order inside a
//! pass: bridges, MACs, membership, ports up/down, bridges up, so a bridge never comes up with a
//! random MAC. A pass is best-effort: a bridge the kernel refuses (or cannot be found) is reported
//! at the end, after every other LAN was dealt with.

use openfeo_netlink::{Cache, Error as NetlinkError, Link, LinkKind, Netlink};
use openfeo_reconcile::links::DesiredLinks;

use crate::{ApplyError, Pass, Report, resolve};

/// Makes the kernel's links match [`DesiredLinks`].
#[derive(Debug, Default)]
pub struct LinksApplier;

impl LinksApplier {
    /// A fresh applier (it keeps no state: the cache is the state).
    #[must_use]
    pub fn new() -> Self {
        LinksApplier
    }

    /// One pass over every bridge and port.
    ///
    /// # Errors
    ///
    /// The first failure of the pass, after everything else was attempted:
    /// [`ApplyError::Netlink`] when the kernel refused an operation, [`ApplyError::Unresolvable`]
    /// when a desired bridge cannot be found even by name.
    pub async fn apply(
        &mut self,
        desired: &DesiredLinks,
        observed: &Cache,
        nl: &Netlink,
    ) -> Result<Report, ApplyError> {
        let mut pass = Pass::default();
        bridges(&mut pass, desired, observed, nl).await;
        bridge_macs(&mut pass, desired, observed, nl).await;
        membership(&mut pass, desired, observed, nl).await;
        up_down(&mut pass, desired, observed, nl).await;
        mtus(&mut pass, desired, observed, nl).await;
        pass.finish()
    }
}

/// Ports with a desired MTU (a DHCP WAN's lease) that the kernel does not have yet.
async fn mtus(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
    for (port_name, port) in &desired.ports {
        let (Some(mtu), Some(link)) = (port.mtu, observed.link_by_name(port_name)) else {
            continue;
        };
        if link.mtu != mtu {
            pass.op(
                &format!("set {port_name} mtu {mtu}"),
                nl.link_set_mtu(link.index, mtu).await,
                |_| false,
            );
        }
    }
}

fn is_our_bridge(link: &Link) -> bool {
    link.kind == Some(LinkKind::Bridge) && link.name.starts_with("br-")
}

/// Create missing bridges, delete stray `br-*` bridges.
async fn bridges(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
    for (name, bridge) in &desired.bridges {
        if observed.link_by_name(name).is_none() {
            pass.op(
                &format!("add bridge {name}"),
                nl.link_add_bridge(name, bridge.vlan_filtering).await,
                NetlinkError::is_exist,
            );
        }
    }
    for link in observed.links.values() {
        if is_our_bridge(link) && !desired.bridges.contains_key(&link.name) {
            pass.op(
                &format!("del bridge {}", link.name),
                nl.link_del(link.index).await,
                NetlinkError::is_absent,
            );
        }
    }
}

/// Bridge MAC = lowest member MAC (SPEC §7.1), set whenever it differs or the bridge is new.
async fn bridge_macs(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
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
        let index = match resolve(observed, nl, name).await {
            Ok(index) => index,
            Err(err) => {
                pass.fail(err);
                continue;
            }
        };
        pass.op(
            &format!("set {name} mac {mac}"),
            nl.link_set_mac(index, mac.0).await,
            |_| false,
        );
    }
}

/// Enslave ports to their bridge; release ports that sit on one of our bridges without a role.
async fn membership(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
    for (port_name, port) in &desired.ports {
        let Some(link) = observed.link_by_name(port_name) else {
            continue;
        };
        if let Some(bridge) = &port.master {
            let master = match resolve(observed, nl, bridge).await {
                Ok(index) => index,
                Err(err) => {
                    pass.fail(err);
                    continue;
                }
            };
            if link.master != Some(master) {
                pass.op(
                    &format!("enslave {port_name} -> {bridge}"),
                    nl.link_set_master(link.index, Some(master)).await,
                    |_| false,
                );
            }
        } else if let Some(bridge) = link
            .master
            .and_then(|master| observed.links.get(&master))
            .filter(|controller| is_our_bridge(controller))
        {
            pass.op(
                &format!("release {port_name} from {}", bridge.name),
                nl.link_set_master(link.index, None).await,
                |_| false,
            );
        }
    }
}

/// Ports up iff they have a role; bridges up.
async fn up_down(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
    for (port_name, port) in &desired.ports {
        let Some(link) = observed.link_by_name(port_name) else {
            continue;
        };
        if link.up != port.up {
            let state = if port.up { "up" } else { "down" };
            pass.op(
                &format!("set {port_name} {state}"),
                nl.link_set_up(link.index, port.up).await,
                |_| false,
            );
        }
    }
    for (name, bridge) in &desired.bridges {
        if bridge.up && !observed.link_by_name(name).is_some_and(|link| link.up) {
            let index = match resolve(observed, nl, name).await {
                Ok(index) => index,
                Err(err) => {
                    pass.fail(err);
                    continue;
                }
            };
            pass.op(
                &format!("set {name} up"),
                nl.link_set_up(index, true).await,
                |_| false,
            );
        }
    }
}
