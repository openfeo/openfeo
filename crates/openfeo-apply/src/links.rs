// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The links applier: create the LAN bridges (VLAN filtering on), delete stray `br-*` bridges,
//! create the VLAN sub-interfaces `pN.V` and delete stray ones (ADR-0017), set bridge MACs,
//! enslave and release ports, bring ports and bridges up or down. Order inside a pass: bridges,
//! VLANs, MACs, membership, ports up/down, bridges up, so a bridge never comes up with a random
//! MAC. A pass is best-effort: a bridge the kernel refuses (or cannot be found) is reported at
//! the end, after every other LAN was dealt with.

use std::net::Ipv6Addr;

use openfeo_netlink::{Cache, Error as NetlinkError, Link, LinkKind, Netlink};
use openfeo_platform::sysctl;
use openfeo_reconcile::links::{DesiredLinks, PortKind};

use crate::{ApplyError, Pass, Report, is_vlan_port_name, resolve};

/// Makes the kernel's links match [`DesiredLinks`].
#[derive(Debug, Default)]
pub struct LinksApplier {
    /// The persisted stable-privacy secret (SPEC §7.3), written to an IPv6 WAN's port before it
    /// comes up; `None` leaves every port's link-local address to the kernel's default.
    ipv6_secret: Option<[u8; 16]>,
}

impl LinksApplier {
    /// A fresh applier (it keeps no state: the cache is the state) with no secret.
    #[must_use]
    pub fn new() -> Self {
        LinksApplier { ipv6_secret: None }
    }

    /// A fresh applier that gives IPv6 WAN ports stable-privacy link-local addresses from
    /// `secret`.
    #[must_use]
    pub fn with_ipv6_secret(secret: [u8; 16]) -> Self {
        LinksApplier {
            ipv6_secret: Some(secret),
        }
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
        vlans(&mut pass, desired, observed, nl).await;
        bridge_macs(&mut pass, desired, observed, nl).await;
        membership(&mut pass, desired, observed, nl).await;
        up_down(&mut pass, desired, observed, nl, self.ipv6_secret).await;
        mtus(&mut pass, desired, observed, nl).await;
        pass.finish()
    }
}

/// `addr_gen_mode = 2` (stable-privacy) and the secret, as the kernel wants it, on one port.
/// The kernel generates the link-local address when the port comes up, in the mode set then.
fn stable_privacy(port: &str, secret: [u8; 16]) -> std::io::Result<()> {
    sysctl::write(
        &format!("net/ipv6/conf/{port}/stable_secret"),
        &Ipv6Addr::from(secret).to_string(),
    )?;
    sysctl::write(&format!("net/ipv6/conf/{port}/addr_gen_mode"), "2")
}

/// Whether the port already generates stable-privacy addresses.
fn has_stable_privacy(port: &str) -> bool {
    sysctl::read(&format!("net/ipv6/conf/{port}/addr_gen_mode"))
        .is_ok_and(|mode| mode.trim() == "2")
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

/// Create missing VLAN sub-interfaces (a parent that cannot be found fails the pass for that
/// one), delete `pN.V` links that no LAN or WAN wants.
async fn vlans(pass: &mut Pass, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) {
    for (name, port) in &desired.ports {
        let PortKind::Vlan { parent, id } = &port.kind else {
            continue;
        };
        if observed.link_by_name(name).is_some() {
            continue;
        }
        let parent_index = match resolve(observed, nl, parent).await {
            Ok(index) => index,
            Err(err) => {
                pass.fail(err);
                continue;
            }
        };
        pass.op(
            &format!("add vlan {name}"),
            nl.link_add_vlan(parent_index, *id, name).await,
            NetlinkError::is_exist,
        );
    }
    for link in observed.links.values() {
        if link.kind == Some(LinkKind::Vlan)
            && is_vlan_port_name(&link.name)
            && !desired.ports.contains_key(&link.name)
        {
            pass.op(
                &format!("del vlan {}", link.name),
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
async fn up_down(
    pass: &mut Pass,
    desired: &DesiredLinks,
    observed: &Cache,
    nl: &Netlink,
    ipv6_secret: Option<[u8; 16]>,
) {
    for (port_name, port) in &desired.ports {
        let Some(link) = observed.link_by_name(port_name) else {
            continue;
        };
        // An IPv6 WAN port gets its stable-privacy secret before it comes up; a port that is
        // already up without it (a configuration change while running) is bounced once.
        if let Some(secret) = ipv6_secret
            && port.ipv6_stable_privacy
            && port.up
            && !has_stable_privacy(port_name)
        {
            if link.up {
                pass.op(
                    &format!("set {port_name} down (ipv6 stable-privacy)"),
                    nl.link_set_up(link.index, false).await,
                    |_| false,
                );
            }
            match stable_privacy(port_name, secret) {
                Ok(()) => pass.op(
                    &format!("set {port_name} up (ipv6 stable-privacy)"),
                    nl.link_set_up(link.index, true).await,
                    |_| false,
                ),
                Err(source) => pass.fail(ApplyError::Io {
                    path: format!("net/ipv6/conf/{port_name}/stable_secret"),
                    source,
                }),
            }
            continue;
        }
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
