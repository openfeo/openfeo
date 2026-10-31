// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired time settings (SPEC §7.10): the pure translation of `[system] ntp_servers`, the
//! active WAN's learned servers and the LANs into what the SNTP task runs with.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use openfeo_config::wan;
use openfeo_proto_sntp::ServerSpec;
use openfeo_world::World;
use serde::Serialize;

use crate::bridge_name;
use crate::dns::active_wan;

/// The servers asked when `[system] ntp_servers` names none (SPEC §7.10).
pub const DEFAULT_NTP_SERVERS: [&str; 2] = ["0.pool.ntp.org", "1.pool.ntp.org"];

/// What the time task runs with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredTime {
    /// `[system] ntp_servers` as typed (addresses or names), or the defaults when empty.
    pub servers: Vec<String>,
    /// The active WAN's lease NTP servers, those not already typed, in order.
    pub learned: Vec<Ipv4Addr>,
    /// The WAN whose servers were appended.
    pub learned_from: Option<String>,
    /// `br-<lan>` per LAN whose address parses: where the router serves time.
    pub listeners: Vec<String>,
}

/// The time settings the World calls for.
#[must_use]
pub fn desired(world: &World) -> DesiredTime {
    let typed: Vec<String> = world
        .config
        .system
        .as_ref()
        .map(|system| system.ntp_servers.clone())
        .unwrap_or_default();
    let servers: Vec<String> = if typed.is_empty() {
        DEFAULT_NTP_SERVERS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        typed
    };
    let mut learned = Vec::new();
    let mut learned_from = None;
    if let Some(active) = active_wan(world)
        && matches!(active.kind, Some(wan::Kind::Dhcp(_)))
        && let Some(lease) = world.dhcp4.get(&active.name)
    {
        for addr in &lease.ntp {
            if !servers.contains(&addr.to_string()) && !learned.contains(addr) {
                learned.push(*addr);
            }
        }
        if !lease.ntp.is_empty() {
            learned_from = Some(active.name.clone());
        }
    }
    DesiredTime {
        servers,
        learned,
        learned_from,
        listeners: world
            .config
            .lans
            .iter()
            .filter(|lan| lan.ipv4.parse::<Ipv4Net>().is_ok())
            .map(|lan| bridge_name(&lan.name))
            .collect(),
    }
}

/// `servers` as the driver takes them: an IPv4 address parses as one, anything else is a name;
/// a name that does not parse is skipped.
#[must_use]
pub fn server_specs(desired: &DesiredTime) -> Vec<ServerSpec> {
    desired
        .servers
        .iter()
        .filter_map(|text| {
            text.parse::<Ipv4Addr>().map_or_else(
                |_| text.parse().ok().map(ServerSpec::Name),
                |addr| Some(ServerSpec::Address(addr)),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    #[test]
    fn defaults_apply_when_nothing_is_typed_and_the_dhcp_wan_lends_its_server() {
        let d = desired(&fixtures::dhcp_world());
        insta::assert_yaml_snapshot!(d);
        assert_eq!(d.servers, vec!["0.pool.ntp.org", "1.pool.ntp.org"]);
        assert_eq!(
            (d.learned.clone(), d.learned_from.as_deref()),
            (vec![Ipv4Addr::new(203, 0, 113, 1)], Some("wan0"))
        );
        assert_eq!(d.listeners, vec!["br-lan0"]);
        let without = desired(&fixtures::dhcp_world_without_lease());
        assert_eq!((without.learned.len(), without.learned_from), (0, None));
        let static_world = desired(&fixtures::static_world());
        assert_eq!(
            (static_world.learned.len(), static_world.learned_from),
            (0, None),
            "a static WAN names no time server"
        );
    }

    #[test]
    fn typed_servers_replace_the_defaults_and_become_specs() {
        let mut world = fixtures::dhcp_world();
        Arc::make_mut(&mut world.config)
            .system
            .as_mut()
            .unwrap()
            .ntp_servers = vec![
            "ntp.isp.example".into(),
            "203.0.113.1".into(),
            "bad..name".into(),
        ];
        let d = desired(&world);
        assert_eq!(
            d.servers,
            vec!["ntp.isp.example", "203.0.113.1", "bad..name"]
        );
        assert_eq!(d.learned, Vec::<Ipv4Addr>::new(), "already typed");
        assert_eq!(
            server_specs(&d),
            vec![
                ServerSpec::Name("ntp.isp.example".parse().unwrap()),
                ServerSpec::Address(Ipv4Addr::new(203, 0, 113, 1)),
            ]
        );
    }
}
