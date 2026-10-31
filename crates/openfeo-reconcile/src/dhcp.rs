// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired DHCPv4 server settings per LAN (SPEC §7.6, §6.2's `reconcile::dhcp_dns`): the pure
//! translation of `[lans.dhcp]` and `[system]` into what one server task runs with.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use openfeo_config::load::DEFAULT_DOMAIN;
use openfeo_config::validate::parse_mac;
use openfeo_config::{LanDhcp, StaticLease};
use openfeo_proto_dhcp4::identity::from_hex;
use openfeo_proto_dhcp4::server::DEFAULT_LEASE_SECS;
use openfeo_proto_dhcp4::{Reservation, ServerConfig};
use openfeo_world::World;
use serde::Serialize;

use crate::bridge_name;

/// A static lease, parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredReservation {
    pub mac: [u8; 6],
    /// Matches the client identifier instead of the MAC when set.
    pub client_id: Option<Vec<u8>>,
    pub address: Ipv4Addr,
    pub hostname: Option<String>,
}

/// One LAN's server settings: the bridge to serve on and the core's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredDhcpServer {
    /// `br-<lan>`.
    pub ifname: String,
    /// The LAN address: option 54, option 3 and the default option 6.
    pub server: Ipv4Addr,
    pub prefix: u8,
    /// Inclusive.
    pub pool: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    /// Never empty: the router when nothing is configured.
    pub dns: Vec<Ipv4Addr>,
    /// `[system] domain`, else `home.arpa`.
    pub domain: Option<String>,
    pub reservations: Vec<DesiredReservation>,
}

/// The servers the World calls for, keyed by LAN name. A LAN without `[lans.dhcp]`, or whose
/// address or range does not parse, contributes nothing; a static lease that does not parse is
/// skipped (validation already refused all of these).
#[must_use]
pub fn servers(world: &World) -> BTreeMap<String, DesiredDhcpServer> {
    let domain = world
        .config
        .system
        .as_ref()
        .map(|system| system.domain.as_str())
        .filter(|domain| !domain.is_empty())
        .unwrap_or(DEFAULT_DOMAIN)
        .to_owned();
    let mut desired = BTreeMap::new();
    for lan in &world.config.lans {
        let Some(dhcp) = &lan.dhcp else {
            continue;
        };
        let Ok(net) = lan.ipv4.parse::<Ipv4Net>() else {
            continue;
        };
        let Some(pool) = pool_of(&dhcp.range) else {
            continue;
        };
        desired.insert(
            lan.name.clone(),
            DesiredDhcpServer {
                ifname: bridge_name(&lan.name),
                server: net.addr(),
                prefix: net.prefix_len(),
                pool,
                lease_secs: lease_secs(dhcp),
                dns: dns_of(dhcp, net.addr()),
                domain: Some(domain.clone()),
                reservations: dhcp.r#static.iter().filter_map(reservation).collect(),
            },
        );
    }
    desired
}

/// The core's configuration for `desired`.
#[must_use]
pub fn server_config(desired: &DesiredDhcpServer) -> ServerConfig {
    ServerConfig {
        server: desired.server,
        prefix: desired.prefix,
        pool: desired.pool,
        lease_secs: desired.lease_secs,
        dns: desired.dns.clone(),
        domain: desired.domain.clone(),
        reservations: desired
            .reservations
            .iter()
            .map(|reservation| Reservation {
                mac: reservation.mac,
                client_id: reservation.client_id.clone(),
                address: reservation.address,
                hostname: reservation.hostname.clone(),
            })
            .collect(),
    }
}

fn pool_of(range: &[String]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let [first, last] = range else {
        return None;
    };
    Some((first.parse().ok()?, last.parse().ok()?))
}

fn lease_secs(dhcp: &LanDhcp) -> u32 {
    if dhcp.lease_secs == 0 {
        DEFAULT_LEASE_SECS
    } else {
        dhcp.lease_secs
    }
}

fn dns_of(dhcp: &LanDhcp, server: Ipv4Addr) -> Vec<Ipv4Addr> {
    let dns: Vec<Ipv4Addr> = dhcp
        .dns
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    if dns.is_empty() { vec![server] } else { dns }
}

fn reservation(lease: &StaticLease) -> Option<DesiredReservation> {
    let client_id = if lease.client_id.is_empty() {
        None
    } else {
        Some(from_hex(&lease.client_id)?)
    };
    Some(DesiredReservation {
        mac: parse_mac(&lease.mac)?,
        client_id,
        address: lease.ip.parse().ok()?,
        hostname: (!lease.hostname.is_empty()).then(|| lease.hostname.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use openfeo_config::StaticLease;
    use std::sync::Arc;

    #[test]
    fn static_lan_serves_its_pool_with_the_nas_reservation() {
        let desired = servers(&fixtures::static_world());
        insta::assert_yaml_snapshot!(desired);
        let lan0 = &desired["lan0"];
        assert_eq!(
            (lan0.ifname.as_str(), lan0.server, lan0.prefix),
            ("br-lan0", Ipv4Addr::new(192, 168, 1, 1), 24)
        );
        assert_eq!(
            lan0.pool,
            (
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 200)
            )
        );
        assert_eq!(
            (lan0.lease_secs, lan0.domain.as_deref()),
            (43_200, Some("home.arpa"))
        );
        assert_eq!(lan0.dns, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(
            lan0.reservations,
            vec![DesiredReservation {
                mac: [0x52, 0x54, 0, 0xfe, 0x10, 0x10],
                client_id: None,
                address: Ipv4Addr::new(192, 168, 1, 10),
                hostname: Some("nas".into()),
            }]
        );
        let config = server_config(lan0);
        assert_eq!(
            (
                config.server,
                config.pool,
                config.lease_secs,
                config.reservations.len()
            ),
            (lan0.server, lan0.pool, 43_200, 1)
        );
    }

    #[test]
    fn first_boot_lan_serves_the_default_pool() {
        let desired = servers(&fixtures::first_boot_world());
        insta::assert_yaml_snapshot!(desired);
        assert_eq!(
            desired["lan0"].pool,
            (
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 250)
            )
        );
        assert_eq!(desired["lan0"].lease_secs, 43_200);
    }

    #[test]
    fn a_lan_without_dhcp_serves_nothing() {
        let mut world = fixtures::static_world();
        Arc::make_mut(&mut world.config).lans[0].dhcp = None;
        assert!(servers(&world).is_empty());
    }

    #[test]
    fn configured_dns_and_a_client_id_reservation_pass_through() {
        let mut world = fixtures::static_world();
        let dhcp = Arc::make_mut(&mut world.config).lans[0]
            .dhcp
            .as_mut()
            .unwrap();
        dhcp.dns = vec!["1.1.1.1".into(), "9.9.9.9".into()];
        dhcp.r#static.push(StaticLease {
            mac: "52:54:00:fe:10:11".into(),
            ip: "192.168.1.11".into(),
            hostname: String::new(),
            client_id: "ff01020304".into(),
        });
        let lan0 = &servers(&world)["lan0"];
        assert_eq!(
            lan0.dns,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)]
        );
        assert_eq!(
            lan0.reservations[1],
            DesiredReservation {
                mac: [0x52, 0x54, 0, 0xfe, 0x10, 0x11],
                client_id: Some(vec![0xff, 1, 2, 3, 4]),
                address: Ipv4Addr::new(192, 168, 1, 11),
                hostname: None,
            }
        );
    }
}
