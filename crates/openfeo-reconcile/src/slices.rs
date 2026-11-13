// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The slice of the config each per-WAN task depends on (SPEC §6.3). A task family's manager
//! compares an instance's slice before and after a change of config: equal means the instance
//! is left alone, different means it is restarted, absent means it is stopped. What a change
//! of config does ([`crate::effects`]) is worked out from the same slices, so the two cannot
//! disagree.
//!
//! The DHCPv4 server's slice is its desired state, [`crate::dhcp::DesiredDhcpServer`].

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use openfeo_config::{Config, Wan, rules, wan};

use crate::{wan_ifname, wan_netdev};

/// What a WAN's DHCPv4 client is started with (SPEC §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp4ClientSlice {
    /// The port, or its VLAN sub-interface.
    pub port: String,
    /// Option 12, when one is sent.
    pub hostname: Option<String>,
    /// Option 60, when one is sent.
    pub vendor_class: Option<Vec<u8>>,
}

/// What a WAN's PPPoE client is started with (SPEC §7.2).
#[derive(Clone, PartialEq, Eq)]
pub struct PppoeSlice {
    /// The port, or its VLAN sub-interface, that the PPPoE frames cross.
    pub port: String,
    /// The account.
    pub username: String,
    /// Its password.
    pub password: Vec<u8>,
    /// A service name to insist on.
    pub service: Option<String>,
    /// An access-concentrator name to insist on.
    pub ac: Option<String>,
}

impl std::fmt::Debug for PppoeSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PppoeSlice")
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("service", &self.service)
            .field("ac", &self.ac)
            .finish()
    }
}

/// What a WAN's router-advertisement client is started with (SPEC §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaClientSlice {
    /// The WAN's port (or VLAN sub-interface): its MAC is the identity.
    pub port: String,
    /// The interface the client runs on: the port, or `ppp-<wan>` over PPPoE (ADR-0023).
    pub netdev: String,
    /// A typed default gateway, when the config names one.
    pub gateway: Option<Ipv6Addr>,
}

/// What a WAN's DHCPv6 client is started with (SPEC §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6ClientSlice {
    /// The WAN's port (or VLAN sub-interface): the binding's identity is its MAC.
    pub port: String,
    /// The interface the client runs on: the port, or `ppp-<wan>` over PPPoE (ADR-0023).
    pub netdev: String,
    /// The delegation length asked for.
    pub pd_hint: u8,
}

fn none_if_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

/// The DHCPv4 client of every WAN of kind DHCP, by WAN name.
#[must_use]
pub fn dhcp4_clients(config: &Config) -> BTreeMap<String, Dhcp4ClientSlice> {
    config
        .wans
        .iter()
        .filter_map(|wan| {
            let Some(wan::Kind::Dhcp(dhcp)) = &wan.kind else {
                return None;
            };
            Some((
                wan.name.clone(),
                Dhcp4ClientSlice {
                    port: wan_ifname(wan),
                    hostname: none_if_empty(&dhcp.hostname),
                    vendor_class: none_if_empty(&dhcp.vendor_class).map(String::into_bytes),
                },
            ))
        })
        .collect()
}

/// The PPPoE client of every WAN of kind PPPoE, by WAN name.
#[must_use]
pub fn pppoe_clients(config: &Config) -> BTreeMap<String, PppoeSlice> {
    config
        .wans
        .iter()
        .filter_map(|wan| {
            let Some(wan::Kind::Pppoe(pppoe)) = &wan.kind else {
                return None;
            };
            Some((
                wan.name.clone(),
                PppoeSlice {
                    port: wan_ifname(wan),
                    username: pppoe.username.clone(),
                    password: pppoe.password.clone().into_bytes(),
                    service: none_if_empty(&pppoe.service),
                    ac: none_if_empty(&pppoe.ac),
                },
            ))
        })
        .collect()
}

/// The `[wans.ipv6]` of a WAN that carries IPv6: present and not `disabled`.
fn ipv6_of(wan: &Wan) -> Option<&openfeo_config::Ipv6Wan> {
    wan.ipv6.as_ref().filter(|ipv6| ipv6.mode != "disabled")
}

/// The router-advertisement client of every WAN that carries IPv6, by WAN name.
#[must_use]
pub fn ra_clients(config: &Config) -> BTreeMap<String, RaClientSlice> {
    config
        .wans
        .iter()
        .filter_map(|wan| {
            let ipv6 = ipv6_of(wan)?;
            Some((
                wan.name.clone(),
                RaClientSlice {
                    port: wan_ifname(wan),
                    netdev: wan_netdev(wan),
                    gateway: ipv6.gateway.parse().ok(),
                },
            ))
        })
        .collect()
}

/// The DHCPv6 client of every WAN that carries IPv6 and has no typed prefix, by WAN name.
#[must_use]
pub fn dhcp6_clients(config: &Config) -> BTreeMap<String, Dhcp6ClientSlice> {
    config
        .wans
        .iter()
        .filter_map(|wan| {
            let ipv6 = ipv6_of(wan).filter(|ipv6| ipv6.prefix.is_empty())?;
            Some((
                wan.name.clone(),
                Dhcp6ClientSlice {
                    port: wan_ifname(wan),
                    netdev: wan_netdev(wan),
                    pd_hint: rules::pd_hint(ipv6),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use openfeo_config::{Config, DhcpWan, Firewall, PortForward, StaticLease, wan};

    use super::*;
    use crate::fixtures;

    fn dhcp() -> Config {
        (*fixtures::dhcp_world().config).clone()
    }

    fn pppoe() -> Config {
        (*fixtures::pppoe_world().config).clone()
    }

    fn pd() -> Config {
        (*fixtures::pd_world().config).clone()
    }

    fn ipv6() -> Config {
        (*fixtures::ipv6_world().config).clone()
    }

    fn names<T>(slices: &BTreeMap<String, T>) -> Vec<&str> {
        slices.keys().map(String::as_str).collect()
    }

    /// The four maps of a config, for comparing before and after.
    #[derive(Debug, PartialEq)]
    struct All {
        dhcp4: BTreeMap<String, Dhcp4ClientSlice>,
        pppoe: BTreeMap<String, PppoeSlice>,
        ra: BTreeMap<String, RaClientSlice>,
        dhcp6: BTreeMap<String, Dhcp6ClientSlice>,
    }

    fn all(config: &Config) -> All {
        All {
            dhcp4: dhcp4_clients(config),
            pppoe: pppoe_clients(config),
            ra: ra_clients(config),
            dhcp6: dhcp6_clients(config),
        }
    }

    #[test]
    fn a_wan_of_each_kind_is_in_its_own_families() {
        // DHCP, no IPv6.
        let config = dhcp();
        assert_eq!(names(&dhcp4_clients(&config)), ["wan0"]);
        assert_eq!(names(&pppoe_clients(&config)), [""; 0]);
        assert_eq!(names(&ra_clients(&config)), [""; 0]);
        assert_eq!(names(&dhcp6_clients(&config)), [""; 0]);
        assert_eq!(
            dhcp4_clients(&config)["wan0"],
            Dhcp4ClientSlice {
                port: "p0".to_owned(),
                hostname: Some("openfeo-lab".to_owned()),
                vendor_class: None,
            }
        );
        // PPPoE with a typed IPv6 prefix.
        let config = pppoe();
        assert_eq!(names(&dhcp4_clients(&config)), [""; 0]);
        assert_eq!(names(&pppoe_clients(&config)), ["wan0"]);
        assert_eq!(names(&ra_clients(&config)), ["wan0"]);
        assert_eq!(names(&dhcp6_clients(&config)), [""; 0]);
        let slice = &pppoe_clients(&config)["wan0"];
        assert_eq!(slice.port, "p0");
        assert_eq!(slice.username, "openfeo@isp.example");
        assert_eq!(slice.password, b"example-secret");
        assert_eq!(
            (slice.service.as_deref(), slice.ac.as_deref()),
            (None, None)
        );
        // DHCP asking for a delegation.
        let config = pd();
        assert_eq!(names(&dhcp4_clients(&config)), ["wan0"]);
        assert_eq!(names(&ra_clients(&config)), ["wan0"]);
        assert_eq!(
            dhcp6_clients(&config)["wan0"],
            Dhcp6ClientSlice {
                port: "p0".to_owned(),
                netdev: "p0".to_owned(),
                pd_hint: 56,
            }
        );
        // Static with a typed prefix: neither DHCP client.
        let config = ipv6();
        assert_eq!(names(&dhcp4_clients(&config)), [""; 0]);
        assert_eq!(names(&pppoe_clients(&config)), [""; 0]);
        assert_eq!(
            ra_clients(&config)["wan0"],
            RaClientSlice {
                port: "p0".to_owned(),
                netdev: "p0".to_owned(),
                gateway: None,
            }
        );
    }

    #[test]
    fn the_options_a_wan_names_are_in_its_slice() {
        let mut config = dhcp();
        config.wans[0].kind = Some(wan::Kind::Dhcp(DhcpWan {
            hostname: String::new(),
            vendor_class: "isp-box".to_owned(),
        }));
        assert_eq!(
            dhcp4_clients(&config)["wan0"],
            Dhcp4ClientSlice {
                port: "p0".to_owned(),
                hostname: None,
                vendor_class: Some(b"isp-box".to_vec()),
            }
        );
        let mut config = pppoe();
        let Some(wan::Kind::Pppoe(account)) = &mut config.wans[0].kind else {
            panic!("the fixture's WAN is PPPoE");
        };
        account.service = "internet".to_owned();
        account.ac = "bras1".to_owned();
        let slice = &pppoe_clients(&config)["wan0"];
        assert_eq!(
            (slice.service.as_deref(), slice.ac.as_deref()),
            (Some("internet"), Some("bras1"))
        );
        let mut config = ipv6();
        config.wans[0].ipv6.as_mut().unwrap().gateway = "fe80::1".to_owned();
        assert_eq!(
            ra_clients(&config)["wan0"].gateway,
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn a_vlan_tag_changes_every_slice_of_its_wan() {
        let mut config = pd();
        let before = all(&config);
        config.wans[0].vlan = 101;
        let after = all(&config);
        assert_eq!(after.dhcp4["wan0"].port, "p0.101");
        assert_eq!(after.ra["wan0"].port, "p0.101");
        assert_eq!(after.ra["wan0"].netdev, "p0.101");
        assert_eq!(after.dhcp6["wan0"].port, "p0.101");
        assert_ne!(before.dhcp4, after.dhcp4);
        assert_ne!(before.ra, after.ra);
        assert_ne!(before.dhcp6, after.dhcp6);
        let mut config = pppoe();
        config.wans[0].vlan = 101;
        assert_eq!(pppoe_clients(&config)["wan0"].port, "p0.101");
    }

    #[test]
    fn a_change_elsewhere_changes_no_slice() {
        for mut config in [dhcp(), pppoe(), pd(), ipv6()] {
            let before = all(&config);
            config.wans[0].priority += 5;
            config.lans[0]
                .dhcp
                .get_or_insert_with(Default::default)
                .r#static
                .push(StaticLease {
                    mac: "02:00:00:00:00:10".to_owned(),
                    ip: "192.168.1.10".to_owned(),
                    hostname: "nas".to_owned(),
                    client_id: String::new(),
                });
            config
                .firewall
                .get_or_insert_with(Firewall::default)
                .port_forwards
                .push(PortForward::default());
            config.system.get_or_insert_with(Default::default).hostname = "edge".to_owned();
            assert_eq!(all(&config), before);
        }
    }

    #[test]
    fn a_pppoe_wan_keeps_its_port_for_discovery_and_runs_ipv6_on_the_ppp_netdev() {
        let config = pppoe();
        let ra = &ra_clients(&config)["wan0"];
        assert_eq!(ra.port, "p0");
        assert_eq!(ra.netdev, "ppp-wan0");
        // With no typed prefix the DHCPv6 client runs over the session too.
        let mut config = pppoe();
        config.wans[0].ipv6.as_mut().unwrap().prefix = String::new();
        let dhcp6 = &dhcp6_clients(&config)["wan0"];
        assert_eq!(
            (dhcp6.port.as_str(), dhcp6.netdev.as_str()),
            ("p0", "ppp-wan0")
        );
    }

    #[test]
    fn a_typed_prefix_means_no_dhcp6_client() {
        let mut config = pd();
        assert_eq!(names(&dhcp6_clients(&config)), ["wan0"]);
        config.wans[0].ipv6.as_mut().unwrap().prefix = "2001:db8:1::/48".to_owned();
        assert_eq!(names(&dhcp6_clients(&config)), [""; 0]);
        assert_eq!(names(&ra_clients(&config)), ["wan0"]);
    }

    #[test]
    fn ipv6_disabled_means_neither() {
        let mut config = pd();
        config.wans[0].ipv6.as_mut().unwrap().mode = "disabled".to_owned();
        assert_eq!(names(&ra_clients(&config)), [""; 0]);
        assert_eq!(names(&dhcp6_clients(&config)), [""; 0]);
        config.wans[0].ipv6 = None;
        assert_eq!(names(&ra_clients(&config)), [""; 0]);
        assert_eq!(names(&dhcp6_clients(&config)), [""; 0]);
    }

    #[test]
    fn a_pppoe_slice_never_prints_its_password() {
        let slice = pppoe_clients(&pppoe())["wan0"].clone();
        let printed = format!("{slice:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains("example-secret"), "{printed}");
        assert!(printed.contains("openfeo@isp.example"), "{printed}");
    }
}
