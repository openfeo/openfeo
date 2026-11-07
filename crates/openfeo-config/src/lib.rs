// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Configuration for OpenFeO (SPEC §8). The protobuf schema in `proto/openfeo/v1/` is the single
//! source of truth; this crate holds its prost types with pbjson serde using the proto field
//! names, so the on-disk TOML (§8.2) is the canonical JSON mapping spelled in TOML.

#![forbid(unsafe_code)]

mod error;
pub mod file;
mod generated;
pub mod load;
pub mod migrate;
mod portmap;
pub mod portname;
pub mod rules;
pub mod validate;

pub use error::ConfigError;
pub use generated::{
    Config, Dhcp4Lease, Dhcp4Route, Dhcp4ServerLease, Dhcp4ServerLeases, Dhcp6Binding,
    Dhcp6Deprecated, Dhcp6Lease, DhcpWan, Dns, Firewall, Ipv6Wan, Lan, LanDhcp, PortForward,
    PortMap, PortMapEntry, PppoeWan, PublicIpv4, Record, Rule, StaticLease, StaticWan, System, Wan,
    wan,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_uses_proto_field_names_and_round_trips() {
        let cfg = Config {
            config_version: 1,
            lans: vec![Lan {
                name: "lan0".into(),
                ports: vec!["p2".into()],
                ipv4: "192.168.1.1/24".into(),
                dhcp: None,
                reaches: Vec::new(),
                ipv6: String::new(),
                ra: None,
                ipv6_index: 0,
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["config_version"], 1);
        assert_eq!(json["lans"][0]["ipv4"], "192.168.1.1/24");
        assert_eq!(serde_json::from_value::<Config>(json).unwrap(), cfg);
    }
}
