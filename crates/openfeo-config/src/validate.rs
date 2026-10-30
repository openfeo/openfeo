// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Semantic validation (SPEC §8.1): CIDRs, overlaps, unique names, port references against the
//! live port map. Protobuf types alone validate nothing; every finding is structured as
//! `(path, code, message)` so the console, the API and the panel can all show it.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

use crate::{Config, PortMap, wan};

/// What kind of rule a [`Violation`] breaks. Displays as its `snake_case` name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Code {
    /// Not an `address/prefix` in the expected family.
    InvalidCidr,
    /// Not an IP address.
    InvalidAddress,
    /// A WAN or LAN name used twice.
    DuplicateName,
    /// A port name the live port map does not know.
    UnknownPort,
    /// A port given to two roles.
    PortUsedTwice,
    /// Two subnets that overlap.
    Overlap,
    /// A static WAN gateway outside the WAN subnet.
    GatewayOutsideSubnet,
    /// A WAN without a `[wans.<kind>]` table.
    MissingKind,
    /// A LAN with no ports.
    EmptyPorts,
    /// `[[ports]]` disagrees with the live port map.
    PortMapMismatch,
}

impl Code {
    /// The `snake_case` name used in logs and the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Code::InvalidCidr => "invalid_cidr",
            Code::InvalidAddress => "invalid_address",
            Code::DuplicateName => "duplicate_name",
            Code::UnknownPort => "unknown_port",
            Code::PortUsedTwice => "port_used_twice",
            Code::Overlap => "overlap",
            Code::GatewayOutsideSubnet => "gateway_outside_subnet",
            Code::MissingKind => "missing_kind",
            Code::EmptyPorts => "empty_ports",
            Code::PortMapMismatch => "port_map_mismatch",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Where, as a JSON-pointer-like path with indexes: `lans[0].ports[1]`.
    pub path: String,
    /// Which rule.
    pub code: Code,
    /// Human-readable detail.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.path, self.code, self.message)
    }
}

/// Check `config` against the rules and the live port map `ports`. Returns every violation in
/// document order (`ports`, then `wans`, then `lans`, then subnet overlaps); empty means valid.
/// Where two items conflict (a name or port used twice, two overlapping subnets) the later one in
/// document order is flagged.
#[must_use]
pub fn validate(config: &Config, ports: &PortMap) -> Vec<Violation> {
    let mut report = Report::default();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut used_ports: BTreeSet<&str> = BTreeSet::new();
    let mut subnets: Vec<(String, Ipv4Net)> = Vec::new();

    for (i, entry) in config.ports.iter().enumerate() {
        let live_name = ports.name_of(&entry.id);
        if live_name != Some(entry.name.as_str())
            || ports.id_of(&entry.name) != Some(entry.id.as_str())
        {
            report.push(
                format!("ports[{i}]"),
                Code::PortMapMismatch,
                format!(
                    "config maps {} to {} but this box has {}",
                    entry.id,
                    entry.name,
                    live_name.unwrap_or("no such port")
                ),
            );
        }
    }

    for (i, wan) in config.wans.iter().enumerate() {
        let path = format!("wans[{i}]");
        report.name(&mut names, &format!("{path}.name"), &wan.name);
        report.port(&mut used_ports, ports, &format!("{path}.port"), &wan.port);
        match &wan.kind {
            None => report.push(
                format!("{path}.kind"),
                Code::MissingKind,
                "a WAN needs exactly one of [wans.static], [wans.dhcp]".to_owned(),
            ),
            Some(wan::Kind::Dhcp(_)) => {}
            Some(wan::Kind::Static(s)) => {
                let net = report.cidr(&format!("{path}.static.address"), &s.address);
                let gateway = report.addr4(&format!("{path}.static.gateway"), &s.gateway);
                if let (Some(net), Some(gateway)) = (net, gateway)
                    && !net.contains(&gateway)
                {
                    report.push(
                        format!("{path}.static.gateway"),
                        Code::GatewayOutsideSubnet,
                        format!("{gateway} is not inside {}", net.trunc()),
                    );
                }
                for (j, dns) in s.dns.iter().enumerate() {
                    if dns.parse::<IpAddr>().is_err() {
                        report.push(
                            format!("{path}.static.dns[{j}]"),
                            Code::InvalidAddress,
                            format!("{dns:?} is not an IP address"),
                        );
                    }
                }
                if let Some(net) = net {
                    subnets.push((format!("{path}.static.address"), net));
                }
            }
        }
    }

    for (i, lan) in config.lans.iter().enumerate() {
        let path = format!("lans[{i}]");
        report.name(&mut names, &format!("{path}.name"), &lan.name);
        if lan.ports.is_empty() {
            report.push(
                format!("{path}.ports"),
                Code::EmptyPorts,
                "a LAN needs at least one port".to_owned(),
            );
        }
        for (j, port) in lan.ports.iter().enumerate() {
            report.port(&mut used_ports, ports, &format!("{path}.ports[{j}]"), port);
        }
        if let Some(net) = report.cidr(&format!("{path}.ipv4"), &lan.ipv4) {
            subnets.push((format!("{path}.ipv4"), net));
        }
    }

    for (k, (path, net)) in subnets.iter().enumerate() {
        if let Some((other_path, other)) = subnets[..k].iter().find(|(_, o)| overlaps(*o, *net)) {
            report.push(
                path.clone(),
                Code::Overlap,
                format!("{} overlaps {} ({other_path})", net.trunc(), other.trunc()),
            );
        }
    }
    report.0
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[derive(Default)]
struct Report(Vec<Violation>);

impl Report {
    fn push(&mut self, path: String, code: Code, message: String) {
        self.0.push(Violation {
            path,
            code,
            message,
        });
    }

    fn name<'c>(&mut self, names: &mut BTreeSet<&'c str>, path: &str, name: &'c str) {
        if !names.insert(name) {
            self.push(
                path.to_owned(),
                Code::DuplicateName,
                format!("{name:?} is already used"),
            );
        }
    }

    fn port<'c>(
        &mut self,
        used: &mut BTreeSet<&'c str>,
        live: &PortMap,
        path: &str,
        port: &'c str,
    ) {
        if live.id_of(port).is_none() {
            let have: Vec<&str> = live.names().collect();
            self.push(
                path.to_owned(),
                Code::UnknownPort,
                format!(
                    "no port named {port:?} on this box (have: {})",
                    have.join(", ")
                ),
            );
        } else if !used.insert(port) {
            self.push(
                path.to_owned(),
                Code::PortUsedTwice,
                format!("{port:?} is already assigned"),
            );
        }
    }

    fn cidr(&mut self, path: &str, text: &str) -> Option<Ipv4Net> {
        if let Ok(net) = text.parse::<Ipv4Net>() {
            return Some(net);
        }
        self.push(
            path.to_owned(),
            Code::InvalidCidr,
            format!("{text:?} is not an IPv4 address/prefix"),
        );
        None
    }

    fn addr4(&mut self, path: &str, text: &str) -> Option<Ipv4Addr> {
        if let Ok(addr) = text.parse::<Ipv4Addr>() {
            return Some(addr);
        }
        self.push(
            path.to_owned(),
            Code::InvalidAddress,
            format!("{text:?} is not an IPv4 address"),
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Lan, PortMap, PortMapEntry, StaticWan, Wan, wan};

    fn entry(id: &str, name: &str) -> PortMapEntry {
        PortMapEntry {
            id: id.into(),
            name: name.into(),
        }
    }

    fn live() -> PortMap {
        PortMap {
            ports: vec![
                entry("pci-0000:00:03.0", "p0"),
                entry("pci-0000:00:04.0", "p1"),
                entry("pci-0000:00:05.0", "p2"),
            ],
        }
    }

    fn static_wan(address: &str, gateway: &str, dns: &[&str]) -> Wan {
        Wan {
            name: "wan0".into(),
            port: "p0".into(),
            vlan: 0,
            priority: 10,
            kind: Some(wan::Kind::Static(StaticWan {
                address: address.into(),
                gateway: gateway.into(),
                dns: dns.iter().map(|s| (*s).to_owned()).collect(),
            })),
        }
    }

    fn lan(name: &str, ports: &[&str], ipv4: &str) -> Lan {
        Lan {
            name: name.into(),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
            ipv4: ipv4.into(),
        }
    }

    fn base() -> Config {
        Config {
            config_version: 1,
            wans: vec![static_wan(
                "203.0.113.10/24",
                "203.0.113.1",
                &["203.0.113.1"],
            )],
            lans: vec![lan("lan0", &["p1", "p2"], "192.168.1.1/24")],
            ..Default::default()
        }
    }

    fn found(cfg: &Config) -> Vec<(String, Code)> {
        validate(cfg, &live())
            .into_iter()
            .map(|v| (v.path, v.code))
            .collect()
    }

    #[test]
    fn valid_config_has_no_violations() {
        assert_eq!(validate(&base(), &live()), vec![]);
    }

    #[test]
    fn unknown_port_is_a_violation() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p7".into()];
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ports[0]".to_owned(), Code::UnknownPort)]
        );
    }

    #[test]
    fn port_used_twice() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p0".into(), "p2".into()];
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ports[0]".to_owned(), Code::PortUsedTwice)]
        );
    }

    #[test]
    fn duplicate_names() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p1".into()];
        cfg.lans.push(lan("lan0", &["p2"], "192.168.2.1/24"));
        assert_eq!(
            found(&cfg),
            vec![("lans[1].name".to_owned(), Code::DuplicateName)]
        );
        let mut cfg = base();
        cfg.wans[0].name = "lan0".into();
        assert_eq!(
            found(&cfg),
            vec![("lans[0].name".to_owned(), Code::DuplicateName)]
        );
    }

    #[test]
    fn invalid_cidr_and_address() {
        let mut cfg = base();
        cfg.wans[0] = static_wan("nonsense", "203.0.113.999", &["203.0.113.1", "bad"]);
        cfg.lans[0].ipv4 = "192.168.1.1".into();
        let got = found(&cfg);
        for expected in [
            ("wans[0].static.address", Code::InvalidCidr),
            ("wans[0].static.gateway", Code::InvalidAddress),
            ("wans[0].static.dns[1]", Code::InvalidAddress),
            ("lans[0].ipv4", Code::InvalidCidr),
        ] {
            assert!(
                got.contains(&(expected.0.to_owned(), expected.1)),
                "{expected:?} not in {got:?}"
            );
        }
        assert_eq!(got.len(), 4, "{got:?}");
    }

    #[test]
    fn overlapping_subnets_are_a_violation() {
        let mut cfg = base();
        cfg.wans[0] = static_wan("192.168.1.10/16", "192.168.0.1", &[]);
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ipv4".to_owned(), Code::Overlap)]
        );
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p1".into()];
        cfg.lans.push(lan("lan1", &["p2"], "192.168.1.200/24"));
        assert_eq!(
            found(&cfg),
            vec![("lans[1].ipv4".to_owned(), Code::Overlap)]
        );
    }

    #[test]
    fn gateway_outside_subnet() {
        let mut cfg = base();
        cfg.wans[0] = static_wan("203.0.113.10/24", "203.0.114.1", &[]);
        assert_eq!(
            found(&cfg),
            vec![(
                "wans[0].static.gateway".to_owned(),
                Code::GatewayOutsideSubnet
            )]
        );
    }

    #[test]
    fn missing_kind() {
        let mut cfg = base();
        cfg.wans[0].kind = None;
        assert_eq!(
            found(&cfg),
            vec![("wans[0].kind".to_owned(), Code::MissingKind)]
        );
    }

    #[test]
    fn empty_lan_ports() {
        let mut cfg = base();
        cfg.lans[0].ports.clear();
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ports".to_owned(), Code::EmptyPorts)]
        );
    }

    #[test]
    fn portmap_mismatch() {
        let mut cfg = base();
        cfg.ports = vec![entry("pci-0000:00:03.0", "p1")];
        assert_eq!(
            found(&cfg),
            vec![("ports[0]".to_owned(), Code::PortMapMismatch)]
        );
        let mut cfg = base();
        cfg.ports = live().ports;
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn violation_displays_path_code_message() {
        let v = Violation {
            path: "lans[0].ports[0]".into(),
            code: Code::UnknownPort,
            message: "no port named p7".into(),
        };
        assert_eq!(
            v.to_string(),
            "lans[0].ports[0]: unknown_port: no port named p7"
        );
    }
}
