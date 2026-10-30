// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Semantic validation (SPEC §8.1): CIDRs, overlaps, unique names, port references against the
//! live port map. Protobuf types alone validate nothing; every finding is structured as
//! `(path, code, message)` so the console, the API and the panel can all show it.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

use crate::{Config, Firewall, PortMap, wan};

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
    /// A WAN or LAN name the kernel could not take as part of an interface name.
    InvalidName,
    /// A port forward protocol other than `tcp` or `udp`.
    InvalidProto,
    /// A port outside 1-65535 (or, for `to_port`, outside 0-65535).
    InvalidPort,
    /// A port forward target that is in no LAN subnet.
    ForwardTargetOutsideLan,
    /// A port forward on a port the router itself serves.
    ReservedPort,
}

/// Ports the router's own services use on the WAN side (DNS, DHCP, HTTP, NTP, HTTPS): a forward
/// on one of them would silently hijack that service, so it is refused (SPEC §7.5, §9).
pub const RESERVED_WAN_PORTS: [u16; 6] = [53, 67, 68, 80, 123, 443];
/// Longest port forward name (logs and API only; not an interface name).
pub const MAX_FORWARD_NAME: usize = 32;

/// Longest LAN name: `br-<lan>` must fit the kernel's 15-byte interface name.
pub const MAX_LAN_NAME: usize = 15 - "br-".len();
/// Longest WAN name: `ppp-<wan>` (M3) must fit the kernel's 15-byte interface name.
pub const MAX_WAN_NAME: usize = 15 - "ppp-".len();

/// A logical name the kernel accepts inside an interface name: `[a-z0-9][a-z0-9_-]*`, at most
/// `max_len` bytes.
#[must_use]
pub fn is_valid_name(name: &str, max_len: usize) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= max_len
        && first.is_ascii_lowercase() | first.is_ascii_digit()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
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
            Code::InvalidName => "invalid_name",
            Code::InvalidProto => "invalid_proto",
            Code::InvalidPort => "invalid_port",
            Code::ForwardTargetOutsideLan => "forward_target_outside_lan",
            Code::ReservedPort => "reserved_port",
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
/// document order (`ports`, then `wans`, then `lans`, then `firewall`, then subnet overlaps);
/// empty means valid.
/// Where two items conflict (a name or port used twice, two overlapping subnets) the later one in
/// document order is flagged.
#[must_use]
pub fn validate(config: &Config, ports: &PortMap) -> Vec<Violation> {
    let mut report = Report::default();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut used_ports: BTreeSet<&str> = BTreeSet::new();
    let mut subnets: Vec<(String, Ipv4Net)> = Vec::new();
    let mut lan_subnets: Vec<Ipv4Net> = Vec::new();

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
        report.name(&mut names, &format!("{path}.name"), &wan.name, MAX_WAN_NAME);
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
        report.name(&mut names, &format!("{path}.name"), &lan.name, MAX_LAN_NAME);
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
            lan_subnets.push(net);
        }
    }

    if let Some(firewall) = &config.firewall {
        port_forwards(&mut report, firewall, &lan_subnets);
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

/// `firewall.port_forwards[i]`: name, protocol, port (not one of the router's own), target
/// inside a LAN, target port.
fn port_forwards(report: &mut Report, firewall: &Firewall, lan_subnets: &[Ipv4Net]) {
    let mut forward_names: BTreeSet<&str> = BTreeSet::new();
    for (i, forward) in firewall.port_forwards.iter().enumerate() {
        let path = format!("firewall.port_forwards[{i}]");
        report.name(
            &mut forward_names,
            &format!("{path}.name"),
            &forward.name,
            MAX_FORWARD_NAME,
        );
        if !matches!(forward.proto.as_str(), "tcp" | "udp") {
            report.push(
                format!("{path}.proto"),
                Code::InvalidProto,
                format!("{:?} is not \"tcp\" or \"udp\"", forward.proto),
            );
        }
        match u16::try_from(forward.port) {
            Ok(port) if port != 0 => {
                if RESERVED_WAN_PORTS.contains(&port) {
                    report.push(
                        format!("{path}.port"),
                        Code::ReservedPort,
                        format!("port {port} is one of the router's own services"),
                    );
                }
            }
            _ => report.push(
                format!("{path}.port"),
                Code::InvalidPort,
                format!("{} is not a port (1-65535)", forward.port),
            ),
        }
        if let Some(to) = report.addr4(&format!("{path}.to"), &forward.to)
            && !lan_subnets.iter().any(|net| net.contains(&to))
        {
            report.push(
                format!("{path}.to"),
                Code::ForwardTargetOutsideLan,
                format!("{to} is inside no LAN subnet"),
            );
        }
        if u16::try_from(forward.to_port).is_err() {
            report.push(
                format!("{path}.to_port"),
                Code::InvalidPort,
                format!(
                    "{} is not a port (0 = same as port, or 1-65535)",
                    forward.to_port
                ),
            );
        }
    }
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

    fn name<'c>(
        &mut self,
        names: &mut BTreeSet<&'c str>,
        path: &str,
        name: &'c str,
        max_len: usize,
    ) {
        if !is_valid_name(name, max_len) {
            self.push(
                path.to_owned(),
                Code::InvalidName,
                format!(
                    "{name:?} must be 1 to {max_len} characters of [a-z0-9_-] starting with a letter or digit"
                ),
            );
            return;
        }
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
    use crate::{Config, Firewall, Lan, PortForward, PortMap, PortMapEntry, StaticWan, Wan, wan};

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

    #[test]
    fn invalid_names_are_rejected() {
        for (bad, what) in [
            ("guest-network", "13 chars: br- prefix would exceed 15"),
            ("Lan0", "uppercase"),
            ("lan 0", "space"),
            ("", "empty"),
            ("-lan", "leading dash"),
            ("lan/0", "slash"),
        ] {
            let mut cfg = base();
            cfg.lans[0].name = bad.into();
            let got = found(&cfg);
            assert!(
                got.contains(&("lans[0].name".to_owned(), Code::InvalidName)),
                "{what}: {got:?}"
            );
        }
        let mut cfg = base();
        cfg.wans[0].name = "wan-too-long".into();
        assert!(found(&cfg).contains(&("wans[0].name".to_owned(), Code::InvalidName)));
        let mut cfg = base();
        cfg.lans[0].name = "guest_lan_12".into();
        cfg.wans[0].name = "wan_long_11".into();
        assert_eq!(found(&cfg), vec![]);
    }

    fn forward(name: &str, proto: &str, port: u32, to: &str, to_port: u32) -> PortForward {
        PortForward {
            name: name.into(),
            proto: proto.into(),
            port,
            to: to.into(),
            to_port,
        }
    }

    fn with_forwards(forwards: Vec<PortForward>) -> Config {
        let mut cfg = base();
        cfg.firewall = Some(Firewall {
            port_forwards: forwards,
            wan_ping: true,
        });
        cfg
    }

    #[test]
    fn port_forward_valid_passes() {
        let cfg = with_forwards(vec![forward("lan-http", "tcp", 2222, "192.168.1.2", 8080)]);
        assert_eq!(found(&cfg), vec![]);
        let cfg = with_forwards(vec![forward("same-port", "udp", 5000, "192.168.1.3", 0)]);
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn forward_target_must_be_in_a_lan() {
        let cfg = with_forwards(vec![forward("nowhere", "tcp", 2222, "10.9.9.9", 8080)]);
        assert_eq!(
            found(&cfg),
            vec![(
                "firewall.port_forwards[0].to".to_owned(),
                Code::ForwardTargetOutsideLan
            )]
        );
    }

    #[test]
    fn reserved_ports_are_rejected() {
        assert_eq!(RESERVED_WAN_PORTS, [53, 67, 68, 80, 123, 443]);
        for port in RESERVED_WAN_PORTS {
            let cfg = with_forwards(vec![forward(
                "svc",
                "tcp",
                u32::from(port),
                "192.168.1.2",
                0,
            )]);
            assert_eq!(
                found(&cfg),
                vec![(
                    "firewall.port_forwards[0].port".to_owned(),
                    Code::ReservedPort
                )],
                "port {port}"
            );
        }
    }

    #[test]
    fn invalid_proto_and_ports() {
        let cfg = with_forwards(vec![forward("bad", "sctp", 0, "nonsense", 70000)]);
        let got = found(&cfg);
        for expected in [
            ("firewall.port_forwards[0].proto", Code::InvalidProto),
            ("firewall.port_forwards[0].port", Code::InvalidPort),
            ("firewall.port_forwards[0].to", Code::InvalidAddress),
            ("firewall.port_forwards[0].to_port", Code::InvalidPort),
        ] {
            assert!(
                got.contains(&(expected.0.to_owned(), expected.1)),
                "{expected:?} not in {got:?}"
            );
        }
        assert_eq!(got.len(), 4, "{got:?}");
    }

    #[test]
    fn duplicate_forward_names() {
        let cfg = with_forwards(vec![
            forward("lan-http", "tcp", 2222, "192.168.1.2", 8080),
            forward("lan-http", "udp", 2222, "192.168.1.2", 8080),
        ]);
        assert_eq!(
            found(&cfg),
            vec![(
                "firewall.port_forwards[1].name".to_owned(),
                Code::DuplicateName
            )]
        );
        // Forward names are their own namespace: a forward may share a LAN's name.
        let cfg = with_forwards(vec![forward("lan0", "tcp", 2222, "192.168.1.2", 8080)]);
        assert_eq!(found(&cfg), vec![]);
    }
}
