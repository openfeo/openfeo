// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Semantic validation (SPEC §8.1): CIDRs, overlaps, unique names, port references against the
//! live port map. Protobuf types alone validate nothing; every finding is structured as
//! `(path, code, message)` so the console, the API and the panel can all show it.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;

use crate::{Config, DhcpWan, Dns, Firewall, LanDhcp, PortMap, StaticLease, System, wan};

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
    /// The same protocol and port forwarded twice.
    DuplicateForward,
    /// A `[wans.dhcp]` hostname that is not a DNS host name.
    InvalidHostname,
    /// A `[wans.dhcp]` vendor class that is empty, over 255 bytes or not printable ASCII.
    InvalidVendorClass,
    /// A `[lans.dhcp]` range that is not two IPv4 addresses with the first not above the last.
    InvalidRange,
    /// A `[lans.dhcp]` range end that is not a host address of the LAN subnet.
    RangeOutsideSubnet,
    /// A `[lans.dhcp]` range containing the router's own address.
    RouterInRange,
    /// A `[lans.dhcp]` lease time under [`MIN_LEASE_SECS`] (0 means the default).
    LeaseTooShort,
    /// A static lease MAC that is not `aa:bb:cc:dd:ee:ff`.
    InvalidMac,
    /// A static lease address that is not a host address of the LAN subnet, or is the router's.
    StaticOutsideSubnet,
    /// A static lease MAC or address used twice within one LAN.
    DuplicateStatic,
    /// A static lease client identifier that is not hex of 1 to 255 bytes.
    InvalidClientId,
    /// `[dns] blocklists` is set; block lists arrive after M1 (SPEC §7.7).
    BlocklistsUnsupported,
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

/// Longest host name sent as DHCP option 12 (RFC 1035 §2.3.4).
pub const MAX_HOSTNAME: usize = 253;
/// Longest vendor class sent as DHCP option 60 (one option's payload).
pub const MAX_VENDOR_CLASS: usize = 255;
/// Longest DNS label (a static lease's hostname).
pub const MAX_LABEL: usize = 63;
/// Shortest DHCPv4 lease `[lans.dhcp] lease_secs` may ask for; 0 means the default.
pub const MIN_LEASE_SECS: u32 = 60;

/// A DNS host name (RFC 1123 §2.1): dot-separated labels of `[A-Za-z0-9-]`, 1 to 63 bytes each,
/// never starting or ending with a hyphen, at most [`MAX_HOSTNAME`] bytes in all.
#[must_use]
pub fn is_valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOSTNAME
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// A vendor class identifier: 1 to [`MAX_VENDOR_CLASS`] bytes of printable ASCII.
#[must_use]
pub fn is_valid_vendor_class(class: &str) -> bool {
    !class.is_empty()
        && class.len() <= MAX_VENDOR_CLASS
        && class.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

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
            Code::DuplicateForward => "duplicate_forward",
            Code::InvalidHostname => "invalid_hostname",
            Code::InvalidVendorClass => "invalid_vendor_class",
            Code::InvalidRange => "invalid_range",
            Code::RangeOutsideSubnet => "range_outside_subnet",
            Code::RouterInRange => "router_in_range",
            Code::LeaseTooShort => "lease_too_short",
            Code::InvalidMac => "invalid_mac",
            Code::StaticOutsideSubnet => "static_outside_subnet",
            Code::DuplicateStatic => "duplicate_static",
            Code::InvalidClientId => "invalid_client_id",
            Code::BlocklistsUnsupported => "blocklists_unsupported",
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
/// document order (`system`, then `ports`, then `wans`, then `lans`, then `firewall`, then
/// `dns`, then subnet overlaps); empty means valid.
/// Where two items conflict (a name or port used twice, two overlapping subnets) the later one in
/// document order is flagged.
#[must_use]
pub fn validate(config: &Config, ports: &PortMap) -> Vec<Violation> {
    let mut report = Report::default();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut used_ports: BTreeSet<&str> = BTreeSet::new();
    let mut subnets: Vec<(String, Ipv4Net)> = Vec::new();
    let mut lan_subnets: Vec<Ipv4Net> = Vec::new();

    if let Some(system_config) = &config.system {
        system(&mut report, system_config);
    }

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
            Some(wan::Kind::Dhcp(dhcp)) => dhcp_wan(&mut report, &path, dhcp),
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
            if let Some(dhcp) = &lan.dhcp {
                lan_dhcp(&mut report, &path, net, dhcp);
            }
        }
    }

    if let Some(firewall) = &config.firewall {
        port_forwards(&mut report, firewall, &lan_subnets);
    }

    if let Some(dns_config) = &config.dns {
        dns(&mut report, dns_config);
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

/// `[system]`: the hostname is one DNS label and the domain a host name (together they are the
/// router's own name and the local DNS zone, SPEC §7.7); empty means the default.
fn system(report: &mut Report, system: &System) {
    if !system.hostname.is_empty() && !is_valid_label(&system.hostname) {
        report.push(
            "system.hostname".to_owned(),
            Code::InvalidHostname,
            format!(
                "{:?} is not a DNS label: [A-Za-z0-9-] up to {MAX_LABEL} bytes, not starting or ending with a hyphen",
                system.hostname
            ),
        );
    }
    if !system.domain.is_empty() && !is_valid_hostname(&system.domain) {
        report.push(
            "system.domain".to_owned(),
            Code::InvalidHostname,
            format!(
                "{:?} is not a domain name: labels of [A-Za-z0-9-] up to 63 bytes, not starting or ending with a hyphen, {MAX_HOSTNAME} bytes in all",
                system.domain
            ),
        );
    }
}

/// The `[wans.dhcp]` options: a host name and a vendor class, each checked only when set.
fn dhcp_wan(report: &mut Report, path: &str, dhcp: &DhcpWan) {
    if !dhcp.hostname.is_empty() && !is_valid_hostname(&dhcp.hostname) {
        report.push(
            format!("{path}.dhcp.hostname"),
            Code::InvalidHostname,
            format!(
                "{:?} is not a host name: labels of [A-Za-z0-9-] up to 63 bytes, not starting or ending with a hyphen, {MAX_HOSTNAME} bytes in all",
                dhcp.hostname
            ),
        );
    }
    if !dhcp.vendor_class.is_empty() && !is_valid_vendor_class(&dhcp.vendor_class) {
        report.push(
            format!("{path}.dhcp.vendor_class"),
            Code::InvalidVendorClass,
            format!(
                "{:?} must be 1 to {MAX_VENDOR_CLASS} bytes of printable ASCII",
                dhcp.vendor_class
            ),
        );
    }
}

/// `lans[i].dhcp` (SPEC §7.6): a pool of two ordered host addresses of the subnet with the
/// router outside it, a lease time of at least [`MIN_LEASE_SECS`] (0 for the default), static
/// leases with a MAC, a host address, a label and an optional client identifier, and DNS
/// servers that are addresses.
fn lan_dhcp(report: &mut Report, path: &str, net: Ipv4Net, dhcp: &LanDhcp) {
    let path = format!("{path}.dhcp");
    dhcp_range(report, &format!("{path}.range"), net, &dhcp.range);
    if dhcp.lease_secs != 0 && dhcp.lease_secs < MIN_LEASE_SECS {
        report.push(
            format!("{path}.lease_secs"),
            Code::LeaseTooShort,
            format!(
                "{} s; at least {MIN_LEASE_SECS} s, or 0 for the default",
                dhcp.lease_secs
            ),
        );
    }
    let mut seen = (BTreeSet::new(), BTreeSet::new());
    for (j, lease) in dhcp.r#static.iter().enumerate() {
        static_lease(
            report,
            &format!("{path}.static[{j}]"),
            net,
            lease,
            &mut seen,
        );
    }
    for (k, dns) in dhcp.dns.iter().enumerate() {
        if dns.parse::<Ipv4Addr>().is_err() {
            report.push(
                format!("{path}.dns[{k}]"),
                Code::InvalidAddress,
                format!("{dns:?} is not an IPv4 address"),
            );
        }
    }
}

/// A host address of `net`: inside it, neither the network nor the broadcast address.
fn is_host_address(net: Ipv4Net, addr: Ipv4Addr) -> bool {
    net.contains(&addr) && addr != net.network() && addr != net.broadcast()
}

/// `lans[i].dhcp.range`: two ordered host addresses of the subnet, the router outside them.
fn dhcp_range(report: &mut Report, path: &str, net: Ipv4Net, range: &[String]) {
    let [first, last] = range else {
        report.push(
            path.to_owned(),
            Code::InvalidRange,
            format!(
                "a range is exactly two addresses, first and last, not {}",
                range.len()
            ),
        );
        return;
    };
    let router = net.addr();
    match (first.parse::<Ipv4Addr>(), last.parse::<Ipv4Addr>()) {
        (Ok(first), Ok(last)) if first > last => report.push(
            path.to_owned(),
            Code::InvalidRange,
            format!("{first} comes after {last}"),
        ),
        (Ok(first), Ok(last)) if !is_host_address(net, first) || !is_host_address(net, last) => {
            report.push(
                path.to_owned(),
                Code::RangeOutsideSubnet,
                format!("{first}-{last} must be host addresses of {}", net.trunc()),
            );
        }
        (Ok(first), Ok(last)) if (first..=last).contains(&router) => report.push(
            path.to_owned(),
            Code::RouterInRange,
            format!("the router's address {router} lies inside {first}-{last}"),
        ),
        (Ok(_), Ok(_)) => {}
        _ => report.push(
            path.to_owned(),
            Code::InvalidRange,
            format!("{range:?} are not two IPv4 addresses"),
        ),
    }
}

/// `lans[i].dhcp.static[j]`: a MAC and a host address not seen before in this LAN, a label,
/// an optional hex client identifier.
fn static_lease(
    report: &mut Report,
    path: &str,
    net: Ipv4Net,
    lease: &StaticLease,
    seen: &mut (BTreeSet<[u8; 6]>, BTreeSet<Ipv4Addr>),
) {
    match parse_mac(&lease.mac) {
        None => report.push(
            format!("{path}.mac"),
            Code::InvalidMac,
            format!(
                "{:?} is not a MAC address like aa:bb:cc:dd:ee:ff",
                lease.mac
            ),
        ),
        Some(mac) if !seen.0.insert(mac) => report.push(
            format!("{path}.mac"),
            Code::DuplicateStatic,
            format!("{} already has a static lease", lease.mac),
        ),
        Some(_) => {}
    }
    match lease.ip.parse::<Ipv4Addr>() {
        Err(_) => report.push(
            format!("{path}.ip"),
            Code::InvalidAddress,
            format!("{:?} is not an IPv4 address", lease.ip),
        ),
        Ok(ip) if !is_host_address(net, ip) || ip == net.addr() => report.push(
            format!("{path}.ip"),
            Code::StaticOutsideSubnet,
            format!(
                "{ip} must be a host address of {} other than the router's",
                net.trunc()
            ),
        ),
        Ok(ip) if !seen.1.insert(ip) => report.push(
            format!("{path}.ip"),
            Code::DuplicateStatic,
            format!("{ip} already has a static lease"),
        ),
        Ok(_) => {}
    }
    if !lease.hostname.is_empty() && !is_valid_label(&lease.hostname) {
        report.push(
            format!("{path}.hostname"),
            Code::InvalidHostname,
            format!(
                "{:?} is not a DNS label: [A-Za-z0-9-] up to {MAX_LABEL} bytes, not starting or ending with a hyphen",
                lease.hostname
            ),
        );
    }
    if !lease.client_id.is_empty() && !is_valid_client_id(&lease.client_id) {
        report.push(
            format!("{path}.client_id"),
            Code::InvalidClientId,
            format!(
                "{:?} is not a client identifier: an even number of hex digits, 1 to 255 bytes",
                lease.client_id
            ),
        );
    }
}

/// One DNS label: 1 to [`MAX_LABEL`] bytes of `[A-Za-z0-9-]`, not starting or ending with a
/// hyphen.
#[must_use]
pub fn is_valid_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LABEL
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `aa:bb:cc:dd:ee:ff`, either case.
#[must_use]
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// Lowercase or uppercase hex of 1 to 255 bytes.
fn is_valid_client_id(text: &str) -> bool {
    text.len().is_multiple_of(2)
        && (2..=510).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `firewall.port_forwards[i]`: name, protocol, port (not one of the router's own), target
/// inside a LAN, target port.
fn port_forwards(report: &mut Report, firewall: &Firewall, lan_subnets: &[Ipv4Net]) {
    let mut forward_names: BTreeSet<&str> = BTreeSet::new();
    let mut forwarded: BTreeSet<(&str, u16)> = BTreeSet::new();
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
                } else if !forwarded.insert((forward.proto.as_str(), port)) {
                    report.push(
                        format!("{path}.port"),
                        Code::DuplicateForward,
                        format!("{port}/{} is already forwarded", forward.proto),
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

/// `[dns]` (SPEC §7.7): upstreams that are IPv4 addresses, no block lists yet, allow-listed
/// names that are host names.
fn dns(report: &mut Report, dns: &Dns) {
    for (i, upstream) in dns.upstreams.iter().enumerate() {
        report.addr4(&format!("dns.upstreams[{i}]"), upstream);
    }
    if !dns.blocklists.is_empty() {
        report.push(
            "dns.blocklists".to_owned(),
            Code::BlocklistsUnsupported,
            "block lists are not supported yet; leave the list empty".to_owned(),
        );
    }
    for (i, name) in dns.rebind_allow.iter().enumerate() {
        if !is_valid_hostname(name) {
            report.push(
                format!("dns.rebind_allow[{i}]"),
                Code::InvalidHostname,
                format!(
                    "{name:?} is not a host name: labels of [A-Za-z0-9-] up to 63 bytes, not starting or ending with a hyphen, {MAX_HOSTNAME} bytes in all"
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
    use crate::{
        Config, DhcpWan, Firewall, Lan, PortForward, PortMap, PortMapEntry, StaticWan, Wan, wan,
    };

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

    fn dhcp_wan(hostname: &str, vendor_class: &str) -> Wan {
        Wan {
            name: "wan0".into(),
            port: "p0".into(),
            vlan: 0,
            priority: 10,
            kind: Some(wan::Kind::Dhcp(DhcpWan {
                hostname: hostname.into(),
                vendor_class: vendor_class.into(),
            })),
        }
    }

    fn lan(name: &str, ports: &[&str], ipv4: &str) -> Lan {
        Lan {
            name: name.into(),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
            ipv4: ipv4.into(),
            dhcp: None,
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
    fn dhcp_wan_options_are_validated() {
        let mut cfg = base();
        cfg.wans = vec![dhcp_wan("openfeo-lab", "OpenFeO/0.1")];
        assert_eq!(found(&cfg), vec![]);
        cfg.wans = vec![dhcp_wan("", "")];
        assert_eq!(found(&cfg), vec![], "empty means the option is not sent");
        let long_labels = format!("{}.{}", "a".repeat(63), "b".repeat(63));
        cfg.wans = vec![dhcp_wan(&long_labels, "")];
        assert_eq!(
            found(&cfg),
            vec![],
            "63-byte labels are the limit, not over it"
        );
        for bad in [
            "-bad",
            "bad-",
            "a..b",
            "under_score",
            "sp ace",
            &"a".repeat(64),
        ] {
            cfg.wans = vec![dhcp_wan(bad, "")];
            assert_eq!(
                found(&cfg),
                vec![("wans[0].dhcp.hostname".to_owned(), Code::InvalidHostname)],
                "{bad:?}"
            );
        }
        for bad in [&"x".repeat(256), "tab\there", "ünïcödé"] {
            cfg.wans = vec![dhcp_wan("", bad)];
            assert_eq!(
                found(&cfg),
                vec![(
                    "wans[0].dhcp.vendor_class".to_owned(),
                    Code::InvalidVendorClass
                )],
                "{bad:?}"
            );
        }
        cfg.wans = vec![dhcp_wan("", &"x".repeat(255))];
        assert_eq!(found(&cfg), vec![], "255 bytes is the limit");
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

    #[test]
    fn same_proto_and_port_forwarded_twice() {
        let cfg = with_forwards(vec![
            forward("a", "tcp", 2222, "192.168.1.2", 8080),
            forward("b", "tcp", 2222, "192.168.1.3", 0),
            forward("c", "udp", 2222, "192.168.1.3", 0),
        ]);
        assert_eq!(
            found(&cfg),
            vec![(
                "firewall.port_forwards[1].port".to_owned(),
                Code::DuplicateForward
            )]
        );
    }
}

#[cfg(test)]
mod lan_dhcp_tests {
    use super::*;
    use crate::{PortMap, PortMapEntry};

    const VM_STATIC: &str = include_str!("../../../harness/fixtures/vm-static.toml");
    const VM_DHCP: &str = include_str!("../../../harness/fixtures/vm-dhcp.toml");

    fn live() -> PortMap {
        PortMap {
            ports: ["pci-0000:00:03.0", "pci-0000:00:04.0", "pci-0000:00:05.0"]
                .iter()
                .enumerate()
                .map(|(i, id)| PortMapEntry {
                    id: (*id).to_owned(),
                    name: format!("p{i}"),
                })
                .collect(),
        }
    }

    /// A minimal config with one LAN and the given `[lans.dhcp]` body, so the only violations
    /// are the DHCP block's.
    fn with_dhcp(fragment: &str) -> Config {
        crate::file::parse(&format!(
            "config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p2\"]\nipv4 = \"192.168.1.1/24\"\n[lans.dhcp]\n{fragment}\n"
        ))
        .expect("test config parses")
    }

    fn codes(violations: &[Violation]) -> Vec<(String, Code)> {
        violations
            .iter()
            .map(|v| (v.path.clone(), v.code))
            .collect()
    }

    const RANGE: &str = "range = [\"192.168.1.100\", \"192.168.1.200\"]\n";

    #[test]
    fn fixture_dhcp_sections_are_valid() {
        for fixture in [VM_STATIC, VM_DHCP] {
            let config = crate::file::parse(fixture).expect("fixture parses");
            assert!(config.lans[0].dhcp.is_some(), "fixture has [lans.dhcp]");
            assert_eq!(validate(&config, &live()), vec![]);
        }
    }

    #[test]
    fn range_must_be_two_ordered_host_addresses_of_the_subnet_without_the_router() {
        let range = |text: &str| codes(&validate(&with_dhcp(&format!("range = {text}")), &live()));
        assert_eq!(
            range(r#"["192.168.1.100"]"#),
            vec![("lans[0].dhcp.range".to_owned(), Code::InvalidRange)]
        );
        assert_eq!(
            range(r#"["192.168.1.200", "192.168.1.100"]"#),
            vec![("lans[0].dhcp.range".to_owned(), Code::InvalidRange)]
        );
        assert_eq!(
            range(r#"["192.168.1.0", "192.168.1.255"]"#),
            vec![("lans[0].dhcp.range".to_owned(), Code::RangeOutsideSubnet)]
        );
        assert_eq!(
            range(r#"["192.168.2.10", "192.168.2.20"]"#),
            vec![("lans[0].dhcp.range".to_owned(), Code::RangeOutsideSubnet)]
        );
        assert_eq!(
            range(r#"["192.168.1.1", "192.168.1.20"]"#),
            vec![("lans[0].dhcp.range".to_owned(), Code::RouterInRange)]
        );
    }

    #[test]
    fn lease_secs_zero_is_the_default_and_under_60_is_refused() {
        assert_eq!(validate(&with_dhcp(RANGE), &live()), vec![]);
        assert_eq!(
            codes(&validate(
                &with_dhcp(&format!("{RANGE}lease_secs = 30")),
                &live()
            )),
            vec![("lans[0].dhcp.lease_secs".to_owned(), Code::LeaseTooShort)]
        );
        assert_eq!(
            validate(&with_dhcp(&format!("{RANGE}lease_secs = 60")), &live()),
            vec![]
        );
    }

    #[test]
    fn statics_need_a_mac_a_host_address_a_label_and_no_duplicates() {
        let bad = format!(
            "{RANGE}[[lans.dhcp.static]]\nmac = \"zz:00\"\nip = \"192.168.1.1\"\nhostname = \"nas.home\"\nclient_id = \"abc\"\n\
             [[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:10\"\nip = \"192.168.1.10\"\nhostname = \"nas\"\n\
             [[lans.dhcp.static]]\nmac = \"52:54:00:FE:10:10\"\nip = \"192.168.1.11\"\nhostname = \"nas2\"\n\
             [[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:11\"\nip = \"192.168.1.10\"\nhostname = \"nas3\"\n"
        );
        assert_eq!(
            codes(&validate(&with_dhcp(&bad), &live())),
            vec![
                ("lans[0].dhcp.static[0].mac".to_owned(), Code::InvalidMac),
                (
                    "lans[0].dhcp.static[0].ip".to_owned(),
                    Code::StaticOutsideSubnet
                ),
                (
                    "lans[0].dhcp.static[0].hostname".to_owned(),
                    Code::InvalidHostname
                ),
                (
                    "lans[0].dhcp.static[0].client_id".to_owned(),
                    Code::InvalidClientId
                ),
                (
                    "lans[0].dhcp.static[2].mac".to_owned(),
                    Code::DuplicateStatic
                ),
                (
                    "lans[0].dhcp.static[3].ip".to_owned(),
                    Code::DuplicateStatic
                ),
            ]
        );
    }

    #[test]
    fn dns_entries_must_be_addresses() {
        assert_eq!(
            codes(&validate(
                &with_dhcp(&format!("{RANGE}dns = [\"1.1.1.1\", \"dns.example\"]")),
                &live()
            )),
            vec![("lans[0].dhcp.dns[1]".to_owned(), Code::InvalidAddress)]
        );
    }

    #[test]
    fn labels_and_macs_parse() {
        assert!(is_valid_label("nas") && is_valid_label("Nas-2"));
        assert!(!is_valid_label("-nas") && !is_valid_label("nas.home") && !is_valid_label(""));
        assert!(!is_valid_label(&"a".repeat(64)) && is_valid_label(&"a".repeat(63)));
        assert_eq!(
            parse_mac("52:54:00:FE:10:10"),
            Some([0x52, 0x54, 0, 0xfe, 0x10, 0x10])
        );
        assert_eq!(parse_mac("52-54-00-fe-10-10"), None);
        assert_eq!(parse_mac("52:54:00:fe:10"), None);
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;
    use crate::{PortMap, PortMapEntry, file};

    fn live() -> PortMap {
        PortMap {
            ports: vec![PortMapEntry {
                id: "pci-0000:00:03.0".to_owned(),
                name: "p0".to_owned(),
            }],
        }
    }

    fn codes(violations: &[Violation]) -> Vec<(String, Code)> {
        violations
            .iter()
            .map(|v| (v.path.clone(), v.code))
            .collect()
    }

    #[test]
    fn dns_upstreams_must_be_addresses_blocklists_must_be_empty_and_allow_names_valid() {
        let config = file::parse(
            "config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\", \"dns.quad9.net\"]\nblocklists = [\"hagezi\"]\nrebind_allow = [\"plex.direct\", \"-bad\"]\n",
        )
        .unwrap();
        assert_eq!(
            codes(&validate(&config, &live())),
            vec![
                ("dns.upstreams[1]".to_owned(), Code::InvalidAddress),
                ("dns.blocklists".to_owned(), Code::BlocklistsUnsupported),
                ("dns.rebind_allow[1]".to_owned(), Code::InvalidHostname),
            ]
        );
        let ok = file::parse(
            "config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\"]\nuse_wan_dns = false\n",
        )
        .unwrap();
        assert_eq!(validate(&ok, &live()), vec![]);
        assert_eq!(ok.dns.as_ref().and_then(|d| d.use_wan_dns), Some(false));
        assert_eq!(
            file::parse("config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\"]\n")
                .unwrap()
                .dns
                .unwrap()
                .use_wan_dns,
            None,
            "absent means the default, true"
        );
    }

    /// Review finding: `[system]` feeds the DNS local zone, and a name that does not parse
    /// there took the forwarder down; the hostname is one label, the domain a host name.
    #[test]
    fn system_hostname_is_a_label_and_domain_a_host_name() {
        let bad = file::parse(
            "config_version = 1\n[system]\nhostname = \"my router\"\ndomain = \".home.arpa\"\n",
        )
        .unwrap();
        assert_eq!(
            codes(&validate(&bad, &live())),
            vec![
                ("system.hostname".to_owned(), Code::InvalidHostname),
                ("system.domain".to_owned(), Code::InvalidHostname),
            ]
        );
        for domain in [".", "home..arpa", "-bad.arpa", "a.b."] {
            let config = file::parse(&format!(
                "config_version = 1\n[system]\ndomain = \"{domain}\"\n"
            ))
            .unwrap();
            assert_eq!(
                codes(&validate(&config, &live())),
                vec![("system.domain".to_owned(), Code::InvalidHostname)],
                "{domain:?}"
            );
        }
        let dotted = file::parse("config_version = 1\n[system]\nhostname = \"a.b\"\n").unwrap();
        assert_eq!(
            codes(&validate(&dotted, &live())),
            vec![("system.hostname".to_owned(), Code::InvalidHostname)],
            "a hostname is one label"
        );
        for ok in [
            "config_version = 1\n[system]\nhostname = \"\"\ndomain = \"\"\n",
            "config_version = 1\n[system]\nhostname = \"Router-2\"\ndomain = \"lan.example\"\n",
        ] {
            assert_eq!(
                validate(&file::parse(ok).unwrap(), &live()),
                vec![],
                "{ok:?}"
            );
        }
    }
}
