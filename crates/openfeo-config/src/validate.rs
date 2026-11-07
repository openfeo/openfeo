// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Semantic validation (SPEC §8.1): CIDRs, overlaps, unique names, port references against the
//! live port map. Protobuf types alone validate nothing; every finding is structured as
//! `(path, code, message)` so the console, the API and the panel can all show it.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::rules;
use crate::{
    Config, DhcpWan, Dns, Firewall, Ipv6Wan, LanDhcp, PortMap, PppoeWan, Record, StaticLease,
    StaticWan, System, Wan, portname, wan,
};

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
    /// A VLAN id outside 1-4094 on a WAN or a tagged LAN member.
    InvalidVlan,
    /// A tagged LAN member on a port that is a WAN (a port is a WAN or carries LANs, not both).
    PortRoleConflict,
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
    /// A static lease MAC, address or hostname used twice within one LAN.
    DuplicateStatic,
    /// A static lease client identifier that is not hex of 1 to 255 bytes.
    InvalidClientId,
    /// `[dns] blocklists` is set; block lists arrive after M1 (SPEC §7.7).
    BlocklistsUnsupported,
    /// A `[[public_ipv4]]` block that is not global unicast space or overlaps another block or a
    /// WAN subnet.
    InvalidPublicBlock,
    /// A LAN numbered from global unicast space that no `[[public_ipv4]]` block declares.
    UndeclaredPublicLan,
    /// A port forward `address` that is not an address inside an unclaimed public block.
    InvalidForwardAddress,
    /// A `reaches` entry or a rule's `from` that is not `wan`, `none` (reaches only) or a LAN.
    InvalidZone,
    /// A rule's `to` that is not an address, range or CIDR inside one other LAN.
    InvalidRuleTarget,
    /// A rule's `ports` missing or wrong for tcp/udp, or present for icmp/any.
    InvalidRulePorts,
    /// Two rules from one zone in the same set whose targets and ports partly overlap (the
    /// kernel refuses such interval elements, in an order-dependent way).
    OverlappingRules,
    /// A `[wans.ipv6] prefix` that is not global unicast space, has host bits set, or is longer
    /// than a /63 (its first /64 is the router's own).
    InvalidIpv6Prefix,
    /// `[wans.ipv6]` on a second WAN (one WAN carries IPv6 until M6).
    Ipv6WanTwice,
    /// A `[wans.ipv6] mode` other than `auto` or `disabled`.
    InvalidIpv6Mode,
    /// `mode = "disabled"` beside a prefix, a gateway, a `pd_hint` or a LAN `ipv6`, which would
    /// then describe nothing.
    Ipv6Disabled,
    /// A `[wans.ipv6] pd_hint` outside 48 to 64.
    InvalidPdHint,
    /// `[wans.pppoe].username` is empty, over 255 bytes or carries a NUL.
    PppoeUsername,
    /// `[wans.pppoe].password` is empty, over 255 bytes or carries a NUL.
    PppoePassword,
    /// `[wans.pppoe].service` or `.ac` is over 255 bytes.
    PppoeFilter,
    /// A LAN `ipv6_index` above 65535.
    InvalidIpv6Index,
    /// Two LANs with the same `ipv6_index`.
    Ipv6IndexTwice,
    /// `ra` or `ipv6_index` beside `ipv6 = "none"`, which carries no IPv6 to advertise or number.
    Ipv6None,
    /// A LAN `ipv6` outside the routed prefix.
    LanPrefixOutsideRouted,
    /// A LAN `ipv6` in the routed prefix's first /64, the router's own.
    LanPrefixReserved,
    /// A LAN `ipv6` with no routed prefix to lie in.
    LanPrefixWithoutRouted,
    /// `ra` on a LAN that carries no IPv6: no routed /64 and no WAN with `[wans.ipv6]`.
    RaWithoutIpv6,
    /// Two `[[dns.records]]` with the same name and address family.
    DuplicateRecord,
    /// A `[[dns.records]]` name the router already answers for.
    RecordNameTaken,
    /// A `[[dns.records]]` full name outside `[system] domain`, which the forwarder never answers.
    RecordOutsideDomain,
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
/// The longest PPPoE credential or filter: PAP and CHAP count their strings in one byte.
pub const MAX_PPPOE_STRING: usize = 255;
// The DHCPv4 server's own limits, so the file and the server agree on them: the longest DNS
// label (a static lease's hostname) and the shortest lease `[lans.dhcp] lease_secs` may ask for
// (0 means the default).
pub use openfeo_proto_dhcp4::server::{MAX_LABEL, MIN_LEASE_SECS};

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
            Code::InvalidVlan => "invalid_vlan",
            Code::PortRoleConflict => "port_role_conflict",
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
            Code::InvalidPublicBlock => "invalid_public_block",
            Code::UndeclaredPublicLan => "undeclared_public_lan",
            Code::InvalidForwardAddress => "invalid_forward_address",
            Code::InvalidZone => "invalid_zone",
            Code::InvalidRuleTarget => "invalid_rule_target",
            Code::InvalidRulePorts => "invalid_rule_ports",
            Code::OverlappingRules => "overlapping_rules",
            Code::InvalidIpv6Prefix => "invalid_ipv6_prefix",
            Code::Ipv6WanTwice => "ipv6_wan_twice",
            Code::InvalidIpv6Mode => "invalid_ipv6_mode",
            Code::Ipv6Disabled => "ipv6_disabled",
            Code::InvalidPdHint => "invalid_pd_hint",
            Code::PppoeUsername => "pppoe_username",
            Code::PppoePassword => "pppoe_password",
            Code::PppoeFilter => "pppoe_filter",
            Code::InvalidIpv6Index => "invalid_ipv6_index",
            Code::Ipv6IndexTwice => "ipv6_index_twice",
            Code::Ipv6None => "ipv6_none",
            Code::LanPrefixOutsideRouted => "lan_prefix_outside_routed",
            Code::LanPrefixReserved => "lan_prefix_reserved",
            Code::LanPrefixWithoutRouted => "lan_prefix_without_routed",
            Code::RaWithoutIpv6 => "ra_without_ipv6",
            Code::DuplicateRecord => "duplicate_record",
            Code::RecordNameTaken => "record_name_taken",
            Code::RecordOutsideDomain => "record_outside_domain",
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
    let mut owners = PortOwners::default();
    let mut pools = Pools::default();
    let mut ipv6_wans = false;
    let lans_have_ipv6 = config
        .lans
        .iter()
        .any(|lan| !lan.ipv6.is_empty() && !rules::lan_is_ipv4_only(lan));
    // Once a WAN carries `[wans.ipv6]` every LAN takes a ULA /64 (SPEC §7.3), so `ra` means
    // something on any LAN that is not IPv4-only.
    pools.router_has_ipv6 = config.wans.iter().any(|wan| {
        wan.ipv6
            .as_ref()
            .is_some_and(|ipv6| ipv6.mode != "disabled")
    });

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
        wan_port(&mut report, &mut owners, ports, &path, wan);
        if let Some(ipv6) = &wan.ipv6 {
            ipv6_wan(
                &mut report,
                &mut pools,
                &path,
                ipv6,
                &mut ipv6_wans,
                lans_have_ipv6,
            );
        }
        match &wan.kind {
            None => report.push(
                format!("{path}.kind"),
                Code::MissingKind,
                "a WAN needs exactly one of [wans.static], [wans.dhcp], [wans.pppoe]".to_owned(),
            ),
            Some(wan::Kind::Dhcp(dhcp)) => dhcp_wan(&mut report, &path, dhcp),
            Some(wan::Kind::Static(s)) => static_wan(&mut report, &mut pools, &path, s),
            Some(wan::Kind::Pppoe(pppoe)) => pppoe_wan(&mut report, &path, pppoe),
        }
    }

    let blocks = public_blocks(&mut report, config, &pools.subnets);
    lans(
        &mut report,
        config,
        ports,
        &mut names,
        &mut owners,
        &blocks,
        &mut pools,
    );

    if let Some(firewall) = &config.firewall {
        port_forwards(&mut report, firewall, &pools.lan_subnets, &blocks);
        firewall_rules(&mut report, firewall, &pools.lans);
    }

    if let Some(dns_config) = &config.dns {
        dns(&mut report, dns_config, &pools, config.system.as_ref());
    }

    let subnets = &pools.subnets;
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

/// What the WAN and LAN passes collect for the checks that follow them.
#[derive(Default)]
struct Pools<'c> {
    /// Every WAN static and LAN subnet with its path, for the overlap check.
    subnets: Vec<(String, Ipv4Net)>,
    /// Every LAN subnet as written (host bits kept), for the forward and DNS checks.
    lan_subnets: Vec<Ipv4Net>,
    /// Every LAN as a zone, for `reaches` and the rules.
    lans: Vec<LanZone<'c>>,
    /// The one routed IPv6 prefix, when a WAN declares it (SPEC §7.3).
    ipv6_prefix: Option<Ipv6Net>,
    /// Every LAN `ipv6` as written, with its path, for the overlap check.
    lan_prefixes6: Vec<(String, Ipv6Net)>,
    /// Every LAN's IPv6 router address, for the upstream check.
    lan_addrs6: Vec<Ipv6Addr>,
    /// Every effective `ipv6_index` (typed, or the LAN's position) with its path and whether it
    /// was typed, for the uniqueness check.
    indexes6: Vec<(String, u32, bool)>,
    /// Whether a WAN carries `[wans.ipv6]` in mode auto: then every LAN that is not IPv4-only
    /// carries at least the ULA /64 (SPEC §7.3).
    router_has_ipv6: bool,
    /// Every reservation hostname, lowercase, for the record check.
    hostnames: BTreeSet<String>,
}

/// One LAN as the firewall sees it.
struct LanZone<'c> {
    name: &'c str,
    /// The subnet, when `ipv4` parsed.
    net: Option<Ipv4Net>,
    /// The /64, when `ipv6` is set and parsed.
    net6: Option<Ipv6Net>,
}

/// `[[public_ipv4]]` (SPEC §7.4, §7.5): every block global unicast space, disjoint from the
/// other blocks and from the WAN static subnets. Returns the blocks that parsed.
fn public_blocks(
    report: &mut Report,
    config: &Config,
    wan_subnets: &[(String, Ipv4Net)],
) -> Vec<Ipv4Net> {
    let mut blocks: Vec<(String, Ipv4Net)> = Vec::new();
    for (i, block) in config.public_ipv4.iter().enumerate() {
        let path = format!("public_ipv4[{i}].prefix");
        let Some(net) = report.cidr(&path, &block.prefix) else {
            continue;
        };
        let net = net.trunc();
        if !rules::is_global_unicast_v4(net) {
            report.push(
                path,
                Code::InvalidPublicBlock,
                format!("{net} is not global unicast space"),
            );
            continue;
        }
        let clash = blocks
            .iter()
            .chain(wan_subnets)
            .find(|(_, other)| overlaps(*other, net));
        if let Some((other_path, other)) = clash {
            report.push(
                path,
                Code::InvalidPublicBlock,
                format!("{net} overlaps {} ({other_path})", other.trunc()),
            );
            continue;
        }
        blocks.push((path, net));
    }
    blocks.into_iter().map(|(_, net)| net).collect()
}

/// `[[lans]]`: names, members (SPEC §7.1), the subnet (public space must lie inside a declared
/// block, SPEC §7.5), `reaches` and `[lans.dhcp]`; the subnets join the overlap pool and the LAN
/// lists the firewall and DNS checks read.
fn lans<'c>(
    report: &mut Report,
    config: &'c Config,
    ports: &PortMap,
    names: &mut BTreeSet<&'c str>,
    owners: &mut PortOwners<'c>,
    blocks: &[Ipv4Net],
    pools: &mut Pools<'c>,
) {
    let lan_names: BTreeSet<&str> = config.lans.iter().map(|lan| lan.name.as_str()).collect();
    for (i, lan) in config.lans.iter().enumerate() {
        let path = format!("lans[{i}]");
        report.name(names, &format!("{path}.name"), &lan.name, MAX_LAN_NAME);
        if lan.ports.is_empty() {
            report.push(
                format!("{path}.ports"),
                Code::EmptyPorts,
                "a LAN needs at least one port".to_owned(),
            );
        }
        for (j, member) in lan.ports.iter().enumerate() {
            lan_member(report, owners, ports, &format!("{path}.ports[{j}]"), member);
        }
        lan_member_forms(report, &path, lan);
        let net = report.cidr(&format!("{path}.ipv4"), &lan.ipv4);
        if let Some(net) = net {
            pools.subnets.push((format!("{path}.ipv4"), net));
            pools.lan_subnets.push(net);
            if rules::is_global_unicast_v4(net.trunc())
                && !blocks.iter().any(|block| block.contains(&net.trunc()))
            {
                report.push(
                    format!("{path}.ipv4"),
                    Code::UndeclaredPublicLan,
                    format!(
                        "{} is public space that no [[public_ipv4]] block declares; declare the \
                         block the ISP routes to this router, or use private space",
                        net.trunc()
                    ),
                );
            }
            if let Some(dhcp) = &lan.dhcp {
                lan_dhcp(report, &path, net, dhcp);
            }
        }
        reaches(report, &path, lan, &lan_names);
        let net6 = lan_ipv6(report, &path, lan, pools);
        if rules::lan_is_ipv4_only(lan) {
            if lan.ra.is_some() {
                report.push(
                    format!("{path}.ra"),
                    Code::Ipv6None,
                    "ipv6 = \"none\" leaves nothing to advertise; drop ra".to_owned(),
                );
            }
            if lan.ipv6_index != 0 {
                report.push(
                    format!("{path}.ipv6_index"),
                    Code::Ipv6None,
                    "ipv6 = \"none\" takes no /64 from any prefix; drop ipv6_index".to_owned(),
                );
            }
        } else {
            if lan.ra.is_some() && lan.ipv6.is_empty() && !pools.router_has_ipv6 {
                report.push(
                    format!("{path}.ra"),
                    Code::RaWithoutIpv6,
                    "ra applies to a LAN that carries IPv6; set the LAN's /64, give a WAN \
                     [wans.ipv6], or drop ra"
                        .to_owned(),
                );
            }
            lan_ipv6_index(report, &path, lan, pools, i + 1);
        }
        for reservation in lan.dhcp.iter().flat_map(|dhcp| &dhcp.r#static) {
            if !reservation.hostname.is_empty() {
                pools
                    .hostnames
                    .insert(reservation.hostname.to_ascii_lowercase());
            }
        }
        pools.lans.push(LanZone {
            name: &lan.name,
            net,
            net6,
        });
    }
}

/// One LAN may not carry the same port both untagged and tagged: `p2` and `p2.223` on one
/// bridge would flood every frame twice onto the wire. The later form in the list is flagged.
fn lan_member_forms(report: &mut Report, path: &str, lan: &crate::Lan) {
    let mut untagged: BTreeSet<&str> = BTreeSet::new();
    let mut tagged_parents: BTreeSet<&str> = BTreeSet::new();
    for (j, member) in lan.ports.iter().enumerate() {
        let clash = match member.split_once('.') {
            None => {
                untagged.insert(member);
                tagged_parents.contains(member.as_str())
            }
            Some((port, _)) => {
                tagged_parents.insert(port);
                untagged.contains(port)
            }
        };
        if clash {
            report.push(
                format!("{path}.ports[{j}]"),
                Code::PortUsedTwice,
                format!(
                    "{member:?}: this LAN already carries its port in the other form (untagged \
                     and tagged on one bridge would duplicate every frame)"
                ),
            );
        }
    }
}

/// `reaches` (SPEC §7.5): each entry `"wan"`, `"none"` or another LAN's name, `"none"` alone,
/// nothing twice. Empty means `["wan"]` and needs no check.
fn reaches(report: &mut Report, path: &str, lan: &crate::Lan, lan_names: &BTreeSet<&str>) {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (j, zone) in lan.reaches.iter().enumerate() {
        let path = format!("{path}.reaches[{j}]");
        let known = zone == "wan"
            || zone == "none"
            || (lan_names.contains(zone.as_str()) && *zone != lan.name);
        if !known {
            report.push(
                path,
                Code::InvalidZone,
                format!("{zone:?} is not \"wan\", \"none\" or another LAN"),
            );
        } else if !seen.insert(zone) {
            report.push(path, Code::InvalidZone, format!("{zone:?} is listed twice"));
        } else if zone == "none" && lan.reaches.len() > 1 {
            report.push(path, Code::InvalidZone, "\"none\" stands alone".to_owned());
        }
    }
}

/// `[[firewall.rules]]` (SPEC §7.5): a name, a zone to come from, a target inside one other
/// LAN, a protocol, and ports for tcp/udp only.
fn firewall_rules(report: &mut Report, firewall: &Firewall, lans: &[LanZone<'_>]) {
    let mut rule_names: BTreeSet<&str> = BTreeSet::new();
    let mut holes: Vec<Hole<'_>> = Vec::new();
    for (i, rule) in firewall.rules.iter().enumerate() {
        let path = format!("firewall.rules[{i}]");
        report.name(
            &mut rule_names,
            &format!("{path}.name"),
            &rule.name,
            MAX_FORWARD_NAME,
        );
        overlapping_rules(report, &path, rule, &mut holes);
        if rule.from != "wan" && !lans.iter().any(|lan| lan.name == rule.from) {
            report.push(
                format!("{path}.from"),
                Code::InvalidZone,
                format!("{:?} is not \"wan\" or a LAN name", rule.from),
            );
        }
        rule_target(report, &path, &rule.from, &rule.to, lans);
        if !rules::PROTOS.contains(&rule.proto.as_str()) {
            report.push(
                format!("{path}.proto"),
                Code::InvalidProto,
                format!(
                    "{:?} is not \"tcp\", \"udp\", \"icmp\" or \"any\"",
                    rule.proto
                ),
            );
        }
        let wants_ports = matches!(rule.proto.as_str(), "tcp" | "udp");
        if wants_ports && rules::parse_ports(&rule.ports).is_none() {
            report.push(
                format!("{path}.ports"),
                Code::InvalidRulePorts,
                "ports must be at least one of \"1\"-\"65535\" or an \"a-b\" range".to_owned(),
            );
        } else if !wants_ports && !rule.ports.is_empty() {
            report.push(
                format!("{path}.ports"),
                Code::InvalidRulePorts,
                "ports apply to tcp and udp only".to_owned(),
            );
        }
    }
}

/// One element a rule contributes to a rules set: the zone, the set (tcp, udp, icmp or any), the
/// target's bounds and, for tcp/udp, one port range.
struct Hole<'c> {
    name: &'c str,
    from: &'c str,
    proto: &'c str,
    /// The target's bounds; both ends of one family, so the sets of each family stay apart.
    target: (IpAddr, IpAddr),
    ports: Option<(u16, u16)>,
}

impl Hole<'_> {
    /// Partly overlapping: same zone and set, intersecting targets and ports, not identical.
    /// Identical holes merge in the kernel; partial overlaps are refused there.
    fn clashes_with(&self, other: &Self) -> bool {
        let same_set = self.from == other.from
            && self.proto == other.proto
            && self.target.0.is_ipv6() == other.target.0.is_ipv6();
        let targets_meet = self.target.0 <= other.target.1 && other.target.0 <= self.target.1;
        let ports_meet = match (self.ports, other.ports) {
            (Some(a), Some(b)) => a.0 <= b.1 && b.0 <= a.1,
            _ => true,
        };
        let identical = self.target == other.target && self.ports == other.ports;
        same_set && targets_meet && ports_meet && !identical
    }
}

/// The kernel's interval sets refuse an element that partly overlaps another, and which of two
/// such rules fails depends on their order in the file; two rules from one zone whose targets and
/// ports overlap are refused here instead, naming both (SPEC §7.5). A rule whose target or ports
/// do not parse is left to the checks that report that.
fn overlapping_rules<'c>(
    report: &mut Report,
    path: &str,
    rule: &'c crate::Rule,
    holes: &mut Vec<Hole<'c>>,
) {
    let target = if let Some(target) = rules::parse_target(&rule.to) {
        let (first, last) = target.bounds();
        (IpAddr::V4(first), IpAddr::V4(last))
    } else if let Some(target) = rules::parse_target6(&rule.to) {
        let (first, last) = target.bounds();
        (IpAddr::V6(first), IpAddr::V6(last))
    } else {
        return;
    };
    let ports: Vec<Option<(u16, u16)>> = match rule.proto.as_str() {
        "tcp" | "udp" => match rules::parse_ports(&rule.ports) {
            Some(ranges) => ranges.into_iter().map(Some).collect(),
            None => return,
        },
        "icmp" | "any" => vec![None],
        _ => return,
    };
    let new: Vec<Hole<'c>> = ports
        .into_iter()
        .map(|ports| Hole {
            name: &rule.name,
            from: &rule.from,
            proto: &rule.proto,
            target,
            ports,
        })
        .collect();
    if let Some(other) = holes
        .iter()
        .find(|old| new.iter().any(|hole| hole.clashes_with(old)))
    {
        report.push(
            path.to_owned(),
            Code::OverlappingRules,
            format!(
                "{:?} overlaps {:?} (from {:?}, {}): the kernel refuses holes from one zone that \
                 partly overlap; merge them or make them disjoint",
                rule.name, other.name, rule.from, rule.proto
            ),
        );
    }
    holes.extend(new);
}

/// A rule's `to`: an address, an `a-b` range or a CIDR, inside exactly one LAN that is not the
/// zone the rule comes from.
fn rule_target(report: &mut Report, path: &str, from: &str, to: &str, lans: &[LanZone<'_>]) {
    let path = format!("{path}.to");
    let inside = if let Some(target) = rules::parse_target(to) {
        lans.iter()
            .find(|lan| lan.net.is_some_and(|net| target.within(net.trunc())))
    } else if let Some(target) = rules::parse_target6(to) {
        // A ULA target is placed on its LAN at run time, by the LAN's ULA /64 (SPEC §7.5):
        // the ULA is generated on the box, so validation cannot know which LAN that is.
        let (first, last) = target.bounds();
        if rules::is_ula(Ipv6Net::from(first)) && rules::is_ula(Ipv6Net::from(last)) {
            return;
        }
        lans.iter()
            .find(|lan| lan.net6.is_some_and(|net| target.within(net.trunc())))
    } else {
        report.push(
            path,
            Code::InvalidRuleTarget,
            format!("{to:?} is not an address, an a-b range or a CIDR"),
        );
        return;
    };
    match inside {
        None => report.push(
            path,
            Code::InvalidRuleTarget,
            format!("{to} is inside no LAN subnet"),
        ),
        Some(lan) if lan.name == from => report.push(
            path,
            Code::InvalidRuleTarget,
            format!("{to} is inside {from:?} itself; a rule opens a hole from another zone"),
        ),
        Some(_) => {}
    }
}

/// `[wans.static]` (SPEC §7.2): the address a CIDR, the gateway inside it, the resolvers IP
/// addresses; the subnet joins the overlap check.
fn static_wan(report: &mut Report, pools: &mut Pools<'_>, path: &str, s: &StaticWan) {
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
        pools.subnets.push((format!("{path}.static.address"), net));
    }
}

/// `[wans.ipv6]` (SPEC §7.3): one WAN at most, `mode` auto or disabled, the routed prefix global
/// unicast with no host bits and at most a /63, a typed gateway an IPv6 address. A prefix that
/// passes is the one the LANs' `ipv6` must lie in.
fn ipv6_wan(
    report: &mut Report,
    pools: &mut Pools<'_>,
    path: &str,
    ipv6: &Ipv6Wan,
    seen: &mut bool,
    lans_have_ipv6: bool,
) {
    let path = format!("{path}.ipv6");
    if ipv6.mode == "disabled" && (!ipv6.prefix.is_empty() || lans_have_ipv6) {
        report.push(
            format!("{path}.mode"),
            Code::Ipv6Disabled,
            "\"disabled\" runs no IPv6 on this WAN, so a routed prefix or a LAN ipv6 would describe \
             nothing; set mode = \"auto\" or drop them"
                .to_owned(),
        );
    }
    if std::mem::replace(seen, true) {
        report.push(
            path.clone(),
            Code::Ipv6WanTwice,
            "IPv6 runs on one WAN until multi-WAN IPv6 (M6); drop [wans.ipv6] from the others"
                .to_owned(),
        );
    }
    match ipv6.mode.as_str() {
        "" | "auto" | "disabled" => {}
        other => report.push(
            format!("{path}.mode"),
            Code::InvalidIpv6Mode,
            format!("{other:?} is not \"auto\" or \"disabled\""),
        ),
    }
    if !ipv6.prefix.is_empty()
        && let Some(net) = report.cidr6(&format!("{path}.prefix"), &ipv6.prefix)
    {
        if net.addr() != net.network() {
            report.push(
                format!("{path}.prefix"),
                Code::InvalidIpv6Prefix,
                format!(
                    "{} has host bits set; write the prefix as {}",
                    ipv6.prefix,
                    net.trunc()
                ),
            );
        } else if !rules::is_global_unicast_v6(net) {
            report.push(
                format!("{path}.prefix"),
                Code::InvalidIpv6Prefix,
                format!("{net} is not global unicast space (2000::/3)"),
            );
        } else if net.prefix_len() > 63 {
            report.push(
                format!("{path}.prefix"),
                Code::InvalidIpv6Prefix,
                format!(
                    "{net} leaves no /64 for a LAN: the prefix's first /64 is the router's own, so a \
                     routed prefix is at most a /63"
                ),
            );
        } else {
            pools.ipv6_prefix = Some(net);
        }
    }
    if !ipv6.gateway.is_empty() {
        report.addr6(&format!("{path}.gateway"), &ipv6.gateway);
        if ipv6.mode == "disabled" {
            report.push(
                format!("{path}.gateway"),
                Code::Ipv6Disabled,
                "\"disabled\" installs no IPv6 default, so a gateway would describe nothing; set \
                 mode = \"auto\" or drop it"
                    .to_owned(),
            );
        }
    }
    if ipv6.pd_hint != 0 {
        if !(48..=64).contains(&ipv6.pd_hint) {
            report.push(
                format!("{path}.pd_hint"),
                Code::InvalidPdHint,
                format!(
                    "{} is not a delegation length an ISP hands out; use 48 to 64 (56 when absent)",
                    ipv6.pd_hint
                ),
            );
        }
        if ipv6.mode == "disabled" {
            report.push(
                format!("{path}.pd_hint"),
                Code::Ipv6Disabled,
                "\"disabled\" runs no DHCPv6 client, so a pd_hint would describe nothing; set \
                 mode = \"auto\" or drop it"
                    .to_owned(),
            );
        }
    }
}

/// A LAN's `ipv6_index` (SPEC §7.3): typed 1 to 65535 (0 is absent), or the LAN's 1-based
/// `position` counting every LAN; the effective index is no other LAN's, a clash being flagged
/// on the later LAN in configuration order.
fn lan_ipv6_index(
    report: &mut Report,
    path: &str,
    lan: &crate::Lan,
    pools: &mut Pools<'_>,
    position: usize,
) {
    let path = format!("{path}.ipv6_index");
    let typed = lan.ipv6_index != 0;
    if lan.ipv6_index > 0xffff {
        report.push(
            path,
            Code::InvalidIpv6Index,
            format!(
                "{} is above 65535, the most a ULA /48 can number; use 1 to 65535",
                lan.ipv6_index
            ),
        );
        return;
    }
    let index = if typed {
        lan.ipv6_index
    } else {
        u32::try_from(position).unwrap_or(u32::MAX)
    };
    if let Some((other_path, _, other_typed)) =
        pools.indexes6.iter().find(|(_, other, _)| *other == index)
    {
        let other = if *other_typed {
            format!("{other_path}'s")
        } else {
            format!(
                "{}'s by position; pin that LAN's ipv6_index or choose another",
                other_path.trim_end_matches(".ipv6_index")
            )
        };
        report.push(
            path,
            Code::Ipv6IndexTwice,
            if typed {
                format!("index {index} is already {other}")
            } else {
                format!(
                    "this LAN's index by position, {index}, is already {other}; pin its \
                     ipv6_index"
                )
            },
        );
        return;
    }
    pools.indexes6.push((path, index, typed));
}

/// A LAN's `ipv6` (SPEC §7.3): a host address with a /64 prefix, inside the routed prefix, not
/// its first /64, and no other LAN's; or empty; or the word `none`. Returns the /64 that passed.
fn lan_ipv6(
    report: &mut Report,
    path: &str,
    lan: &crate::Lan,
    pools: &mut Pools<'_>,
) -> Option<Ipv6Net> {
    if lan.ipv6.is_empty() || rules::lan_is_ipv4_only(lan) {
        return None;
    }
    let path = format!("{path}.ipv6");
    let net = match lan.ipv6.parse::<Ipv6Net>() {
        Ok(net) if net.prefix_len() == 64 && net.addr() != net.network() => net,
        _ => {
            report.push(
                path,
                Code::InvalidCidr,
                format!(
                    "{:?} is not the router's IPv6 address with the LAN's /64, like \"2001:db8:1:222::1/64\"",
                    lan.ipv6
                ),
            );
            return None;
        }
    };
    let block = net.trunc();
    let Some(routed) = pools.ipv6_prefix else {
        report.push(
            path,
            Code::LanPrefixWithoutRouted,
            format!(
                "{block} has no routed prefix to lie in; declare the prefix the ISP routes to this \
                 router under [wans.ipv6].prefix"
            ),
        );
        return None;
    };
    if !routed.contains(&block) {
        report.push(
            path,
            Code::LanPrefixOutsideRouted,
            format!("{block} is outside the routed prefix {routed}"),
        );
        return None;
    }
    if block == Ipv6Net::new_assert(routed.network(), 64) {
        report.push(
            path,
            Code::LanPrefixReserved,
            format!(
                "{block} is the first /64 of {routed}, reserved for the router's own address; use \
                 another /64"
            ),
        );
        return None;
    }
    if let Some((other_path, _)) = pools
        .lan_prefixes6
        .iter()
        .find(|(_, other)| other.trunc() == block)
    {
        report.push(
            path,
            Code::Overlap,
            format!("{block} is already {other_path}'s"),
        );
        return None;
    }
    pools.lan_prefixes6.push((path, net));
    pools.lan_addrs6.push(net.addr());
    Some(net)
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
    for (i, server) in system.ntp_servers.iter().enumerate() {
        if server.parse::<Ipv4Addr>().is_err() && !is_valid_hostname(server) {
            report.push(
                format!("system.ntp_servers[{i}]"),
                Code::InvalidHostname,
                format!("{server:?} is neither an IPv4 address nor a host name"),
            );
        }
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

/// `wans[i].pppoe` (SPEC §7.2, §8.2): a username and a password of 1 to 255 bytes without a
/// NUL (PAP and CHAP carry them as counted byte strings), and filters of at most 255 bytes.
fn pppoe_wan(report: &mut Report, path: &str, pppoe: &PppoeWan) {
    let credential =
        |text: &str| !text.is_empty() && text.len() <= MAX_PPPOE_STRING && !text.contains('\0');
    if !credential(&pppoe.username) {
        report.push(
            format!("{path}.pppoe.username"),
            Code::PppoeUsername,
            format!("the account name must be 1 to {MAX_PPPOE_STRING} bytes without a NUL"),
        );
    }
    if !credential(&pppoe.password) {
        report.push(
            format!("{path}.pppoe.password"),
            Code::PppoePassword,
            format!("the password must be 1 to {MAX_PPPOE_STRING} bytes without a NUL"),
        );
    }
    for (field, value) in [("service", &pppoe.service), ("ac", &pppoe.ac)] {
        if value.len() > MAX_PPPOE_STRING || value.contains('\0') {
            report.push(
                format!("{path}.pppoe.{field}"),
                Code::PppoeFilter,
                format!("at most {MAX_PPPOE_STRING} bytes without a NUL; absent means any"),
            );
        }
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
    let mut seen = SeenStatics::default();
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
    for (k, ntp) in dhcp.ntp.iter().enumerate() {
        if ntp.parse::<Ipv4Addr>().is_err() {
            report.push(
                format!("{path}.ntp[{k}]"),
                Code::InvalidAddress,
                format!("{ntp:?} is not an IPv4 address"),
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

/// What one LAN's static leases have claimed so far: a MAC, an address or a hostname (compared
/// without case, as DNS does) may appear once.
#[derive(Default)]
struct SeenStatics {
    macs: BTreeSet<[u8; 6]>,
    addrs: BTreeSet<Ipv4Addr>,
    hostnames: BTreeSet<String>,
}

/// `lans[i].dhcp.static[j]`: a MAC, a host address and a hostname not seen before in this LAN,
/// the hostname a label, an optional hex client identifier.
fn static_lease(
    report: &mut Report,
    path: &str,
    net: Ipv4Net,
    lease: &StaticLease,
    seen: &mut SeenStatics,
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
        Some(mac) if !seen.macs.insert(mac) => report.push(
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
        Ok(ip) if !seen.addrs.insert(ip) => report.push(
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
    } else if !lease.hostname.is_empty()
        && !seen.hostnames.insert(lease.hostname.to_ascii_lowercase())
    {
        report.push(
            format!("{path}.hostname"),
            Code::DuplicateStatic,
            format!(
                "{:?} already names a static lease in this LAN (names compare without case)",
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
fn port_forwards(
    report: &mut Report,
    firewall: &Firewall,
    lan_subnets: &[Ipv4Net],
    blocks: &[Ipv4Net],
) {
    let mut forward_names: BTreeSet<&str> = BTreeSet::new();
    let mut forwarded: BTreeSet<(&str, &str, u16)> = BTreeSet::new();
    for (i, forward) in firewall.port_forwards.iter().enumerate() {
        let path = format!("firewall.port_forwards[{i}]");
        report.name(
            &mut forward_names,
            &format!("{path}.name"),
            &forward.name,
            MAX_FORWARD_NAME,
        );
        if !forward.address.is_empty() {
            forward_address(report, &path, &forward.address, lan_subnets, blocks);
        }
        if !matches!(forward.proto.as_str(), "tcp" | "udp") {
            report.push(
                format!("{path}.proto"),
                Code::InvalidProto,
                format!("{:?} is not \"tcp\" or \"udp\"", forward.proto),
            );
        }
        match u16::try_from(forward.port) {
            Ok(port) if port != 0 => {
                // The router serves nothing on a public-block address, so a forward there may
                // take any port; on the WAN address the router's own services win.
                if RESERVED_WAN_PORTS.contains(&port) && forward.address.is_empty() {
                    report.push(
                        format!("{path}.port"),
                        Code::ReservedPort,
                        format!("port {port} is one of the router's own services"),
                    );
                } else if !forwarded.insert((
                    forward.address.as_str(),
                    forward.proto.as_str(),
                    port,
                )) {
                    report.push(
                        format!("{path}.port"),
                        Code::DuplicateForward,
                        format!(
                            "{port}/{} is already forwarded on {}",
                            forward.proto,
                            if forward.address.is_empty() {
                                "the WAN address"
                            } else {
                                forward.address.as_str()
                            }
                        ),
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

/// A forward's `address` (SPEC §7.5): an address inside a declared public block, outside every
/// LAN subnet, and neither the block's network nor its broadcast address.
fn forward_address(
    report: &mut Report,
    path: &str,
    text: &str,
    lan_subnets: &[Ipv4Net],
    blocks: &[Ipv4Net],
) {
    let path = format!("{path}.address");
    let Ok(addr) = text.parse::<Ipv4Addr>() else {
        report.push(
            path,
            Code::InvalidForwardAddress,
            format!("{text:?} is not an IPv4 address"),
        );
        return;
    };
    let Some(block) = blocks.iter().find(|block| block.contains(&addr)) else {
        report.push(
            path,
            Code::InvalidForwardAddress,
            format!("{addr} is inside no [[public_ipv4]] block"),
        );
        return;
    };
    if let Some(lan) = lan_subnets.iter().find(|net| net.contains(&addr)) {
        report.push(
            path,
            Code::InvalidForwardAddress,
            format!("{addr} is inside the LAN subnet {}", lan.trunc()),
        );
    } else if addr == block.network() || addr == block.broadcast() {
        report.push(
            path,
            Code::InvalidForwardAddress,
            format!("{addr} is the network or broadcast address of {block}"),
        );
    }
}

/// `[dns]` (SPEC §7.7): upstreams that are IPv4 addresses a resolver could answer from (not
/// loopback, multicast, broadcast, `0.0.0.0/8` or the router's own LAN address, which would be
/// the forwarder asking itself), no block lists yet, allow-listed names that are host names.
fn dns(report: &mut Report, dns: &Dns, pools: &Pools<'_>, system: Option<&System>) {
    let lan_subnets = &pools.lan_subnets;
    for (i, upstream) in dns.upstreams.iter().enumerate() {
        let path = format!("dns.upstreams[{i}]");
        let addr = match upstream.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => addr,
            Ok(IpAddr::V6(addr)) => {
                let loopback6 = pools.ipv6_prefix.map(|prefix| {
                    let mut segments = prefix.network().segments();
                    segments[7] = 1;
                    Ipv6Addr::from(segments)
                });
                let why = if addr.is_loopback() {
                    Some("a loopback address")
                } else if addr.is_multicast() {
                    Some("a multicast address")
                } else if addr.is_unspecified() {
                    Some("the unspecified address")
                } else if pools.lan_addrs6.contains(&addr) || loopback6 == Some(addr) {
                    Some("the router's own address, so the forwarder would be asking itself")
                } else {
                    None
                };
                if let Some(why) = why {
                    report.push(
                        path,
                        Code::InvalidAddress,
                        format!("{upstream} is {why}, not a resolver"),
                    );
                }
                continue;
            }
            Err(_) => {
                report.push(
                    path,
                    Code::InvalidAddress,
                    format!("{upstream:?} is not an IP address"),
                );
                continue;
            }
        };
        let [first, ..] = addr.octets();
        let why = if addr.is_loopback() {
            Some("a loopback address")
        } else if addr.is_multicast() {
            Some("a multicast address")
        } else if addr.is_broadcast() {
            Some("the broadcast address")
        } else if first == 0 {
            Some("in 0.0.0.0/8")
        } else if lan_subnets.iter().any(|net| net.addr() == addr) {
            Some("the router's own address, so the forwarder would be asking itself")
        } else {
            None
        };
        if let Some(why) = why {
            report.push(
                path,
                Code::InvalidAddress,
                format!("{upstream} is {why}, not a resolver"),
            );
        }
    }
    if !dns.blocklists.is_empty() {
        report.push(
            "dns.blocklists".to_owned(),
            Code::BlocklistsUnsupported,
            "block lists are not supported yet; leave the list empty".to_owned(),
        );
    }
    records(report, &dns.records, system, &pools.hostnames);
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

/// `[[dns.records]]` (SPEC §7.7): a host name (a label under the domain, or a full name ending
/// in it: the forwarder answers names in its own domain only) and a unicast address, unique per
/// name and family, and never a name the router already answers for: its own, or a reservation's.
fn records(
    report: &mut Report,
    records: &[Record],
    system: Option<&System>,
    hostnames: &BTreeSet<String>,
) {
    let domain = system
        .map(|system| system.domain.as_str())
        .filter(|domain| !domain.is_empty())
        .unwrap_or("home.arpa")
        .to_ascii_lowercase();
    let hostname = system
        .map(|system| system.hostname.as_str())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or("openfeo")
        .to_ascii_lowercase();
    let mut seen: BTreeSet<(String, bool)> = BTreeSet::new();
    for (i, record) in records.iter().enumerate() {
        let path = format!("dns.records[{i}]");
        if !is_valid_hostname(&record.name) {
            report.push(
                path,
                Code::InvalidHostname,
                format!(
                    "{:?} is not a host name: labels of [A-Za-z0-9-] up to 63 bytes, not starting or ending with a hyphen, {MAX_HOSTNAME} bytes in all",
                    record.name
                ),
            );
            continue;
        }
        let Ok(address) = record.address.parse::<IpAddr>() else {
            report.push(
                path,
                Code::InvalidAddress,
                format!("{:?} is not an IP address", record.address),
            );
            continue;
        };
        let unicast = match address {
            IpAddr::V4(a) => !(a.is_multicast() || a.is_broadcast() || a.is_unspecified()),
            IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified()),
        };
        if !unicast {
            report.push(
                path,
                Code::InvalidAddress,
                format!("{address} is not a unicast address"),
            );
            continue;
        }
        let name = record.name.trim_end_matches('.').to_ascii_lowercase();
        if name.contains('.') && !name.ends_with(&format!(".{domain}")) {
            report.push(
                path,
                Code::RecordOutsideDomain,
                format!(
                    "{:?} is not under the domain {domain:?}: the router answers names in its own domain only; use a label, or a full name ending in .{domain}",
                    record.name
                ),
            );
            continue;
        }
        let short = name
            .strip_suffix(&format!(".{domain}"))
            .unwrap_or(&name)
            .to_owned();
        if short == hostname || hostnames.contains(&short) {
            report.push(
                path,
                Code::RecordNameTaken,
                format!(
                    "{:?} is a name the router already answers for (its own, or a reservation's)",
                    record.name
                ),
            );
            continue;
        }
        if !seen.insert((name.clone(), address.is_ipv6())) {
            report.push(
                path,
                Code::DuplicateRecord,
                format!(
                    "{:?} already has a record of this family; a name may have one A and one AAAA",
                    record.name
                ),
            );
        }
    }
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Who owns which port (SPEC §7.1): a physical port is a WAN or an untagged LAN member at most
/// once; a `(port, vlan)` pair is a tagged member or a tagged WAN at most once; a WAN's port
/// carries no LAN at all.
#[derive(Default)]
struct PortOwners<'c> {
    /// WAN ports and untagged LAN members.
    untagged: BTreeSet<&'c str>,
    /// Tagged members and tagged WANs.
    tagged: BTreeSet<(&'c str, u16)>,
    /// Every WAN's physical port.
    wan: BTreeSet<&'c str>,
}

/// A WAN's port and VLAN: the port must exist and be unassigned; `vlan` is 0 (untagged) or a
/// VLAN id, and a tagged WAN takes its `(port, vlan)` pair.
fn wan_port<'c>(
    report: &mut Report,
    owners: &mut PortOwners<'c>,
    live: &PortMap,
    path: &str,
    wan: &'c Wan,
) {
    report.port(
        &mut owners.untagged,
        live,
        &format!("{path}.port"),
        &wan.port,
    );
    owners.wan.insert(&wan.port);
    if wan.vlan == 0 {
        return;
    }
    let Some(vlan) = u16::try_from(wan.vlan)
        .ok()
        .filter(|vlan| (portname::MIN_VLAN..=portname::MAX_VLAN).contains(vlan))
    else {
        report.push(
            format!("{path}.vlan"),
            Code::InvalidVlan,
            format!("{} is not a VLAN id (1-4094)", wan.vlan),
        );
        return;
    };
    if !owners.tagged.insert((&wan.port, vlan)) {
        report.push(
            format!("{path}.vlan"),
            Code::PortUsedTwice,
            format!(
                "{:?} is already assigned",
                portname::vlan_ifname(&wan.port, vlan)
            ),
        );
    }
}

/// One LAN member, `pN` or `pN.V` (SPEC §7.1): the port must exist; untagged, it is assigned
/// once like a WAN port; tagged, its VLAN id must be valid, its port must not be a WAN's, and
/// the `(port, vlan)` pair is assigned once.
fn lan_member<'c>(
    report: &mut Report,
    owners: &mut PortOwners<'c>,
    live: &PortMap,
    path: &str,
    member: &'c str,
) {
    let Some((port, vid)) = member.split_once('.') else {
        report.port(&mut owners.untagged, live, path, member);
        return;
    };
    if live.id_of(port).is_none() {
        // The same "no port named …" message as for an untagged member.
        report.port(&mut owners.untagged, live, path, member);
        return;
    }
    let Some(vlan) = portname::parse_vlan(vid) else {
        report.push(
            path.to_owned(),
            Code::InvalidVlan,
            format!("{vid:?} is not a VLAN id (1-4094)"),
        );
        return;
    };
    if owners.wan.contains(port) {
        report.push(
            path.to_owned(),
            Code::PortRoleConflict,
            format!("{port:?} is a WAN port and may not carry a LAN"),
        );
        return;
    }
    if !owners.tagged.insert((port, vlan)) {
        report.push(
            path.to_owned(),
            Code::PortUsedTwice,
            format!("{member:?} is already assigned"),
        );
    }
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

    fn cidr6(&mut self, path: &str, text: &str) -> Option<Ipv6Net> {
        if let Ok(net) = text.parse::<Ipv6Net>() {
            return Some(net);
        }
        self.push(
            path.to_owned(),
            Code::InvalidCidr,
            format!("{text:?} is not an IPv6 address/prefix"),
        );
        None
    }

    fn addr6(&mut self, path: &str, text: &str) -> Option<Ipv6Addr> {
        if let Ok(addr) = text.parse::<Ipv6Addr>() {
            return Some(addr);
        }
        self.push(
            path.to_owned(),
            Code::InvalidAddress,
            format!("{text:?} is not an IPv6 address"),
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
        Config, DhcpWan, Firewall, Lan, PortForward, PortMap, PortMapEntry, PublicIpv4, Rule,
        StaticWan, Wan, wan,
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
            ipv6: None,
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
            ipv6: None,
        }
    }

    fn lan(name: &str, ports: &[&str], ipv4: &str) -> Lan {
        Lan {
            name: name.into(),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
            ipv4: ipv4.into(),
            dhcp: None,
            reaches: Vec::new(),
            ipv6: String::new(),
            ra: None,
            ipv6_index: 0,
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

    fn codes(cfg: &Config) -> Vec<Code> {
        found(cfg).into_iter().map(|(_, code)| code).collect()
    }

    fn pppoe_wan(username: &str, password: &str, service: &str, ac: &str) -> Wan {
        Wan {
            name: "wan0".into(),
            port: "p0".into(),
            vlan: 0,
            priority: 10,
            kind: Some(wan::Kind::Pppoe(PppoeWan {
                username: username.into(),
                password: password.into(),
                service: service.into(),
                ac: ac.into(),
            })),
            ipv6: None,
        }
    }

    fn with_pppoe(wan: Wan) -> Config {
        Config {
            wans: vec![wan],
            ..base()
        }
    }

    #[test]
    fn a_pppoe_wan_needs_a_username_and_a_password() {
        let ok = with_pppoe(pppoe_wan("openfeo@isp.example", "example-secret", "", ""));
        assert_eq!(found(&ok), vec![]);
        let no_user = with_pppoe(pppoe_wan("", "example-secret", "", ""));
        assert_eq!(
            found(&no_user),
            vec![("wans[0].pppoe.username".to_owned(), Code::PppoeUsername)]
        );
        let no_password = with_pppoe(pppoe_wan("openfeo@isp.example", "", "", ""));
        assert_eq!(
            found(&no_password),
            vec![("wans[0].pppoe.password".to_owned(), Code::PppoePassword)]
        );
    }

    #[test]
    fn pppoe_strings_are_at_most_255_bytes_without_nul() {
        let long = "x".repeat(256);
        let fine = "x".repeat(255);
        assert_eq!(
            found(&with_pppoe(pppoe_wan(&fine, &fine, &fine, &fine))),
            vec![]
        );
        assert_eq!(
            codes(&with_pppoe(pppoe_wan(&long, "pw", "", ""))),
            vec![Code::PppoeUsername]
        );
        assert_eq!(
            codes(&with_pppoe(pppoe_wan("user", &long, "", ""))),
            vec![Code::PppoePassword]
        );
        assert_eq!(
            codes(&with_pppoe(pppoe_wan("user", "p\0w", "", ""))),
            vec![Code::PppoePassword],
            "a NUL cannot cross PAP or CHAP"
        );
        assert_eq!(
            found(&with_pppoe(pppoe_wan("user", "pw", &long, &long))),
            vec![
                ("wans[0].pppoe.service".to_owned(), Code::PppoeFilter),
                ("wans[0].pppoe.ac".to_owned(), Code::PppoeFilter),
            ]
        );
    }

    #[test]
    fn a_pppoe_wan_may_carry_ipv6_in_every_shape() {
        let mut routed = pppoe_wan("openfeo@isp.example", "example-secret", "", "");
        routed.ipv6 = Some(Ipv6Wan {
            prefix: "2001:db8:1::/48".into(),
            ..Default::default()
        });
        let mut cfg = with_pppoe(routed);
        cfg.lans[0].ipv6 = "2001:db8:1:222::1/64".into();
        assert_eq!(found(&cfg), vec![], "a routed prefix over PPP");
        let mut delegated = pppoe_wan("openfeo@isp.example", "example-secret", "", "");
        delegated.ipv6 = Some(Ipv6Wan {
            pd_hint: 56,
            ..Default::default()
        });
        assert_eq!(
            found(&with_pppoe(delegated)),
            vec![],
            "a delegation over PPP"
        );
        let mut gateway = pppoe_wan("openfeo@isp.example", "example-secret", "", "");
        gateway.ipv6 = Some(Ipv6Wan {
            gateway: "fe80::1".into(),
            ..Default::default()
        });
        assert_eq!(
            found(&with_pppoe(gateway)),
            vec![],
            "a typed gateway over PPP"
        );
    }

    #[test]
    fn the_pppoe_fixtures_validate() {
        for text in [
            include_str!("../../../harness/fixtures/vm-pppoe.toml"),
            include_str!("../../../harness/fixtures/vm-pppoe-pd.toml"),
        ] {
            let cfg = crate::file::parse(text).expect("the fixture parses");
            assert!(
                matches!(cfg.wans[0].kind, Some(wan::Kind::Pppoe(_))),
                "the fixture's WAN is PPPoE"
            );
            assert_eq!(found(&cfg), vec![]);
        }
    }

    #[test]
    fn a_tagged_member_is_accepted_and_its_port_may_carry_other_lans() {
        let mut cfg = base(); // lan0 untagged on p1 and p2
        cfg.lans
            .push(lan("guest", &["p1.223", "p2.223"], "192.168.2.1/24"));
        cfg.lans.push(lan("trusted", &["p1.224"], "192.168.3.1/24"));
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn a_tagged_member_is_refused_twice_and_with_a_bad_vlan() {
        let mut cfg = base();
        cfg.lans.push(lan("guest", &["p1.223"], "192.168.2.1/24"));
        cfg.lans.push(lan("more", &["p1.223"], "192.168.4.1/24"));
        cfg.lans.push(lan("bad", &["p2.4095"], "192.168.5.1/24"));
        let codes = codes(&cfg);
        assert!(
            codes.contains(&Code::PortUsedTwice) && codes.contains(&Code::InvalidVlan),
            "{codes:?}"
        );
    }

    #[test]
    fn a_wan_port_may_not_carry_a_lan_and_a_wan_vlan_is_checked() {
        let mut cfg = base(); // wan0 on p0
        cfg.lans.push(lan("side", &["p0.10"], "192.168.6.1/24"));
        cfg.wans[0].vlan = 4095;
        let codes = codes(&cfg);
        assert!(
            codes.contains(&Code::PortRoleConflict) && codes.contains(&Code::InvalidVlan),
            "{codes:?}"
        );
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
            address: String::new(),
        }
    }

    fn with_forwards(forwards: Vec<PortForward>) -> Config {
        let mut cfg = base();
        cfg.firewall = Some(Firewall {
            port_forwards: forwards,
            wan_ping: true,
            rules: Vec::new(),
        });
        cfg
    }

    fn public(prefixes: &[&str]) -> Vec<PublicIpv4> {
        prefixes
            .iter()
            .map(|p| PublicIpv4 {
                prefix: (*p).to_owned(),
            })
            .collect()
    }

    fn rule(name: &str, from: &str, to: &str, proto: &str, ports: &[&str]) -> Rule {
        Rule {
            name: name.into(),
            from: from.into(),
            to: to.into(),
            proto: proto.into(),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn a_public_lan_is_accepted_inside_a_declared_block() {
        let mut cfg = base();
        cfg.public_ipv4 = public(&["192.0.2.232/29", "192.0.2.248/29"]);
        cfg.lans[0].ports = vec!["p1".into()];
        cfg.lans.push(lan("dmz", &["p2"], "192.0.2.233/29"));
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn a_lan_in_global_space_must_be_inside_a_declared_block() {
        let mut cfg = base();
        cfg.lans[0].ipv4 = "192.0.2.233/29".into();
        let violations = validate(&cfg, &live());
        assert_eq!(
            violations[0].code,
            Code::UndeclaredPublicLan,
            "{violations:?}"
        );
        assert!(
            violations[0].message.contains("[[public_ipv4]]"),
            "{}",
            violations[0].message
        );
    }

    #[test]
    fn public_blocks_must_be_global_and_disjoint_from_each_other_and_from_private_lans() {
        let mut cfg = base();
        cfg.public_ipv4 = public(&[
            "10.9.0.0/29",
            "192.0.2.232/29",
            "192.0.2.232/30",
            "192.168.1.0/24",
        ]);
        let codes = codes(&cfg);
        assert_eq!(
            codes
                .iter()
                .filter(|c| **c == Code::InvalidPublicBlock)
                .count(),
            3,
            "{codes:?}"
        );
    }

    #[test]
    fn a_forward_address_comes_from_an_unclaimed_block_and_joins_the_duplicate_key() {
        let mut cfg = with_forwards(vec![
            forward("a", "tcp", 8443, "192.168.1.2", 0),
            forward("b", "tcp", 443, "192.168.1.3", 0),
        ]);
        cfg.public_ipv4 = public(&["192.0.2.248/29"]);
        cfg.firewall.as_mut().unwrap().port_forwards[1].address = "192.0.2.249".into();
        assert_eq!(
            found(&cfg),
            vec![],
            "443 is the router's own port on the WAN address only; a public address may forward it"
        );
        let first = &mut cfg.firewall.as_mut().unwrap().port_forwards[0];
        first.address = "192.0.2.249".into();
        first.port = 443;
        assert!(
            codes(&cfg).contains(&Code::DuplicateForward),
            "the same address, protocol and port twice: {:?}",
            found(&cfg)
        );
        for bad in [
            "192.0.2.248",
            "192.0.2.255",
            "192.168.1.9",
            "203.0.113.77",
            "nope",
        ] {
            cfg.firewall.as_mut().unwrap().port_forwards[0].address = bad.into();
            assert!(
                codes(&cfg).contains(&Code::InvalidForwardAddress),
                "{bad}: {:?}",
                found(&cfg)
            );
        }
    }

    #[test]
    fn reaches_names_wan_none_or_another_lan() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p2".into()];
        cfg.lans.push(lan("guest", &["p1"], "192.168.2.1/24"));
        cfg.lans[0].reaches = vec!["wan".into(), "guest".into()];
        assert_eq!(found(&cfg), vec![]);
        cfg.lans[0].reaches = vec!["none".into()];
        assert_eq!(found(&cfg), vec![]);
        for bad in [
            vec!["lan0"],
            vec!["wan", "wan"],
            vec!["none", "wan"],
            vec!["dmz"],
        ] {
            cfg.lans[0].reaches = bad.iter().map(|s| (*s).to_owned()).collect();
            assert!(codes(&cfg).contains(&Code::InvalidZone), "{bad:?}");
        }
    }

    /// The kernel refuses an interval element that partly overlaps another in the same set, and
    /// which of two overlapping rules it refuses depends on their order; validation refuses the
    /// pair up front. Identical holes merge, and holes in other zones, sets or ports are fine.
    #[test]
    fn overlapping_rules_from_one_zone_are_refused() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p2".into()];
        cfg.lans.push(lan("dmz", &["p1"], "192.0.2.233/29"));
        cfg.public_ipv4 = public(&["192.0.2.232/29"]);
        let web = rule("dmz-web", "wan", "192.0.2.234-192.0.2.238", "tcp", &["80"]);
        let with = |other: Rule| {
            let mut c = cfg.clone();
            c.firewall.get_or_insert_with(Default::default).rules = vec![web.clone(), other];
            c
        };
        for accepted in [
            rule("dup", "wan", "192.0.2.234-192.0.2.238", "tcp", &["80"]),
            rule("other-zone", "lan0", "192.0.2.236", "tcp", &["80"]),
            rule("other-set", "wan", "192.0.2.236", "udp", &["80"]),
            rule("other-port", "wan", "192.0.2.236", "tcp", &["443"]),
        ] {
            let name = accepted.name.clone();
            assert_eq!(found(&with(accepted)), vec![], "{name}");
        }
        for refused in [
            rule("one-host", "wan", "192.0.2.236", "tcp", &["80"]),
            rule(
                "wider-ports",
                "wan",
                "192.0.2.234-192.0.2.238",
                "tcp",
                &["80-443"],
            ),
            rule("subnet", "wan", "192.0.2.232/29", "tcp", &["80"]),
            rule(
                "range2",
                "wan",
                "192.0.2.237-192.0.2.238",
                "tcp",
                &["70-90"],
            ),
        ] {
            let name = refused.name.clone();
            let violations = validate(&with(refused), &live());
            assert_eq!(violations.len(), 1, "{name}: {violations:?}");
            assert_eq!(violations[0].code, Code::OverlappingRules, "{name}");
            assert_eq!(violations[0].path, "firewall.rules[1]", "{name}");
            assert!(
                violations[0].message.contains("dmz-web"),
                "{}",
                violations[0].message
            );
        }
        let mut c = cfg.clone();
        c.firewall.get_or_insert_with(Default::default).rules = vec![
            rule("all-dmz", "lan0", "192.0.2.232/29", "any", &[]),
            rule("one-any", "lan0", "192.0.2.234", "any", &[]),
        ];
        assert!(
            codes(&c).contains(&Code::OverlappingRules),
            "{:?}",
            found(&c)
        );
    }

    /// One LAN listing a port both untagged and tagged would enslave `p2` and `p2.223` to the
    /// same bridge, which floods every frame twice onto the wire; the same shapes across two LANs
    /// are a trunk.
    #[test]
    fn a_port_carried_untagged_and_tagged_by_one_lan_is_refused() {
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p2".into(), "p2.223".into()];
        let violations = validate(&cfg, &live());
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(
            (violations[0].path.as_str(), violations[0].code),
            ("lans[0].ports[1]", Code::PortUsedTwice)
        );
        cfg.lans[0].ports = vec!["p2.223".into(), "p2".into()];
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ports[1]".to_owned(), Code::PortUsedTwice)],
            "the later form is the one flagged"
        );
        cfg.lans[0].ports = vec!["p2".into()];
        cfg.lans.push(lan("guest", &["p2.223"], "192.168.2.1/24"));
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn rules_name_a_zone_a_target_inside_another_lan_a_proto_and_ports() {
        type Case<'a> = (&'a str, &'a str, &'a str, &'a str, &'a [&'a str], Code);
        let mut cfg = base();
        cfg.lans[0].ports = vec!["p2".into()];
        cfg.lans.push(lan("dmz", &["p1"], "192.0.2.233/29"));
        cfg.public_ipv4 = public(&["192.0.2.232/29"]);
        let fw = cfg.firewall.get_or_insert_with(Default::default);
        fw.rules = vec![
            rule(
                "dmz-web",
                "wan",
                "192.0.2.234-192.0.2.238",
                "tcp",
                &["80", "443"],
            ),
            rule("ping-dmz", "lan0", "192.0.2.232/29", "icmp", &[]),
            rule("all-dmz", "lan0", "192.0.2.237", "any", &[]),
        ];
        assert_eq!(found(&cfg), vec![]);
        let cases: [Case<'_>; 7] = [
            (
                "x",
                "wan",
                "192.0.2.234",
                "tcp",
                &[],
                Code::InvalidRulePorts,
            ),
            (
                "y",
                "wan",
                "192.0.2.234",
                "icmp",
                &["80"],
                Code::InvalidRulePorts,
            ),
            ("z", "wan", "192.0.2.234", "gre", &[], Code::InvalidProto),
            (
                "w",
                "dmz",
                "192.0.2.234",
                "tcp",
                &["80"],
                Code::InvalidRuleTarget,
            ),
            (
                "v",
                "wan",
                "203.0.113.5",
                "tcp",
                &["80"],
                Code::InvalidRuleTarget,
            ),
            (
                "u",
                "nowhere",
                "192.0.2.234",
                "tcp",
                &["80"],
                Code::InvalidZone,
            ),
            (
                "dmz-web",
                "wan",
                "192.0.2.234",
                "tcp",
                &["80"],
                Code::DuplicateName,
            ),
        ];
        for (name, from, to, proto, ports, code) in cases {
            let mut c = cfg.clone();
            c.firewall
                .as_mut()
                .unwrap()
                .rules
                .push(rule(name, from, to, proto, ports));
            assert!(codes(&c).contains(&code), "{name}: {:?}", found(&c));
        }
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

    /// The M2 part 1 fixtures (tagged members, a tagged WAN, `reaches`, rules, public blocks, a
    /// forward on a public address) are valid on the four-port lab.
    #[test]
    fn m2_fixtures_are_valid() {
        let mut live4 = live();
        live4.ports.push(PortMapEntry {
            id: "pci-0000:00:06.0".to_owned(),
            name: "p3".to_owned(),
        });
        for fixture in [
            include_str!("../../../harness/fixtures/vm-vlans.toml"),
            include_str!("../../../harness/fixtures/vm-public.toml"),
        ] {
            let config = crate::file::parse(fixture).expect("fixture parses");
            assert_eq!(validate(&config, &live4), vec![]);
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
    fn lan_ntp_entries_must_be_addresses_and_system_ntp_servers_addresses_or_names() {
        assert_eq!(
            codes(&validate(
                &with_dhcp(&format!("{RANGE}ntp = [\"192.168.1.1\", \"time.example\"]")),
                &live()
            )),
            vec![("lans[0].dhcp.ntp[1]".to_owned(), Code::InvalidAddress)]
        );
        let bad = crate::file::parse(
            "config_version = 1\n[system]\nntp_servers = [\"0.pool.ntp.org\", \"203.0.113.1\", \"-bad\"]\n",
        )
        .unwrap();
        assert_eq!(
            codes(&validate(&bad, &live())),
            vec![("system.ntp_servers[2]".to_owned(), Code::InvalidHostname)]
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

    #[test]
    fn duplicate_static_hostnames_are_refused() {
        let bad = format!(
            "{RANGE}[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:10\"\nip = \"192.168.1.10\"\nhostname = \"nas\"\n[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:11\"\nip = \"192.168.1.11\"\nhostname = \"NAS\"\n"
        );
        assert_eq!(
            codes(&validate(&with_dhcp(&bad), &live())),
            vec![(
                "lans[0].dhcp.static[1].hostname".to_owned(),
                Code::DuplicateStatic
            )]
        );
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

    #[test]
    fn local_addresses_are_not_upstreams() {
        for bad in [
            "127.0.0.1",
            "224.0.0.251",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "192.168.1.1",
        ] {
            let config = file::parse(&format!(
                "config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p0\"]\nipv4 = \"192.168.1.1/24\"\n[dns]\nupstreams = [\"{bad}\"]\n"
            ))
            .unwrap();
            assert_eq!(
                codes(&validate(&config, &live())),
                vec![("dns.upstreams[0]".to_owned(), Code::InvalidAddress)],
                "{bad}"
            );
        }
        let fine = file::parse(
            "config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p0\"]\nipv4 = \"192.168.1.1/24\"\n[dns]\nupstreams = [\"192.168.1.53\"]\n",
        )
        .unwrap();
        assert_eq!(
            codes(&validate(&fine, &live())),
            vec![],
            "a resolver on the LAN is fine; the router itself is not"
        );
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;
    use crate::{PortMap, PortMapEntry};

    const VM_IPV6: &str = include_str!("../../../harness/fixtures/vm-ipv6.toml");
    const VM_PD: &str = include_str!("../../../harness/fixtures/vm-pd.toml");

    fn live4() -> PortMap {
        PortMap {
            ports: [
                "pci-0000:00:03.0",
                "pci-0000:00:04.0",
                "pci-0000:00:05.0",
                "pci-0000:00:06.0",
            ]
            .iter()
            .enumerate()
            .map(|(i, id)| PortMapEntry {
                id: (*id).to_owned(),
                name: format!("p{i}"),
            })
            .collect(),
        }
    }

    /// A static IPv4 WAN with `[wans.ipv6]` holding `wan_ipv6`, lan0 on p2 with the `lan0`
    /// lines (its `ipv6` among them) and a `nas` reservation, then `tail`.
    fn config(wan_ipv6: &str, lan0: &str, tail: &str) -> Config {
        crate::file::parse(&config_text(wan_ipv6, lan0, tail)).expect("test config parses")
    }

    /// The TOML behind [`config`], for a test that expects the parser itself to refuse it.
    fn config_text(wan_ipv6: &str, lan0: &str, tail: &str) -> String {
        format!(
            "config_version = 1\n[system]\nhostname = \"openfeo\"\ndomain = \"home.arpa\"\n\
             [[wans]]\nname = \"wan0\"\nport = \"p0\"\n[wans.static]\naddress = \"203.0.113.10/24\"\n\
             gateway = \"203.0.113.1\"\n{wan_ipv6}\n\
             [[lans]]\nname = \"lan0\"\nports = [\"p2\"]\nipv4 = \"192.168.1.1/24\"\n{lan0}\n\
             [lans.dhcp]\nrange = [\"192.168.1.100\", \"192.168.1.200\"]\n\
             [[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:10\"\nip = \"192.168.1.10\"\nhostname = \"nas\"\n\
             {tail}\n"
        )
    }

    const ROUTED: &str = "[wans.ipv6]\nprefix = \"2001:db8:1::/48\"\n";
    const LAN0_V6: &str = "ipv6 = \"2001:db8:1:222::1/64\"\n";

    fn found(cfg: &Config) -> Vec<(String, Code)> {
        validate(cfg, &live4())
            .into_iter()
            .map(|v| (v.path, v.code))
            .collect()
    }

    #[test]
    fn the_pd_fixture_validates() {
        let cfg = crate::file::parse(VM_PD).expect("fixture parses");
        assert_eq!(validate(&cfg, &live4()), vec![]);
        assert_eq!(rules::pd_hint(cfg.wans[0].ipv6.as_ref().unwrap()), 56);
        assert_eq!((cfg.lans[0].ipv6_index, cfg.lans[1].ipv6_index), (1, 2));
    }

    #[test]
    fn the_ipv6_fixture_validates() {
        let cfg = crate::file::parse(VM_IPV6).expect("fixture parses");
        assert_eq!(validate(&cfg, &live4()), vec![]);
    }

    #[test]
    fn a_second_ipv6_wan_is_refused() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[wans]]\nname = \"wan1\"\nport = \"p1\"\npriority = 20\n[wans.static]\n\
             address = \"198.51.100.10/24\"\ngateway = \"198.51.100.1\"\n[wans.ipv6]\n",
        );
        assert!(
            found(&cfg).contains(&("wans[1].ipv6".to_owned(), Code::Ipv6WanTwice)),
            "{:?}",
            found(&cfg)
        );
    }

    #[test]
    fn an_ipv6_prefix_must_be_global_unicast_and_at_most_63_bits() {
        for prefix in [
            "fd00::/48",
            "2001:db8:1::/64",
            "fe80::/48",
            "2001:db8:1::1/48",
        ] {
            let cfg = config(&format!("[wans.ipv6]\nprefix = \"{prefix}\"\n"), "", "");
            assert!(
                found(&cfg).contains(&("wans[0].ipv6.prefix".to_owned(), Code::InvalidIpv6Prefix)),
                "{prefix}: {:?}",
                found(&cfg)
            );
        }
        assert_eq!(
            found(&config("[wans.ipv6]\nprefix = \"2001:db8::/56\"\n", "", "")),
            vec![]
        );
    }

    #[test]
    fn a_typed_gateway_must_be_an_ipv6_address() {
        let cfg = config("[wans.ipv6]\ngateway = \"203.0.113.1\"\n", "", "");
        assert_eq!(
            found(&cfg),
            vec![("wans[0].ipv6.gateway".to_owned(), Code::InvalidAddress)]
        );
        for gateway in ["fe80::1", "2001:db8:ffff::1"] {
            let cfg = config(&format!("[wans.ipv6]\ngateway = \"{gateway}\"\n"), "", "");
            assert_eq!(found(&cfg), vec![], "{gateway}");
        }
    }

    #[test]
    fn mode_disabled_beside_a_prefix_or_a_lan_prefix_is_refused() {
        let cfg = config(
            "[wans.ipv6]\nmode = \"disabled\"\nprefix = \"2001:db8:1::/48\"\n",
            "",
            "",
        );
        assert_eq!(
            found(&cfg),
            vec![("wans[0].ipv6.mode".to_owned(), Code::Ipv6Disabled)]
        );
        let cfg = config("[wans.ipv6]\nmode = \"disabled\"\n", "", "");
        assert_eq!(found(&cfg), vec![], "disabled alone is fine");
        let cfg = config("[wans.ipv6]\nmode = \"sometimes\"\n", "", "");
        assert_eq!(
            found(&cfg),
            vec![("wans[0].ipv6.mode".to_owned(), Code::InvalidIpv6Mode)]
        );
    }

    #[test]
    fn a_lan_prefix_outside_the_routed_prefix_is_refused() {
        let cfg = config(ROUTED, "ipv6 = \"2001:db8:2:222::1/64\"\n", "");
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ipv6".to_owned(), Code::LanPrefixOutsideRouted)]
        );
    }

    #[test]
    fn a_lan_may_not_take_the_prefixs_first_slash_64() {
        let cfg = config(ROUTED, "ipv6 = \"2001:db8:1::1/64\"\n", "");
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ipv6".to_owned(), Code::LanPrefixReserved)]
        );
    }

    #[test]
    fn a_lan_prefix_must_be_a_slash_64_with_a_host_address() {
        for ipv6 in [
            "2001:db8:1:222::1/56",
            "2001:db8:1:222::/64",
            "2001:db8:1:222::1",
            "192.168.1.1/24",
        ] {
            let cfg = config(ROUTED, &format!("ipv6 = \"{ipv6}\"\n"), "");
            assert_eq!(
                found(&cfg),
                vec![("lans[0].ipv6".to_owned(), Code::InvalidCidr)],
                "{ipv6}"
            );
        }
    }

    #[test]
    fn a_lan_prefix_needs_a_routed_prefix() {
        for wan_ipv6 in ["", "[wans.ipv6]\n"] {
            let cfg = config(wan_ipv6, LAN0_V6, "");
            assert_eq!(
                found(&cfg),
                vec![("lans[0].ipv6".to_owned(), Code::LanPrefixWithoutRouted)],
                "{wan_ipv6:?}"
            );
        }
    }

    #[test]
    fn two_lans_may_not_share_a_slash_64() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[lans]]\nname = \"guest\"\nports = [\"p3\"]\nipv4 = \"192.168.2.1/24\"\n\
             ipv6 = \"2001:db8:1:222::2/64\"\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("lans[1].ipv6".to_owned(), Code::Overlap)]
        );
    }

    #[test]
    fn ra_without_any_ipv6_is_refused_and_allowed_once_a_wan_has_ipv6() {
        // No WAN carries IPv6: nothing to advertise, so `ra` describes nothing.
        let cfg = config("", "ra = false\n", "");
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ra".to_owned(), Code::RaWithoutIpv6)]
        );
        // A disabled WAN is no WAN with IPv6 either.
        let cfg = config("[wans.ipv6]\nmode = \"disabled\"\n", "ra = false\n", "");
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ra".to_owned(), Code::RaWithoutIpv6)]
        );
        // Once a WAN has IPv6 every LAN carries at least the ULA /64 (SPEC §7.3), so `ra`
        // applies with or without a routed /64.
        assert_eq!(found(&config(ROUTED, "ra = false\n", "")), vec![]);
        assert_eq!(found(&config("[wans.ipv6]\n", "ra = false\n", "")), vec![]);
        assert_eq!(
            found(&config(
                ROUTED,
                "ipv6 = \"2001:db8:1:222::1/64\"\nra = false\n",
                ""
            )),
            vec![]
        );
    }

    #[test]
    fn pd_hint_outside_48_to_64_is_refused() {
        for bad in ["47", "65", "0x1"] {
            let Ok(cfg) = crate::file::parse(&config_text(
                &format!("[wans.ipv6]\npd_hint = {bad}\n"),
                "",
                "",
            )) else {
                continue; // `0x1` is not TOML's integer; the parser refuses it first
            };
            assert_eq!(
                found(&cfg),
                vec![("wans[0].ipv6.pd_hint".to_owned(), Code::InvalidPdHint)],
                "pd_hint = {bad}"
            );
        }
        for good in ["48", "56", "64"] {
            let cfg = config(&format!("[wans.ipv6]\npd_hint = {good}\n"), "", "");
            assert_eq!(found(&cfg), vec![], "pd_hint = {good}");
        }
    }

    #[test]
    fn ipv6_index_above_65535_is_refused_and_zero_is_absent() {
        let cfg = config("[wans.ipv6]\n", "ipv6_index = 65536\n", "");
        assert_eq!(
            found(&cfg),
            vec![("lans[0].ipv6_index".to_owned(), Code::InvalidIpv6Index)]
        );
        assert_eq!(
            found(&config("[wans.ipv6]\n", "ipv6_index = 0\n", "")),
            vec![]
        );
        assert_eq!(
            found(&config("[wans.ipv6]\n", "ipv6_index = 65535\n", "")),
            vec![]
        );
    }

    #[test]
    fn two_lans_with_one_ipv6_index_are_refused() {
        let cfg = config(
            "[wans.ipv6]\n",
            "ipv6_index = 3\n",
            "[[lans]]\nname = \"lan1\"\nports = [\"p3\"]\nipv4 = \"192.168.2.1/24\"\nipv6_index = 3\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("lans[1].ipv6_index".to_owned(), Code::Ipv6IndexTwice)]
        );
        // An unpinned LAN's index is its position (lan0 is 1): a later LAN pinned to it clashes,
        // and so does a later unpinned LAN whose position an earlier pin took.
        let cfg = config(
            "[wans.ipv6]\n",
            "",
            "[[lans]]\nname = \"lan1\"\nports = [\"p3\"]\nipv4 = \"192.168.2.1/24\"\nipv6_index = 1\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("lans[1].ipv6_index".to_owned(), Code::Ipv6IndexTwice)]
        );
        let cfg = config(
            "[wans.ipv6]\n",
            "ipv6_index = 2\n",
            "[[lans]]\nname = \"lan1\"\nports = [\"p3\"]\nipv4 = \"192.168.2.1/24\"\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("lans[1].ipv6_index".to_owned(), Code::Ipv6IndexTwice)]
        );
        // An IPv4-only LAN takes no index, so it clashes with nobody.
        let cfg = config(
            "[wans.ipv6]\n",
            "ipv6_index = 3\n",
            "[[lans]]\nname = \"lan1\"\nports = [\"p3\"]\nipv4 = \"192.168.2.1/24\"\nipv6 = \"none\"\n",
        );
        assert_eq!(found(&cfg), vec![]);
    }

    #[test]
    fn ipv6_none_refuses_ra_and_an_index() {
        let cfg = config(
            "[wans.ipv6]\n",
            "ipv6 = \"none\"\nra = true\nipv6_index = 2\n",
            "",
        );
        assert_eq!(
            found(&cfg),
            vec![
                ("lans[0].ra".to_owned(), Code::Ipv6None),
                ("lans[0].ipv6_index".to_owned(), Code::Ipv6None),
            ]
        );
        assert_eq!(
            found(&config("[wans.ipv6]\n", "ipv6 = \"none\"\n", "")),
            vec![]
        );
        // `none` is fine without any IPv6 WAN too: it says the same thing the absence says.
        assert_eq!(found(&config("", "ipv6 = \"none\"\n", "")), vec![]);
    }

    #[test]
    fn disabled_mode_refuses_a_gateway_and_a_pd_hint() {
        let cfg = config(
            "[wans.ipv6]\nmode = \"disabled\"\ngateway = \"fe80::1\"\npd_hint = 56\n",
            "",
            "",
        );
        assert_eq!(
            found(&cfg),
            vec![
                ("wans[0].ipv6.gateway".to_owned(), Code::Ipv6Disabled),
                ("wans[0].ipv6.pd_hint".to_owned(), Code::Ipv6Disabled),
            ]
        );
    }

    #[test]
    fn a_rule_may_target_a_ula_address() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[firewall.rules]]\nname = \"ula\"\nfrom = \"wan\"\nto = \"fd12:3456:789a:1::10\"\n\
             proto = \"tcp\"\nports = [\"80\"]\n",
        );
        assert_eq!(found(&cfg), vec![]);
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[firewall.rules]]\nname = \"far\"\nfrom = \"wan\"\nto = \"2001:db8:9::10\"\n\
             proto = \"tcp\"\nports = [\"80\"]\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("firewall.rules[0].to".to_owned(), Code::InvalidRuleTarget)]
        );
    }

    #[test]
    fn records_are_unique_per_name_and_family() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[dns.records]]\nname = \"www\"\naddress = \"2001:db8:1:222::10\"\n\
             [[dns.records]]\nname = \"WWW\"\naddress = \"2001:db8:1:222::11\"\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("dns.records[1]".to_owned(), Code::DuplicateRecord)]
        );
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[dns.records]]\nname = \"www\"\naddress = \"192.168.1.20\"\n\
             [[dns.records]]\nname = \"www\"\naddress = \"2001:db8:1:222::10\"\n",
        );
        assert_eq!(
            found(&cfg),
            vec![],
            "one A and one AAAA for a dual-stack name"
        );
    }

    /// The forwarder answers names in its own domain only: a full name elsewhere would be typed
    /// and never answered.
    #[test]
    fn a_record_name_outside_the_domain_is_refused() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[dns.records]]\nname = \"printer.office.example\"\naddress = \"2001:db8:1:222::10\"\n",
        );
        assert_eq!(
            found(&cfg),
            vec![("dns.records[0]".to_owned(), Code::RecordOutsideDomain)]
        );
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[[dns.records]]\nname = \"printer.home.arpa\"\naddress = \"2001:db8:1:222::10\"\n",
        );
        assert_eq!(found(&cfg), vec![], "a full name under the domain");
    }

    #[test]
    fn a_record_may_not_name_the_router_or_a_reservation() {
        for name in ["openfeo", "openfeo.home.arpa", "nas", "Nas.home.arpa"] {
            let cfg = config(
                ROUTED,
                LAN0_V6,
                &format!("[[dns.records]]\nname = \"{name}\"\naddress = \"2001:db8:1:222::10\"\n"),
            );
            assert_eq!(
                found(&cfg),
                vec![("dns.records[0]".to_owned(), Code::RecordNameTaken)],
                "{name}"
            );
        }
        for (name, address) in [
            ("bad name", "2001:db8:1:222::10"),
            ("www", "ff02::1"),
            ("www", "::"),
        ] {
            let cfg = config(
                ROUTED,
                LAN0_V6,
                &format!("[[dns.records]]\nname = \"{name}\"\naddress = \"{address}\"\n"),
            );
            assert_eq!(found(&cfg).len(), 1, "{name} {address}: {:?}", found(&cfg));
        }
    }

    #[test]
    fn an_ipv6_upstream_is_accepted_and_the_routers_own_lan_address_is_not() {
        let cfg = config(
            ROUTED,
            LAN0_V6,
            "[dns]\nupstreams = [\"2001:db8:ffff::1\"]\n",
        );
        assert_eq!(found(&cfg), vec![]);
        for upstream in ["2001:db8:1:222::1", "::1", "ff02::1", "2001:db8:1::1"] {
            let cfg = config(
                ROUTED,
                LAN0_V6,
                &format!("[dns]\nupstreams = [\"{upstream}\"]\n"),
            );
            assert_eq!(
                found(&cfg),
                vec![("dns.upstreams[0]".to_owned(), Code::InvalidAddress)],
                "{upstream}"
            );
        }
    }

    #[test]
    fn an_ipv6_rule_target_lies_inside_one_lans_slash_64() {
        let rule = |to: &str| {
            config(
                ROUTED,
                LAN0_V6,
                &format!(
                    "[[firewall.rules]]\nname = \"r\"\nfrom = \"wan\"\nto = \"{to}\"\nproto = \"tcp\"\nports = [\"80\"]\n"
                ),
            )
        };
        assert_eq!(
            found(&rule("2001:db8:1:5::10")),
            vec![("firewall.rules[0].to".to_owned(), Code::InvalidRuleTarget)]
        );
        assert_eq!(
            found(&rule("2001:db8:1:222::10-2001:db8:1:222::20")),
            vec![]
        );
        assert_eq!(found(&rule("2001:db8:1:222::/64")), vec![]);
        assert_eq!(
            found(&rule("2001:db8:1:222::20-2001:db8:1:222::10")),
            vec![("firewall.rules[0].to".to_owned(), Code::InvalidRuleTarget)],
            "a backwards range"
        );
    }

    #[test]
    fn ipv6_rules_overlap_within_their_family_only() {
        let rules = |a: &str, b: &str| {
            config(
                ROUTED,
                LAN0_V6,
                &format!(
                    "[[firewall.rules]]\nname = \"a\"\nfrom = \"wan\"\nto = \"{a}\"\nproto = \"tcp\"\nports = [\"80\"]\n\
                     [[firewall.rules]]\nname = \"b\"\nfrom = \"wan\"\nto = \"{b}\"\nproto = \"tcp\"\nports = [\"80\"]\n"
                ),
            )
        };
        assert_eq!(
            found(&rules(
                "2001:db8:1:222::10-2001:db8:1:222::20",
                "2001:db8:1:222::15"
            )),
            vec![("firewall.rules[1]".to_owned(), Code::OverlappingRules)]
        );
        assert_eq!(found(&rules("192.168.1.10", "2001:db8:1:222::10")), vec![]);
    }
}
