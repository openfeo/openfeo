// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The small parsers behind `[[firewall.rules]]` and `[[public_ipv4]]` (SPEC §7.5), shared by
//! validation and the ruleset generator: a rule's target (an address, an `a-b` range or a CIDR),
//! its ports (`"443"` or `"1000-1010"`), its protocol, and what counts as global unicast space.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// The protocols a rule may name.
pub const PROTOS: [&str; 4] = ["tcp", "udp", "icmp", "any"];

/// A rule's destination hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// One address.
    Addr(Ipv4Addr),
    /// An inclusive range, first not above last.
    Range(Ipv4Addr, Ipv4Addr),
    /// A whole prefix.
    Net(Ipv4Net),
}

impl Target {
    /// Whether every address of the target lies inside `net`.
    #[must_use]
    pub fn within(&self, net: Ipv4Net) -> bool {
        let (first, last) = self.bounds();
        net.contains(&first) && net.contains(&last)
    }

    /// The first and last address of the target.
    #[must_use]
    pub fn bounds(&self) -> (Ipv4Addr, Ipv4Addr) {
        match *self {
            Target::Addr(a) => (a, a),
            Target::Range(a, b) => (a, b),
            Target::Net(n) => (n.network(), n.broadcast()),
        }
    }
}

/// `a`, `a-b` (with `a <= b`) or `a/n`; `None` for anything else.
#[must_use]
pub fn parse_target(text: &str) -> Option<Target> {
    if let Some((a, b)) = text.split_once('-') {
        let (a, b) = (a.parse::<Ipv4Addr>().ok()?, b.parse::<Ipv4Addr>().ok()?);
        return (a <= b).then_some(Target::Range(a, b));
    }
    if text.contains('/') {
        return text.parse::<Ipv4Net>().ok().map(Target::Net);
    }
    text.parse::<Ipv4Addr>().ok().map(Target::Addr)
}

/// Every entry a port (`"443"`) or a range (`"1000-1010"`, first not above last), all within
/// 1..=65535; `None` when any entry is wrong or the list is empty.
#[must_use]
pub fn parse_ports(entries: &[String]) -> Option<Vec<(u16, u16)>> {
    if entries.is_empty() {
        return None;
    }
    entries
        .iter()
        .map(|entry| parse_port_range(entry))
        .collect()
}

fn parse_port_range(text: &str) -> Option<(u16, u16)> {
    let (a, b) = if let Some((a, b)) = text.split_once('-') {
        (parse_port(a)?, parse_port(b)?)
    } else {
        let port = parse_port(text)?;
        (port, port)
    };
    (a <= b).then_some((a, b))
}

fn parse_port(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Whether `net` lies entirely in global unicast space: not RFC 1918, not shared (100.64/10),
/// loopback, link-local, multicast, reserved (240/4) or "this network" (0/8).
#[must_use]
pub fn is_global_unicast_v4(net: Ipv4Net) -> bool {
    const NOT_GLOBAL: [(Ipv4Addr, u8); 9] = [
        (Ipv4Addr::UNSPECIFIED, 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ];
    let (first, last) = (net.network(), net.broadcast());
    NOT_GLOBAL.iter().all(|(addr, len)| {
        let reserved = Ipv4Net::new_assert(*addr, *len);
        !reserved.contains(&first)
            && !reserved.contains(&last)
            && !net.contains(&reserved.network())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_ports_parse_in_their_three_shapes() {
        assert!(matches!(parse_target("192.0.2.234"), Some(Target::Addr(_))));
        assert!(matches!(
            parse_target("192.0.2.234-192.0.2.238"),
            Some(Target::Range(_, _))
        ));
        assert!(matches!(
            parse_target("192.0.2.232/29"),
            Some(Target::Net(_))
        ));
        assert!(parse_target("192.0.2.238-192.0.2.234").is_none());
        assert!(parse_target("192.0.2.234-").is_none());
        assert!(parse_target("nope").is_none());
        let block: Ipv4Net = "192.0.2.232/29".parse().unwrap();
        assert!(
            parse_target("192.0.2.234-192.0.2.238")
                .unwrap()
                .within(block)
        );
        assert!(
            !parse_target("192.0.2.234-192.0.2.240")
                .unwrap()
                .within(block)
        );
        assert!(parse_target("192.0.2.232/30").unwrap().within(block));
        assert!(!parse_target("192.0.2.0/24").unwrap().within(block));
        assert_eq!(
            parse_ports(&["80".into(), "1000-1010".into()]),
            Some(vec![(80, 80), (1000, 1010)])
        );
        for bad in [
            vec!["0".to_string()],
            vec!["70000".to_string()],
            vec!["90-80".to_string()],
            vec!["a".to_string()],
            vec![],
        ] {
            assert!(parse_ports(&bad).is_none(), "{bad:?}");
        }
        assert!(is_global_unicast_v4("192.0.2.232/29".parse().unwrap()));
        for private in [
            "10.0.0.0/8",
            "172.16.5.0/24",
            "192.168.1.0/24",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "0.0.0.0/8",
        ] {
            assert!(!is_global_unicast_v4(private.parse().unwrap()), "{private}");
        }
    }
}
