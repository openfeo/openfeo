// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Port references in the configuration (SPEC §7.1): `pN` names a port untagged, `pN.V` a tagged
//! VLAN `V` (1..=4094) on it. The tagged form is also the kernel's name for the 802.1Q
//! sub-interface the router creates (ADR-0017).

/// The lowest 802.1Q VLAN id a member may carry (0 is the priority tag, never a VLAN).
pub const MIN_VLAN: u16 = 1;
/// The highest 802.1Q VLAN id (4095 is reserved).
pub const MAX_VLAN: u16 = 4094;

/// A parsed member: the physical port and, when tagged, the VLAN id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRef<'a> {
    /// The physical port, `pN`.
    pub port: &'a str,
    /// The VLAN id when the member is tagged.
    pub vlan: Option<u16>,
}

/// Parse `pN` or `pN.V`; `None` for anything else, including a VLAN id outside 1..=4094.
#[must_use]
pub fn parse_port_ref(text: &str) -> Option<PortRef<'_>> {
    let (port, vlan) = match text.split_once('.') {
        None => (text, None),
        Some((port, vid)) => (port, Some(parse_vlan(vid)?)),
    };
    is_port_name(port).then_some(PortRef { port, vlan })
}

/// `p` followed by one or more digits: the names the port map hands out.
#[must_use]
pub fn is_port_name(text: &str) -> bool {
    text.strip_prefix('p')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// A VLAN id written as plain digits and within 1..=4094.
#[must_use]
pub fn parse_vlan(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u16>()
        .ok()
        .filter(|vlan| (MIN_VLAN..=MAX_VLAN).contains(vlan))
}

/// The kernel name of the 802.1Q sub-interface for `vlan` on `port`: `p1.101`.
#[must_use]
pub fn vlan_ifname(port: &str, vlan: u16) -> String {
    format!("{port}.{vlan}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_refs_parse_untagged_and_tagged_names() {
        assert_eq!(
            parse_port_ref("p1").map(|r| (r.port, r.vlan)),
            Some(("p1", None))
        );
        assert_eq!(
            parse_port_ref("p12.4094").map(|r| (r.port, r.vlan)),
            Some(("p12", Some(4094)))
        );
        for bad in [
            "p1.", "p1.0", "p1.4095", "p1.1.2", "p1a", "br-lan0", ".5", "p1.01x", "", "p1.+1",
        ] {
            assert!(parse_port_ref(bad).is_none(), "{bad}");
        }
        assert_eq!(vlan_ifname("p1", 101), "p1.101");
    }
}
