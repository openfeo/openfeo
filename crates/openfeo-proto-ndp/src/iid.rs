// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! RFC 7217 stable interface identifiers: the same prefix, interface and secret always give the
//! same address, a different prefix a different one, and nobody can derive the hardware address
//! from it. The reserved identifiers of RFC 5453 are skipped by bumping the DAD counter.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

use crate::sha256;

/// The address RFC 7217 §5 gives for `prefix` on `ifname` with `secret`: the first 64 bits of
/// `SHA-256(prefix || ifname || counter || secret)` as the interface identifier, with
/// `dad_counter` bumped past any identifier RFC 5453 reserves. Only the prefix's first 64 bits
/// count; the caller passes a /64.
#[must_use]
pub fn stable_address(
    prefix: Ipv6Net,
    ifname: &str,
    secret: &[u8; 16],
    dad_counter: u8,
) -> Ipv6Addr {
    let iid = first_unreserved(|counter| {
        identifier(prefix, ifname, secret, counter.wrapping_add(dad_counter))
    });
    let net = u128::from(prefix.network()) & !((1u128 << 64) - 1);
    Ipv6Addr::from(net | u128::from(iid))
}

/// The raw RFC 7217 function for one counter value.
fn identifier(prefix: Ipv6Net, ifname: &str, secret: &[u8; 16], counter: u8) -> u64 {
    let mut input = Vec::with_capacity(16 + ifname.len() + 1 + 16);
    input.extend_from_slice(&prefix.network().octets()[..8]);
    input.extend_from_slice(ifname.as_bytes());
    input.push(counter);
    input.extend_from_slice(secret);
    let hash = sha256::digest(&input);
    u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// The first identifier `f` yields, for counters from 0 upwards, that RFC 5453 does not
/// reserve; the last one tried if all 256 are (which no secret produces in practice).
fn first_unreserved(mut f: impl FnMut(u8) -> u64) -> u64 {
    let mut iid = f(0);
    let mut counter: u8 = 0;
    while is_reserved(iid) && counter < u8::MAX {
        counter += 1;
        iid = f(counter);
    }
    iid
}

/// RFC 5453: the subnet-router anycast identifier, the IANA ethernet block
/// (`0200:5EFF:FE00:0000` to `0200:5EFF:FEFF:FFFF`, proxy mobile IPv6 included) and the subnet
/// anycast identifiers (`FDFF:FFFF:FFFF:FF80` to `FDFF:FFFF:FFFF:FFFF`).
#[must_use]
pub fn is_reserved(iid: u64) -> bool {
    iid == 0
        || (0x0200_5EFF_FE00_0000..=0x0200_5EFF_FEFF_FFFF).contains(&iid)
        || (0xFDFF_FFFF_FFFF_FF80..=0xFDFF_FFFF_FFFF_FFFF).contains(&iid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;

    const SECRET: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn prefix(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    #[test]
    fn the_address_is_stable_for_the_same_inputs_and_differs_per_prefix_ifname_secret_and_counter()
    {
        let base = stable_address(prefix("2001:db8:ffff::/64"), "p0", &SECRET, 0);
        assert_eq!(
            base,
            stable_address(prefix("2001:db8:ffff::/64"), "p0", &SECRET, 0)
        );
        assert_ne!(
            base,
            stable_address(prefix("2001:db8:fffe::/64"), "p0", &SECRET, 0)
        );
        assert_ne!(
            base,
            stable_address(prefix("2001:db8:ffff::/64"), "p1", &SECRET, 0)
        );
        assert_ne!(
            base,
            stable_address(prefix("2001:db8:ffff::/64"), "p0", &[7; 16], 0)
        );
        assert_ne!(
            base,
            stable_address(prefix("2001:db8:ffff::/64"), "p0", &SECRET, 1)
        );
    }

    #[test]
    fn the_address_lies_in_the_prefix() {
        let net = prefix("2001:db8:ffff::/64");
        let addr = stable_address(net, "p0", &SECRET, 0);
        assert!(net.contains(&addr), "{addr}");
        assert_ne!(addr, net.network(), "never the subnet-router anycast");
    }

    #[test]
    fn reserved_identifiers_are_skipped_by_bumping_the_counter() {
        assert!(is_reserved(0));
        assert!(is_reserved(0x0200_5EFF_FE00_0000));
        assert!(is_reserved(0x0200_5EFF_FE00_5213));
        assert!(is_reserved(0x0200_5EFF_FEFF_FFFF));
        assert!(is_reserved(0xFDFF_FFFF_FFFF_FF80));
        assert!(is_reserved(0xFDFF_FFFF_FFFF_FFFF));
        assert!(!is_reserved(1));
        assert!(!is_reserved(0x0200_5EFF_FD00_0000));
        assert!(!is_reserved(0xFDFF_FFFF_FFFF_FF7F));
        // A generator whose first two identifiers are reserved: the third is taken.
        let picked = first_unreserved(|counter| match counter {
            0 => 0,
            1 => 0xFDFF_FFFF_FFFF_FFFF,
            n => 0x1000 + u64::from(n),
        });
        assert_eq!(picked, 0x1002);
    }
}
