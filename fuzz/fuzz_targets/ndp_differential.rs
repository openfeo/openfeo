// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Our NDP decoder against smoltcp's (ADR-0018): a solicitation or advertisement smoltcp parses
//! and we refuse is a finding about ours; when both parse an advertisement, the header fields
//! and the RFC 4861 options smoltcp keeps (one source link-layer address, one MTU, one prefix
//! information) must agree. A packet we parse and smoltcp refuses is tolerated, and the RFC
//! 8106 and RFC 4191 options are ours alone. A non-zero ICMP code is the one refusal we make
//! that smoltcp does not: RFC 4861 §6.1.1 and §6.1.2 say to discard such a message, and smoltcp
//! never looks at the code, so those inputs are skipped rather than compared.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ndp::wire::{Message, NdOption};
use smoltcp::wire::{Icmpv6Packet, NdiscRepr};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 && data[1] != 0 {
        return;
    }
    let Ok(packet) = Icmpv6Packet::new_checked(data) else {
        return;
    };
    let theirs = NdiscRepr::parse(&packet);
    let ours = Message::decode(data);
    match (ours, theirs) {
        (Err(err), Ok(NdiscRepr::RouterSolicit { .. } | NdiscRepr::RouterAdvert { .. })) => {
            panic!("smoltcp decodes what we refuse: {err}")
        }
        (
            Ok(Message::RouterAdvertisement(ra)),
            Ok(NdiscRepr::RouterAdvert {
                hop_limit,
                flags,
                router_lifetime,
                reachable_time,
                retrans_time,
                lladdr,
                mtu,
                prefix_info,
            }),
        ) => {
            assert_eq!(ra.cur_hop_limit, hop_limit);
            assert_eq!(
                ra.managed,
                flags.contains(smoltcp::wire::NdiscRouterFlags::MANAGED)
            );
            assert_eq!(
                ra.other,
                flags.contains(smoltcp::wire::NdiscRouterFlags::OTHER)
            );
            assert_eq!(u64::from(ra.router_lifetime), router_lifetime.secs());
            assert_eq!(u64::from(ra.reachable_time), reachable_time.total_millis());
            assert_eq!(u64::from(ra.retrans_timer), retrans_time.total_millis());
            // smoltcp keeps the last option of each kind it understands (each one overwrites
            // the field) and reads a link-layer address, an MTU or a prefix out of an option
            // whose length is not the Ethernet one; we keep every option and leave an ill-sized
            // one as bytes. So the last of ours of that kind is compared only when it is the
            // typed variant; an `Unknown` of that kind in last place ends the comparison.
            let last_of_kind = |kind: u8| {
                ra.options.iter().rev().find(|o| match o {
                    NdOption::SourceLinkLayer(_) => kind == 1,
                    NdOption::PrefixInformation { .. } => kind == 3,
                    NdOption::Mtu(_) => kind == 5,
                    NdOption::Unknown { kind: k, .. } => *k == kind,
                    _ => false,
                })
            };
            if let (Some(theirs), Some(NdOption::SourceLinkLayer(ours))) = (lladdr, last_of_kind(1))
            {
                assert_eq!(theirs.as_bytes(), &ours[..]);
            }
            if let (Some(theirs), Some(NdOption::Mtu(ours))) = (mtu, last_of_kind(5)) {
                assert_eq!(theirs, *ours);
            }
            if let (
                Some(theirs),
                Some(NdOption::PrefixInformation {
                    prefix,
                    valid,
                    preferred,
                    ..
                }),
            ) = (prefix_info, last_of_kind(3))
            {
                assert_eq!(theirs.prefix_len, prefix.prefix_len());
                assert_eq!(theirs.valid_lifetime.secs(), u64::from(*valid));
                assert_eq!(theirs.preferred_lifetime.secs(), u64::from(*preferred));
            }
        }
        _ => {}
    }
});
