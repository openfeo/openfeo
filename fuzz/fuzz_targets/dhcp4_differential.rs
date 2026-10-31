// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Our DHCPv4 decoder against dhcproto's: when both accept an input they must agree on the
//! header fields and on the set of option codes. The oracle only sees inputs our decoder typed
//! completely (no [`DhcpOption::Unknown`]): dhcproto 0.15 panics on malformed payloads of
//! several codes (`debug_assert!`s on option lengths, live under cargo-fuzz's debug assertions,
//! and an `unwrap()` on a classless-route prefix over 32), and those are exactly the inputs the
//! two decoders are allowed to treat differently. When the oracle then rejects an input nothing
//! is asserted either. dhcproto does not read options overloaded into `sname` and `file`
//! (option 52), so the option codes are compared only when no overload is present.

#![no_main]

use dhcproto::v4::Opcode;
use dhcproto::{Decodable, Decoder};
use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp4::wire::{DhcpOption, FLAG_BROADCAST, Message, Op};

fuzz_target!(|data: &[u8]| {
    let Ok(ours) = Message::decode(data) else {
        return;
    };
    if ours
        .options
        .iter()
        .any(|option| matches!(option, DhcpOption::Unknown { .. }))
    {
        return;
    }
    let Ok(theirs) = dhcproto::v4::Message::decode(&mut Decoder::new(data)) else {
        return;
    };
    let our_op = match ours.op {
        Op::BootRequest => 1,
        Op::BootReply => 2,
    };
    let their_op = match theirs.opcode() {
        Opcode::BootRequest => 1,
        Opcode::BootReply => 2,
        Opcode::Unknown(other) => other,
    };
    assert_eq!(our_op, their_op);
    assert_eq!(ours.xid, theirs.xid());
    assert_eq!(ours.secs, theirs.secs());
    assert_eq!(ours.flags & FLAG_BROADCAST != 0, theirs.flags().broadcast());
    assert_eq!(ours.ciaddr, theirs.ciaddr());
    assert_eq!(ours.yiaddr, theirs.yiaddr());
    assert_eq!(ours.siaddr, theirs.siaddr());
    assert_eq!(ours.giaddr, theirs.giaddr());
    assert_eq!(ours.hlen, theirs.hlen());
    // dhcproto's `chaddr()` slices by `hlen` and panics past 16; compare only sane lengths.
    if ours.hlen <= 16 {
        let their_chaddr = theirs.chaddr();
        assert_eq!(&ours.chaddr[..their_chaddr.len().min(16)], their_chaddr);
    }

    let overloaded = ours
        .options
        .iter()
        .any(|option| matches!(option, DhcpOption::OptionOverload(_)));
    if overloaded {
        return;
    }
    let mut our_codes: Vec<u8> = ours.options.iter().map(DhcpOption::code).collect();
    our_codes.sort_unstable();
    our_codes.dedup();
    let mut their_codes: Vec<u8> = theirs
        .opts()
        .iter()
        .map(|(code, _)| -> u8 { (*code).into() })
        .collect();
    their_codes.sort_unstable();
    their_codes.dedup();
    // dhcproto stops at the first option it cannot type and keeps what it had (an empty first
    // occurrence that RFC 3396 joining completes, for one), so its list may be a prefix of
    // ours. What it did type, we must have typed too.
    for code in &their_codes {
        assert!(
            our_codes.contains(code),
            "dhcproto decoded option {code} that we did not: ours {our_codes:?}, theirs {their_codes:?}"
        );
    }
});
