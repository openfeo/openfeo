// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Our DHCPv6 decoder against dhcproto's: when both accept an input they must agree on the
//! message type, the transaction id and the set of top-level option codes. As for DHCPv4, the
//! oracle only sees inputs our decoder typed completely (no [`Dhcp6Option::Unknown`] at any
//! level), since dhcproto 0.15's debug assertions on malformed option bodies are live under
//! cargo-fuzz and those inputs are exactly where the two decoders may differ. When the oracle
//! rejects an input nothing is asserted.

#![no_main]

use dhcproto::v6::OptionCode;
use dhcproto::{Decodable, Decoder};
use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp6::wire::{Dhcp6Option, Message};

fn has_unknown(options: &[Dhcp6Option]) -> bool {
    options.iter().any(|option| match option {
        Dhcp6Option::Unknown { .. } => true,
        Dhcp6Option::IaNa { options, .. }
        | Dhcp6Option::IaAddr { options, .. }
        | Dhcp6Option::IaPd { options, .. }
        | Dhcp6Option::IaPrefix { options, .. } => has_unknown(options),
        _ => false,
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(ours) = Message::decode(data) else {
        return;
    };
    if has_unknown(&ours.options) {
        return;
    }
    let Ok(theirs) = dhcproto::v6::Message::decode(&mut Decoder::new(data)) else {
        return;
    };
    assert_eq!(u8::from(ours.kind), u8::from(theirs.msg_type()));
    assert_eq!(ours.xid, theirs.xid_num());
    let mut our_codes: Vec<u16> = ours.options.iter().map(Dhcp6Option::code).collect();
    let mut their_codes: Vec<u16> = theirs
        .opts()
        .iter()
        .map(|option| u16::from(OptionCode::from(option)))
        .collect();
    our_codes.sort_unstable();
    their_codes.sort_unstable();
    assert_eq!(our_codes, their_codes);
});
