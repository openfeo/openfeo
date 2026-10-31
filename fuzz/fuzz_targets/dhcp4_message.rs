// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the DHCPv4 wire format and the IPv4/UDP decapsulation (SPEC §11): arbitrary bytes only
//! ever produce `Ok` or an error, never a panic, and whatever decodes re-decodes from our own
//! encoding with the same transaction id, hardware address and option codes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp4::udp;
use openfeo_proto_dhcp4::wire::Message;

fn codes(message: &Message) -> Vec<u8> {
    message.options.iter().map(|option| option.code()).collect()
}

fuzz_target!(|data: &[u8]| {
    let _ = udp::decapsulate(data);
    if let Ok(message) = Message::decode(data) {
        let again = Message::decode(&message.encode()).expect("our own encoding decodes");
        assert_eq!(again.xid, message.xid);
        assert_eq!(again.chaddr, message.chaddr);
        assert_eq!(codes(&again), codes(&message));
    }
});
