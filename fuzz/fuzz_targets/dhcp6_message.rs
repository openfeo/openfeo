// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv6 codec on arbitrary bytes: decoding never panics, and whatever decodes encodes
//! back to bytes that decode to the same message (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp6::wire::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        let again = Message::decode(&message.encode());
        assert_eq!(again, Ok(message));
    }
});
