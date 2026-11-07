// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PAP and CHAP packet decoders on arbitrary bytes: decoding never panics, and whatever
//! decodes encodes back to a packet that decodes to the same message (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::frame::Packet;
use openfeo_proto_ppp::{chap, pap};

fuzz_target!(|data: &[u8]| {
    let Some((which, rest)) = data.split_first() else {
        return;
    };
    let Ok(packet) = Packet::decode(rest) else {
        return;
    };
    if which & 1 == 0 {
        if let Ok(message) = pap::Message::decode(&packet) {
            let again = pap::Message::decode(&message.encode(packet.id));
            assert_eq!(again.ok(), Some(message));
        }
    } else if let Ok(message) = chap::Message::decode(&packet) {
        let again = chap::Message::decode(&message.encode(packet.id));
        assert_eq!(again.ok(), Some(message));
    }
});
