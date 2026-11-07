// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE discovery codec on arbitrary bytes: decoding never panics, and whatever decodes
//! encodes back to bytes that decode to the same packet (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::pppoe::Discovery;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Discovery::decode(data) {
        let again = Discovery::decode(&packet.encode());
        assert_eq!(again, Ok(packet));
    }
});
