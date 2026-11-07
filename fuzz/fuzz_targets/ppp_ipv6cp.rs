// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The option decoder of `Ipv6cp` on arbitrary bytes: decoding never panics, and whatever
//! decodes encodes back to bytes that decode to the same options (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::fsm::Options;
use openfeo_proto_ppp::ipv6cp::Ipv6cp;

fuzz_target!(|data: &[u8]| {
    if let Ok(opts) = Ipv6cp::decode(data) {
        let again = Ipv6cp::decode(&Ipv6cp::encode(&opts));
        assert_eq!(again.ok(), Some(opts));
    }
});
