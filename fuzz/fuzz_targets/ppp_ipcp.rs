// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The option decoder of `Ipcp` on arbitrary bytes: decoding never panics, and whatever
//! decodes encodes back to bytes that decode to the same options (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::fsm::Options;
use openfeo_proto_ppp::ipcp::Ipcp;

fuzz_target!(|data: &[u8]| {
    if let Ok(opts) = Ipcp::decode(data) {
        let again = Ipcp::decode(&Ipcp::encode(&opts));
        assert_eq!(again.ok(), Some(opts));
    }
});
