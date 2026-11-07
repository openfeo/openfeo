// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! LCP's option decoder on arbitrary bytes: decoding never panics, and whatever decodes
//! encodes back to bytes that decode to the same options (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::fsm::Options;
use openfeo_proto_ppp::lcp::Lcp;

fuzz_target!(|data: &[u8]| {
    if let Ok(opts) = Lcp::decode(data) {
        let again = Lcp::decode(&Lcp::encode(&opts));
        assert_eq!(again.ok(), Some(opts));
    }
});
