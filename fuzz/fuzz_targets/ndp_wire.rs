// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Arbitrary bytes as a router solicitation or advertisement (SPEC §11): decoding must never
//! panic, and what decodes must encode back to bytes that decode to the same value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ndp::wire::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        let again = Message::decode(&message.encode());
        assert_eq!(again, Ok(message), "a decoded message round-trips");
    }
});
