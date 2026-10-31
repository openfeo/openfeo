// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the DNS wire format (SPEC §11): arbitrary bytes only ever produce `Ok` or an error,
//! never a panic; whatever decodes re-decodes identically from our own encoding, and a reply
//! with one question always fits 512 bytes once truncated.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dns::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        let again = Message::decode(&message.encode()).expect("our own encoding decodes");
        assert_eq!(again, message);
        let within = message.encode_within(512);
        assert!(
            Message::decode(&within).is_ok(),
            "a truncated encoding decodes"
        );
        if message.questions.len() <= 1 {
            assert!(
                within.len() <= 512,
                "{} bytes after truncation",
                within.len()
            );
        }
    }
});
