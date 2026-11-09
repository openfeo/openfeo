// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The stateless DHCPv6 responder on arbitrary bytes: it never panics, and whatever it
//! answers is a Reply that decodes (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp6::server::{Config, INFORMATION_REFRESH_TIME, reply};
use openfeo_proto_dhcp6::wire::{Message, MessageType};

fuzz_target!(|data: &[u8]| {
    let config = Config {
        duid: vec![0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 2],
        dns: vec!["fd12:3456:789a:1::1".parse().unwrap()],
        domains: vec!["home.arpa".to_owned()],
        refresh_secs: INFORMATION_REFRESH_TIME,
    };
    if let Some(answer) = reply(&config, "fe80::1".parse().unwrap(), data) {
        let answer = Message::decode(&answer).expect("the responder encodes what decodes");
        assert_eq!(answer.kind, MessageType::Reply);
    }
});
