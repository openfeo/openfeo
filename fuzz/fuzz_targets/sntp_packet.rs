// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the SNTP packet codec (SPEC §11): arbitrary bytes only ever produce `Ok` or an error,
//! never a panic, and whatever decodes re-encodes to its first 48 bytes exactly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_sntp::Packet;
use openfeo_proto_sntp::packet::PACKET_LEN;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Packet::decode(data) {
        assert_eq!(&packet.encode()[..], &data[..PACKET_LEN]);
        let again = Packet::decode(&packet.encode()).expect("our own encoding decodes");
        assert_eq!(again, packet);
    }
});
