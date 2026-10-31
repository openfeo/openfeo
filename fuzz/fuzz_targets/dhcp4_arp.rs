// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the ARP codec (SPEC §11): arbitrary bytes only ever produce `Ok` or an error, and
//! whatever decodes re-decodes identically from our own encoding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp4::arp::ArpPacket;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = ArpPacket::decode(data) {
        assert_eq!(ArpPacket::decode(&packet.encode()), Ok(packet));
    }
});
