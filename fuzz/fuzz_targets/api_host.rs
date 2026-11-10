// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the host and origin checks (SPEC §9, §11): arbitrary text as a `Host` header or an
//! `Origin` never panics, and is never allowed unless it names the router or one of the
//! addresses it holds.

#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use openfeo_api::gate::{Names, host_allowed, https_authority, origin_allowed};
use openfeo_config::{Config, PortMap};
use openfeo_world::{AddrFact, World};

fn world() -> World {
    let mut world = World::new(Config::default(), PortMap::default());
    world.addresses = Arc::new(
        ["192.168.1.1/24", "2001:db8:1:1::1/64"]
            .into_iter()
            .map(|net| AddrFact {
                ifname: "br-lan0".to_owned(),
                net: net.parse().expect("a CIDR"),
                peer: None,
                deprecated: false,
            })
            .collect(),
    );
    world
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (world, names) = (world(), Names::of(None));
    let lower = text.to_ascii_lowercase();
    let could_be_ours = lower.contains("openfeo") || lower.contains("192.168.1.1") || lower.contains("2001:db8:1:1:");
    if host_allowed(text, &names, &world) {
        assert!(could_be_ours, "{text:?} is not the router");
        assert!(https_authority(text).is_some(), "an allowed host has somewhere to be sent");
    }
    if origin_allowed(Some(text), &names, &world) {
        assert!(lower.starts_with("https://") && could_be_ours, "{text:?} is not the router's origin");
    }
});
