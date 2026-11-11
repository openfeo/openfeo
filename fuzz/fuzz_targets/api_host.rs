// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the host and origin checks (SPEC §9, §11): arbitrary text as a `Host` header or an
//! `Origin` never panics, and is never allowed unless it names the router or one of the
//! addresses it holds, or the one extra host a harness build was told.

#![no_main]

use std::net::IpAddr;
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

/// Whether an authority without its port names the router: one of its two names, or (in any
/// spelling) one of the addresses it holds.
fn is_router(authority: &str, names: &Names, world: &World) -> bool {
    let bare = authority.trim_start_matches('[').trim_end_matches(']');
    let name = bare.strip_suffix('.').unwrap_or(bare).to_ascii_lowercase();
    name == names.hostname
        || name == names.fqdn
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|ip| world.addresses.iter().any(|addr| addr.net.addr() == ip))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (world, names) = (world(), Names::of(None));
    if host_allowed(text, &names, &world) {
        let authority = https_authority(text).expect("an allowed host has somewhere to be sent");
        assert!(is_router(&authority, &names, &world), "{text:?} is not the router");
    }
    if origin_allowed(Some(text), &names, &world) {
        let authority = text.strip_prefix("https://").expect("an allowed origin is https");
        assert!(host_allowed(authority, &names, &world), "{text:?} is not the router's origin");
        assert!(!authority.contains('/'), "an origin has no path");
    }
    // A harness build may be told one more host (the lab's relay). Given the input's first
    // line as that host, it lets through that host and nothing else that was refused before.
    if let Some((extra, rest)) = text.split_once('\n') {
        let with_extra = Names::of(None).with_extra(Some(extra));
        if host_allowed(rest, &with_extra, &world) && !host_allowed(rest, &names, &world) {
            let authority =
                https_authority(rest).expect("an allowed host has somewhere to be sent");
            // The host as the gate reads it: an address literal loses its one pair of brackets.
            let bare = authority
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(&authority);
            let name = bare.strip_suffix('.').unwrap_or(bare).to_ascii_lowercase();
            assert_eq!(
                Some(name.as_str()),
                with_extra.extra.as_deref(),
                "{rest:?} is neither the router nor its extra host"
            );
        }
    }
});
