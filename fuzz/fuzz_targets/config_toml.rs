// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the configuration file parsers (SPEC §11 lists `config TOML` among the parsers that must
//! have a target): arbitrary bytes must only ever produce `Ok` or a `ConfigError`, never a panic.
//! A file that parses is validated against a four-port box, since the member (`pN.V`), target
//! (`a-b`), port-range and block parsers live in validation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_config::{PortMap, PortMapEntry};

fn ports() -> PortMap {
    PortMap {
        ports: (0..4)
            .map(|i| PortMapEntry {
                id: format!("pci-0000:00:0{}.0", 3 + i),
                name: format!("p{i}"),
            })
            .collect(),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(config) = openfeo_config::file::parse(text) {
            let _ = openfeo_config::validate::validate(&config, &ports());
        }
        let _ = openfeo_config::file::parse_portmap(text);
    }
});
