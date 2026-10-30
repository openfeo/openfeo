// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the configuration file parsers (SPEC §11 lists `config TOML` among the parsers that must
//! have a target): arbitrary bytes must only ever produce `Ok` or a `ConfigError`, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = openfeo_config::file::parse(text);
        let _ = openfeo_config::file::parse_portmap(text);
    }
});
