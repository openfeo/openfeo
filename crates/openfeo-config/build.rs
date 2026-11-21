// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Compile `proto/openfeo/v1/*.proto` with protox (a pure-Rust compiler, so no `protoc` is
//! needed), then generate the prost types and their pbjson serde impls. pbjson keeps the proto
//! field names on serialisation so the TOML on disk reads as SPEC §8.2 shows it.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    println!("cargo:rerun-if-changed={}", proto_root.display());
    let out = PathBuf::from(std::env::var("OUT_DIR")?);

    let fds = protox::compile(
        [
            "openfeo/v1/config.proto",
            "openfeo/v1/state.proto",
            "openfeo/v1/events.proto",
            "openfeo/v1/api.proto",
        ],
        [proto_root],
    )?;
    let bytes = prost::Message::encode_to_vec(&fds);
    std::fs::write(out.join("descriptors.bin"), &bytes)?;

    // The messages that carry a secret get no derived `Debug`: theirs is written by hand in
    // `src/secrets.rs`, so that a password, a token or a hash is never printed, by them or by
    // any message that holds them. A test there holds this list to the proto files.
    prost_build::Config::new()
        .out_dir(&out)
        .skip_debug([
            ".openfeo.v1.Admin",
            ".openfeo.v1.PppoeWan",
            ".openfeo.v1.Auth",
            ".openfeo.v1.Session",
            ".openfeo.v1.LoginRequest",
            ".openfeo.v1.SetInitialPasswordRequest",
            ".openfeo.v1.ChangePasswordRequest",
        ])
        .compile_fds(fds)?;
    pbjson_build::Builder::new()
        .register_descriptors(&bytes)?
        .preserve_proto_field_names()
        .out_dir(&out)
        .build(&[".openfeo.v1"])?;
    Ok(())
}
