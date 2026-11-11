// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Generate the gRPC service code for `proto/openfeo/v1/api.proto` (SPEC §8.1, §8.3). The
//! messages are `openfeo-config`'s: the whole `openfeo.v1` package is mapped onto that crate, so
//! only the service traits (and, with the `client` feature, the client stubs) are emitted here.
//! Compiled with `protox`, as `openfeo-config` does, so no `protoc` is needed.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    println!("cargo:rerun-if-changed={}", proto_root.display());
    let fds = protox::compile(["openfeo/v1/api.proto"], [proto_root])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(std::env::var_os("CARGO_FEATURE_CLIENT").is_some())
        .build_transport(false)
        .extern_path(".openfeo.v1", "::openfeo_config::pb")
        .compile_fds(fds)?;
    Ok(())
}
