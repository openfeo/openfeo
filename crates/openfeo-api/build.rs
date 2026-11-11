// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Generate the gRPC service code for `proto/openfeo/v1/api.proto` (SPEC §8.1, §8.3). The
//! messages are `openfeo-config`'s: the whole `openfeo.v1` package is mapped onto that crate, so
//! only the service traits (and, with the `client` feature, the client stubs) are emitted here.
//! Compiled with `protox`, as `openfeo-config` does, so no `protoc` is needed.

use std::path::PathBuf;

include!("build/assets.rs");

/// Embed the panel `make panel` built (ADR-0025): `OPENFEO_PANEL_DIST` names its directory,
/// and without it the table is empty and the listener serves a placeholder page, so a plain
/// `cargo build` needs no Node. Each file's bytes go into `OUT_DIR` and `panel_assets.rs`
/// lists them for `src/assets.rs` to include.
fn embed_panel() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=OPENFEO_PANEL_DIST");
    println!("cargo:rerun-if-changed=build/assets.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let mut table = String::from("&[\n");
    if let Some(dist) = std::env::var_os("OPENFEO_PANEL_DIST").filter(|dist| !dist.is_empty()) {
        let dist = PathBuf::from(dist);
        println!("cargo:rerun-if-changed={}", dist.display());
        let built = build_table(&dist)
            .map_err(|why| format!("OPENFEO_PANEL_DIST={}: {why}", dist.display()))?;
        for (n, file) in built.iter().enumerate() {
            let bytes = out.join(format!("panel-{n}.bin"));
            std::fs::write(&bytes, &file.body)?;
            // As a string literal for include_bytes!, quoted and escaped.
            let bytes = bytes.to_string_lossy();
            writeln!(
                table,
                "    Asset {{ path: {:?}, content_type: {:?}, gzip: {}, etag: {:?}, body: include_bytes!({:?}) }},",
                file.path, file.content_type, file.gzip, file.etag, bytes
            )?;
        }
    }
    table.push_str("]\n");
    std::fs::write(out.join("panel_assets.rs"), table)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    embed_panel()?;
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
