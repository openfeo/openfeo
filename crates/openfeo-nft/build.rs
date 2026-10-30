// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Builds jansson, libmnl, libnftnl and nftables statically from the sources `nft/fetch.sh`
//! verified and extracted (ADR-0012), for the host (sandbox tests) and for musl (the binary),
//! and links `libnftables.a` and its dependencies into this crate.
//!
//! Inputs, exported by the Makefile: `OPENFEO_NFT_SRC` (the directory holding
//! `<name>-<version>/` source trees) and `OPENFEO_UAPI_INCLUDE` (the UAPI headers installed from
//! our pinned kernel, so the libraries never see the host's). Each library is configured
//! out-of-tree under `$OUT_DIR/build/<name>` and installed into `$OUT_DIR/prefix`; a library whose
//! archive is already there is skipped, so a rebuild of the Rust code costs nothing.

#![allow(clippy::disallowed_methods)] // build-time only: configure and make of the vendored C libraries

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Name, archive, extra configure flags; in dependency order.
const LIBRARIES: [(&str, &str, &[&str]); 4] = [
    ("jansson", "libjansson.a", &[]),
    ("libmnl", "libmnl.a", &[]),
    ("libnftnl", "libnftnl.a", &[]),
    (
        "nftables",
        "libnftables.a",
        // SPEC §13: --with-json --with-mini-gmp --without-cli --without-xtables.
        &[
            "--with-json",
            "--with-mini-gmp",
            "--without-cli",
            "--without-xtables",
            "--disable-man-doc",
        ],
    ),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../nft/sources.txt");
    println!("cargo:rerun-if-env-changed=OPENFEO_NFT_SRC");
    println!("cargo:rerun-if-env-changed=OPENFEO_UAPI_INCLUDE");

    let sources = required_dir("OPENFEO_NFT_SRC");
    let uapi = required_dir("OPENFEO_UAPI_INCLUDE");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| panic!("OUT_DIR unset")));
    let prefix = out_dir.join("prefix");
    let target = env::var("TARGET").unwrap_or_default();
    let musl = target.contains("musl");
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".to_owned());

    for (name, archive, flags) in LIBRARIES {
        if prefix.join("lib").join(archive).is_file() {
            continue;
        }
        let src = source_tree(&sources, name);
        let build = out_dir.join("build").join(name);
        fs::create_dir_all(&build)
            .unwrap_or_else(|err| panic!("create {}: {err}", build.display()));

        let mut configure = Command::new(src.join("configure"));
        configure
            .current_dir(&build)
            .arg(format!("--prefix={}", prefix.display()))
            .arg("--disable-shared")
            .arg("--enable-static")
            .args(flags)
            .env("CFLAGS", format!("-O2 -fPIC -isystem {}", uapi.display()))
            // nftables finds jansson by a link test (AC_CHECK_LIB), not pkg-config: point the
            // preprocessor and the linker at our prefix so neither build sees a host copy.
            .env(
                "CPPFLAGS",
                format!("-I{}", prefix.join("include").display()),
            )
            .env("LDFLAGS", format!("-L{}", prefix.join("lib").display()))
            .env("PKG_CONFIG_LIBDIR", prefix.join("lib").join("pkgconfig"))
            .env_remove("PKG_CONFIG_PATH")
            .env_remove("PKG_CONFIG_SYSROOT_DIR");
        if musl {
            configure
                .arg("--host=x86_64-linux-musl")
                .env("CC", "musl-gcc");
        } else {
            configure.env("CC", "cc");
        }
        run(configure, &build.join("configure.log"), name, "configure");

        let mut make = Command::new("make");
        make.current_dir(&build)
            .arg(format!("-j{jobs}"))
            .arg("install");
        run(make, &build.join("make.log"), name, "make install");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    for lib in ["nftables", "nftnl", "mnl", "jansson"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
}

fn required_dir(var: &str) -> PathBuf {
    let value = env::var(var).unwrap_or_else(|_| {
        panic!("{var} is not set: run through make (make bin/lint/test), or set it (CLAUDE.md)")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_dir(),
        "{var}={} is not a directory: run `make nft-src kernel-headers`",
        path.display()
    );
    path
}

/// `<sources>/<name>-<version>/`, whatever version `nft/sources.txt` pins.
fn source_tree(sources: &Path, name: &str) -> PathBuf {
    let prefix = format!("{name}-");
    let mut matches: Vec<PathBuf> = fs::read_dir(sources)
        .unwrap_or_else(|err| panic!("read {}: {err}", sources.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|file| file.to_str())
                    .is_some_and(|file| file.starts_with(&prefix))
        })
        .collect();
    matches.sort();
    match matches.as_slice() {
        [one] => one.clone(),
        [] => panic!(
            "no {prefix}* under {}: run `make nft-src`",
            sources.display()
        ),
        many => panic!(
            "several {prefix}* trees under {}: {many:?}",
            sources.display()
        ),
    }
}

/// Runs `command` with its output in `log`; on failure the panic carries the log's tail.
fn run(mut command: Command, log: &Path, name: &str, step: &str) {
    let file =
        fs::File::create(log).unwrap_or_else(|err| panic!("create {}: {err}", log.display()));
    let stderr = file
        .try_clone()
        .unwrap_or_else(|err| panic!("clone {}: {err}", log.display()));
    let status = command
        .stdout(file)
        .stderr(stderr)
        .status()
        .unwrap_or_else(|err| panic!("{name}: {step}: {err}"));
    assert!(
        status.success(),
        "{name}: {step} failed ({status}); log tail:\n{}",
        tail(log)
    );
}

fn tail(log: &Path) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(40);
    lines[start..].join("\n")
}
