#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# The notices of the Rust crates in the binary (SPEC §13), for /licences.txt: `cargo about`,
# at the one version the build is written for, against the lockfile and offline, so that
# nothing but the crates as they were published decides what a licence text is. What it accepts
# and looks at is about.toml; what it writes is about.hbs's shape.
#
#   scripts/rust-notices.sh <cargo-about-version> <out-file> [features]
#
# `make panel` runs it. The out-file is left untouched when nothing in it changed.
set -euo pipefail

want=${1:?usage: rust-notices.sh <cargo-about-version> <out-file> [features]}
out=${2:?usage: rust-notices.sh <cargo-about-version> <out-file> [features]}
features=${3:-}

have=$(cargo about --version 2>/dev/null | awk '{print $2}') || true
if [ "${have:-}" != "$want" ]; then
  echo "rust-notices: cargo-about $want writes the notices in /licences.txt, and ${have:-none} is installed:" >&2
  echo "  cargo install cargo-about --locked --version $want" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# Fetched as the build itself fetches them; from here on nothing is asked of the network.
cargo fetch --locked --target x86_64-unknown-linux-musl
mkdir -p "$(dirname "$out")"
cargo about generate --frozen -m crates/openfeo/Cargo.toml ${features:+--features "$features"} \
  -o "$out.new" about.hbs
if [ ! -s "$out.new" ]; then
  echo "rust-notices: cargo about wrote nothing" >&2
  exit 1
fi
if cmp -s "$out.new" "$out"; then
  rm "$out.new"
else
  mv "$out.new" "$out"
fi
