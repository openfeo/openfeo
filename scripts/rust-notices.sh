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
# Every crate in the lockfile is fetched, not only this target's: `cargo about` reads the
# whole of it before it leaves out what the binary does not link, and a machine that has built
# nothing yet (CI's image job, a fresh clone) has none of them. From here on nothing is asked
# of the network.
cargo fetch --locked
mkdir -p "$(dirname "$out")"
# --fail: a crate whose licence cannot be read is a build that stops, not a notice left out.
cargo about generate --frozen --fail -m crates/openfeo/Cargo.toml ${features:+--features "$features"} \
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
