#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# Fetch, verify and extract the C sources that openfeo-nft's build script compiles (ADR-0012).
# Every tarball named in nft/sources.txt is downloaded once into $BUILD/nft/dl, checked against
# the sha256 pinned there (a mismatch deletes the file and fails), and extracted into
# $BUILD/nft/src/<name>-<version>/ unless that directory already exists. Idempotent.
#
# Usage: nft/fetch.sh            Environment: BUILD (<repo>/build)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${BUILD:-$ROOT/build}
DL=$BUILD/nft/dl
SRC=$BUILD/nft/src
SOURCES=$ROOT/nft/sources.txt

mkdir -p "$DL" "$SRC"

while read -r name version url sha256; do
  case "$name" in ''|'#'*) continue ;; esac
  file=$DL/$(basename "$url")
  if [ ! -f "$file" ]; then
    echo "nft: downloading $url"
    curl -sSfL --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  if ! echo "$sha256  $file" | sha256sum -c --quiet --status; then
    rm -f "$file"
    echo "nft: $(basename "$file"): sha256 mismatch" >&2
    exit 1
  fi
  dir=$SRC/$name-$version
  if [ ! -d "$dir" ]; then
    tar -C "$SRC" -xf "$file"
    [ -d "$dir" ] || { echo "nft: $file did not extract to $dir" >&2; exit 1; }
  fi
  echo "nft: $name-$version ok"
done < "$SOURCES"
