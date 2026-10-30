#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# SPEC §8.1: `buf lint` always, `buf breaking` against origin/main whenever main already carries
# the schema (so field numbers are never reused or retyped).
set -euo pipefail
cd "$(dirname "$0")/.."

buf lint proto
if git cat-file -e origin/main:proto/buf.yaml 2>/dev/null; then
    buf breaking proto --against '.git#ref=origin/main,subdir=proto'
    echo "buf: lint and breaking ok"
else
    echo "buf: lint ok; breaking skipped (no schema on origin/main yet)"
fi
