#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# SPEC §13 dependency rules, checked over `cargo tree` (normal dependencies only):
#   - pure crates (`openfeo-reconcile`, `openfeo-world`, `openfeo-proto-*`) carry no tokio, libc,
#     nix, socket2 or netlink crate anywhere in their dependency trees;
#   - only the kernel-facing crates (`openfeo-netlink`, `openfeo-nft`, `openfeo-net`,
#     `openfeo-platform`, `openfeo-init`; plus `openfeo-harness`, which may use anything) depend
#     directly on libc, nix or the netlink crates.
# Crates that do not exist yet are skipped. Exit 1 names every violation.
set -euo pipefail
cd "$(dirname "$0")/.."

PURE_RE='^(openfeo-reconcile|openfeo-world|openfeo-proto-.*)$'
KERNEL_RE='^(openfeo-netlink|openfeo-nft|openfeo-net|openfeo-platform|openfeo-init|openfeo-harness)$'
BANNED_IN_PURE='tokio libc nix socket2 rtnetlink netlink-sys netlink-proto'
KERNEL_ONLY='libc nix rtnetlink netlink-sys netlink-proto netlink-packet-route netlink-packet-core'

member_names() {
    local manifest
    for manifest in crates/*/Cargo.toml harness/Cargo.toml; do
        sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$manifest" | head -n 1
    done
}

# Package names in the tree of $1, at most $2 levels deep (omit for the whole tree), the root included.
tree_names() {
    local crate=$1 depth=${2:-}
    local -a extra=()
    if [[ -n $depth ]]; then
        extra=(--depth "$depth")
    fi
    cargo tree -p "$crate" -e normal --prefix none -f '{p}' "${extra[@]}" | awk '{print $1}' | sort -u
}

rc=0
for crate in $(member_names); do
    if [[ $crate =~ $PURE_RE ]]; then
        names=$(tree_names "$crate")
        for dep in $BANNED_IN_PURE; do
            if grep -qx -- "$dep" <<<"$names"; then
                echo "dependency rule violated: $crate -> $dep (pure crate, SPEC §13)"
                rc=1
            fi
        done
    fi
    if [[ ! $crate =~ $KERNEL_RE ]]; then
        names=$(tree_names "$crate" 1)
        for dep in $KERNEL_ONLY; do
            if grep -qx -- "$dep" <<<"$names"; then
                echo "dependency rule violated: $crate -> $dep (only kernel-facing crates may, SPEC §13)"
                rc=1
            fi
        done
    fi
done
if [[ $rc -eq 0 ]]; then
    echo "dependency rules: ok"
fi
exit "$rc"
