#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# Prepares an ephemeral Ubuntu 24.04 sandbox, such as a Claude Code on the web cloud environment,
# to build OpenFeO and run as much of the harness as the sandbox's kernel allows. It mirrors what
# .github/workflows/ci.yml does to a runner: packages, the Rust toolchain, buf and cargo-deny, the
# pinned sources and UAPI headers (ADR-0012), and the kernel knobs the rootless harness wants
# (ADR-0006) where the sandbox permits them. What the sandbox refuses is reported, not fatal:
# without /dev/kvm QEMU runs under TCG (about 1.2x the wall time), without the nft and 802.1Q
# modules those scenarios skip with a reason. `make check-env` in the session gives the full table.
#
# Cloud-environment rules this script is shaped by: it runs as root before the session starts,
# environment variables are not set yet, and the filesystem is snapshotted for later sessions
# only when it finishes within about five minutes, so the slow steps (the kernel, compiling
# anything) stay out of it. Build products go to $BUILD (default /opt/openfeo/build), outside the
# repository clone, so the snapshot keeps them; set the same BUILD in the environment's variables
# and every `make` in the session finds them (the Makefile honours BUILD from the environment).
#
# The cloud clones the repository after this script has run, so in a cloud environment no checkout
# is found and the session's first `make` fetches the sources (about a minute); the knob below
# fetches them here instead, from a throwaway clone, so the snapshot keeps them.
#
# Usage: scripts/cloud-setup.sh [REPO]   (REPO defaults to the enclosing checkout, then a search)
#   BUILD=/opt/openfeo/build   where sources, headers and the kernel go
#   OPENFEO_CLOUD_SOURCES=1    without a checkout, fetch the sources from a throwaway clone of main
#   OPENFEO_CLOUD_FETCH=1      also warm the crate registry (cargo fetch)
#   OPENFEO_CLOUD_KERNEL=1     also build the kernel (`make kernel`): minutes, breaks the snapshot budget
set -euo pipefail

log() { printf '\n==> %s\n' "$*"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO=sudo
  else
    echo "cloud-setup: not root and no password-less sudo; cannot install packages" >&2
    exit 1
  fi
fi

# The checkout: the argument, the enclosing repository, or a shallow search of the usual roots.
REPO="${1:-}"
if [ -z "$REPO" ]; then
  REPO=$(git rev-parse --show-toplevel 2>/dev/null || true)
fi
if [ -z "$REPO" ] || [ ! -f "$REPO/kernel/build.sh" ]; then
  REPO=$(find /root /home /workspace /workspaces /work /src /mnt -maxdepth 4 -type f -path '*/kernel/build.sh' \
    2>/dev/null | head -n 1 | xargs -r dirname | xargs -r dirname || true)
fi
export BUILD="${BUILD:-/opt/openfeo/build}"

log "packages (the two CI jobs' lists, without recommends to stay inside the snapshot budget)"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git xz-utils kmod procps rsync \
  musl-tools pkg-config bison flex bc libelf-dev libssl-dev ccache zstd cpio e2fsprogs \
  qemu-system-x86 kea-dhcp4-server busybox-static dnsmasq-base bind9-dnsutils ntpsec-ntpdate \
  iproute2 iputils-ping python3

log "Rust toolchain (rust-toolchain.toml: stable, musl target, clippy, rustfmt)"
if ! command -v rustup >/dev/null 2>&1; then
  # No rustup on the image: install one system-wide and front it with wrappers in /usr/local/bin,
  # so any user and any shell, login or not, gets this toolchain ahead of whatever the image has.
  export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
  curl -fsSL https://sh.rustup.rs | $SUDO env RUSTUP_HOME=$RUSTUP_HOME CARGO_HOME=$CARGO_HOME \
    sh -s -- -y --profile minimal --no-modify-path
  for tool in rustup cargo rustc cargo-clippy clippy-driver cargo-fmt rustfmt; do
    printf '#!/bin/sh\nexport RUSTUP_HOME=%s CARGO_HOME="${CARGO_HOME:-%s}"\nexec %s/bin/%s "$@"\n' \
      "$RUSTUP_HOME" "$CARGO_HOME" "$CARGO_HOME" "$tool" | $SUDO tee "/usr/local/bin/$tool" >/dev/null
    $SUDO chmod 0755 "/usr/local/bin/$tool"
  done
fi
rustup toolchain install stable --profile minimal
rustup target add --toolchain stable x86_64-unknown-linux-musl
rustup component add --toolchain stable clippy rustfmt

log "cargo-deny and buf (make lint)"
if ! cargo deny --version >/dev/null 2>&1; then
  # The release tag, from the redirect GitHub answers for /releases/latest; the prebuilt musl
  # tarball when that works, a source build otherwise.
  tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    https://github.com/EmbarkStudios/cargo-deny/releases/latest | sed 's#.*/tag/##')
  if [ -z "$tag" ] || ! curl -fsSL \
    "https://github.com/EmbarkStudios/cargo-deny/releases/download/$tag/cargo-deny-$tag-x86_64-unknown-linux-musl.tar.gz" \
    | $SUDO tar -xz -C /usr/local/bin --strip-components=1 --wildcards '*/cargo-deny'; then
    cargo install cargo-deny --locked
  fi
fi
if ! command -v buf >/dev/null 2>&1; then
  curl -fsSL https://github.com/bufbuild/buf/releases/latest/download/buf-Linux-x86_64 -o /tmp/buf
  $SUDO install -m 0755 /tmp/buf /usr/local/bin/buf
  rm -f /tmp/buf
fi

log "superpowers plugin (the project enables it in .claude/settings.json; the VM must hold a copy)"
# A cloud session reads the project's enabledPlugins but installs nothing itself (probed
# 2026-11-01: the session had no superpowers skills), so install the plugin here, as the session's
# user. Tolerated failure: the facts below say whether it is present.
if command -v claude >/dev/null 2>&1; then
  timeout 180 claude plugin install superpowers@claude-plugins-official --json </dev/null 2>&1 | tail -n 1 || true
else
  echo "claude: not on PATH here; the session must install the plugin itself"
fi

log "kernel knobs the harness wants (each may fail: the facts below and check-env report it)"
# Ubuntu confines unprivileged user namespaces behind AppArmor; the harness needs them (ADR-0006).
$SUDO sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
$SUDO sysctl -q -w kernel.unprivileged_userns_clone=1 2>/dev/null || true
# Ubuntu's kea profile pins its config to /etc/kea; the lab writes its own (ADR-0006).
$SUDO apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp4 2>/dev/null || true
# Autoload from a user namespace is not guaranteed; load what the sandboxed scenarios use.
for m in nf_conntrack nft_ct nft_fib_inet nft_nat nft_masq nft_chain_nat nft_limit 8021q; do
  $SUDO modprobe "$m" 2>/dev/null || true
done
if [ -e /dev/kvm ]; then
  $SUDO chmod 0666 /dev/kvm 2>/dev/null || true
fi
if [ ! -e /dev/net/tun ]; then
  # A sandbox whose kernel has TUN but whose /dev lacks the node.
  { $SUDO mkdir -p /dev/net && $SUDO mknod /dev/net/tun c 10 200; } 2>/dev/null || true
fi
$SUDO chmod 0666 /dev/net/tun 2>/dev/null || true

$SUDO mkdir -p "$BUILD" && $SUDO chown "$(id -u):$(id -g)" "$BUILD"
fetch_sources() {
  log "pinned sources and UAPI headers into $BUILD (from $PWD)"
  make kernel-src kernel-headers nft-src
}
if [ -n "$REPO" ]; then
  cd "$REPO"
  git fetch -q origin main 2>/dev/null || true # buf breaking compares against it
  fetch_sources
  if [ "${OPENFEO_CLOUD_FETCH:-0}" = 1 ]; then
    cargo fetch --locked
    cargo fetch --locked --manifest-path fuzz/Cargo.toml || true
  fi
  if [ "${OPENFEO_CLOUD_KERNEL:-0}" = 1 ]; then
    log "kernel (OPENFEO_CLOUD_KERNEL=1)"
    make kernel
  fi
elif [ "${OPENFEO_CLOUD_SOURCES:-0}" = 1 ]; then
  scratch=$(mktemp -d)
  git clone -q --depth 1 https://github.com/openfeo/openfeo "$scratch/openfeo"
  (cd "$scratch/openfeo" && fetch_sources)
  rm -rf "$scratch"
else
  log "no checkout (the cloud clones the repository after this script): packages and toolchain only"
fi

log 'sandbox facts (make check-env in the session says more)'
echo "kernel: $(uname -r); cpus: $(nproc); user: $(id -un) ($(id -u))"
virt=$(grep -c -E 'vmx|svm' /proc/cpuinfo 2>/dev/null || true)
echo "cpus reporting vmx/svm: ${virt:-0}"
for dev in /dev/kvm /dev/net/tun; do
  if [ -e "$dev" ]; then echo "$dev: $(stat -c '%A %U:%G' "$dev")"; else echo "$dev: absent"; fi
done
if unshare -Urn true 2>/dev/null; then echo "unprivileged user+net namespaces: ok"; else echo "unprivileged user+net namespaces: REFUSED"; fi
loaded=""
for m in nf_conntrack nft_ct nft_fib_inet nft_nat nft_limit 8021q; do
  if grep -q "^$m " /proc/modules 2>/dev/null; then loaded="$loaded$m "; fi
done
echo "modules loaded: ${loaded:-none (built in, or unavailable: check-env tells which)}"
version_of() {
  case "$1" in
    cargo-deny) cargo deny --version 2>&1 ;; # a cargo subcommand: found wherever cargo looks
    kea-dhcp4) kea-dhcp4 -v 2>&1 ;;
    *) "$1" --version 2>&1 ;;
  esac | head -n 1
}
for tool in rustc cargo cargo-deny buf qemu-system-x86_64 kea-dhcp4 dnsmasq; do
  if version=$(version_of "$tool") && [ -n "$version" ]; then
    echo "$tool: $version"
  else
    echo "$tool: MISSING"
  fi
done
if command -v claude >/dev/null 2>&1; then
  plugins=$(timeout 60 claude plugin list </dev/null 2>&1 | grep -i 'superpowers' | head -n 1 || true)
  echo "superpowers plugin: ${plugins:-not installed (the session will lack the process skills)}"
fi
echo "BUILD=$BUILD (set the same BUILD in the environment's variables so every make reuses it)"
echo "setup took ${SECONDS}s (under about 300 s the filesystem is snapshotted for later sessions)"
