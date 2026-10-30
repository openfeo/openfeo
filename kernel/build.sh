#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
#
# Fetch, configure, check and build the OpenFeO x86_64 kernel with the binary embedded as its
# initramfs (SPEC §4.2). The config is allnoconfig plus kernel/required.config and
# kernel/x86_64.config; every option they ask for must survive Kconfig's dependency solving or
# the build stops and names the missing ones.
#
# Usage: kernel/build.sh fetch | headers | config <binary> | check | build | all <binary>
# Environment: KERNEL_VERSION (6.18.59), BUILD (<repo>/build), JOBS (nproc), SOURCE_DATE_EPOCH
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL_VERSION=${KERNEL_VERSION:-6.18.59}
BUILD=${BUILD:-$ROOT/build}
SRC=$BUILD/kernel/linux-$KERNEL_VERSION
OUT=$BUILD/kernel/out
TARBALL=$BUILD/kernel/linux-$KERNEL_VERSION.tar.xz
URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz
FRAGMENTS=("$ROOT/kernel/required.config" "$ROOT/kernel/x86_64.config")
JOBS=${JOBS:-$(nproc)}

fetch() {
  mkdir -p "$BUILD/kernel"
  if [ ! -f "$TARBALL" ]; then
    echo "kernel: downloading $URL"
    curl -fL --retry 3 --no-progress-meter -o "$TARBALL.part" "$URL"
    mv "$TARBALL.part" "$TARBALL"
  fi
  (cd "$BUILD/kernel" && sha256sum -c "$ROOT/kernel/linux-$KERNEL_VERSION.sha256")
  if [ ! -f "$SRC/Makefile" ]; then
    echo "kernel: extracting $TARBALL"
    tar -C "$BUILD/kernel" -xf "$TARBALL"
  fi
}

# Write the initramfs description (SPEC §4.2: /init plus empty mount points, nothing else) and
# the machine-local fragment, merge everything over allnoconfig, then check.
config() {
  local bin=${1:?usage: build.sh config <binary>}
  [ -f "$bin" ] || { echo "kernel: binary not found: $bin (run make bin)" >&2; exit 1; }
  bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")
  mkdir -p "$OUT"
  cat > "$OUT/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /run 0755 0 0
dir /state 0700 0 0
dir /boot 0755 0 0
dir /tmp 1777 0 0
file /init $bin 0755 0 0
EOF
  printf 'CONFIG_INITRAMFS_SOURCE="%s"\n' "$OUT/initramfs.list" > "$OUT/local.config"
  (cd "$SRC" && ARCH=x86_64 scripts/kconfig/merge_config.sh -n -O "$OUT" "${FRAGMENTS[@]}" "$OUT/local.config")
  check
}

# Every line of the fragments must hold in the final .config.
check() {
  local cfg=$OUT/.config missing=0 line sym
  [ -f "$cfg" ] || { echo "kernel: $cfg missing; run config first" >&2; exit 1; }
  for frag in "${FRAGMENTS[@]}"; do
    while IFS= read -r line; do
      case "$line" in
        CONFIG_*=*)
          if ! grep -qxF -- "$line" "$cfg"; then
            echo "kernel config: $line requested but not in final .config (check its dependencies)"
            missing=1
          fi ;;
        "# CONFIG_"*" is not set")
          sym=${line#\# }; sym=${sym% is not set}
          if grep -qE -- "^$sym=[ym]" "$cfg"; then
            echo "kernel config: $line requested but the final .config enables it"
            missing=1
          fi ;;
      esac
    done < "$frag"
  done
  if [ "$missing" != 0 ]; then
    exit 1
  fi
  echo "kernel config: every requested option is present"
}

# Install the UAPI headers of our pinned kernel (not the host's) for the C libraries that
# openfeo-nft builds (ADR-0012).
headers() {
  [ -f "$SRC/Makefile" ] || { echo "kernel: source not found at $SRC (run fetch first)" >&2; exit 1; }
  make -C "$SRC" O="$OUT" ARCH=x86_64 INSTALL_HDR_PATH="$BUILD/kernel/headers" -j"$JOBS" headers_install >/dev/null
  echo "kernel: UAPI headers in $BUILD/kernel/headers/include"
}

build() {
  local epoch
  epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}
  make -C "$SRC" O="$OUT" ARCH=x86_64 CC="ccache gcc" HOSTCC="ccache gcc" \
    KBUILD_BUILD_USER=openfeo KBUILD_BUILD_HOST=openfeo \
    KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$epoch")" -j"$JOBS" bzImage
  cp "$OUT/arch/x86/boot/bzImage" "$BUILD/bzImage"
  echo "kernel: $BUILD/bzImage ($(stat -c %s "$BUILD/bzImage") bytes)"
}

case "${1:-}" in
  fetch) fetch ;;
  headers) headers ;;
  config) config "${2:-}" ;;
  check) check ;;
  build) build ;;
  all) fetch; config "${2:-}"; build ;;
  *) echo "usage: kernel/build.sh fetch | headers | config <binary> | check | build | all <binary>" >&2; exit 2 ;;
esac
