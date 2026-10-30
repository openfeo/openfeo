# 0012 — libnftables and its dependencies are built from pinned sources in the build pipeline

Status: Accepted (30 October 2026)

## Context

ADR-0003 chose libnftables linked in-process, statically, driven through its JSON interface.
Something has to build it, and its three dependencies (libnftnl, libmnl, jansson), for the musl
target the binary is, and for the host so the sandboxed tests can exercise the real library
without QEMU. Distribution packages do not help: Debian's `musl-dev` ships neither the libraries
nor the kernel UAPI headers they need, and the host's static libraries, where they exist, are
built against the host's kernel headers rather than ours.

The project already has one answer to "compile a pinned upstream source tree" in `kernel/`:
a sha256 pinned in the repository, a verified fetch, an out-of-tree build driven by `make`. An
ad-hoc build of downloaded sources outside that pipeline is exactly what a careful reviewer (and
this project's own tooling) refuses, so the nftables build takes the same shape as the kernel's.

## Decision

- `nft/sources.txt` pins nftables 1.1.7, libnftnl 1.3.2, libmnl 1.0.5 and jansson 2.15.1 by URL
  and sha256 (the netfilter sums from the projects' published `.sha256sum` files; jansson's
  recorded on 2026-10-30 and pinned). `nft/fetch.sh` downloads each tarball once into
  `build/nft/dl`, verifies it against that sum and nowhere else, deletes it on a mismatch and
  fails, and extracts it into `build/nft/src/<name>-<version>/`.
- `kernel/build.sh headers` runs `make headers_install` of our pinned kernel into
  `build/kernel/headers`; the libraries compile with `-isystem` on that directory, so they see the
  UAPI of the kernel they will talk to, never the host's.
- `crates/openfeo-nft/build.rs` configures each library out-of-tree under `$OUT_DIR` with
  `--disable-shared --enable-static` (nftables additionally `--with-json --with-mini-gmp
  --without-cli --without-xtables --disable-man-doc`, SPEC §13), `CC=musl-gcc` and
  `--host=x86_64-linux-musl` for the musl target, `cc` for the host, `PKG_CONFIG_LIBDIR` confined
  to its own prefix, and installs into `$OUT_DIR/prefix`; a library whose archive is already there
  is skipped. It links `nftables`, `nftnl`, `mnl` and `jansson` statically. It is the one place
  outside `harness/` and `image/` allowed to spawn processes, at build time only.
- `make bin`, `make lint` and `make test` depend on `kernel-headers` and `nft-src` and export
  `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE` to cargo; CI runs the same targets and caches the
  tarballs by the hash of the two pin files.

## Consequences

- Build dependencies: `musl-gcc`, `pkg-config`, `bison`, `flex` (and `make`, `cc`); `make
  check-env` lists them. A cold build of the four libraries takes well under a minute per target
  on a workstation and is skipped afterwards.
- A bare `cargo build` without the two variables fails with a message pointing at `make`.
- Updating a library is a one-line change to `nft/sources.txt` (the build script finds the tree
  by name prefix); the CI cache key follows.
- The shipped binary is a GPLv2 work because libnftables is GPL-2.0-only (SPEC §14, ADR-0002);
  `docs/third-party.md` lists the four libraries, versions and licences.
- The sandboxed `harness/tests/nft.rs` scenarios run the real library against the host kernel in
  the rootless sandbox's own network namespace.
