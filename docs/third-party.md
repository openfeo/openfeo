# Third-party code linked into the OpenFeO binary

OpenFeO's own code is GPL-2.0-or-later (`LICENSE`). The binary additionally links the C libraries
below, built statically from the sources pinned in `nft/sources.txt` (ADR-0012). Because
libnftables is GPL-2.0-only, the combined binary is distributed under GPL-2.0 (SPEC §14,
ADR-0002). Rust crate licences are checked by `cargo deny` (`deny.toml`).

| Library | Version | Licence | Source |
|---|---|---|---|
| nftables (libnftables) | 1.1.7 | GPL-2.0-only | https://www.netfilter.org/projects/nftables/ |
| libnftnl | 1.3.2 | GPL-2.0-only | https://www.netfilter.org/projects/libnftnl/ |
| libmnl | 1.0.5 | LGPL-2.1-or-later | https://www.netfilter.org/projects/libmnl/ |
| jansson | 2.15.1 | MIT | https://github.com/akheron/jansson |

mini-gmp, used by nftables for its arbitrary-precision arithmetic (`--with-mini-gmp`), ships
inside the nftables tarball under the LGPL-3.0-or-later / GPL-2.0-or-later dual licence of GMP;
OpenFeO uses it under GPL-2.0-or-later, so the GPLv2 combination stands.

Since M4 the binary also carries [ring](https://github.com/briansmith/ring) 0.17 (Apache-2.0
AND ISC), the cryptography under rustls for the API's HTTPS listener: a Rust crate whose
primitives are C and assembly derived from BoringSSL, built by its own build script and checked
by `cargo deny` like every other crate. No OpenSSL and no aws-lc is linked; `deny.toml` bans
both.

Since M4 part 1b the binary also carries the web panel: JavaScript, a stylesheet, two fonts and
five logo files, embedded when the image is built (ADR-0025). The page is built from
[Vue](https://vuejs.org) and [Vue Router](https://router.vuejs.org) (MIT),
[@bufbuild/protobuf](https://github.com/bufbuild/protobuf-es) (Apache-2.0 AND BSD-3-Clause) and a
handful of [Lucide](https://lucide.dev) icons (ISC). The fonts are
[Instrument Sans](https://github.com/Instrument/instrument-sans) and
[JetBrains Mono](https://github.com/JetBrains/JetBrainsMono), both SIL OFL 1.1, accepted for font
files only (SPEC §14). `web/scripts/check-licences.mjs`, part of `make lint`, holds every npm
package that can reach the page to the list `cargo deny` applies; the panel's build writes each
one's licence text and the fonts' into one file, which the router serves at `/licences.txt` without
a login. That file names more packages than the page contains (a package's build-time helpers are
counted with it), which errs on the side of saying too much. @bufbuild/protobuf is published
without its licence file; its text is kept in `web/scripts/licence-texts/`.

Not in the binary: [dhcproto](https://github.com/bluecatengineering/dhcproto) (MIT) is a
dev-dependency of `openfeo-proto-dhcp4` and a dependency of the fuzz crate, where it serves as
the second opinion our own DHCPv4 codec is checked against. It reaches no shipped artefact.
Likewise [hickory-proto](https://github.com/hickory-dns/hickory-dns) (MIT or Apache-2.0) is a
dev-dependency of `openfeo-proto-dns` and a dependency of the fuzz crate, the oracle for our DNS
codec (ADR-0015), and reaches no shipped artefact either. And
[smoltcp](https://github.com/smoltcp-rs/smoltcp) (0BSD) is a dev-dependency of
`openfeo-proto-ndp` and a dependency of the fuzz crate, the oracle for the neighbour-discovery
codec's header and RFC 4861 options (ADR-0018); it reaches no shipped artefact.
