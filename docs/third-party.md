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

Not in the binary: [dhcproto](https://github.com/bluecatengineering/dhcproto) (MIT) is a
dev-dependency of `openfeo-proto-dhcp4` and a dependency of the fuzz crate, where it serves as
the second opinion our own DHCPv4 codec is checked against. It reaches no shipped artefact.
Likewise [hickory-proto](https://github.com/hickory-dns/hickory-dns) (MIT or Apache-2.0) is a
dev-dependency of `openfeo-proto-dns` and a dependency of the fuzz crate, the oracle for our DNS
codec (ADR-0015), and reaches no shipped artefact either.
