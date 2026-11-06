// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router's ULA /48 under `/state/identity/` (SPEC §5.2, §7.3), generated once from the
//! kernel's random pool and kept beside the DUID (`dhcp4.rs`) and the IPv6 stable-privacy
//! secret (`ipv6.rs`): identity a backup restores and a reinstall regenerates.

use std::fs;
use std::io;
use std::net::Ipv6Addr;
use std::path::Path;

use ipnet::Ipv6Net;
use openfeo_config::load::STATE_FILE_MODE;
use openfeo_platform::atomic;
use tracing::warn;

use crate::ipv6::random_secret;

/// The box's ULA /48 as text, `fdxx:xxxx:xxxx::/48` (SPEC §5.2 `identity/`).
pub const ULA_PATH: &str = "/state/identity/ula";

/// The ULA at `path`, or a fresh one written there (mode 0600): `fd00::/8` with 40 random bits
/// (RFC 4193 §3.2.1); `true` when it was just made. A file that is not a ULA /48 is replaced
/// with a warning.
///
/// # Errors
///
/// When the file cannot be read for a reason other than its absence, cannot be written, or
/// `/dev/urandom` cannot be read.
pub fn load_or_create_ula(path: &Path) -> io::Result<(Ipv6Net, bool)> {
    match fs::read_to_string(path) {
        Ok(text) => {
            if let Some(ula) = parse_ula(text.trim()) {
                return Ok((ula, false));
            }
            warn!("identity: {}: not a ULA /48; replacing it", path.display());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let random = random_secret()?;
    let ula = Ipv6Net::new_assert(
        Ipv6Addr::new(
            0xfd00 | u16::from(random[0]),
            u16::from_be_bytes([random[1], random[2]]),
            u16::from_be_bytes([random[3], random[4]]),
            0,
            0,
            0,
            0,
            0,
        ),
        48,
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic::write(path, format!("{ula}\n").as_bytes(), STATE_FILE_MODE)?;
    Ok((ula, true))
}

/// A ULA /48 under `fd00::/8` with no host bits, or `None`.
fn parse_ula(text: &str) -> Option<Ipv6Net> {
    let net: Ipv6Net = text.parse().ok()?;
    (net.prefix_len() == 48 && net.addr() == net.network() && net.addr().segments()[0] >> 8 == 0xfd)
        .then_some(net)
}

/// `identity: ula fd12:3456:789a::/48 (created)` or `(loaded)`.
#[must_use]
pub fn ula_line(ula: Ipv6Net, created: bool) -> String {
    format!(
        "identity: ula {ula} ({})",
        if created { "created" } else { "loaded" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_new_ula_is_fd00_8_with_48_bits_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity").join("ula");
        let (ula, created) = load_or_create_ula(&path).unwrap();
        assert!(created);
        assert_eq!(ula.prefix_len(), 48);
        assert_eq!(ula.addr().segments()[0] >> 8, 0xfd);
        assert_eq!(ula.addr(), ula.network(), "no host bits");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("{ula}\n"),
            "the file is the prefix as text"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            STATE_FILE_MODE
        );
        let (again, created) = load_or_create_ula(&path).unwrap();
        assert!(!created);
        assert_eq!(again, ula);
        let (other, _) = load_or_create_ula(&dir.path().join("other")).unwrap();
        assert_ne!(other, ula, "forty random bits");
    }

    #[test]
    fn a_corrupt_ula_file_is_replaced_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ula");
        for bad in [
            "not a prefix\n",
            "2001:db8::/48\n",
            "fd12:3456:789a::/56\n",
            "fd12:3456:789a::1/48\n",
        ] {
            fs::write(&path, bad).unwrap();
            let (ula, created) = load_or_create_ula(&path).unwrap();
            assert!(created, "{bad:?} is replaced");
            assert_eq!(ula.prefix_len(), 48);
        }
    }

    #[test]
    fn ula_line_follows_the_contract() {
        let ula: Ipv6Net = "fd12:3456:789a::/48".parse().unwrap();
        assert_eq!(
            ula_line(ula, true),
            "identity: ula fd12:3456:789a::/48 (created)"
        );
        assert_eq!(
            ula_line(ula, false),
            "identity: ula fd12:3456:789a::/48 (loaded)"
        );
    }
}
