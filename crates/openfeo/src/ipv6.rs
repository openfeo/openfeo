// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The IPv6 side of a WAN (SPEC §7.3): the stable-privacy secret the box keeps for life under
//! `/state/identity` (SPEC §5.2), from which the kernel derives the WAN ports' link-local
//! addresses and the client its RFC 7217 addresses.

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use openfeo_config::load::STATE_FILE_MODE;
use openfeo_platform::atomic;
use openfeo_proto_dhcp4::identity::{from_hex, hex};
use tracing::warn;

/// The box's IPv6 stable-privacy secret as 32 lowercase hex digits (SPEC §5.2 `identity/`).
pub const IPV6_SECRET_PATH: &str = "/state/identity/ipv6-secret";

/// The secret at `path`, or a fresh random one written there (mode 0600); `true` when it was
/// just made. A file that is not 32 hex digits is replaced with a warning.
///
/// # Errors
///
/// When the file cannot be read for a reason other than its absence, cannot be written, or
/// `/dev/urandom` cannot be read.
pub fn load_or_create_ipv6_secret(path: &Path) -> io::Result<([u8; 16], bool)> {
    match fs::read_to_string(path) {
        Ok(text) => {
            if let Some(secret) = from_hex(text.trim())
                && let Ok(secret) = <[u8; 16]>::try_from(secret)
            {
                return Ok((secret, false));
            }
            warn!("identity: {}: not a secret; replacing it", path.display());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let secret = random_secret()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic::write(
        path,
        format!("{}\n", hex(&secret)).as_bytes(),
        STATE_FILE_MODE,
    )?;
    Ok((secret, true))
}

/// Sixteen bytes from the kernel's random pool.
///
/// # Errors
///
/// When `/dev/urandom` cannot be opened or read in full.
pub fn random_secret() -> io::Result<[u8; 16]> {
    let mut secret = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_missing_secret_is_made_persisted_and_read_back_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity").join("ipv6-secret");
        let (secret, new) = load_or_create_ipv6_secret(&path).unwrap();
        assert!(new);
        assert_ne!(secret, [0; 16], "sixteen random bytes, not zeros");
        let (again, new) = load_or_create_ipv6_secret(&path).unwrap();
        assert!(!new);
        assert_eq!(again, secret);
    }

    #[test]
    fn a_corrupt_secret_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipv6-secret");
        let (first, _) = load_or_create_ipv6_secret(&path).unwrap();
        for junk in ["not hex at all\n", "abcd\n", ""] {
            fs::write(&path, junk).unwrap();
            let (replaced, new) = load_or_create_ipv6_secret(&path).unwrap();
            assert!(new, "{junk:?} is replaced");
            assert_ne!(replaced, first);
        }
    }

    #[test]
    fn the_secret_file_is_mode_0600_and_32_hex_digits_plus_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipv6-secret");
        let (secret, _) = load_or_create_ipv6_secret(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("{}\n", hex(&secret)));
        assert_eq!(text.trim().len(), 32);
        assert!(text.trim().bytes().all(|b| b.is_ascii_hexdigit()));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
