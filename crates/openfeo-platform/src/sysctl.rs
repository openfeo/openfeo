// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Read and write kernel parameters under `/proc/sys`. Keys are paths relative to it with `/`
//! separators (`net/ipv4/ip_forward`), the form the reconciler emits.

use std::io;
use std::path::{Path, PathBuf};

/// Where the kernel exposes its parameters.
pub const ROOT: &str = "/proc/sys";

/// The current value of `key`, trimmed.
///
/// # Errors
///
/// The underlying read error (`ENOENT` for a key or interface that does not exist).
pub fn read(key: &str) -> io::Result<String> {
    read_at(Path::new(ROOT), key)
}

/// Set `key` to `value`.
///
/// # Errors
///
/// The underlying write error (`ENOENT` for a key or interface that does not exist, `EACCES`
/// without the capability).
pub fn write(key: &str, value: &str) -> io::Result<()> {
    write_at(Path::new(ROOT), key, value)
}

/// [`read`] under another root (tests).
///
/// # Errors
///
/// As [`read`].
pub fn read_at(root: &Path, key: &str) -> io::Result<String> {
    let text = std::fs::read_to_string(path(root, key))?;
    Ok(text.trim().to_owned())
}

/// [`write`] under another root (tests).
///
/// # Errors
///
/// As [`write`].
pub fn write_at(root: &Path, key: &str, value: &str) -> io::Result<()> {
    std::fs::write(path(root, key), format!("{value}\n"))
}

fn path(root: &Path, key: &str) -> PathBuf {
    root.join(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_trims_and_write_appends_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net/ipv4")).unwrap();
        write_at(dir.path(), "net/ipv4/ip_forward", "1").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("net/ipv4/ip_forward")).unwrap(),
            "1\n"
        );
        assert_eq!(read_at(dir.path(), "net/ipv4/ip_forward").unwrap(), "1");
        assert_eq!(
            read_at(dir.path(), "net/ipv4/conf/nosuchif/send_redirects")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
