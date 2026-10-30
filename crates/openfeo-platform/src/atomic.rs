// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Durable file writes (SPEC §5.2): a temporary file in the same directory, `fsync`, `rename`
//! over the target, then `fsync` of the directory, so a power cut leaves either the old file or
//! the new one and never a torn one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Write `data` to `path` atomically, creating it with permission bits `mode` (`0o600` for
/// everything under `/state`, SPEC §5.2).
///
/// # Errors
///
/// Any I/O failure; the temporary file is removed on failure where possible, and the target is
/// either untouched or complete.
pub fn write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp); // a stale temporary from an interrupted earlier attempt
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_new_file_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write(&path, b"a = 1\n", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"a = 1\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }

    #[test]
    fn replaces_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, "old").unwrap();
        write(&path, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            leftovers.len(),
            1,
            "temporary file left behind: {leftovers:?}"
        );
    }

    #[test]
    fn parent_missing_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write(&dir.path().join("missing/f"), b"x", 0o600).is_err());
    }
}
