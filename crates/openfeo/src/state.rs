// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! State files written off the runtime's threads: `atomic::write` syncs and renames, which on
//! flash can take long enough to stall every task sharing the worker, so the write runs on a
//! blocking thread and the task awaits it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use openfeo_config::load::STATE_FILE_MODE;
use openfeo_platform::atomic;

/// Write `text` to `path` atomically with [`STATE_FILE_MODE`], creating the parent directory,
/// on a blocking thread.
///
/// # Errors
///
/// When the directory cannot be made or the file cannot be written, or the writer thread
/// panicked.
pub async fn write(path: &Path, text: String) -> io::Result<()> {
    let path: PathBuf = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic::write(&path, text.as_bytes(), STATE_FILE_MODE)
    })
    .await
    .map_err(|err| io::Error::other(format!("state file writer: {err}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[tokio::test]
    async fn writes_the_file_with_its_directory_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases").join("dhcp4-wan0.toml");
        write(&path, "wan = \"wan0\"\n".to_owned()).await.unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "wan = \"wan0\"\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            STATE_FILE_MODE
        );
    }
}
