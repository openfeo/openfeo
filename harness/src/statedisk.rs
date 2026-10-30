// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `/state` for the VM as an ext4 image labelled `openfeo-state` (ADR-0010), built without root:
//! `mkfs.ext4 -d <dir>` populates the filesystem from a staging directory, and QEMU attaches the
//! image as a virtio-blk drive that PID 1 mounts in `vm` mode.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

/// The filesystem label (SPEC §5.2).
pub const LABEL: &str = "openfeo-state";
/// Image size; sparse, so it costs nothing until written.
pub const SIZE_MIB: u64 = 64;

/// Build `image` holding `files` (`(relative path, contents)`, each mode 0600, parents created).
/// An existing image is replaced.
///
/// # Errors
///
/// When the staging directory or image cannot be written, or `mkfs.ext4` fails or is missing.
pub fn create(image: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    let staging = image.with_extension("staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).with_context(|| format!("mkdir {}", staging.display()))?;
    for (relative, bytes) in files {
        let path = staging.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        file.write_all(bytes)?;
    }
    let _ = fs::remove_file(image);
    fs::File::create(image)
        .with_context(|| format!("create {}", image.display()))?
        .set_len(SIZE_MIB * 1024 * 1024)?;
    let output = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-L", LABEL, "-E", "root_owner=0:0", "-d"])
        .arg(&staging)
        .arg(image)
        .output()
        .context("run mkfs.ext4 (e2fsprogs)")?;
    let _ = fs::remove_dir_all(&staging);
    ensure!(
        output.status.success(),
        "mkfs.ext4 failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn debugfs(image: &Path, request: &str) -> String {
        let out = Command::new("debugfs")
            .args(["-R", request])
            .arg(image)
            .output()
            .expect("debugfs runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn statedisk_image_has_the_label_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("state.img");
        create(
            &image,
            &[
                ("config.toml", b"config_version = 1\n"),
                (
                    "identity/portmap",
                    b"[[ports]]\nid = \"x\"\nname = \"p0\"\n",
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&image).unwrap().len(),
            SIZE_MIB * 1024 * 1024
        );
        assert!(
            debugfs(&image, "stats").contains(&format!("Filesystem volume name:   {LABEL}")),
            "label"
        );
        assert_eq!(debugfs(&image, "cat /config.toml"), "config_version = 1\n");
        assert!(debugfs(&image, "cat /identity/portmap").contains("name = \"p0\""));
        assert!(
            !image.with_extension("staging").exists(),
            "staging dir removed"
        );
    }
}
