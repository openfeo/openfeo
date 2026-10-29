// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Enter a private user + mount + network namespace so the rest of the harness can create taps,
//! namespaces and daemons without sudo (ADR-0006).

use std::fs;

use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{getegid, geteuid};

use crate::netns;

/// Directories every lab expects to exist on the private `/run`.
const RUN_DIRS: [&str; 3] = ["/run/netns", "/run/kea", "/run/openfeo-harness"];

/// Become uid 0 in a fresh user namespace, then take a private mount namespace (with a tmpfs on
/// `/run` for `ip netns`) and a fresh network namespace. Idempotent. Must be called while the
/// process is still single-threaded: `unshare(CLONE_NEWUSER)` refuses otherwise.
///
/// # Errors
///
/// When user namespaces are unavailable (the error names the usual causes) or a mount fails.
pub fn enter() -> Result<()> {
    if is_inside() {
        return Ok(());
    }
    let (uid, gid) = (geteuid(), getegid());
    unshare(CloneFlags::CLONE_NEWUSER).map_err(|err| {
        let hint = hint(&err).map(|h| format!(": {h}")).unwrap_or_default();
        anyhow::anyhow!("unshare(CLONE_NEWUSER): {err}{hint}")
    })?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).context("write uid_map")?;
    fs::write("/proc/self/setgroups", "deny\n").context("write setgroups")?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).context("write gid_map")?;
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET)
        .context("unshare(CLONE_NEWNS | CLONE_NEWNET)")?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make / private")?;
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=0755"),
    )
    .context("mount tmpfs on /run")?;
    for dir in RUN_DIRS {
        fs::create_dir_all(dir).with_context(|| format!("mkdir {dir}"))?;
    }
    netns::ip(&["link", "set", "lo", "up"])?;
    Ok(())
}

/// Whether this process already runs as the mapped root of a user namespace (the identity map
/// `0 0 4294967295` means the initial namespace).
#[must_use]
pub fn is_inside() -> bool {
    geteuid().is_root()
        && fs::read_to_string("/proc/self/uid_map")
            .is_ok_and(|map| map.split_whitespace().nth(2) != Some("4294967295"))
}

/// What to check when entering a user namespace is refused.
#[must_use]
pub fn hint(err: &nix::Error) -> Option<&'static str> {
    match err {
        nix::Error::EPERM | nix::Error::EACCES => Some(
            "unprivileged user namespaces are unavailable: check /proc/sys/user/max_user_namespaces \
             and, on Ubuntu, sysctl kernel.apparmor_restrict_unprivileged_userns",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eperm_gets_a_userns_hint() {
        assert!(
            hint(&nix::Error::EPERM)
                .unwrap()
                .contains("user namespaces")
        );
        assert!(hint(&nix::Error::ENOENT).is_none());
    }
}
