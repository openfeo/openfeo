// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The filesystems PID 1 mounts before anything else runs (SPEC §6.1).

use std::io;

use crate::log::Log;

/// One mount.
#[derive(Debug, Clone, Copy)]
pub struct MountSpec {
    /// Source (a device or a filesystem name).
    pub source: &'static str,
    /// Mount point; must already exist (the initramfs carries every one of them).
    pub target: &'static str,
    /// Filesystem type.
    pub fstype: &'static str,
    /// `MS_*` flags.
    pub flags: libc::c_ulong,
    /// Option string.
    pub data: &'static str,
    /// Boot cannot continue without it.
    pub required: bool,
}

const STD: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

/// Everything mounted before the command line is read, in order. Optional entries are absent on
/// kernels or machines without the feature (a VM without EFI, say) and are skipped with a warning.
pub const EARLY: &[MountSpec] = &[
    MountSpec {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        flags: STD,
        data: "",
        required: true,
    },
    MountSpec {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        flags: STD,
        data: "",
        required: true,
    },
    MountSpec {
        source: "devtmpfs",
        target: "/dev",
        fstype: "devtmpfs",
        flags: libc::MS_NOSUID,
        data: "mode=0755",
        required: true,
    },
    MountSpec {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        flags: STD,
        data: "mode=0755",
        required: true,
    },
    MountSpec {
        source: "tmpfs",
        target: "/tmp",
        fstype: "tmpfs",
        flags: STD,
        data: "mode=1777",
        required: true,
    },
    MountSpec {
        source: "cgroup2",
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        flags: STD,
        data: "nsdelegate",
        required: false,
    },
    MountSpec {
        source: "efivarfs",
        target: "/sys/firmware/efi/efivars",
        fstype: "efivarfs",
        flags: STD,
        data: "",
        required: false,
    },
    MountSpec {
        source: "pstore",
        target: "/sys/fs/pstore",
        fstype: "pstore",
        flags: STD,
        data: "",
        required: false,
    },
];

/// `/state` until persistent storage arrives in M5: a private tmpfs, so nothing survives a reboot.
pub const STATE_FALLBACK: MountSpec = MountSpec {
    source: "tmpfs",
    target: "/state",
    fstype: "tmpfs",
    flags: STD,
    data: "mode=0700",
    required: true,
};

/// What became of one mount attempt that did not simply succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Mounted now.
    Mounted,
    /// Something (the kernel, say) had already mounted it: `EBUSY`.
    AlreadyMounted,
    /// Optional and unavailable on this kernel or machine.
    Skipped,
}

/// A required mount failed, or an optional one failed for a reason other than absence.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// The kernel refused.
    #[error("mount {target} ({fstype}): {source}")]
    Failed {
        /// Mount point.
        target: &'static str,
        /// Filesystem type.
        fstype: &'static str,
        /// The errno.
        source: io::Error,
    },
}

/// Decide what a mount failure means: `EBUSY` is fine (already mounted); `ENODEV`/`ENOENT` on an
/// optional mount means the feature is absent; everything else is fatal.
///
/// # Errors
///
/// [`MountError::Failed`] when boot cannot sensibly continue.
pub fn classify(spec: &MountSpec, err: io::Error) -> Result<Outcome, MountError> {
    match err.raw_os_error() {
        Some(libc::EBUSY) => Ok(Outcome::AlreadyMounted),
        Some(libc::ENODEV | libc::ENOENT) if !spec.required => Ok(Outcome::Skipped),
        _ => Err(MountError::Failed {
            target: spec.target,
            fstype: spec.fstype,
            source: err,
        }),
    }
}

/// Mount every spec in order.
///
/// # Errors
///
/// The first fatal failure (see [`classify`]).
pub fn mount_all(specs: &[MountSpec], log: &Log) -> Result<(), MountError> {
    for spec in specs {
        let Err(err) =
            crate::sys::mount(spec.source, spec.target, spec.fstype, spec.flags, spec.data)
        else {
            continue;
        };
        let reason = err.to_string();
        match classify(spec, err)? {
            Outcome::Mounted | Outcome::AlreadyMounted => {}
            Outcome::Skipped => log.warn(&format!("mount {} skipped: {reason}", spec.target)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    const fn spec(required: bool) -> MountSpec {
        MountSpec {
            source: "x",
            target: "/x",
            fstype: "x",
            flags: 0,
            data: "",
            required,
        }
    }

    #[test]
    fn busy_means_already_mounted() {
        assert!(matches!(
            classify(&spec(true), e(libc::EBUSY)),
            Ok(Outcome::AlreadyMounted)
        ));
    }

    #[test]
    fn optional_nodev_is_skipped() {
        assert!(matches!(
            classify(&spec(false), e(libc::ENODEV)),
            Ok(Outcome::Skipped)
        ));
        assert!(matches!(
            classify(&spec(false), e(libc::ENOENT)),
            Ok(Outcome::Skipped)
        ));
    }

    #[test]
    fn required_nodev_is_fatal() {
        let err = classify(&spec(true), e(libc::ENODEV)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mount /x (x): No such device (os error 19)"
        );
    }

    #[test]
    fn optional_eacces_is_fatal() {
        assert!(classify(&spec(false), e(libc::EACCES)).is_err());
    }

    #[test]
    fn early_mount_order_starts_with_proc_sys_dev() {
        let targets: Vec<_> = EARLY.iter().map(|m| m.target).collect();
        assert_eq!(&targets[..3], &["/proc", "/sys", "/dev"]);
        assert_eq!(STATE_FALLBACK.target, "/state");
    }
}
