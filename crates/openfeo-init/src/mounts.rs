// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The filesystems PID 1 mounts before anything else runs (SPEC §6.1).

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cmdline::Mode;
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

/// `/state` in `vm` mode: the harness's virtio-blk ext4 image (ADR-0010), mounted with the
/// SPEC §5.2 options. Optional: a VM without the disk falls back to the tmpfs.
pub const STATE_VM: MountSpec = MountSpec {
    source: "/dev/vda",
    target: "/state",
    fstype: "ext4",
    flags: libc::MS_NOATIME | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
    data: "",
    required: false,
};

/// How long `vm` mode waits for `/dev/vda` to show up in devtmpfs before giving up on the disk.
/// Built-in virtio-blk probes before init runs, so this is a safety net, not the normal path, and
/// a VM without a disk pays it on every boot.
pub const STATE_DISK_WAIT: Duration = Duration::from_secs(1);

/// The mounts to try for `/state`, in order, for `mode`.
#[must_use]
pub fn state_plan(mode: Mode) -> &'static [MountSpec] {
    match mode {
        Mode::Vm => &[STATE_VM, STATE_FALLBACK],
        _ => &[STATE_FALLBACK],
    }
}

/// Try each spec of `plan` in order with `mount`; the first that mounts (or was already mounted)
/// wins, an optional spec whose source is absent is skipped.
///
/// # Errors
///
/// The first failure that is neither success nor an optional absence, or the last spec's
/// failure when every spec was skipped.
pub fn mount_state_with(
    plan: &'static [MountSpec],
    mount: &mut dyn FnMut(&MountSpec) -> io::Result<()>,
) -> Result<&'static MountSpec, MountError> {
    let mut last: Option<MountError> = None;
    for spec in plan {
        match mount(spec) {
            Ok(()) => return Ok(spec),
            Err(err) => match classify(spec, err)? {
                Outcome::Mounted | Outcome::AlreadyMounted => return Ok(spec),
                Outcome::Skipped => {
                    last = Some(MountError::Failed {
                        target: spec.target,
                        fstype: spec.fstype,
                        source: io::Error::from_raw_os_error(libc::ENODEV),
                    });
                }
            },
        }
    }
    Err(last.unwrap_or(MountError::Failed {
        target: "/state",
        fstype: "none",
        source: io::Error::from_raw_os_error(libc::ENODEV),
    }))
}

/// Mount `/state` for `mode` (SPEC §6.1). In `vm` mode the disk may appear a moment after PID 1
/// starts, so its node is awaited for up to [`STATE_DISK_WAIT`].
///
/// # Errors
///
/// As [`mount_state_with`].
pub fn mount_state(mode: Mode) -> Result<&'static MountSpec, MountError> {
    if mode == Mode::Vm {
        let deadline = Instant::now() + STATE_DISK_WAIT;
        while !Path::new(STATE_VM.source).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    mount_state_with(state_plan(mode), &mut |spec: &MountSpec| {
        crate::sys::mount(spec.source, spec.target, spec.fstype, spec.flags, spec.data)
    })
}

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

/// Decide what a mount failure means: `EBUSY` is fine (already mounted); `ENODEV`/`ENOENT`/`ENXIO`
/// on an optional mount means the feature or device is absent; everything else is fatal.
///
/// # Errors
///
/// [`MountError::Failed`] when boot cannot sensibly continue.
pub fn classify(spec: &MountSpec, err: io::Error) -> Result<Outcome, MountError> {
    match err.raw_os_error() {
        Some(libc::EBUSY) => Ok(Outcome::AlreadyMounted),
        Some(libc::ENODEV | libc::ENOENT | libc::ENXIO) if !spec.required => Ok(Outcome::Skipped),
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

    fn sources(plan: &[MountSpec]) -> Vec<&'static str> {
        plan.iter().map(|m| m.source).collect()
    }

    #[test]
    fn vm_plan_tries_the_disk_first() {
        assert_eq!(sources(state_plan(Mode::Vm)), ["/dev/vda", "tmpfs"]);
        assert_eq!(STATE_VM.fstype, "ext4");
        assert_eq!(STATE_VM.target, "/state");
        assert_eq!(
            STATE_VM.flags,
            libc::MS_NOATIME | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC
        );
    }

    #[test]
    fn metal_plan_is_fallback_only_until_m5() {
        for mode in [Mode::Metal, Mode::Container, Mode::Installer, Mode::Rescue] {
            assert_eq!(sources(state_plan(mode)), ["tmpfs"], "{mode}");
        }
    }

    #[test]
    fn disk_absent_falls_back() {
        let mut attempts = Vec::new();
        let chosen = mount_state_with(state_plan(Mode::Vm), &mut |spec: &MountSpec| {
            attempts.push(spec.source);
            if spec.source == "/dev/vda" {
                Err(e(libc::ENXIO))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, ["/dev/vda", "tmpfs"]);
        assert_eq!(chosen.source, STATE_FALLBACK.source);
    }

    #[test]
    fn disk_present_stops_there() {
        let mut attempts = Vec::new();
        let chosen = mount_state_with(state_plan(Mode::Vm), &mut |spec: &MountSpec| {
            attempts.push(spec.source);
            Ok(())
        })
        .unwrap();
        assert_eq!(attempts, ["/dev/vda"]);
        assert_eq!(chosen.source, "/dev/vda");
    }

    #[test]
    fn disk_error_other_than_absence_is_fatal() {
        let result = mount_state_with(state_plan(Mode::Vm), &mut |spec: &MountSpec| {
            if spec.source == "/dev/vda" {
                Err(e(libc::EIO))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
    }

    #[test]
    fn enoent_and_enxio_on_an_optional_spec_are_skipped() {
        assert!(matches!(
            classify(&spec(false), e(libc::ENXIO)),
            Ok(Outcome::Skipped)
        ));
        assert!(classify(&spec(true), e(libc::ENXIO)).is_err());
    }
}
