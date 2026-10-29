// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The only module in the crate allowed `unsafe`: thin wrappers over libc. Every `unsafe` block
//! carries a `// SAFETY:` comment; every `-1` becomes `io::Error::last_os_error()`.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::Duration;

use crate::ctl::CHILD_CTL_FD;

/// `_IOWR('W', 6, int)`: set the watchdog timeout in seconds; the driver writes back what it kept.
#[allow(clippy::cast_possible_wrap)] // musl types ioctl requests as c_int; the kernel reads them as unsigned
const WDIOC_SETTIMEOUT: libc::Ioctl = 0xC004_5706_u32 as libc::Ioctl;
/// `_IOR('W', 5, int)`: pet the watchdog.
#[allow(clippy::cast_possible_wrap)]
const WDIOC_KEEPALIVE: libc::Ioctl = 0x8004_5705_u32 as libc::Ioctl;

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}

/// mount(2).
///
/// # Errors
///
/// The errno from the kernel.
pub fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = cstr(fstype)?;
    let data = cstr(data)?;
    // SAFETY: all four pointers are valid NUL-terminated strings that outlive the call; `data` is
    // an option string, which is what every filesystem we mount expects.
    check(unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    })
}

/// sethostname(2).
///
/// # Errors
///
/// The errno from the kernel.
pub fn sethostname(name: &str) -> io::Result<()> {
    // SAFETY: the pointer and length describe `name`'s bytes, valid for the call.
    check(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) })
}

/// Bring `lo` up by setting `IFF_UP` through sysfs (`/sys/class/net/lo/flags` is writable).
///
/// # Errors
///
/// When sysfs is not mounted or the write is refused.
pub fn loopback_up() -> io::Result<()> {
    const FLAGS: &str = "/sys/class/net/lo/flags";
    let current = std::fs::read_to_string(FLAGS)?;
    let current = u32::from_str_radix(current.trim().trim_start_matches("0x"), 16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(FLAGS, format!("{:#x}", current | 0x1))
}

/// Reopen `/dev/console` as descriptors 0, 1 and 2, so PID 1 and its child always have a console
/// even if the kernel could not open one for us.
///
/// # Errors
///
/// When `/dev/console` cannot be opened.
pub fn reopen_console() -> io::Result<()> {
    let path = cstr("/dev/console")?;
    // SAFETY: open(2) on a valid path; the descriptor is owned by `console` and closed on drop.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    check(fd)?;
    // SAFETY: `fd` is a fresh descriptor we own.
    let console = unsafe { File::from_raw_fd(fd) };
    for target in [0, 1, 2] {
        // SAFETY: dup2 onto the standard descriptors; `console` stays open until the loop ends.
        check(unsafe { libc::dup2(console.as_raw_fd(), target) })?;
    }
    Ok(())
}

/// What reboot(2) should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootCmd {
    /// Restart the machine.
    Restart,
    /// Power it off.
    PowerOff,
}

/// sync(2) then reboot(2).
///
/// # Errors
///
/// The errno from the kernel (`EPERM` in a container without `CAP_SYS_BOOT`).
pub fn reboot(cmd: RebootCmd) -> io::Result<()> {
    let how = match cmd {
        RebootCmd::Restart => libc::LINUX_REBOOT_CMD_RESTART,
        RebootCmd::PowerOff => libc::LINUX_REBOOT_CMD_POWER_OFF,
    };
    // SAFETY: neither call takes a pointer.
    unsafe { libc::sync() };
    // SAFETY: as above.
    check(unsafe { libc::reboot(how) })
}

/// `WDIOC_SETTIMEOUT`: ask for `secs`; returns the timeout the driver actually set.
///
/// # Errors
///
/// The errno from the driver.
pub fn wdt_set_timeout(dev: &File, secs: u32) -> io::Result<u32> {
    let mut value = libc::c_int::try_from(secs)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timeout too large"))?;
    // SAFETY: the ioctl reads and writes one int at the pointer we pass; `value` outlives the call.
    check(unsafe { libc::ioctl(dev.as_raw_fd(), WDIOC_SETTIMEOUT, &raw mut value) })?;
    u32::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative watchdog timeout"))
}

/// `WDIOC_KEEPALIVE`: pet the watchdog.
///
/// # Errors
///
/// The errno from the driver.
pub fn wdt_keepalive(dev: &File) -> io::Result<()> {
    let mut unused: libc::c_int = 0;
    // SAFETY: the ioctl writes one int at the pointer we pass; the value is meaningless.
    check(unsafe { libc::ioctl(dev.as_raw_fd(), WDIOC_KEEPALIVE, &raw mut unused) })
}

/// Block `signals` for this process and return a non-blocking signalfd for them.
///
/// # Errors
///
/// The errno from `sigprocmask` or `signalfd`.
pub fn signalfd(signals: &[libc::c_int]) -> io::Result<File> {
    // SAFETY: sigset_t is plain data for which all-zero is a valid value; every call below takes a
    // pointer to `set`, which outlives them.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    check(unsafe { libc::sigemptyset(&raw mut set) })?;
    for &signal in signals {
        // SAFETY: as above.
        check(unsafe { libc::sigaddset(&raw mut set, signal) })?;
    }
    // SAFETY: as above; a null old-set pointer is permitted.
    check(unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) })?;
    // SAFETY: as above.
    let fd = unsafe { libc::signalfd(-1, &raw const set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    check(fd)?;
    // SAFETY: `fd` is a fresh descriptor we own.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Read one pending signal number from a signalfd; `None` when nothing is pending.
///
/// # Errors
///
/// The errno from read(2) other than `EAGAIN`.
pub fn read_signal(fd: &File) -> io::Result<Option<libc::c_int>> {
    // SAFETY: signalfd_siginfo is plain data for which all-zero is valid; read(2) writes at most
    // its size into it.
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let n = unsafe {
        libc::read(
            fd.as_raw_fd(),
            (&raw mut info).cast(),
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(err)
        };
    }
    Ok(Some(libc::c_int::try_from(info.ssi_signo).unwrap_or(0)))
}

/// One descriptor to poll for readability.
#[derive(Debug, Clone, Copy)]
pub struct PollFd {
    /// The descriptor.
    pub fd: RawFd,
    /// Set by [`poll`]: readable, hung up or in error.
    pub readable: bool,
}

/// poll(2) for `POLLIN` on each descriptor. `EINTR` counts as "nothing ready".
///
/// # Errors
///
/// The errno from poll(2).
pub fn poll(fds: &mut [PollFd], timeout: Duration) -> io::Result<usize> {
    let mut raw: Vec<libc::pollfd> = fds
        .iter()
        .map(|p| libc::pollfd {
            fd: p.fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    let count = libc::nfds_t::try_from(raw.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many descriptors"))?;
    // SAFETY: `raw` is a valid array of `count` pollfd structs for the duration of the call.
    let n = unsafe { libc::poll(raw.as_mut_ptr(), count, ms) };
    if n < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::Interrupted {
            Ok(0)
        } else {
            Err(err)
        };
    }
    for (p, r) in fds.iter_mut().zip(&raw) {
        p.readable = r.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

/// pipe2(2) with `O_CLOEXEC` on both ends: `(read, write)`.
///
/// # Errors
///
/// The errno from pipe2(2).
pub fn pipe() -> io::Result<(File, File)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the array we own.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: both descriptors are fresh and owned by the returned Files.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

/// fork(2) and execve(2) `exe`, with `ctl_fd` installed as [`CHILD_CTL_FD`] and the signal mask
/// cleared in the child. Returns the child's pid. Only sound while the caller is single-threaded,
/// which PID 1 is.
///
/// # Errors
///
/// The errno from fork(2). An exec failure makes the child exit with status 127.
pub fn spawn(
    exe: &CStr,
    argv: &[CString],
    envp: &[CString],
    ctl_fd: RawFd,
) -> io::Result<libc::pid_t> {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());
    // SAFETY: PID 1 is single-threaded, so fork() cannot leave locks held in the child, and the
    // child only calls async-signal-safe functions below before it execs or exits.
    let pid = unsafe { libc::fork() };
    check(pid)?;
    if pid == 0 {
        // SAFETY (child): descriptors and NUL-terminated pointer arrays built above stay valid
        // until exec; sigset_t is plain data.
        unsafe {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut());
            if ctl_fd == CHILD_CTL_FD {
                libc::fcntl(ctl_fd, libc::F_SETFD, 0);
            } else if libc::dup2(ctl_fd, CHILD_CTL_FD) < 0 {
                libc::_exit(126);
            }
            libc::execve(exe.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Exited with this status.
    Exited(i32),
    /// Killed by this signal.
    Signaled(i32),
}

impl ExitStatus {
    /// Decode a raw wait status.
    #[must_use]
    pub fn from_wait_status(raw: libc::c_int) -> Self {
        if libc::WIFEXITED(raw) {
            Self::Exited(libc::WEXITSTATUS(raw))
        } else {
            Self::Signaled(libc::WTERMSIG(raw))
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exit({code})"),
            Self::Signaled(signal) => write!(f, "signal({signal})"),
        }
    }
}

/// Reap one exited child without blocking; `None` when none has exited.
///
/// # Errors
///
/// The errno from waitpid(2) other than `ECHILD`.
pub fn reap() -> io::Result<Option<(libc::pid_t, ExitStatus)>> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid writes the status into the int we own.
    let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
    if pid < 0 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::ECHILD) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    if pid == 0 {
        return Ok(None);
    }
    Ok(Some((pid, ExitStatus::from_wait_status(status))))
}

/// kill(2).
///
/// # Errors
///
/// The errno from the kernel.
pub fn kill(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: no pointers.
    check(unsafe { libc::kill(pid, signal) })
}

/// Take ownership of an inherited descriptor (the control pipe PID 1 hands its child) as a `File`.
/// The caller must not use `fd` afterwards.
///
/// # Errors
///
/// `EBADF` when `fd` is not open.
pub fn file_from_fd(fd: RawFd) -> io::Result<File> {
    // SAFETY: F_GETFD takes no pointer; it only validates the descriptor.
    check(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    // SAFETY: the descriptor is open and, by contract, not used by anyone else afterwards.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn wait_status_decodes() {
        assert_eq!(ExitStatus::from_wait_status(3 << 8).to_string(), "exit(3)");
        assert_eq!(ExitStatus::from_wait_status(9).to_string(), "signal(9)");
    }

    #[test]
    fn pipe_round_trip() {
        let (mut r, mut w) = pipe().unwrap();
        w.write_all(b"H").unwrap();
        let mut b = [0u8; 1];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"H");
    }

    #[test]
    fn file_from_fd_rejects_closed_descriptor() {
        assert!(file_from_fd(987_654).is_err());
    }
}
