// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Node and Chromium inside a lab namespace (SPEC §11): the client's own tests and the
//! panel's Playwright run reach the router as a LAN host does. Both come from the web
//! workspace (`web/node_modules`), never from the network at test time.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::daemons::Daemon;
use crate::lab::workspace_root;
use crate::netns::NetNs;
use crate::scenario::Skip;

/// The oldest Node the workspace's tools run on (`web/package.json`'s `engines`).
const NODE_FLOOR: (u32, u32) = (22, 12);
/// How much of a failed command's log an error carries.
const LOG_TAIL: usize = 40;
const POLL: Duration = Duration::from_millis(50);
/// How long a host's addresses may take to settle before a browser is started on it.
const SETTLE: Duration = Duration::from_secs(10);

/// The web workspace.
#[must_use]
pub fn web_dir() -> PathBuf {
    workspace_root().join("web")
}

/// `22.16.0` out of `v22.16.0`.
fn parse_node_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.trim().strip_prefix('v')?.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

fn new_enough((major, minor, _): (u32, u32, u32)) -> bool {
    (major, minor) >= NODE_FLOOR
}

/// The version of the `node` on the path, when it is new enough for the workspace.
///
/// # Errors
///
/// A reason, when there is no `node`, its version cannot be read, or it is too old.
pub fn node_version() -> Result<String, String> {
    let output = Command::new("node")
        .arg("--version")
        .output()
        .map_err(|err| format!("no node on the path ({err})"))?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let version = parse_node_version(&text).ok_or_else(|| format!("node says {text:?}"))?;
    if new_enough(version) {
        Ok(text)
    } else {
        Err(format!(
            "node {text} is older than {}.{}",
            NODE_FLOOR.0, NODE_FLOOR.1
        ))
    }
}

/// Whether the workspace's packages are installed (`make web-install`).
#[must_use]
pub fn installed() -> bool {
    web_dir().join("node_modules/.package-lock.json").is_file()
}

/// Where Playwright keeps its browsers: `PLAYWRIGHT_BROWSERS_PATH`, or its cache directory.
fn browsers_root() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        return Some(PathBuf::from(path));
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(cache.join("ms-playwright"))
}

/// The directory Playwright runs headless Chromium from: `browsers.json` (in
/// `playwright-core`) names the revision, and an installed browser carries a marker.
fn chromium_dir(browsers_json: &str, root: &Path) -> Result<PathBuf, String> {
    let json: serde_json::Value =
        serde_json::from_str(browsers_json).map_err(|err| format!("browsers.json: {err}"))?;
    let revision = json["browsers"]
        .as_array()
        .and_then(|browsers| {
            browsers
                .iter()
                .find(|browser| browser["name"] == "chromium-headless-shell")
        })
        .and_then(|browser| browser["revision"].as_str())
        .ok_or("browsers.json names no chromium-headless-shell")?;
    let dir = root.join(format!("chromium_headless_shell-{revision}"));
    if dir.join("INSTALLATION_COMPLETE").is_file() {
        Ok(dir)
    } else {
        Err(format!("revision {revision} is not in {}", root.display()))
    }
}

/// The Chromium the installed Playwright will run.
///
/// # Errors
///
/// A reason, when the workspace is not installed or the browser is not on disk.
pub fn chromium() -> Result<PathBuf, String> {
    let manifest = web_dir().join("node_modules/playwright-core/browsers.json");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|err| format!("{}: {err}", manifest.display()))?;
    let root = browsers_root().ok_or("no home directory to look for browsers in")?;
    chromium_dir(&text, &root)
}

/// Whether this machine can run the scenarios that need Node and a browser.
///
/// # Errors
///
/// A [`Skip`] that says what is missing and how to get it.
pub fn ready() -> Result<(), Skip> {
    node_ready()?;
    chromium()
        .map(|_| ())
        .map_err(|why| Skip(format!("Playwright's Chromium: {why} (make panel-browser)")))
}

/// One of the workspace's own tools (`web/node_modules/.bin/<name>`), to be started inside
/// `ns` from the workspace's directory.
///
/// # Errors
///
/// When the namespace handle cannot be opened.
pub fn tool(ns: &NetNs, name: &str) -> Result<Command> {
    let program = web_dir().join("node_modules/.bin").join(name);
    let mut cmd = ns.command(&program.to_string_lossy())?;
    cmd.current_dir(web_dir());
    Ok(cmd)
}

/// The `node` on the path, started the same way.
///
/// # Errors
///
/// When the namespace handle cannot be opened.
pub fn node(ns: &NetNs) -> Result<Command> {
    let mut cmd = ns.command("node")?;
    cmd.current_dir(web_dir());
    Ok(cmd)
}

/// Whether `ip -6 -o addr show dev <ifname>` lists addresses that will not change by
/// themselves: at least one, and none still being checked for a duplicate.
fn settled(addrs: &str) -> bool {
    let mut lines = addrs
        .lines()
        .filter(|line| !line.trim().is_empty())
        .peekable();
    lines.peek().is_some()
        && lines.all(|line| line.split_whitespace().all(|word| word != "tentative"))
}

/// Wait until the IPv6 addresses of `ifname` in `ns` have settled, before a browser is
/// started there.
///
/// An interface just brought up checks its link-local address for a duplicate for a second
/// or two, and the kernel announces the address only when that ends. Chromium watches those
/// announcements and gives up everything it has in flight when one comes
/// (`net::ERR_NETWORK_CHANGED`), so a page asked for in that instant fails to load. Node has
/// no such watch; only the browser needs this.
///
/// # Errors
///
/// When `ip` fails, or the addresses have not settled in ten seconds.
pub fn settle(ns: &NetNs, ifname: &str) -> Result<()> {
    let deadline = Instant::now() + SETTLE;
    loop {
        let addrs = ns.ip(&["-6", "-o", "addr", "show", "dev", ifname])?;
        if settled(&addrs) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "{ifname}'s addresses did not settle within {SETTLE:?}: {}",
                addrs.trim()
            );
        }
        std::thread::sleep(POLL);
    }
}

/// Run `cmd` to its end with both its outputs kept in `log`, calling `tick` while it runs.
/// The command leads a process group, so a browser it started goes with it.
fn run_with(
    cmd: Command,
    log: &Path,
    timeout: Duration,
    mut tick: impl FnMut() -> Result<()>,
) -> Result<()> {
    let name = log.file_stem().map_or_else(
        || "command".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let mut child = Daemon::spawn_group(&name, cmd)?;
    let deadline = Instant::now() + timeout;
    let mut ticked = Ok(());
    let status = loop {
        if let Some(status) = child.exit_status() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        ticked = tick();
        if ticked.is_err() {
            break None;
        }
        std::thread::sleep(POLL);
    };
    // The reader drains the pipe on its own thread; give it the last lines.
    std::thread::sleep(POLL * 2);
    let lines = child.log.tail(usize::MAX);
    std::fs::write(log, lines.join("\n") + "\n")
        .with_context(|| format!("write {}", log.display()))?;
    let tail = lines[lines.len().saturating_sub(LOG_TAIL)..].join("\n");
    ticked.with_context(|| format!("while {name} ran; the end of its log:\n{tail}"))?;
    match status {
        Some(status) if status.success() => Ok(()),
        Some(status) => bail!(
            "{name} failed ({status}); the end of {}:\n{tail}",
            log.display()
        ),
        None => bail!(
            "{name} did not finish in {timeout:?}; the end of {}:\n{tail}",
            log.display()
        ),
    }
}

/// Run `cmd` to its end with both its outputs kept in `log`.
///
/// # Errors
///
/// When it cannot be started, fails, or outlives `timeout`; the error carries the end of
/// the log.
pub fn run_logged(cmd: Command, log: &Path, timeout: Duration) -> Result<()> {
    run_with(cmd, log, timeout, || Ok(()))
}

/// Whether this machine can run the scenarios that need Node alone.
///
/// # Errors
///
/// A [`Skip`] that says what is missing and how to get it.
pub fn node_ready() -> Result<(), Skip> {
    node_version().map_err(Skip)?;
    if installed() {
        Ok(())
    } else {
        Err(Skip(
            "web/node_modules is not installed (make web-install)".to_owned(),
        ))
    }
}

/// How a test running in a lab namespace asks the lab for something only the harness can do
/// (take a port's carrier away, give it back). The test writes `<n>.req` holding a verb into
/// this directory, numbering from 1, and waits for `<n>.ack`: `ok`, or `error: <why>`.
/// `web/scripts/labctl.mjs` is the other end.
#[derive(Debug)]
pub struct LabCtl {
    dir: PathBuf,
}

impl LabCtl {
    /// A fresh control directory under `run_dir`.
    ///
    /// # Errors
    ///
    /// When the directory cannot be made.
    pub fn new(run_dir: &Path) -> Result<Self> {
        let dir = run_dir.join("labctl");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).with_context(|| format!("clear {}", dir.display()))?;
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// The directory, for the test's `OPENFEO_LAB_CTL`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Run `cmd` to its end as [`run_logged`] does, answering its requests in order while it
    /// runs: `act` is given each verb, and what it returns is the acknowledgement. A verb
    /// `act` refuses is the test's to hear about, not the end of the run.
    ///
    /// # Errors
    ///
    /// As [`run_logged`], and when the control directory cannot be read or written.
    pub fn serve_while(
        &self,
        cmd: Command,
        log: &Path,
        timeout: Duration,
        mut act: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        let mut next = 1u32;
        run_with(cmd, log, timeout, || {
            let request = self.dir.join(format!("{next}.req"));
            let verb = match std::fs::read_to_string(&request) {
                Ok(verb) => verb,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(err).with_context(|| format!("read {}", request.display())),
            };
            let answer = match act(verb.trim()) {
                Ok(()) => "ok".to_owned(),
                Err(err) => format!("error: {err:#}"),
            };
            // Written beside and moved into place, so the test never reads half an answer.
            let ack = self.dir.join(format!("{next}.ack"));
            let beside = self.dir.join(format!("{next}.ack.tmp"));
            std::fs::write(&beside, answer)
                .with_context(|| format!("write {}", beside.display()))?;
            std::fs::rename(&beside, &ack).with_context(|| format!("write {}", ack.display()))?;
            next += 1;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_22_12_is_new_enough_and_22_11_is_not() {
        assert_eq!(parse_node_version("v22.16.0\n"), Some((22, 16, 0)));
        assert_eq!(parse_node_version("v24.0.0-nightly"), Some((24, 0, 0)));
        assert_eq!(parse_node_version("22.16.0"), None);
        assert_eq!(parse_node_version("vX"), None);
        assert!(new_enough((22, 12, 0)));
        assert!(new_enough((24, 0, 0)));
        assert!(!new_enough((22, 11, 9)));
        assert!(!new_enough((20, 19, 0)));
    }

    #[test]
    fn addresses_have_settled_once_there_is_one_and_none_is_tentative() {
        // As `ip -6 -o addr show dev lan0` prints them in the lab.
        let checking = "2: lan0    inet6 fe80::3ca1:caff:fe4d:e569/64 scope link tentative proto kernel_ll \\       valid_lft forever preferred_lft forever\n";
        let usable = "2: lan0    inet6 fe80::3ca1:caff:fe4d:e569/64 scope link proto kernel_ll \\       valid_lft forever preferred_lft forever\n";
        let second = "2: lan0    inet6 fd12:3456:789a:1::2/64 scope global tentative \\       valid_lft forever preferred_lft forever\n";
        let refused = "2: lan0    inet6 fe80::1/64 scope link dadfailed tentative \\       valid_lft forever preferred_lft forever\n";
        assert!(settled(usable));
        assert!(
            !settled(checking),
            "duplicate address detection has not finished"
        );
        assert!(
            !settled(""),
            "an interface just brought up may not have its address yet"
        );
        assert!(!settled("\n"));
        assert!(
            !settled(&format!("{usable}{second}")),
            "one of two is still checked"
        );
        assert!(!settled(refused));
        // The word, not the letters: an interface may be called anything.
        let named = usable.replace("lan0", "tentative0");
        assert!(settled(&named));
    }

    #[test]
    fn the_headless_shell_revision_names_its_directory() {
        let root = tempfile::tempdir().unwrap();
        let manifest = r#"{"browsers":[{"name":"chromium","revision":"1200"},{"name":"chromium-headless-shell","revision":"1234"}]}"#;
        let missing = chromium_dir(manifest, root.path()).unwrap_err();
        assert!(missing.contains("1234"), "{missing}");
        let dir = root.path().join("chromium_headless_shell-1234");
        std::fs::create_dir(&dir).unwrap();
        assert!(
            chromium_dir(manifest, root.path()).is_err(),
            "a download that did not finish"
        );
        std::fs::write(dir.join("INSTALLATION_COMPLETE"), "").unwrap();
        assert_eq!(chromium_dir(manifest, root.path()), Ok(dir));
        assert!(chromium_dir(r#"{"browsers":[]}"#, root.path()).is_err());
        assert!(chromium_dir("not json", root.path()).is_err());
    }

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn a_command_that_ends_well_leaves_its_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("fine.log");
        run_logged(sh("echo out; echo err >&2"), &log, Duration::from_secs(10)).unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("out") && text.contains("err"), "{text}");
    }

    #[test]
    fn a_command_that_fails_is_an_error_with_the_end_of_its_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("broken.log");
        let err = run_logged(sh("echo the reason; exit 3"), &log, Duration::from_secs(10))
            .unwrap_err()
            .to_string();
        assert!(err.contains("broken failed"), "{err}");
        assert!(err.contains("the reason"), "{err}");
    }

    #[test]
    fn requests_are_answered_in_order_and_a_refused_verb_is_an_error_ack() {
        let dir = tempfile::tempdir().unwrap();
        let ctl = LabCtl::new(dir.path()).unwrap();
        let log = dir.path().join("asker.log");
        // What a test does through web/scripts/labctl.mjs: write a request, wait for its ack.
        let script = r#"
            ask() {
                printf '%s' "$2" > "$CTL/$1.req.tmp" && mv "$CTL/$1.req.tmp" "$CTL/$1.req"
                while [ ! -f "$CTL/$1.ack" ]; do sleep 0.02; done
                echo "$2 -> $(cat "$CTL/$1.ack")"
            }
            ask 1 wan-down; ask 2 no-such-verb; ask 3 wan-up
        "#;
        let mut cmd = sh(script);
        cmd.env("CTL", ctl.dir());
        let mut seen = Vec::new();
        ctl.serve_while(cmd, &log, Duration::from_secs(20), |verb| {
            seen.push(verb.to_owned());
            if verb == "no-such-verb" {
                anyhow::bail!("no such verb: {verb}");
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, ["wan-down", "no-such-verb", "wan-up"]);
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("wan-down -> ok"), "{text}");
        assert!(
            text.contains("no-such-verb -> error: no such verb: no-such-verb"),
            "{text}"
        );
        assert!(text.contains("wan-up -> ok"), "{text}");
    }

    #[test]
    fn a_command_that_fails_under_the_lab_is_an_error_too() {
        let dir = tempfile::tempdir().unwrap();
        let ctl = LabCtl::new(dir.path()).unwrap();
        let err = ctl
            .serve_while(
                sh("echo it broke; exit 1"),
                &dir.path().join("broken.log"),
                Duration::from_secs(10),
                |_| Ok(()),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("it broke"), "{err}");
    }

    #[test]
    fn a_command_that_outlives_its_time_is_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("slow.log");
        let started = Instant::now();
        let err = run_logged(sh("echo begun; sleep 30"), &log, Duration::from_millis(300))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish"), "{err}");
        assert!(err.contains("begun"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
