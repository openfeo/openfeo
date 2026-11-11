// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! One more host the API takes as its own, for the lab only.
//!
//! The harness can relay the panel to an address of the developer's machine
//! (`make run PANEL=<address>:<port>`), so that the real panel can be looked at from a browser
//! outside the lab. The API's host check (SPEC §9) refuses a `Host` that is neither one of the
//! router's names nor an address it holds, and that address is neither. A harness build is
//! told the host on the kernel command line; a release build has no such knob.

use openfeo_init::cmdline::Cmdline;

/// The kernel command-line key.
#[cfg(feature = "harness")]
pub const KEY: &str = "openfeo.panel_host";

/// A host is a name or an address literal without its brackets: letters, digits, dots,
/// colons and hyphens, at most as long as a name may be.
#[cfg(feature = "harness")]
fn is_host(text: &str) -> bool {
    (1..=253).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'))
}

/// The knob from the kernel command line. Harness builds only.
#[cfg(feature = "harness")]
#[must_use]
pub fn from_cmdline(cmdline: &Cmdline) -> Option<String> {
    cmdline
        .get(KEY)
        .filter(|host| is_host(host))
        .map(str::to_owned)
}

/// Release builds never read the knob.
#[cfg(not(feature = "harness"))]
#[must_use]
pub fn from_cmdline(_cmdline: &Cmdline) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use openfeo_init::cmdline;

    use super::*;

    #[cfg(feature = "harness")]
    #[test]
    fn the_knob_is_read_with_the_feature() {
        let host = |line: &str| from_cmdline(&cmdline::parse(line));
        assert_eq!(
            host("quiet openfeo.panel_host=192.0.2.10 ro"),
            Some("192.0.2.10".to_owned())
        );
        assert_eq!(
            host("openfeo.panel_host=panel.test"),
            Some("panel.test".to_owned())
        );
        assert_eq!(
            host("openfeo.panel_host=2001:db8::10"),
            Some("2001:db8::10".to_owned())
        );
        assert_eq!(host("quiet ro"), None);
        assert_eq!(host("openfeo.panel_host="), None);
        // A host is letters, digits, dots, colons and hyphens: nothing that could be a path,
        // a port list or a second header.
        for bad in [
            "openfeo.panel_host=\"a b\"",
            "openfeo.panel_host=a/b",
            "openfeo.panel_host=a,b",
            "openfeo.panel_host=[2001:db8::10]",
        ] {
            assert_eq!(host(bad), None, "{bad}");
        }
        let long = format!("openfeo.panel_host={}", "a".repeat(254));
        assert_eq!(host(&long), None);
    }

    #[cfg(not(feature = "harness"))]
    #[test]
    fn a_release_build_has_no_such_knob() {
        let line = cmdline::parse("quiet openfeo.panel_host=192.0.2.10 ro");
        assert_eq!(from_cmdline(&line), None);
    }
}
