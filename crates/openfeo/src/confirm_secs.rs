// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A shorter window for a change of config, for the lab only.
//!
//! An apply that names no window is given 120 s to be confirmed (SPEC §5.5, ADR-0026). The
//! panel never names one, so a browser scenario that lets a window run out would wait two
//! minutes. A harness build is told a shorter default on the kernel command line; a release
//! build has no such knob.

use openfeo_init::cmdline::Cmdline;

/// The kernel command-line key.
#[cfg(feature = "harness")]
pub const KEY: &str = "openfeo.confirm_secs";

/// The knob from the kernel command line: a window a request could name itself, 10 to 600 s.
/// Anything else is said and ignored. Harness builds only.
#[cfg(feature = "harness")]
#[must_use]
pub fn from_cmdline(cmdline: &Cmdline) -> Option<u32> {
    let text = cmdline.get(KEY)?;
    let window = text
        .parse::<u32>()
        .ok()
        .filter(|secs| openfeo_api::keeper::WINDOW_SECS.contains(secs));
    if window.is_none() {
        tracing::warn!("{KEY}={text} is not a window of 10 to 600 s; ignored");
    }
    window
}

/// Release builds never read the knob.
#[cfg(not(feature = "harness"))]
#[must_use]
pub fn from_cmdline(_cmdline: &Cmdline) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use openfeo_init::cmdline;

    use super::*;

    #[cfg(feature = "harness")]
    #[test]
    fn a_harness_build_reads_the_window() {
        let window = |line: &str| from_cmdline(&cmdline::parse(line));
        assert_eq!(window("quiet openfeo.confirm_secs=15 ro"), Some(15));
        assert_eq!(window("openfeo.confirm_secs=10"), Some(10));
        assert_eq!(window("openfeo.confirm_secs=600"), Some(600));
        assert_eq!(window("quiet ro"), None);
        // Only a window a request could name itself: 10 to 600 s, in digits.
        for bad in [
            "openfeo.confirm_secs=",
            "openfeo.confirm_secs=5",
            "openfeo.confirm_secs=9",
            "openfeo.confirm_secs=601",
            "openfeo.confirm_secs=0",
            "openfeo.confirm_secs=soon",
            "openfeo.confirm_secs=15s",
            "openfeo.confirm_secs=-15",
            "openfeo.confirm_secs=4294967311",
        ] {
            assert_eq!(window(bad), None, "{bad}");
        }
        assert_eq!(KEY, "openfeo.confirm_secs");
    }

    #[cfg(not(feature = "harness"))]
    #[test]
    fn a_release_build_has_no_such_knob() {
        let line = cmdline::parse("quiet openfeo.confirm_secs=15 ro");
        assert_eq!(from_cmdline(&line), None);
    }
}
