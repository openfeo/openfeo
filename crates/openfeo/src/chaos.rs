// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fault injection for the harness (ADR-0007): `openfeo.chaos=child-exit:<secs>` makes the router
//! child exit with status 3 after that long; `child-hang:<secs>` makes it stop heartbeating.
//! Without the `harness` feature the knob parser is not compiled and the command line is never
//! consulted.

use std::fmt;
use std::time::Duration;

use openfeo_init::cmdline::Cmdline;

/// What to break, and when. Release builds never construct one: [`from_cmdline`] is a constant
/// `None` there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "harness"), allow(dead_code))]
pub enum Chaos {
    /// Exit with status 3.
    ChildExit {
        /// Time after start.
        after: Duration,
    },
    /// Stop heartbeating but keep running.
    ChildHang {
        /// Time after start.
        after: Duration,
    },
}

impl Chaos {
    /// When the fault fires, measured from the child's start.
    #[must_use]
    pub const fn after(self) -> Duration {
        match self {
            Self::ChildExit { after } | Self::ChildHang { after } => after,
        }
    }
}

impl fmt::Display for Chaos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildExit { after } => write!(f, "child-exit after={}s", after.as_secs()),
            Self::ChildHang { after } => write!(f, "child-hang after={}s", after.as_secs()),
        }
    }
}

/// The kernel command-line key.
#[cfg(feature = "harness")]
pub const KEY: &str = "openfeo.chaos";

/// A value that is not `child-exit:<secs>` or `child-hang:<secs>`.
#[cfg(feature = "harness")]
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(String);

#[cfg(feature = "harness")]
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bad {KEY} value `{}` (expected child-exit:<secs> or child-hang:<secs>)",
            self.0
        )
    }
}

#[cfg(feature = "harness")]
impl std::error::Error for ParseError {}

/// Parse a knob value.
///
/// # Errors
///
/// [`ParseError`] for anything but the two known kinds with a whole number of seconds.
#[cfg(feature = "harness")]
pub fn parse(value: &str) -> Result<Chaos, ParseError> {
    let bad = || ParseError(value.to_owned());
    let (kind, secs) = value.split_once(':').ok_or_else(bad)?;
    let after = secs.parse().map(Duration::from_secs).map_err(|_| bad())?;
    match kind {
        "child-exit" => Ok(Chaos::ChildExit { after }),
        "child-hang" => Ok(Chaos::ChildHang { after }),
        _ => Err(bad()),
    }
}

/// The knob from the kernel command line. Harness builds only.
#[cfg(feature = "harness")]
#[must_use]
pub fn from_cmdline(cmdline: &Cmdline) -> Option<Chaos> {
    cmdline.get(KEY).and_then(|value| parse(value).ok())
}

/// Release builds never read the knob.
#[cfg(not(feature = "harness"))]
#[must_use]
pub fn from_cmdline(_cmdline: &Cmdline) -> Option<Chaos> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_init::cmdline;

    #[cfg(feature = "harness")]
    #[test]
    fn parses_knobs() {
        assert_eq!(
            parse("child-exit:3").unwrap(),
            Chaos::ChildExit {
                after: Duration::from_secs(3)
            }
        );
        assert_eq!(
            parse("child-hang:10").unwrap(),
            Chaos::ChildHang {
                after: Duration::from_secs(10)
            }
        );
    }

    #[cfg(feature = "harness")]
    #[test]
    fn rejects_garbage() {
        assert!(parse("bogus").is_err());
        assert!(parse("child-exit:x").is_err());
        assert!(parse("child-exit").is_err());
    }

    #[cfg(feature = "harness")]
    #[test]
    fn cmdline_knob_is_read_with_feature() {
        let c = cmdline::parse("openfeo.chaos=child-exit:3");
        assert!(from_cmdline(&c).is_some());
    }

    #[cfg(not(feature = "harness"))]
    #[test]
    fn cmdline_knob_is_ignored_without_feature() {
        let c = cmdline::parse("openfeo.chaos=child-exit:3");
        assert!(from_cmdline(&c).is_none());
    }
}
