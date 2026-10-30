// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `<crate version>+<build id>[.harness]`; the build id is `git describe` from the Makefile, or
//! `dev`. Builds with the `harness` feature (test hooks compiled in, ADR-0007) carry a `.harness`
//! marker so a lab image is never mistaken for a release.

/// The version string logged at start and printed by `--version`.
#[must_use]
pub fn version() -> String {
    let marker = if cfg!(feature = "harness") {
        ".harness"
    } else {
        ""
    };
    format!(
        "{}+{}{marker}",
        env!("CARGO_PKG_VERSION"),
        option_env!("OPENFEO_BUILD_ID").unwrap_or("dev")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_has_crate_version_and_build_id() {
        let v = version();
        assert!(v.starts_with("0.1.0+"), "{v}");
        assert!(v.len() > "0.1.0+".len(), "{v}");
    }

    #[test]
    fn harness_builds_are_marked() {
        let v = version();
        assert_eq!(v.ends_with(".harness"), cfg!(feature = "harness"), "{v}");
    }
}
