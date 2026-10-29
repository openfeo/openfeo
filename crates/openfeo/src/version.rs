// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `<crate version>+<build id>`; the build id is `git describe` from the Makefile, or `dev`.

/// The version string logged at start and printed by `--version`.
#[must_use]
pub fn version() -> String {
    format!(
        "{}+{}",
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
}
