// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router's API (SPEC §8.3, §9): one HTTPS listener on the LAN carrying the panel's files,
//! a few HTTP calls, a binary WebSocket and gRPC, behind a password and a session token. The
//! decisions (certificate, backoff, sessions, who may connect, the envelope) are small cores
//! that take the time as an argument; the tokio drivers over them hold no policy.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cert;
pub mod envelope;
pub mod gate;
pub mod limits;
pub mod pb;

/// Served where the panel will be when the binary was built without one (M4 part 1b embeds it).
pub const PLACEHOLDER_PAGE: &str = "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>OpenFeO</title></head>\n<body>\n<h1>OpenFeO</h1>\n<p>The panel was not built into this binary. The API is up.</p>\n</body>\n</html>\n";

#[cfg(test)]
mod tests {
    use super::PLACEHOLDER_PAGE;

    #[test]
    fn the_placeholder_says_the_panel_was_not_built() {
        assert!(PLACEHOLDER_PAGE.starts_with("<!doctype html>"));
        assert!(
            PLACEHOLDER_PAGE.contains("The panel was not built into this binary. The API is up.")
        );
    }

    #[test]
    fn ring_is_the_only_crypto_provider() {
        // Builds a server config on the ring provider: fails to compile if the feature is gone.
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        assert!(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .is_ok()
        );
    }
}
