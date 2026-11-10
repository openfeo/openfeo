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
pub mod events;
pub mod gate;
pub mod grpc;
pub mod http;
pub mod limits;
pub mod listener;
pub mod pb;
pub mod server;
pub mod telemetry;
#[cfg(test)]
pub(crate) mod testing;
pub mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use openfeo_config::admin::ConfigState;
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::{Publisher, WorldRx};
use openfeo_world::World;
use openfeo_world::health::HealthView;
use tokio::sync::watch;

pub use crate::server::Limits;
use crate::telemetry::CounterSource;

/// Whether a connection from this address is taken: [`gate::client_admitted`] in the router.
pub type Admit = Arc<dyn Fn(&World, SocketAddr) -> bool + Send + Sync>;

/// Where to listen and whom to admit.
pub struct Listen {
    /// The HTTPS address: `[::]:443` in the router.
    pub https: SocketAddr,
    /// The address that redirects to HTTPS: `[::]:80` in the router.
    pub http: SocketAddr,
    /// The gate.
    pub admit: Admit,
}

/// What the API needs from the router.
pub struct ApiDeps {
    /// The World.
    pub world: WorldRx,
    /// Its publisher.
    pub publisher: Arc<Publisher>,
    /// The heartbeat's view of health.
    pub health: watch::Receiver<HealthView>,
    /// Where counters are read from.
    pub counters: Arc<dyn CounterSource>,
    /// `/state/config.toml`.
    pub config_path: PathBuf,
    /// `/state/tls`.
    pub tls_dir: PathBuf,
    /// How the running config came to be.
    pub config_state: ConfigState,
    /// The binary's version.
    pub version: String,
    /// The build's epoch, the clock's floor, in Unix seconds.
    pub build_epoch: u64,
    /// Where to listen and whom to admit.
    pub listen: Listen,
    /// The limits in force.
    pub limits: Limits,
}

/// Bind and serve the API until a listener fails.
///
/// # Errors
///
/// When a port cannot be bound, the certificate cannot be made, or a listener stops.
pub async fn run(deps: ApiDeps) -> Result<(), TaskError> {
    listener::Server::bind(deps).await?.serve().await
}

/// Every route on the HTTPS listener, before the guard closes over them: the plain HTTP
/// calls, the WebSocket, and the two gRPC services under their own paths.
pub(crate) fn routes(shared: &Arc<server::Shared>) -> axum::Router<Arc<server::Shared>> {
    use tonic::server::NamedService;

    use pb::auth_service_server::AuthServiceServer;
    use pb::state_service_server::StateServiceServer;

    let grpc = grpc::Grpc::new(shared.clone());
    let auth = AuthServiceServer::new(grpc.clone()).max_decoding_message_size(limits::MAX_BODY);
    let state = StateServiceServer::new(grpc).max_decoding_message_size(limits::MAX_BODY);
    http::routes()
        .route("/ws", axum::routing::get(ws::upgrade))
        .route_service(
            &format!("/{}/{{*call}}", AuthServiceServer::<grpc::Grpc>::NAME),
            auth,
        )
        .route_service(
            &format!("/{}/{{*call}}", StateServiceServer::<grpc::Grpc>::NAME),
            state,
        )
}

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
