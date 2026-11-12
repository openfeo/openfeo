// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The API beside the other services (SPEC §8.3): one supervised task running
//! `openfeo_api::run` on the LAN, given the World, the heartbeat's view of health, and the
//! router's source of counters (netlink for the links, the conntrack sysctls for the rest).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use openfeo_api::telemetry::CounterSource;
use openfeo_api::{ApiDeps, Limits, Listen};
use openfeo_config::admin::ConfigState;
use openfeo_config::state::{Counters, LinkCounters};
use openfeo_netlink::{LinkStats, Netlink};
use openfeo_platform::sysctl;
use openfeo_runtime::clock::boot_ms;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::health::HealthView;
use tokio::sync::watch;
use tracing::debug;

use crate::router::CONFIG_PATH;
use crate::version::build_epoch;

/// Where the listener's certificate and key are kept (SPEC §9).
pub const TLS_DIR: &str = "/state/tls";
/// HTTPS, on every address; the gate and the firewall keep it to the private LANs.
const HTTPS: &str = "[::]:443";
/// Redirects to HTTPS.
const HTTP: &str = "[::]:80";

/// Tracked connections now, as `openfeo_platform::sysctl` names keys (a path under
/// `/proc/sys`).
const CONNTRACK_COUNT: &str = "net/netfilter/nf_conntrack_count";
/// The most the kernel will track.
const CONNTRACK_MAX: &str = "net/netfilter/nf_conntrack_max";

type StatsFuture<'a> = Pin<Box<dyn Future<Output = Option<Vec<LinkStats>>> + Send + 'a>>;
type StatsSource = Box<dyn Fn() -> StatsFuture<'static> + Send + Sync>;
type SysctlSource = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The router's counters: every link's from one netlink dump, and conntrack's count and limit.
pub struct RouterCounters {
    stats: StatsSource,
    sysctl: SysctlSource,
}

impl RouterCounters {
    /// Counters read through `nl` and `/proc/sys`.
    pub fn new(nl: Netlink) -> Self {
        Self::with(
            move || {
                let nl = nl.clone();
                Box::pin(async move {
                    nl.link_stats()
                        .await
                        .map_err(|err| debug!("counters: {err}"))
                        .ok()
                })
            },
            |key| sysctl::read(key).ok(),
        )
    }

    fn with(
        stats: impl Fn() -> StatsFuture<'static> + Send + Sync + 'static,
        sysctl: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        RouterCounters {
            stats: Box::new(stats),
            sysctl: Box::new(sysctl),
        }
    }

    fn number(&self, key: &str) -> u32 {
        (self.sysctl)(key)
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl CounterSource for RouterCounters {
    fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>> {
        Box::pin(async move {
            let links = (self.stats)().await?;
            Some(Counters {
                monotonic_ms: boot_ms(),
                links: links
                    .into_iter()
                    .map(|link| LinkCounters {
                        name: link.name,
                        rx_bytes: link.rx_bytes,
                        tx_bytes: link.tx_bytes,
                        rx_packets: link.rx_packets,
                        tx_packets: link.tx_packets,
                        rx_errors: link.rx_errors,
                        tx_errors: link.tx_errors,
                    })
                    .collect(),
                // Absent until the first connection is tracked: the module's sysctls appear
                // with it.
                conntrack: self.number(CONNTRACK_COUNT),
                conntrack_max: self.number(CONNTRACK_MAX),
            })
        })
    }
}

/// What the API is told once, at boot.
#[derive(Debug, Clone)]
pub struct Boot {
    /// How the running config came to be.
    pub config_state: ConfigState,
    /// The binary's version.
    pub version: String,
    /// One more host the API takes as its own: the lab's relay, in a harness build
    /// ([`crate::panel_host`]); always `None` in a release build.
    pub extra_host: Option<String>,
    /// A shorter window for a change of config, in a harness build ([`crate::confirm_secs`]);
    /// always `None` in a release build, which waits the 120 s of SPEC §5.5.
    pub confirm_secs: Option<u32>,
}

/// Run the API as a supervised task: restarted if it dies, named by health if it will not
/// stay up, like any other.
pub fn spawn(
    supervisor: &Supervisor,
    publisher: &Arc<Publisher>,
    world: &WorldRx,
    health: &watch::Receiver<HealthView>,
    nl: &Netlink,
    boot: Boot,
) {
    let (publisher, world, health) = (publisher.clone(), world.clone(), health.clone());
    let counters: Arc<dyn CounterSource> = Arc::new(RouterCounters::new(nl.clone()));
    supervisor.spawn("api", move || {
        let (publisher, world, health) = (publisher.clone(), world.clone(), health.clone());
        let counters = counters.clone();
        let Boot {
            config_state,
            version,
            extra_host,
            confirm_secs,
        } = boot.clone();
        async move {
            openfeo_api::run(ApiDeps {
                world,
                publisher,
                health,
                counters,
                config_path: PathBuf::from(CONFIG_PATH),
                tls_dir: PathBuf::from(TLS_DIR),
                config_state,
                version,
                build_epoch: build_epoch(),
                listen: Listen {
                    https: HTTPS.parse()?,
                    http: HTTP.parse()?,
                    admit: Arc::new(openfeo_api::gate::client_admitted),
                },
                limits: Limits::default(),
                extra_host,
                confirm_secs: confirm_secs.unwrap_or(openfeo_api::keeper::DEFAULT_WINDOW_SECS),
            })
            .await
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(name: &str, rx_bytes: u64, tx_bytes: u64) -> LinkStats {
        LinkStats {
            name: name.to_owned(),
            rx_bytes,
            tx_bytes,
            ..LinkStats::default()
        }
    }

    #[tokio::test]
    async fn the_routers_counter_source_reports_every_link_and_conntrack() {
        let source = RouterCounters::with(
            || Box::pin(async { Some(vec![stats("p0", 10, 20), stats("br-lan0", 3, 4)]) }),
            |key| match key {
                CONNTRACK_COUNT => Some("42\n".to_owned()),
                CONNTRACK_MAX => Some("262144\n".to_owned()),
                _ => None,
            },
        );
        let counters = source.read().await.unwrap();
        assert_eq!(counters.links.len(), 2);
        assert_eq!(
            (
                counters.links[0].name.as_str(),
                counters.links[0].rx_bytes,
                counters.links[0].tx_bytes
            ),
            ("p0", 10, 20)
        );
        assert_eq!((counters.conntrack, counters.conntrack_max), (42, 262_144));
        assert!(counters.monotonic_ms > 0);
    }

    #[tokio::test]
    async fn no_conntrack_yet_is_zero_and_a_failed_dump_is_no_sample() {
        let quiet = RouterCounters::with(|| Box::pin(async { Some(Vec::new()) }), |_| None);
        let counters = quiet.read().await.unwrap();
        assert_eq!((counters.conntrack, counters.conntrack_max), (0, 0));
        let failing = RouterCounters::with(|| Box::pin(async { None }), |_| None);
        assert_eq!(failing.read().await, None);
    }

    #[test]
    fn the_conntrack_keys_are_paths_the_sysctl_reader_can_open() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net/netfilter");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nf_conntrack_count"), "7\n").unwrap();
        std::fs::write(dir.join("nf_conntrack_max"), "65536\n").unwrap();
        assert_eq!(
            sysctl::read_at(root.path(), CONNTRACK_COUNT)
                .unwrap()
                .trim(),
            "7"
        );
        assert_eq!(
            sysctl::read_at(root.path(), CONNTRACK_MAX).unwrap().trim(),
            "65536"
        );
    }

    #[test]
    fn the_listen_addresses_are_every_address_on_443_and_80() {
        let https: std::net::SocketAddr = HTTPS.parse().unwrap();
        let http: std::net::SocketAddr = HTTP.parse().unwrap();
        assert_eq!((https.port(), http.port()), (443, 80));
        assert!(https.ip().is_unspecified() && http.ip().is_unspecified());
        assert_eq!(TLS_DIR, "/state/tls");
    }
}
