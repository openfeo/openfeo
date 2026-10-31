// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 client tasks (SPEC §7.2): one supervised task per `[wans.dhcp]` WAN, each driving
//! `openfeo_net::dhcp4::Driver` on the WAN's port, publishing the lease as a World fact for the
//! reconcilers, keeping the last lease under `/state/leases` for INIT-REBOOT after a reboot, and
//! the box's DUID under `/state/identity` (SPEC §5.2). Every line logged here is a contract with
//! the harness scenarios.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read as _};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::Ipv4Net;
use openfeo_config::load::STATE_FILE_MODE;
use openfeo_config::{Dhcp4Lease, Dhcp4Route, file, wan};
use openfeo_net::dhcp4::{Driver, DriverConfig, Event};
use openfeo_platform::atomic;
use openfeo_proto_dhcp4::identity::{client_id, duid_ll, from_hex, hex, iaid};
use openfeo_proto_dhcp4::wire::ClasslessRoute;
use openfeo_proto_dhcp4::{ClientConfig, Lease, Unbound};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::{Dhcp4Fact, World};
use tracing::{debug, info, warn};

/// The box's DUID (DUID-LL, RFC 8415 §11.4) as lowercase hex (SPEC §5.2 `identity/`).
pub const DUID_PATH: &str = "/state/identity/duid";
/// Where each WAN's last DHCPv4 lease is kept (SPEC §5.2 `leases/`).
pub const LEASES_DIR: &str = "/state/leases";

/// `/state/leases/dhcp4-<wan>.toml`.
#[must_use]
pub fn lease_path(wan: &str) -> PathBuf {
    Path::new(LEASES_DIR).join(format!("dhcp4-{wan}.toml"))
}

/// The DUID at `path`, or a DUID-LL made from `lowest_mac` and written there (mode 0600);
/// `true` when it was just made. A file that is not hex is replaced.
///
/// # Errors
///
/// When the file cannot be read for a reason other than its absence, or cannot be written.
pub fn load_or_create_duid(path: &Path, lowest_mac: [u8; 6]) -> io::Result<(Vec<u8>, bool)> {
    match fs::read_to_string(path) {
        Ok(text) => {
            if let Some(duid) = from_hex(text.trim()).filter(|duid| !duid.is_empty()) {
                return Ok((duid, false));
            }
            warn!("identity: {}: not a DUID; replacing it", path.display());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let duid = duid_ll(lowest_mac);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic::write(
        path,
        format!("{}\n", hex(&duid)).as_bytes(),
        STATE_FILE_MODE,
    )?;
    Ok((duid, true))
}

/// The lease as the reconcilers see it.
#[must_use]
pub fn fact_from(lease: &Lease) -> Dhcp4Fact {
    Dhcp4Fact {
        address: net(lease.address, lease.prefix),
        server: lease.server,
        gateway: lease.gateway,
        routes: lease
            .routes
            .iter()
            .map(|route| (net(route.dst, route.prefix).trunc(), route.via))
            .collect(),
        dns: lease.dns.clone(),
        domain: lease.domain.clone(),
        mtu: lease.mtu.map(u32::from),
    }
}

fn net(address: Ipv4Addr, prefix: u8) -> Ipv4Net {
    Ipv4Net::new(address, prefix).unwrap_or_else(|_| Ipv4Net::from(address))
}

/// The lease as its file keeps it.
#[must_use]
pub fn lease_file(wan: &str, mac: [u8; 6], lease: &Lease, obtained_unix: u64) -> Dhcp4Lease {
    Dhcp4Lease {
        wan: wan.to_owned(),
        mac: mac_text(mac),
        address: format!("{}/{}", lease.address, lease.prefix),
        server: lease.server.to_string(),
        gateway: lease.gateway.map(|g| g.to_string()).unwrap_or_default(),
        dns: lease.dns.iter().map(ToString::to_string).collect(),
        domain: lease.domain.clone().unwrap_or_default(),
        mtu: lease.mtu.map_or(0, u32::from),
        routes: lease
            .routes
            .iter()
            .map(|route| Dhcp4Route {
                dst: format!("{}/{}", route.dst, route.prefix),
                via: route.via.to_string(),
            })
            .collect(),
        lease_secs: lease.lease_secs,
        t1_secs: lease.t1_secs,
        t2_secs: lease.t2_secs,
        obtained_unix,
        ntp: lease.ntp.iter().map(ToString::to_string).collect(),
        broadcast: lease.broadcast.map(|b| b.to_string()).unwrap_or_default(),
    }
}

/// The lease a file holds, if it is this WAN's and this port's and parses.
#[must_use]
pub fn lease_from_file(file: &Dhcp4Lease, wan: &str, mac: [u8; 6]) -> Option<Lease> {
    if file.wan != wan || file.mac != mac_text(mac) {
        return None;
    }
    let address: Ipv4Net = file.address.parse().ok()?;
    let routes = file
        .routes
        .iter()
        .map(|route| {
            let dst: Ipv4Net = route.dst.parse().ok()?;
            Some(ClasslessRoute {
                dst: dst.addr(),
                prefix: dst.prefix_len(),
                via: route.via.parse().ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Lease {
        address: address.addr(),
        prefix: address.prefix_len(),
        server: file.server.parse().ok()?,
        gateway: optional_addr(&file.gateway).ok()?,
        routes,
        dns: addrs(&file.dns)?,
        domain: (!file.domain.is_empty()).then(|| file.domain.clone()),
        mtu: u16::try_from(file.mtu).ok().filter(|mtu| *mtu != 0),
        ntp: addrs(&file.ntp)?,
        broadcast: optional_addr(&file.broadcast).ok()?,
        lease_secs: file.lease_secs,
        t1_secs: file.t1_secs,
        t2_secs: file.t2_secs,
    })
}

/// `Ok(None)` for an empty field, an error for text that is not an address.
fn optional_addr(text: &str) -> Result<Option<Ipv4Addr>, std::net::AddrParseError> {
    if text.is_empty() {
        Ok(None)
    } else {
        text.parse().map(Some)
    }
}

fn addrs(texts: &[String]) -> Option<Vec<Ipv4Addr>> {
    texts.iter().map(|text| text.parse().ok()).collect()
}

pub(crate) fn mac_text(mac: [u8; 6]) -> String {
    let mut out = String::with_capacity(17);
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `wan wan0 dhcp bound 203.0.113.100/24 via 203.0.113.1 lease=60s t1=20s t2=40s server=203.0.113.1`.
fn bound_line(wan: &str, lease: &Lease) -> String {
    format!(
        "wan {wan} dhcp bound {}/{} via {} lease={}s t1={}s t2={}s server={}",
        lease.address,
        lease.prefix,
        lease
            .default_gateway()
            .map_or_else(|| "none".to_owned(), |gateway| gateway.to_string()),
        lease.lease_secs,
        lease.t1_secs,
        lease.t2_secs,
        lease.server
    )
}

/// `wan wan0 dhcp options dns=203.0.113.1 domain=isp.example mtu=1400 routes=2`.
fn options_line(wan: &str, lease: &Lease) -> String {
    let dns = if lease.dns.is_empty() {
        "none".to_owned()
    } else {
        lease
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "wan {wan} dhcp options dns={dns} domain={} mtu={} routes={}",
        lease.domain.as_deref().unwrap_or("none"),
        lease
            .mtu
            .map_or_else(|| "none".to_owned(), |mtu| mtu.to_string()),
        lease.routes.len()
    )
}

/// One supervised task per `[wans.dhcp]` WAN in the current configuration.
pub fn spawn_all(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    let config = publisher.current().config.clone();
    for wan in &config.wans {
        let Some(wan::Kind::Dhcp(dhcp)) = &wan.kind else {
            continue;
        };
        let task = WanTask {
            wan: wan.name.clone(),
            port: wan.port.clone(),
            hostname: (!dhcp.hostname.is_empty()).then(|| dhcp.hostname.clone()),
            vendor_class: (!dhcp.vendor_class.is_empty())
                .then(|| dhcp.vendor_class.clone().into_bytes()),
        };
        let publisher = publisher.clone();
        let world_rx = world_rx.clone();
        supervisor.spawn(format!("dhcp4-{}", wan.name), move || {
            let task = task.clone();
            let publisher = publisher.clone();
            let world_rx = world_rx.clone();
            async move { run(&task, &publisher, world_rx).await }
        });
    }
}

#[derive(Debug, Clone)]
struct WanTask {
    wan: String,
    port: String,
    hostname: Option<String>,
    vendor_class: Option<Vec<u8>>,
}

/// The task: wait for the port, settle the identity, run the driver, publish what it says, and
/// tell it about carrier changes.
async fn run(
    task: &WanTask,
    publisher: &Publisher,
    mut world_rx: WorldRx,
) -> Result<(), TaskError> {
    let (ifindex, mac) = wait_for_link(&mut world_rx, &task.port).await?;
    let lowest = lowest_port_mac(&world_rx.borrow()).unwrap_or(mac);
    let duid = match load_or_create_duid(Path::new(DUID_PATH), lowest) {
        Ok((duid, new)) => {
            info!(
                "identity: duid {} ({})",
                hex(&duid),
                if new { "new" } else { "known" }
            );
            duid
        }
        Err(err) => {
            warn!("identity: cannot keep {DUID_PATH}: {err}; using an unsaved DUID");
            duid_ll(lowest)
        }
    };
    let path = lease_path(&task.wan);
    let initial_lease = read_lease(&path, &task.wan, mac);
    let mut client = ClientConfig::new(mac, client_id(iaid(mac), &duid));
    client.hostname = task.hostname.clone();
    client.vendor_class = task.vendor_class.clone();
    let failed = |err: openfeo_net::dhcp4::DriverError| {
        TaskError::from(format!("dhcp4 {}: {err}", task.wan))
    };
    let mut driver = Driver::new(DriverConfig {
        ifname: task.port.clone(),
        ifindex,
        mac,
        client,
        initial_lease,
        seed: seed(u64::from(ifindex)),
    })
    .map_err(failed)?;
    let mut carrier = true;
    loop {
        let events = tokio::select! {
            events = driver.step() => events.map_err(failed)?,
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                let (up, index) = {
                    let world = world_rx.borrow_and_update();
                    let link = world.links.get(&task.port);
                    (
                        link.is_some_and(|link| link.up && link.carrier),
                        link.map(|link| link.index),
                    )
                };
                if let Some(index) = index
                    && index != ifindex
                {
                    // The device was replaced (a USB NIC re-plugged, say): the sockets are bound
                    // to the old index, so start over.
                    return Err(format!(
                        "dhcp4 {}: {} changed index {ifindex} -> {index}; restarting",
                        task.wan, task.port
                    )
                    .into());
                }
                if up == carrier {
                    continue;
                }
                carrier = up;
                driver.link(carrier).map_err(failed)?
            }
        };
        for event in events {
            publish(task, mac, &path, publisher, event);
        }
    }
}

/// The port's index and MAC once it is up with carrier.
pub(crate) async fn wait_for_link(
    world_rx: &mut WorldRx,
    port: &str,
) -> Result<(u32, [u8; 6]), TaskError> {
    loop {
        let ready = world_rx
            .borrow_and_update()
            .links
            .get(port)
            .filter(|link| link.up && link.carrier)
            .and_then(|link| link.mac.map(|mac| (link.index, mac.0)));
        if let Some(found) = ready {
            return Ok(found);
        }
        world_rx
            .changed()
            .await
            .map_err(|_| "world publisher gone")?;
    }
}

/// The MAC of the lowest-numbered port that has one: what the DUID is made from.
fn lowest_port_mac(world: &World) -> Option<[u8; 6]> {
    world
        .ports
        .names()
        .find_map(|name| world.links.get(name).and_then(|link| link.mac))
        .map(|mac| mac.0)
}

/// The lease file's lease for this WAN and port, if any.
fn read_lease(path: &Path, wan: &str, mac: [u8; 6]) -> Option<Lease> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!("wan {wan} dhcp cannot read {}: {err}", path.display());
            return None;
        }
    };
    let file = match file::parse_dhcp4_lease(&text) {
        Ok(file) => file,
        Err(err) => {
            warn!("wan {wan} dhcp {}: {err}; ignoring it", path.display());
            return None;
        }
    };
    let lease = lease_from_file(&file, wan, mac);
    if lease.is_none() {
        warn!(
            "wan {wan} dhcp {}: for another WAN or port; ignoring it",
            path.display()
        );
    }
    lease
}

fn save_lease(path: &Path, wan: &str, mac: [u8; 6], lease: &Lease) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let result = file::render_dhcp4_lease(&lease_file(wan, mac, lease, now))
        .map_err(|err| io::Error::other(err.to_string()))
        .and_then(|text| {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            atomic::write(path, text.as_bytes(), STATE_FILE_MODE)
        });
    match result {
        Ok(()) => debug!("wan {wan} dhcp lease saved {}", path.display()),
        Err(err) => warn!(
            "wan {wan} dhcp cannot save lease to {}: {err}",
            path.display()
        ),
    }
}

/// Log the contract line, publish the fact, keep the file.
fn publish(task: &WanTask, mac: [u8; 6], path: &Path, publisher: &Publisher, event: Event) {
    let wan = &task.wan;
    match event {
        Event::Discover => info!("wan {wan} dhcp discover"),
        Event::Offer { address, server } => info!("wan {wan} dhcp offer {address} from {server}"),
        Event::Request(address) => info!("wan {wan} dhcp request {address}"),
        Event::Rebooting(address) => info!("wan {wan} dhcp init-reboot {address}"),
        Event::Bound { lease, renewed } => {
            if renewed {
                info!(
                    "wan {wan} dhcp renewed {}/{} lease={}s",
                    lease.address, lease.prefix, lease.lease_secs
                );
            } else {
                info!("{}", bound_line(wan, &lease));
                info!("{}", options_line(wan, &lease));
            }
            let fact = fact_from(&lease);
            publisher.update(|world| {
                Arc::make_mut(&mut world.dhcp4).insert(wan.clone(), fact);
            });
            save_lease(path, wan, mac, &lease);
        }
        Event::Unbound(why) => {
            match &why {
                Unbound::Nak(text) => {
                    info!("wan {wan} dhcp nak {}", text.as_deref().unwrap_or("-"));
                    if let Err(err) = fs::remove_file(path)
                        && err.kind() != io::ErrorKind::NotFound
                    {
                        warn!("wan {wan} dhcp cannot remove {}: {err}", path.display());
                    }
                }
                Unbound::Expired => info!("wan {wan} dhcp expired"),
                Unbound::RebootTimedOut => info!("wan {wan} dhcp reboot timed out"),
            }
            publisher.update(|world| {
                Arc::make_mut(&mut world.dhcp4).remove(wan);
            });
        }
    }
}

/// Eight random bytes for a protocol core's transaction ids and jitter; `salt` tells the
/// clock fallback's callers apart.
pub(crate) fn seed(salt: u64) -> u64 {
    let mut bytes = [0u8; 8];
    match fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes)) {
        Ok(()) => u64::from_ne_bytes(bytes),
        Err(err) => {
            warn!("/dev/urandom: {err}; seeding from the clock");
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| u64::from(since.subsec_nanos()));
            nanos ^ salt.rotate_left(32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::file::{parse_dhcp4_lease, render_dhcp4_lease};
    use std::os::unix::fs::PermissionsExt;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xfe, 0x00, 0x00];
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

    fn sample_lease() -> Lease {
        Lease {
            address: Ipv4Addr::new(203, 0, 113, 100),
            prefix: 24,
            server: SERVER,
            gateway: None,
            routes: vec![
                ClasslessRoute {
                    dst: Ipv4Addr::UNSPECIFIED,
                    prefix: 0,
                    via: SERVER,
                },
                ClasslessRoute {
                    dst: Ipv4Addr::new(198, 51, 100, 0),
                    prefix: 24,
                    via: SERVER,
                },
            ],
            dns: vec![SERVER],
            domain: Some("isp.example".to_owned()),
            mtu: Some(1400),
            ntp: vec![SERVER],
            broadcast: Some(Ipv4Addr::new(203, 0, 113, 255)),
            lease_secs: 60,
            t1_secs: 20,
            t2_secs: 40,
        }
    }

    #[test]
    fn duid_is_created_once_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity").join("duid");
        let (duid, new) = load_or_create_duid(&path, MAC).unwrap();
        assert!(new);
        assert_eq!(hex(&duid), "00030001525400fe0000");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            "00030001525400fe0000"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let (again, new) = load_or_create_duid(&path, [1; 6]).unwrap();
        assert!(!new, "a known DUID is not regenerated for another MAC");
        assert_eq!(again, duid);

        std::fs::write(&path, "not hex at all\n").unwrap();
        let (replaced, new) = load_or_create_duid(&path, [1; 6]).unwrap();
        assert!(new, "a corrupt file is replaced");
        assert_eq!(replaced, duid_ll([1; 6]));
    }

    #[test]
    fn lease_file_round_trips_through_the_fact_and_back() {
        let lease = sample_lease();
        let file = lease_file("wan0", MAC, &lease, 1_793_491_200);
        assert_eq!(file.mac, "52:54:00:fe:00:00");
        assert_eq!(file.address, "203.0.113.100/24");
        assert_eq!(file.obtained_unix, 1_793_491_200);
        let parsed = parse_dhcp4_lease(&render_dhcp4_lease(&file).unwrap()).unwrap();
        assert_eq!(parsed, file);
        assert_eq!(lease_from_file(&parsed, "wan0", MAC), Some(lease));
        assert_eq!(
            lease_from_file(&parsed, "wan0", [1; 6]),
            None,
            "another port's MAC"
        );
        assert_eq!(lease_from_file(&parsed, "wan1", MAC), None, "another WAN");
        let mut broken = parsed;
        broken.address = "not an address".to_owned();
        assert_eq!(lease_from_file(&broken, "wan0", MAC), None);
    }

    #[test]
    fn fact_from_lease_maps_routes_and_mtu() {
        let fact = fact_from(&sample_lease());
        assert_eq!(fact.address.to_string(), "203.0.113.100/24");
        assert_eq!(fact.server, SERVER);
        assert_eq!(fact.gateway, None, "classless routes win");
        assert_eq!(
            fact.routes,
            vec![
                ("0.0.0.0/0".parse().unwrap(), SERVER),
                ("198.51.100.0/24".parse().unwrap(), SERVER),
            ]
        );
        assert_eq!(fact.dns, vec![SERVER]);
        assert_eq!(fact.domain.as_deref(), Some("isp.example"));
        assert_eq!(fact.mtu, Some(1400));
        assert_eq!(
            lease_path("wan0").to_str(),
            Some("/state/leases/dhcp4-wan0.toml")
        );
    }

    #[test]
    fn console_lines_follow_the_contract() {
        let lease = sample_lease();
        assert_eq!(
            bound_line("wan0", &lease),
            "wan wan0 dhcp bound 203.0.113.100/24 via 203.0.113.1 lease=60s t1=20s t2=40s server=203.0.113.1"
        );
        assert_eq!(
            options_line("wan0", &lease),
            "wan wan0 dhcp options dns=203.0.113.1 domain=isp.example mtu=1400 routes=2"
        );
        let mut bare = lease;
        bare.routes.clear();
        bare.dns.clear();
        bare.domain = None;
        bare.mtu = None;
        assert_eq!(
            bound_line("wan0", &bare),
            "wan wan0 dhcp bound 203.0.113.100/24 via none lease=60s t1=20s t2=40s server=203.0.113.1"
        );
        assert_eq!(
            options_line("wan0", &bare),
            "wan wan0 dhcp options dns=none domain=none mtu=none routes=0"
        );
    }
}
