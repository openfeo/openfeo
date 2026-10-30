// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Physical ports by bus path (SPEC §7.1): in M0 only enumerated and logged; renaming to `pN`
//! arrives with M1. Identity comes from the device's `subsystem`: a PCI device is named by its
//! own address, a virtio device by its PCI parent's; anything else (USB, platform, virtual) is
//! reported as skipped rather than given a made-up id.

use std::fs;
use std::io;
use std::path::Path;

/// One physical port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// Kernel interface name today (`eth0`).
    pub ifname: String,
    /// Stable identity: `pci-DDDD:BB:DD.F`.
    pub id: String,
    /// MAC address as sysfs prints it.
    pub mac: String,
}

/// A netdev that is not (yet) a port, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Kernel interface name.
    pub ifname: String,
    /// Human-readable reason.
    pub reason: String,
}

/// Everything under `/sys/class/net`, sorted into ports and skips.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Ports sorted by (id, mac).
    pub ports: Vec<Port>,
    /// Netdevs without a bus-path identity, in directory order.
    pub skipped: Vec<Skipped>,
}

/// The identity of the device behind a netdev, from its canonical sysfs device path.
///
/// # Errors
///
/// The reason the device has no bus-path identity (not on PCI, or malformed sysfs).
pub fn identity(device: &Path) -> Result<String, String> {
    match subsystem_of(device)?.as_str() {
        "pci" => pci_id(device),
        "virtio" => {
            let parent = device
                .parent()
                .ok_or_else(|| "virtio device without a parent".to_owned())?;
            if subsystem_of(parent)? == "pci" {
                pci_id(parent)
            } else {
                Err("virtio device not on PCI".to_owned())
            }
        }
        other => Err(format!("{other} device: no bus-path identity yet")),
    }
}

/// The basename of the device's `subsystem` link (`pci`, `virtio`, `usb`, `platform`, …).
fn subsystem_of(device: &Path) -> Result<String, String> {
    let link = fs::read_link(device.join("subsystem"))
        .map_err(|err| format!("no subsystem link: {err}"))?;
    link.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| "unreadable subsystem link".to_owned())
}

/// `pci-DDDD:BB:DD.F` from the PCI device's own directory name.
fn pci_id(device: &Path) -> Result<String, String> {
    let name = device
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "unnamed PCI device".to_owned())?;
    if is_pci_bdf(name) {
        Ok(format!("pci-{name}"))
    } else {
        Err(format!("PCI device with unexpected name {name}"))
    }
}

/// `DDDD:BB:DD.F`, all hex.
fn is_pci_bdf(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11]
            .iter()
            .all(|&i| b[i].is_ascii_hexdigit())
}

/// Every netdev under `sysfs_class_net`, as ports (sorted by id, then MAC) or skips with reasons.
/// A broken entry skips that entry only.
///
/// # Errors
///
/// When the directory itself cannot be read.
pub fn enumerate(sysfs_class_net: &Path) -> io::Result<Inventory> {
    let mut inventory = Inventory::default();
    for entry in fs::read_dir(sysfs_class_net)? {
        let entry = entry?;
        let ifname = entry.file_name().to_string_lossy().into_owned();
        match port_of(&entry.path(), &ifname) {
            Ok(port) => inventory.ports.push(port),
            Err(reason) => inventory.skipped.push(Skipped { ifname, reason }),
        }
    }
    inventory
        .ports
        .sort_by(|a, b| (&a.id, &a.mac).cmp(&(&b.id, &b.mac)));
    Ok(inventory)
}

fn port_of(dir: &Path, ifname: &str) -> Result<Port, String> {
    let device = fs::canonicalize(dir.join("device"))
        .map_err(|_| "no device link (virtual interface)".to_owned())?;
    let id = identity(&device)?;
    let mac = fs::read_to_string(dir.join("address"))
        .map_err(|err| format!("cannot read address: {err}"))?
        .trim()
        .to_owned();
    Ok(Port {
        ifname: ifname.to_owned(),
        id,
        mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A sysfs lookalike with `subsystem` links: two virtio NICs and one igc-style NIC on PCI, a
    /// USB NIC behind a PCI xHCI controller, a platform NIC, a PCI NIC without an `address` file,
    /// and `lo`.
    fn fake_sysfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for d in [
            "bus/pci",
            "bus/virtio",
            "bus/usb",
            "bus/platform",
            "devices/pci0000:00/0000:00:04.0/virtio1",
            "devices/pci0000:00/0000:00:03.0/virtio0",
            "devices/pci0000:00/0000:00:05.0",
            "devices/pci0000:00/0000:00:06.0",
            "devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0",
            "devices/platform/fakenic",
            "class/net/eth0",
            "class/net/eth1",
            "class/net/eth2",
            "class/net/eth3",
            "class/net/eth4",
            "class/net/eth5",
            "class/net/lo",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let links = [
            (
                "devices/pci0000:00/0000:00:04.0/subsystem",
                "../../../bus/pci",
            ),
            (
                "devices/pci0000:00/0000:00:03.0/subsystem",
                "../../../bus/pci",
            ),
            (
                "devices/pci0000:00/0000:00:05.0/subsystem",
                "../../../bus/pci",
            ),
            (
                "devices/pci0000:00/0000:00:06.0/subsystem",
                "../../../bus/pci",
            ),
            (
                "devices/pci0000:00/0000:00:14.0/subsystem",
                "../../../bus/pci",
            ),
            (
                "devices/pci0000:00/0000:00:04.0/virtio1/subsystem",
                "../../../../bus/virtio",
            ),
            (
                "devices/pci0000:00/0000:00:03.0/virtio0/subsystem",
                "../../../../bus/virtio",
            ),
            (
                "devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0/subsystem",
                "../../../../../../bus/usb",
            ),
            (
                "devices/platform/fakenic/subsystem",
                "../../../bus/platform",
            ),
            (
                "class/net/eth0/device",
                "../../../devices/pci0000:00/0000:00:04.0/virtio1",
            ),
            (
                "class/net/eth1/device",
                "../../../devices/pci0000:00/0000:00:03.0/virtio0",
            ),
            ("class/net/eth2/device", "../../../devices/platform/fakenic"),
            (
                "class/net/eth3/device",
                "../../../devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0",
            ),
            (
                "class/net/eth4/device",
                "../../../devices/pci0000:00/0000:00:05.0",
            ),
            (
                "class/net/eth5/device",
                "../../../devices/pci0000:00/0000:00:06.0",
            ),
        ];
        for (link, target) in links {
            symlink(target, root.join(link)).unwrap();
        }
        for (ifname, mac) in [
            ("eth0", "52:54:00:fe:00:00"),
            ("eth1", "52:54:00:fe:00:01"),
            ("eth2", "52:54:00:fe:00:02"),
            ("eth3", "52:54:00:fe:00:03"),
            ("eth4", "52:54:00:fe:00:05"),
            ("lo", "00:00:00:00:00:00"),
        ] {
            fs::write(
                root.join("class/net").join(ifname).join("address"),
                format!("{mac}\n"),
            )
            .unwrap();
        }
        dir
    }

    #[test]
    fn enumerates_pci_and_virtio_ports_sorted_by_bus_path() {
        let fake = fake_sysfs();
        let inventory = enumerate(&fake.path().join("class/net")).unwrap();
        assert_eq!(
            inventory
                .ports
                .iter()
                .map(|p| (p.ifname.as_str(), p.id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("eth1", "pci-0000:00:03.0"),
                ("eth0", "pci-0000:00:04.0"),
                ("eth4", "pci-0000:00:05.0"),
            ]
        );
        assert_eq!(inventory.ports[0].mac, "52:54:00:fe:00:01");
    }

    #[test]
    fn skips_usb_platform_virtual_and_unreadable_with_reasons() {
        let fake = fake_sysfs();
        let inventory = enumerate(&fake.path().join("class/net")).unwrap();
        let mut skipped: Vec<(&str, &str)> = inventory
            .skipped
            .iter()
            .map(|s| (s.ifname.as_str(), s.reason.as_str()))
            .collect();
        skipped.sort_unstable();
        assert_eq!(
            skipped.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            ["eth2", "eth3", "eth5", "lo"]
        );
        assert!(skipped[0].1.contains("platform"), "{:?}", skipped[0]);
        assert!(skipped[1].1.contains("usb"), "{:?}", skipped[1]);
        assert!(skipped[2].1.contains("address"), "{:?}", skipped[2]);
        assert!(skipped[3].1.contains("no device"), "{:?}", skipped[3]);
    }

    #[test]
    fn identity_by_subsystem() {
        let fake = fake_sysfs();
        let dev = |p: &str| fake.path().join("devices").join(p);
        assert_eq!(
            identity(&dev("pci0000:00/0000:00:03.0/virtio0")),
            Ok("pci-0000:00:03.0".to_string())
        );
        assert_eq!(
            identity(&dev("pci0000:00/0000:00:05.0")),
            Ok("pci-0000:00:05.0".to_string())
        );
        assert!(
            identity(&dev("pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0"))
                .is_err_and(|r| r.contains("usb"))
        );
        assert!(identity(&dev("platform/fakenic")).is_err_and(|r| r.contains("platform")));
    }
}
