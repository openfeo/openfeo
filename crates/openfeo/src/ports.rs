// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Physical ports by bus path (SPEC §7.1): in M0 only enumerated and logged; renaming to `pN`
//! arrives with M1.

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

/// `pci-DDDD:BB:DD.F` for the last PCI address in a canonical sysfs device path; `None` when the
/// device is not on PCI (platform, USB, virtual).
#[must_use]
pub fn pci_id_from_device_path(canonical: &Path) -> Option<String> {
    canonical
        .components()
        .rev()
        .filter_map(|c| c.as_os_str().to_str())
        .find(|s| is_pci_bdf(s))
        .map(|bdf| format!("pci-{bdf}"))
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

/// Every netdev under `sysfs_class_net` that sits on PCI, sorted by bus path. Interfaces without
/// a `device` link (`lo`, bridges, VLANs) or without a PCI ancestor are left out.
///
/// # Errors
///
/// When the directory or an `address` file cannot be read.
pub fn enumerate(sysfs_class_net: &Path) -> io::Result<Vec<Port>> {
    let mut ports = Vec::new();
    for entry in fs::read_dir(sysfs_class_net)? {
        let entry = entry?;
        let Ok(canonical) = fs::canonicalize(entry.path().join("device")) else {
            continue;
        };
        let Some(id) = pci_id_from_device_path(&canonical) else {
            continue;
        };
        let mac = fs::read_to_string(entry.path().join("address"))?
            .trim()
            .to_owned();
        ports.push(Port {
            ifname: entry.file_name().to_string_lossy().into_owned(),
            id,
            mac,
        });
    }
    ports.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A sysfs lookalike: two virtio NICs on PCI, one platform NIC, and `lo`.
    fn fake_sysfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for d in [
            "devices/pci0000:00/0000:00:04.0/virtio1",
            "devices/pci0000:00/0000:00:03.0/virtio0",
            "devices/platform/fakenic",
            "class/net/eth0",
            "class/net/eth1",
            "class/net/eth2",
            "class/net/lo",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        symlink(
            "../../../devices/pci0000:00/0000:00:04.0/virtio1",
            root.join("class/net/eth0/device"),
        )
        .unwrap();
        symlink(
            "../../../devices/pci0000:00/0000:00:03.0/virtio0",
            root.join("class/net/eth1/device"),
        )
        .unwrap();
        symlink(
            "../../../devices/platform/fakenic",
            root.join("class/net/eth2/device"),
        )
        .unwrap();
        fs::write(root.join("class/net/eth0/address"), "52:54:00:fe:00:00\n").unwrap();
        fs::write(root.join("class/net/eth1/address"), "52:54:00:fe:00:01\n").unwrap();
        fs::write(root.join("class/net/eth2/address"), "52:54:00:fe:00:02\n").unwrap();
        fs::write(root.join("class/net/lo/address"), "00:00:00:00:00:00\n").unwrap();
        dir
    }

    #[test]
    fn enumerates_pci_ports_sorted_by_bus_path_and_skips_the_rest() {
        let fake = fake_sysfs();
        let ports = enumerate(&fake.path().join("class/net")).unwrap();
        assert_eq!(
            ports
                .iter()
                .map(|p| (p.ifname.as_str(), p.id.as_str()))
                .collect::<Vec<_>>(),
            vec![("eth1", "pci-0000:00:03.0"), ("eth0", "pci-0000:00:04.0")]
        );
        assert_eq!(ports[0].mac, "52:54:00:fe:00:01");
    }

    #[test]
    fn pci_id_requires_a_bdf_component() {
        assert_eq!(
            pci_id_from_device_path(Path::new("/sys/devices/pci0000:00/0000:00:03.0/virtio0")),
            Some("pci-0000:00:03.0".to_string())
        );
        assert_eq!(
            pci_id_from_device_path(Path::new("/sys/devices/platform/fakenic")),
            None
        );
    }
}
