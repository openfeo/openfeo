// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Core sysctls PID 1 writes at boot (SPEC §6.1, §7.3, §7.4, §7.9).

use crate::log::Log;

/// `(key under /proc/sys, value)`.
pub const CORE: &[(&str, &str)] = &[
    // An appliance: an oops is a reboot (with panic=10 on the command line). SysRq does not
    // exist on our kernels (MAGIC_SYSRQ is off), so there is no sysctl to disable.
    ("kernel/panic_on_oops", "1"),
    // Forwarding (ip_forward, IPv6 forwarding) is not here: the router child switches it on only
    // together with a ruleset (SPEC §5.6, §7.9), so a box never forwards unfiltered.
    // §7.3: the WAN IPv6 client does RA and SLAAC itself; the kernel does neither anywhere.
    ("net/ipv6/conf/all/accept_ra", "0"),
    ("net/ipv6/conf/default/accept_ra", "0"),
    ("net/ipv6/conf/all/autoconf", "0"),
    ("net/ipv6/conf/default/autoconf", "0"),
    // §7.4: reverse-path filtering is done in nftables, not by the kernel.
    ("net/ipv4/conf/all/rp_filter", "0"),
    ("net/ipv4/conf/default/rp_filter", "0"),
    // §7.1: an interface answers ARP only for its own addresses, so a port carrying only
    // tagged LANs (no address of its own) gives nothing away on its native VLAN (#15). The
    // kernel takes the higher of `all` and the interface's, so one line covers every interface,
    // present and future.
    ("net/ipv4/conf/all/arp_ignore", "1"),
    // Router hygiene: never send or accept ICMP redirects.
    ("net/ipv4/conf/all/send_redirects", "0"),
    ("net/ipv4/conf/default/send_redirects", "0"),
    ("net/ipv4/conf/all/accept_redirects", "0"),
    ("net/ipv4/conf/default/accept_redirects", "0"),
    ("net/ipv6/conf/all/accept_redirects", "0"),
    ("net/ipv6/conf/default/accept_redirects", "0"),
    // §7.9.
    ("net/ipv4/tcp_mtu_probing", "1"),
    // Nothing on the box uses io_uring; its attack surface is not wanted (2 = disabled for all).
    ("kernel/io_uring_disabled", "2"),
];

/// Write every entry of [`CORE`]; a refused write is logged and skipped, never fatal.
pub fn apply(log: &Log) {
    for (key, value) in CORE {
        if let Err(err) = std::fs::write(format!("/proc/sys/{key}"), value) {
            log.warn(&format!("sysctl {key}={value}: {err}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// #15: a port carrying only tagged LANs holds no address, yet without this the kernel
    /// would answer an untagged ARP request on it for any of the router's addresses.
    #[test]
    fn arp_ignore_is_on_for_every_interface() {
        assert!(CORE.contains(&("net/ipv4/conf/all/arp_ignore", "1")));
    }

    #[test]
    fn table_has_no_duplicates_or_leading_slashes() {
        let mut seen = HashSet::new();
        for (key, _) in CORE {
            assert!(!key.starts_with('/'), "{key} must be relative to /proc/sys");
            assert!(seen.insert(key), "{key} listed twice");
        }
        // Forwarding is the router child's lever, written only together with a ruleset
        // (SPEC §5.6, §7.9): PID 1 must not switch it on.
        for key in CORE.iter().map(|(key, _)| *key) {
            assert!(
                !key.ends_with("forwarding") && key != "net/ipv4/ip_forward",
                "{key}"
            );
        }
    }
}
