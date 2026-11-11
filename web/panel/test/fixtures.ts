// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A router's state as the dashboard's tests see it: a PPPoE WAN on a tagged port, a LAN across
// three ports and a second LAN as a VLAN of one of them, with addresses of every origin.

import {
  AddressOrigin,
  CountersSchema,
  create,
  EventSchema,
  PortUseKind,
  StateSchema,
  WanKind,
  WanPhase,
  type Counters,
  type Event,
  type State,
} from '@openfeo/client'

/** 7 November 2026, 09:14:22, in whatever zone the test runs in. */
export const WAN_UP_AT = new Date(2026, 10, 7, 9, 14, 22)
/** Three days and some hours later. */
export const NOW = new Date(2026, 10, 10, 19, 42, 30)
/** How long the fixture's router has been up at NOW: `3d 4h`. */
export const UPTIME_SECS = 273_600
/** When it booted, by NOW's clock. */
export const BOOTED = new Date(NOW.getTime() - UPTIME_SECS * 1000)

export function state(): State {
  return create(StateSchema, {
    generation: 42n,
    system: {
      hostname: 'openfeo',
      domain: 'home.arpa',
      version: '0.4.0',
      uptimeSecs: BigInt(UPTIME_SECS),
      timeSynced: true,
      healthy: true,
      tlsFingerprint: '3F:9A',
    },
    ports: [
      { name: 'p0', id: 'pci-0000:01:00.0', mac: '52:54:00:12:34:00', carrier: true, speedMbps: 2500, uses: [{ kind: PortUseKind.WAN, name: 'wan0', vlan: 911 }] },
      { name: 'p1', id: 'pci-0000:02:00.0', mac: '52:54:00:12:34:01', carrier: true, speedMbps: 2500, uses: [{ kind: PortUseKind.LAN, name: 'lan0' }] },
      { name: 'p2', id: 'pci-0000:03:00.0', mac: '52:54:00:12:34:02', carrier: false, uses: [{ kind: PortUseKind.LAN, name: 'lan0' }] },
      {
        name: 'p3',
        id: 'pci-0000:04:00.0',
        mac: '52:54:00:12:34:03',
        carrier: true,
        speedMbps: 1000,
        uses: [
          { kind: PortUseKind.LAN, name: 'lan0' },
          { kind: PortUseKind.LAN, name: 'iot', vlan: 20 },
        ],
      },
    ],
    wans: [
      {
        name: 'wan0',
        kind: WanKind.PPPOE,
        port: 'p0',
        vlan: 911,
        interface: 'ppp-wan0',
        phase: WanPhase.UP,
        phaseSinceUnixMs: BigInt(WAN_UP_AT.getTime()),
        ipv4: '203.0.113.100',
        ipv4Peer: '203.0.113.1',
        mtu: 1500,
        ipv6Prefixes: ['2001:db8:1::/48'],
        default4: true,
        default6: true,
      },
    ],
    lans: [
      {
        name: 'lan0',
        interface: 'br-lan0',
        members: ['p1', 'p2', 'p3'],
        ipv4: '192.168.1.1/24',
        ipv6: ['2001:db8:1:1::1/64', 'fd12:3456:789a:1::1/64'],
        dhcp: true,
        poolSize: 150,
        leases: 11,
      },
      {
        name: 'iot',
        interface: 'br-iot',
        members: ['p3.20'],
        ipv4: '192.168.20.1/24',
        ipv6: ['2001:db8:1:2::1/64'],
        vlan: 20,
        dhcp: true,
        poolSize: 50,
        leases: 3,
      },
    ],
    addresses: [
      { interface: 'ppp-wan0', address: '203.0.113.100', peer: '203.0.113.1', origin: AddressOrigin.PPP },
      { interface: 'ppp-wan0', address: '2001:db8:0:5:a1b2:c3d4:e5f6:789a/64', origin: AddressOrigin.ROUTER_ADVERTISEMENT },
      { interface: 'ppp-wan0', address: 'fe80::a1b2:c3d4:e5f6:789a/64', origin: AddressOrigin.LINK_LOCAL },
      { interface: 'br-lan0', address: '192.168.1.1/24', origin: AddressOrigin.CONFIG },
      { interface: 'br-lan0', address: '2001:db8:1:1::1/64', origin: AddressOrigin.DELEGATED_PREFIX },
      { interface: 'br-lan0', address: '2001:db8:9:1::1/64', origin: AddressOrigin.DELEGATED_PREFIX, deprecated: true },
      { interface: 'br-lan0', address: 'fd12:3456:789a:1::1/64', origin: AddressOrigin.ULA },
      { interface: 'br-iot', address: '192.168.20.1/24', origin: AddressOrigin.CONFIG },
    ],
  })
}

/** The same router on a DHCP WAN with no VLAN, as the lab's is. */
export function dhcpState(): State {
  const base = state()
  const wan = base.wans[0]
  if (wan !== undefined) {
    wan.kind = WanKind.DHCP
    wan.vlan = 0
    wan.interface = 'p0'
    wan.ipv4 = '203.0.113.100/24'
    wan.ipv4Peer = ''
    wan.gateway4 = '203.0.113.1'
    wan.ipv6Prefixes = []
  }
  return base
}

export function counters(monotonicMs: bigint, links: [name: string, rx: bigint, tx: bigint][], conntrack = 1842): Counters {
  return create(CountersSchema, {
    monotonicMs,
    links: links.map(([name, rxBytes, txBytes]) => ({ name, rxBytes, txBytes })),
    conntrack,
    conntrackMax: 262_144,
  })
}

/**
 * An event that happened at `at`. Its uptime is what the fixture's router would have stamped
 * (the time since BOOTED) unless given: the router's two stamps agree when its clock is right.
 */
export function event(topic: string, fields: Record<string, string> = {}, at: Date = NOW, uptimeMs?: bigint): Event {
  const sinceBoot = BigInt(Math.max(0, at.getTime() - BOOTED.getTime()))
  return create(EventSchema, { topic, fields, timeUnixMs: BigInt(at.getTime()), uptimeMs: uptimeMs ?? sinceBoot })
}
