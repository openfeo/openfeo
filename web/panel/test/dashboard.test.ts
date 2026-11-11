// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { AddressOrigin, WanKind, WanPhase, type LinkRate } from '@openfeo/client'
import { expect, test } from 'vitest'

import { addresses, cards, defaultWan, headline, ports, tiles } from '../src/model/dashboard'
import { dhcpState, state } from './fixtures'

const rateOf = (name: string, rx: number, tx: number): LinkRate => ({ name, rxBitsPerSec: rx, txBitsPerSec: tx })
const noLive = { history: { rx: [], tx: [] } }

test('the headline names the default WAN, since when, and the clients', () => {
  expect(headline(state())).toBe('wan0 up since 7 Nov 09:14 · 14 clients on 2 LANs')
})

test('the headline before the clock is synced gives no date', () => {
  const unsynced = state()
  if (unsynced.system !== undefined) {
    unsynced.system.timeSynced = false
  }
  expect(headline(unsynced)).toBe('wan0 up · 14 clients on 2 LANs')
  const undated = state()
  const wan = undated.wans[0]
  if (wan !== undefined) {
    wan.phaseSinceUnixMs = undefined
  }
  expect(headline(undated)).toBe('wan0 up · 14 clients on 2 LANs')
})

test('a WAN that is down says why, in the card and in the headline', () => {
  const down = state()
  const wan = down.wans[0]
  if (wan !== undefined) {
    wan.phase = WanPhase.DOWN
    wan.reason = 'no carrier'
    wan.ipv4 = ''
    wan.ipv4Peer = ''
    wan.ipv6Prefixes = []
  }
  expect(headline(down)).toBe('wan0 down: no carrier · 14 clients on 2 LANs')
  const card = cards(down, null)[0]
  expect(card?.status).toEqual({ word: 'Down', tone: 'danger' })
  expect(card?.facts[0]).toEqual({ key: 'Reason', value: 'no carrier' })
  expect(card?.facts.map((fact) => fact.key)).toEqual(['Reason', 'Interface', 'MTU'])

  const connecting = state()
  const dialling = connecting.wans[0]
  if (dialling !== undefined) {
    dialling.phase = WanPhase.CONNECTING
    dialling.reason = 'authentication failed'
  }
  expect(headline(connecting)).toBe('wan0 connecting · 14 clients on 2 LANs')
  expect(cards(connecting, null)[0]?.status).toEqual({ word: 'Connecting', tone: 'info' })
  expect(cards(connecting, null)[0]?.facts[0]).toEqual({ key: 'Reason', value: 'authentication failed' })

  if (wan !== undefined) {
    wan.reason = ''
  }
  expect(headline(down)).toBe('wan0 down · 14 clients on 2 LANs')
  expect(cards(down, null)[0]?.facts[0]?.key).toBe('Interface')
})

test('one client on one LAN is singular, and no WAN is said', () => {
  const small = state()
  small.wans = []
  small.lans = small.lans.slice(0, 1)
  const lan = small.lans[0]
  if (lan !== undefined) {
    lan.leases = 1
  }
  expect(headline(small)).toBe('No WAN configured · 1 client on 1 LAN')
  if (lan !== undefined) {
    lan.leases = 0
  }
  expect(headline(small)).toBe('No WAN configured · 0 clients on 1 LAN')
})

test('the default WAN is the one carrying the default route, or failing that the first', () => {
  const two = state()
  const first = two.wans[0]
  if (first === undefined) {
    throw new Error('the fixture has a WAN')
  }
  two.wans = [{ ...first, name: 'wan1', default4: false }, first]
  expect(defaultWan(two)?.name).toBe('wan0')
  first.default4 = false
  expect(defaultWan(two)?.name).toBe('wan1')
  two.wans = []
  expect(defaultWan(two)).toBeUndefined()
})

test("the default WAN's card is the active one and no other", () => {
  const all = cards(state(), null)
  expect(all.map((card) => card.name)).toEqual(['wan0', 'lan0', 'iot'])
  expect(all.map((card) => card.active)).toEqual([true, false, false])
})

test('a PPPoE WAN on a tagged port says so, with its peer as the gateway', () => {
  const card = cards(state(), null)[0]
  expect(card?.role).toBe('WAN · PPPoE · VLAN 911')
  expect(card?.status).toEqual({ word: 'Up', tone: 'ok' })
  expect(card?.facts).toEqual([
    { key: 'IPv4', value: '203.0.113.100' },
    { key: 'Gateway', value: '203.0.113.1' },
    { key: 'Prefix', value: '2001:db8:1::/48' },
    { key: 'Interface', value: 'ppp-wan0 on p0.911' },
    { key: 'MTU', value: '1500' },
  ])
})

test('a DHCP WAN on a bare port is its port, with the gateway it was given', () => {
  const card = cards(dhcpState(), null)[0]
  expect(card?.role).toBe('WAN · DHCP')
  expect(card?.facts).toEqual([
    { key: 'IPv4', value: '203.0.113.100/24' },
    { key: 'Gateway', value: '203.0.113.1' },
    { key: 'Interface', value: 'p0' },
    { key: 'MTU', value: '1500' },
  ])
  const withAddress = dhcpState()
  const wan = withAddress.wans[0]
  if (wan !== undefined) {
    wan.ipv6 = '2001:db8:0:5::2/64'
    wan.ipv6Prefixes = ['2001:db8:1::/48']
    wan.kind = WanKind.STATIC
  }
  const facts = cards(withAddress, null)[0]?.facts
  expect(facts?.find((fact) => fact.key === 'IPv6')?.value).toBe('2001:db8:0:5::2/64')
  expect(facts?.some((fact) => fact.key === 'Prefix')).toBe(false)
  expect(cards(withAddress, null)[0]?.role).toBe('WAN · Static')
})

test('a card never has more than five facts', () => {
  const full = state()
  const wan = full.wans[0]
  if (wan !== undefined) {
    wan.phase = WanPhase.CONNECTING
    wan.reason = 'keepalive lost'
    wan.ipv6 = '2001:db8:0:5::2/64'
  }
  const facts = cards(full, null)[0]?.facts ?? []
  expect(facts).toHaveLength(5)
  expect(facts[0]?.key).toBe('Reason')
})

test('a LAN says its addresses, its ports and its leases', () => {
  const [, lan0, iot] = cards(state(), null)
  expect(lan0?.role).toBe('LAN')
  expect(lan0?.status).toEqual({ word: 'Up', tone: 'ok' })
  expect(lan0?.facts).toEqual([
    { key: 'IPv4', value: '192.168.1.1/24' },
    { key: 'IPv6', value: '2001:db8:1:1::1/64' },
    { key: 'Interface', value: 'br-lan0' },
    { key: 'Ports', value: 'p1 p2 p3' },
    { key: 'DHCP', value: '11 / 150 leases' },
  ])
  expect(iot?.role).toBe('LAN · VLAN 20')
  expect(iot?.facts.at(-1)).toEqual({ key: 'DHCP', value: '3 / 50 leases' })
  expect(iot?.facts.find((fact) => fact.key === 'Ports')?.value).toBe('p3.20')
})

test('a LAN with no member up says No link, and one without DHCP says off', () => {
  const quiet = state()
  for (const port of quiet.ports) {
    if (port.name !== 'p0') {
      port.carrier = false
    }
  }
  const lan = quiet.lans[0]
  if (lan !== undefined) {
    lan.dhcp = false
    lan.ipv6 = []
  }
  const [, lan0, iot] = cards(quiet, null)
  expect(lan0?.status).toEqual({ word: 'No link' })
  expect(iot?.status).toEqual({ word: 'No link' })
  expect(lan0?.facts.map((fact) => fact.key)).toEqual(['IPv4', 'Interface', 'Ports', 'DHCP'])
  expect(lan0?.facts.at(-1)).toEqual({ key: 'DHCP', value: 'off' })
  // A VLAN's member is up when the port under it is.
  const p3 = quiet.ports.find((port) => port.name === 'p3')
  if (p3 !== undefined) {
    p3.carrier = true
  }
  expect(cards(quiet, null)[2]?.status).toEqual({ word: 'Up', tone: 'ok' })
})

test("a card's rates are its own interface's, received down and sent up", () => {
  const rates = new Map([
    ['ppp-wan0', rateOf('ppp-wan0', 412_600_000, 38_200_000)],
    ['br-lan0', rateOf('br-lan0', 37_900_000, 409_100_000)],
  ])
  const [wan, lan0, iot] = cards(state(), rates)
  expect(wan?.rates).toEqual({ rx: { value: '412.6', unit: 'Mbit/s' }, tx: { value: '38.2', unit: 'Mbit/s' } })
  expect(lan0?.rates).toEqual({ rx: { value: '37.9', unit: 'Mbit/s' }, tx: { value: '409.1', unit: 'Mbit/s' } })
  // An interface the counters did not name has no rate, not a zero.
  expect(iot?.rates).toBeNull()
})

test('with no rates the tiles and cards show dashes, not zeros', () => {
  expect(cards(state(), null).every((card) => card.rates === null)).toBe(true)
  const [down, up, clients, connections] = tiles(state(), noLive)
  expect(down).toEqual({ label: 'Download', value: '—', spark: [], series: 1 })
  expect(up).toEqual({ label: 'Upload', value: '—', spark: [], series: 2 })
  expect(clients).toEqual({ label: 'Clients', value: '14', foot: '11 on lan0 · 3 on iot' })
  expect(connections).toEqual({ label: 'Connections', value: '—' })
})

test('the tiles show the default WAN, the leases and the tracked connections', () => {
  const live = {
    rate: rateOf('ppp-wan0', 412_600_000, 38_200_000),
    history: { rx: [1, 2, 3], tx: [3, 2, 1] },
    conntrack: { count: 1842, max: 262_144 },
  }
  expect(tiles(state(), live)).toEqual([
    { label: 'Download', value: '412.6', unit: 'Mbit/s', spark: [1, 2, 3], series: 1 },
    { label: 'Upload', value: '38.2', unit: 'Mbit/s', spark: [3, 2, 1], series: 2 },
    { label: 'Clients', value: '14', foot: '11 on lan0 · 3 on iot' },
    { label: 'Connections', value: '1842', foot: 'of 262144 tracked' },
  ])
  const none = state()
  none.lans = []
  expect(tiles(none, live)[2]).toEqual({ label: 'Clients', value: '0' })
})

test('a port says what it is for, in words', () => {
  expect(ports(state())).toEqual([
    { name: 'p0', speed: '2.5G', wan: true, up: true, title: 'p0 · 52:54:00:12:34:00 · WAN wan0, VLAN 911' },
    { name: 'p1', speed: '2.5G', wan: false, up: true, title: 'p1 · 52:54:00:12:34:01 · LAN lan0' },
    { name: 'p2', speed: '—', wan: false, up: false, title: 'p2 · 52:54:00:12:34:02 · LAN lan0 · no link' },
    { name: 'p3', speed: '1G', wan: false, up: true, title: 'p3 · 52:54:00:12:34:03 · LAN lan0 · LAN iot, VLAN 20' },
  ])
  const spare = state()
  const p1 = spare.ports[1]
  if (p1 !== undefined) {
    p1.uses = []
  }
  expect(ports(spare)[1]?.title).toBe('p1 · 52:54:00:12:34:01 · not in use')
})

test('link-local addresses are left out and a point-to-point one names its peer', () => {
  const rows = addresses(state())
  expect(rows.some((row) => row.address.startsWith('fe80'))).toBe(false)
  expect(rows).toEqual([
    { interface: 'ppp-wan0', first: true, address: '203.0.113.100 peer 203.0.113.1', from: 'PPP', deprecated: false },
    { interface: 'ppp-wan0', first: false, address: '2001:db8:0:5:a1b2:c3d4:e5f6:789a/64', from: 'Router advertisement', deprecated: false },
    { interface: 'br-lan0', first: true, address: '192.168.1.1/24', from: 'Config', deprecated: false },
    { interface: 'br-lan0', first: false, address: '2001:db8:1:1::1/64', from: 'Delegated prefix', deprecated: false },
    { interface: 'br-lan0', first: false, address: '2001:db8:9:1::1/64', from: 'Delegated prefix', deprecated: true },
    { interface: 'br-lan0', first: false, address: 'fd12:3456:789a:1::1/64', from: 'ULA', deprecated: false },
    { interface: 'br-iot', first: true, address: '192.168.20.1/24', from: 'Config', deprecated: false },
  ])
})

test("an interface's addresses are kept together though the router listed them apart", () => {
  const mixed = state()
  const last = mixed.addresses.at(-1)
  const first = mixed.addresses[0]
  if (last !== undefined && first !== undefined) {
    mixed.addresses = [...mixed.addresses, { ...first, address: '203.0.113.200', peer: '', origin: AddressOrigin.DHCP }]
  }
  const rows = addresses(mixed)
  expect(rows.map((row) => row.interface)).toEqual(['ppp-wan0', 'ppp-wan0', 'ppp-wan0', 'br-lan0', 'br-lan0', 'br-lan0', 'br-lan0', 'br-iot'])
  expect(rows[2]).toEqual({ interface: 'ppp-wan0', first: false, address: '203.0.113.200', from: 'DHCP', deprecated: false })
})

test('an unknown enum value reads as Unknown', () => {
  // A newer router behind a page that was cached may say something this code has not met.
  const odd = state()
  const wan = odd.wans[0]
  const address = odd.addresses[0]
  if (wan !== undefined && address !== undefined) {
    wan.kind = 99 as WanKind
    wan.phase = 99 as WanPhase
    address.origin = 99 as AddressOrigin
  }
  const card = cards(odd, null)[0]
  expect(card?.role).toBe('WAN · Unknown · VLAN 911')
  expect(card?.status).toEqual({ word: 'Unknown' })
  expect(addresses(odd)[0]?.from).toBe('Unknown')
  expect(headline(odd)).toBe('wan0 unknown · 14 clients on 2 LANs')
})
