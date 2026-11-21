// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { clone, ConfigSchema, create, LanSchema, type LanDhcp } from '@openfeo/client'
import { expect, test } from 'vitest'

import {
  blockers,
  claimed,
  lanProblems,
  LAN_FIELDS,
  leaseOptions,
  leaseValue,
  newLan,
  portChoices,
  rangeWords,
  setDhcp,
  setLanIpv6,
  setLease,
  sizeOptions,
  stillUnfit,
  unfitWords,
} from '../src/model/lan'
import { labConfig, routerConfig, state } from './fixtures'

test('the sizes say how many addresses each holds, and the current one is always there', () => {
  const sizes = sizeOptions(24)
  expect(sizes.map((size) => size.value)).toEqual(['16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30'])
  expect(sizes.find((size) => size.value === '24')?.label).toBe('/24 · 254 addresses')
  expect(sizes[0]?.label).toBe('/16 · 65534 addresses')
  expect(sizes.at(-1)?.label).toBe('/30 · 2 addresses')
  // One outside the usual run is there too, in its place.
  expect(sizeOptions(8)[0]).toEqual({ value: '8', label: '/8 · 16777214 addresses' })
  expect(sizeOptions(8)).toHaveLength(16)
  expect(sizeOptions(31).at(-1)).toEqual({ value: '31', label: '/31 · no addresses for devices' })
})

test('the subnet size says the range it gives', () => {
  expect(rangeWords('192.168.50.1/24')).toBe('192.168.50.1 to 192.168.50.254.')
  expect(rangeWords('192.168.1.129/25')).toBe('192.168.1.129 to 192.168.1.254.')
  expect(rangeWords('10.0.0.1/16')).toBe('10.0.0.1 to 10.0.255.254.')
  expect(rangeWords('192.168.1.1/31')).toBe('No addresses for devices.')
  expect(rangeWords('')).toBe('')
  expect(rangeWords('192.168.1')).toBe('')
})

test('the lease times are four and Other, and a time that is none of the four is Other', () => {
  expect(leaseOptions()).toEqual([
    { value: '3600', label: '1 hour' },
    { value: '43200', label: '12 hours' },
    { value: '86400', label: '1 day' },
    { value: '604800', label: '1 week' },
    { value: 'other', label: 'Other…' },
  ])
  expect(leaseValue(43200)).toBe('43200')
  // Left to the router, it is twelve hours.
  expect(leaseValue(0)).toBe('43200')
  expect(leaseValue(3600)).toBe('3600')
  expect(leaseValue(7200)).toBe('other')
  // A time that means what the router's config means is written as the router has it.
  const dhcp = labConfig().lans[0]!.dhcp!
  const base = clone(ConfigSchema, labConfig()).lans[0]!.dhcp!
  base.leaseSecs = 0
  setLease(dhcp, 3600, base)
  expect(dhcp.leaseSecs).toBe(3600)
  setLease(dhcp, 43200, base)
  expect(dhcp.leaseSecs).toBe(0)
  setLease(dhcp, 43200, undefined)
  expect(dhcp.leaseSecs).toBe(43200)
})

test('the ticks are its own ports and the free ones; a tagged member is fixed', () => {
  const config = routerConfig()
  const ports = state().ports
  // lan0 has p1, p2 and p3; p0 is the WAN's and is not offered.
  expect(portChoices(ports, config, config.lans[0]!)).toEqual([
    { name: 'p1', hint: '', ticked: true, fixed: false },
    { name: 'p2', hint: '', ticked: true, fixed: false },
    { name: 'p3', hint: '', ticked: true, fixed: false },
  ])
  // iot is a VLAN of p3: that member is shown and cannot be changed here.
  expect(portChoices(ports, config, config.lans[1]!)).toEqual([{ name: 'p3.20', hint: 'tagged: set in the config file', ticked: true, fixed: true }])
  // A port nothing uses is offered, and says it is free.
  config.lans[0]!.ports = ['p1', 'p3']
  expect(portChoices(ports, config, config.lans[0]!)).toEqual([
    { name: 'p1', hint: '', ticked: true, fixed: false },
    { name: 'p2', hint: 'free', ticked: false, fixed: false },
    { name: 'p3', hint: '', ticked: true, fixed: false },
  ])
  expect(portChoices(ports, config, config.lans[1]!).map((choice) => choice.name)).toEqual(['p2', 'p3.20'])
  // A member the router has no such port for is still the LAN's, and says so.
  config.lans[0]!.ports = ['p1', 'p9']
  expect(portChoices(ports, config, config.lans[0]!).at(-1)).toEqual({ name: 'p9', hint: 'not a port of this router', ticked: true, fixed: false })
})

test('a DHCP server turned off and on again is as it was; a first one is given a pool', () => {
  const base = labConfig().lans[0]!
  const lan = clone(LanSchema, base)
  const kept = new Map<string, LanDhcp>()
  lan.dhcp!.range = ['192.168.1.50', '192.168.1.60']
  setDhcp(lan, false, kept, base)
  expect(lan.dhcp).toBeUndefined()
  setDhcp(lan, true, kept, base)
  expect(lan.dhcp?.range).toEqual(['192.168.1.50', '192.168.1.60'])
  expect(lan.dhcp?.static).toHaveLength(1)
  // With nothing kept, what the router has comes back.
  const again = clone(LanSchema, base)
  setDhcp(again, false, new Map(), base)
  setDhcp(again, true, new Map(), base)
  expect(again).toEqual(base)

  // A first server on a subnet with room: the 100th to the 200th address.
  const fresh = newLan('guest')
  expect(fresh).toEqual(create(LanSchema, { name: 'guest' }))
  fresh.ipv4 = '192.168.3.1/24'
  setDhcp(fresh, true, new Map())
  expect(fresh.dhcp?.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(fresh.dhcp?.leaseSecs).toBe(0)
  const wide = newLan('wide')
  wide.ipv4 = '10.0.0.1/16'
  setDhcp(wide, true, new Map())
  expect(wide.dhcp?.range).toEqual(['10.0.0.100', '10.0.0.200'])
  // One with no room for that, or no address yet, has a pool still to be typed.
  const small = newLan('small')
  small.ipv4 = '192.168.3.1/26'
  setDhcp(small, true, new Map())
  expect(small.dhcp?.range).toEqual([])
  const bare = newLan('bare')
  setDhcp(bare, true, new Map())
  expect(bare.dhcp?.range).toEqual([])
})

test('what stands in the way of removing a LAN is named', () => {
  const config = routerConfig()
  const more = create(ConfigSchema, {
    firewall: {
      rules: [
        { name: 'cameras', from: 'iot', to: '192.168.1.64/26', proto: 'tcp', ports: ['554'] },
        { name: 'ssh', from: 'wan', to: '192.168.1.10-192.168.1.12', proto: 'tcp', ports: ['22'] },
        { name: 'six', from: 'wan', to: '2001:db8:1:1::10', proto: 'tcp', ports: ['443'] },
      ],
    },
  })
  config.firewall!.rules = more.firewall!.rules
  config.lans[1]!.reaches = ['wan', 'lan0']
  expect(blockers(config, config.lans[0]!)).toEqual([
    'port forward lan-http points into it',
    'rule cameras points into it',
    'rule ssh points into it',
    'iot may reach it',
  ])
  expect(blockers(config, config.lans[1]!)).toEqual(['rule cameras starts from it'])
  // A LAN nothing points at is free to go; so is one with no address yet.
  const guest = newLan('guest')
  config.lans.push(guest)
  expect(blockers(config, guest)).toEqual([])
  guest.ipv4 = '192.168.3.1/24'
  expect(blockers(config, guest)).toEqual([])
})

test('IPv6 switched off takes what only an IPv6 LAN may have, and on brings back what the router has', () => {
  const base = routerConfig().lans[0]!
  base.ipv6 = '2001:db8:1:1::1/64'
  base.ra = false
  base.ipv6Index = 7
  const lan = clone(LanSchema, base)
  setLanIpv6(lan, false, base)
  expect([lan.ipv6, lan.ra, lan.ipv6Index]).toEqual(['none', undefined, 0])
  setLanIpv6(lan, true, base)
  expect(lan).toEqual(base)
  // Where the router has it off, on is a LAN that takes its /64 from whatever the WAN has.
  const off = clone(LanSchema, base)
  setLanIpv6(off, false, undefined)
  const wasOff = clone(LanSchema, off)
  setLanIpv6(off, true, wasOff)
  expect([off.ipv6, off.ra, off.ipv6Index]).toEqual(['', undefined, 0])
  setLanIpv6(off, false, wasOff)
  expect(off).toEqual(wasOff)
})

test('what is wrong with a LAN as typed is said by its field', () => {
  const lan = labConfig().lans[0]!
  expect(lanProblems(lan)).toEqual({})
  lan.dhcp!.range = ['192.168.1.200', '192.168.9.100']
  lan.dhcp!.leaseSecs = 30
  lan.dhcp!.dns = ['192.168.1.53', 'resolver']
  lan.dhcp!.ntp = ['time.example']
  lan.dhcp!.static[0]!.mac = '52:54:00:fe:10'
  lan.dhcp!.static[0]!.ip = '192.168.2.10'
  lan.ipv6 = '2001:db8:1:1::1'
  lan.ipv6Index = 70000
  expect(lanProblems(lan)).toEqual({
    'dhcp.range[1]': 'Not in 192.168.1.0/24.',
    'dhcp.lease_secs': 'At least 60 seconds.',
    'dhcp.dns': 'resolver is not an address.',
    'dhcp.ntp': 'time.example is not an address.',
    'dhcp.static[0].mac': 'A MAC address is six pairs of hex digits, such as 02:00:00:aa:01:10.',
    'dhcp.static[0].ip': 'Not in 192.168.1.0/24.',
    ipv6: 'A prefix and its length, such as 2001:db8:1::/48.',
    ipv6_index: '1 to 65535.',
  })
  lan.dhcp!.range = ['192.168.1.200', '192.168.1.100']
  expect(lanProblems(lan)['dhcp.range']).toBe('The pool starts after it ends.')
  // A reservation by client identifier has no MAC to be wrong, and IPv6 that is off no /64.
  lan.dhcp!.static[0]!.mac = ''
  lan.dhcp!.static[0]!.clientId = '01020000aa0110'
  lan.ipv6 = 'none'
  const now = lanProblems(lan)
  expect(now['dhcp.static[0].mac']).toBeUndefined()
  expect(now.ipv6).toBeUndefined()
})

test('a violation is claimed by a field of the page, or it is not', () => {
  for (const within of ['ipv4', 'dhcp.range', 'dhcp.range[1]', 'dhcp.lease_secs', 'dhcp.dns[0]', 'dhcp.ntp', 'dhcp.static[2]', 'dhcp.static[2].ip', 'dhcp.static[2].client_id', 'ipv6', 'ipv6_index']) {
    expect(claimed(within), within).toBe(true)
  }
  for (const within of ['', 'ports[1]', 'ports', 'reaches[0]', 'dhcp', 'dhcp.static', 'ra', 'name']) {
    expect(claimed(within), within).toBe(false)
  }
  expect(LAN_FIELDS).toEqual(expect.arrayContaining(['ipv4', 'dhcp.range', 'dhcp.lease_secs', 'dhcp.dns', 'dhcp.ntp', 'ipv6', 'ipv6_index']))
})

test('an address that did not fit says which subnet it has no place in', () => {
  const base = labConfig()
  const draft = clone(ConfigSchema, base)
  draft.lans[0]!.ipv4 = '192.168.2.1/25'
  expect(unfitWords(base, draft, '192.168.1.200')).toBe('Has no place in 192.168.2.0/25.')
  // An address of no LAN that moved is not explained by one.
  expect(unfitWords(base, draft, '10.0.0.5')).toBe('Has no place in the new subnet.')
  expect(unfitWords(base, base, '192.168.1.200')).toBe('Has no place in the new subnet.')
})

test('an address that did not fit is reported while its field still holds it', () => {
  const config = labConfig()
  const dhcp = config.lans[0]!.dhcp!
  dhcp.dns = ['192.168.1.53']
  expect(stillUnfit(config, { path: 'lans[0].dhcp.range[1]', value: '192.168.1.200' })).toBe(true)
  expect(stillUnfit(config, { path: 'lans[0].dhcp.static[0].ip', value: '192.168.1.10' })).toBe(true)
  expect(stillUnfit(config, { path: 'lans[0].dhcp.dns[0]', value: '192.168.1.53' })).toBe(true)
  // Changed by hand since, or no longer there.
  dhcp.range[1] = '192.168.1.120'
  dhcp.static = []
  expect(stillUnfit(config, { path: 'lans[0].dhcp.range[1]', value: '192.168.1.200' })).toBe(false)
  expect(stillUnfit(config, { path: 'lans[0].dhcp.static[0].ip', value: '192.168.1.10' })).toBe(false)
  expect(stillUnfit(config, { path: 'lans[4].dhcp.ntp[0]', value: '192.168.1.123' })).toBe(false)
  // What is on no page here is reported for as long as the draft is this one.
  expect(stillUnfit(config, { path: 'firewall.port_forwards[0].to', value: '192.168.1.2' })).toBe(true)
})
