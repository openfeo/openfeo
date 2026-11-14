// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { clone, WanSchema, type Wan } from '@openfeo/client'
import { expect, test } from 'vitest'

import { ipv6On, nameProblem, newWan, portOptions, setIpv6, setType, typeOf, WAN_FIELDS, wanProblems } from '../src/model/wan'
import { labConfig, routerConfig, state } from './fixtures'

test('a type left and come back to keeps what was typed for it', () => {
  const wan = labConfig().wans[0]!
  const kept = new Map<string, Wan['kind']>()
  expect(typeOf(wan)).toBe('dhcp')
  setType(wan, 'pppoe', kept)
  expect(typeOf(wan)).toBe('pppoe')
  expect(wan.kind).toEqual({ case: 'pppoe', value: expect.objectContaining({ username: '', password: '' }) })
  if (wan.kind.case === 'pppoe') {
    wan.kind.value.username = 'openfeo@isp.example'
    wan.kind.value.password = 'a-typed-secret'
  }
  setType(wan, 'static', kept)
  expect(typeOf(wan)).toBe('static')
  if (wan.kind.case === 'static') {
    wan.kind.value.address = '203.0.113.10/24'
  }
  // Back to each: what was typed for it is there, and what the router had for DHCP.
  setType(wan, 'pppoe', kept)
  expect(wan.kind.case === 'pppoe' && wan.kind.value.username).toBe('openfeo@isp.example')
  expect(wan.kind.case === 'pppoe' && wan.kind.value.password).toBe('a-typed-secret')
  setType(wan, 'dhcp', kept)
  expect(wan.kind.case === 'dhcp' && wan.kind.value.hostname).toBe('openfeo-lab')
  setType(wan, 'static', kept)
  expect(wan.kind.case === 'static' && wan.kind.value.address).toBe('203.0.113.10/24')
  // Choosing the type it already is changes nothing.
  const before = clone(WanSchema, wan)
  setType(wan, 'static', kept)
  expect(wan).toEqual(before)

  // With nothing kept, the type the router's config has comes back as the router has it.
  const again = labConfig().wans[0]!
  setType(again, 'static', new Map())
  setType(again, 'dhcp', new Map(), labConfig().wans[0])
  expect(again).toEqual(labConfig().wans[0])
  // One WAN's tables are not another's.
  const other = clone(WanSchema, again)
  other.name = 'wan1'
  setType(other, 'pppoe', kept)
  expect(other.kind.case === 'pppoe' && other.kind.value.username).toBe('')
})

test('the ports are listed with their link and speed, and where one is in use', () => {
  const config = routerConfig()
  const ports = state().ports
  expect(portOptions(ports, config, config.wans[0]!)).toEqual([
    { value: 'p0', label: 'p0 · 2500 Mbit/s · link up' },
    { value: 'p1', label: 'p1 · 2500 Mbit/s · link up · in lan0' },
    { value: 'p2', label: 'p2 · no link · in lan0' },
    { value: 'p3', label: 'p3 · 1000 Mbit/s · link up · in lan0, iot' },
  ])
  // A second WAN sees the first one's port as taken, and its own as its own.
  const second = clone(WanSchema, config.wans[0]!)
  second.name = 'wan1'
  second.port = 'p2'
  config.wans.push(second)
  config.lans[0]!.ports = ['p1', 'p3']
  const seen = portOptions(ports, config, second)
  expect(seen[0]).toEqual({ value: 'p0', label: 'p0 · 2500 Mbit/s · link up · in wan0' })
  expect(seen[2]).toEqual({ value: 'p2', label: 'p2 · no link' })
  // A link whose speed the driver does not say, and a port the router does not list.
  const silent = state().ports
  silent[0]!.speedMbps = undefined
  second.port = 'p9'
  const more = portOptions(silent, config, second)
  expect(more[0]?.label).toBe('p0 · link up · in wan0')
  expect(more.at(-1)).toEqual({ value: 'p9', label: 'p9 · not a port of this router' })
  // A WAN with no port yet has a line that says so, and it is the one chosen.
  second.port = ''
  expect(portOptions(silent, config, second)[0]).toEqual({ value: '', label: 'Choose a port' })
})

test('a new WAN is DHCP on the first free port, ten above the highest priority', () => {
  const config = labConfig()
  const ports = state().ports
  // The lab's config uses p0 (wan0) and p2 (lan0): p1 is the first that is free.
  const made = newWan(config, ports, 'wan1')
  expect(made.name).toBe('wan1')
  expect(typeOf(made)).toBe('dhcp')
  expect(made.port).toBe('p1')
  expect(made.vlan).toBe(0)
  expect(made.priority).toBe(20)
  expect(made.ipv6).toBeUndefined()
  // With every port in use it has none yet, and with no WAN before it the priority is 10.
  const full = routerConfig()
  expect(newWan(full, ports, 'wan1').port).toBe('')
  full.wans = []
  expect(newWan(full, ports, 'wan0').priority).toBe(10)
  expect(newWan(full, ports, 'wan0').port).toBe('p0')
})

test("a name follows the router's rule and is not in use", () => {
  const rule = (longest: number) => `1 to ${longest} characters: a to z, 0 to 9, - and _, starting with a letter or a digit.`
  expect(nameProblem('wan1', ['wan0'], 11)).toBeNull()
  expect(nameProblem('0-a_b', [], 11)).toBeNull()
  expect(nameProblem('wan0', ['wan0', 'lan0'], 11)).toBe('wan0 is already in use.')
  expect(nameProblem('lan0', ['wan0', 'lan0'], 11)).toBe('lan0 is already in use.')
  expect(nameProblem('', [], 11)).toBe(rule(11))
  expect(nameProblem('Wan1', [], 11)).toBe(rule(11))
  expect(nameProblem('-wan', [], 11)).toBe(rule(11))
  expect(nameProblem('wan 1', [], 11)).toBe(rule(11))
  expect(nameProblem('wan.1', [], 11)).toBe(rule(11))
  // Twelve characters: one too many for a WAN, and just right for a LAN.
  expect('wan-too-long').toHaveLength(12)
  expect(nameProblem('wan-too-long', [], 11)).toBe(rule(11))
  expect(nameProblem('wan-too-long', [], 12)).toBeNull()
  expect(nameProblem('lan-too-long1', [], 12)).toBe(rule(12))
})

test('IPv6 switched off and on again is as it was', () => {
  const base = routerConfig().wans[0]!
  const wan = clone(WanSchema, base)
  const kept = new Map<string, NonNullable<Wan['ipv6']>>()
  expect(ipv6On(wan)).toBe(true)
  wan.ipv6!.gateway = 'fe80::1'
  setIpv6(wan, false, kept, base)
  expect(ipv6On(wan)).toBe(false)
  expect(wan.ipv6).toBeUndefined()
  setIpv6(wan, true, kept, base)
  expect(wan.ipv6?.prefix).toBe('2001:db8:1::/48')
  expect(wan.ipv6?.gateway).toBe('fe80::1')

  // Off on a WAN where the router has it off is the router's own spelling of off.
  const spelt = clone(WanSchema, base)
  spelt.ipv6!.mode = 'disabled'
  spelt.ipv6!.prefix = ''
  const draft = clone(WanSchema, spelt)
  expect(ipv6On(draft)).toBe(false)
  setIpv6(draft, true, new Map(), spelt)
  expect(ipv6On(draft)).toBe(true)
  expect(draft.ipv6?.mode).toBe('')
  setIpv6(draft, false, new Map(), spelt)
  expect(draft).toEqual(spelt)
  // On where the router has none: a table with nothing in it, which asks the ISP.
  const none = labConfig().wans[0]!
  setIpv6(none, true, new Map(), labConfig().wans[0])
  expect(none.ipv6).toEqual(expect.objectContaining({ mode: '', prefix: '', gateway: '', pdHint: 0 }))
  setIpv6(none, false, new Map(), labConfig().wans[0])
  expect(none).toEqual(labConfig().wans[0])
})

test('what is wrong with a WAN as typed is said by its field', () => {
  const wan = routerConfig().wans[0]!
  expect(wanProblems(wan)).toEqual({})
  wan.vlan = 4095
  wan.ipv6!.prefix = '2001:db8:1::'
  wan.ipv6!.pdHint = 47
  wan.ipv6!.gateway = 'fe80::zz'
  expect(wanProblems(wan)).toEqual({
    vlan: '1 to 4094.',
    'ipv6.prefix': 'A prefix and its length, such as 2001:db8:1::/48.',
    'ipv6.pd_hint': '48 to 64.',
    'ipv6.gateway': 'Not an IPv6 address.',
  })
  const fixed = labConfig().wans[0]!
  setType(fixed, 'static', new Map())
  if (fixed.kind.case === 'static') {
    fixed.kind.value.address = '203.0.113.10'
    fixed.kind.value.gateway = '203.0.113'
    fixed.kind.value.dns = ['203.0.113.1', 'dns.example']
  }
  expect(wanProblems(fixed)).toEqual({
    'static.address': 'An address and a size, such as 192.168.1.1/24.',
    'static.gateway': 'Not an IPv4 address.',
    'static.dns': 'dns.example is not an address.',
  })
  // Every field that can be wrong is one the page has.
  for (const path of [...Object.keys(wanProblems(wan)), ...Object.keys(wanProblems(fixed))]) {
    expect(WAN_FIELDS).toContain(path)
  }
  expect(WAN_FIELDS).toEqual(expect.arrayContaining(['port', 'vlan', 'priority', 'pppoe.username', 'pppoe.password', 'dhcp.hostname', 'ipv6.prefix']))
})
