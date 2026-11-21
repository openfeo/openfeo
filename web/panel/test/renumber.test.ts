// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What follows a LAN whose address or subnet changes (SPEC §8.4): every IPv4 address in the
// config that lay in the old subnet. The last test holds the rule to every string field the
// schema has, so a field added later is classified or the test fails.

import { clone, ConfigSchema, create, equals, LanSchema, ScalarType, type Config, type DescMessage } from '@openfeo/client'
import { expect, test } from 'vitest'

import { renumber, STRING_FIELDS } from '../src/model/renumber'
import { labConfig } from './fixtures'

/** Set `lan0`'s address as the page does, then carry what follows it. */
function move(config: Config, to: string) {
  const lan = config.lans[0]
  if (lan === undefined) {
    throw new Error('the config has no LAN')
  }
  const from = lan.ipv4
  lan.ipv4 = to
  return renumber(config, from, to)
}

test('a move to another subnet carries the pool, the reservations and what points in from elsewhere', () => {
  const config = labConfig()
  config.dns = create(ConfigSchema, { dns: { records: [{ name: 'nas', address: '192.168.1.10' }], upstreams: ['192.168.1.53', '203.0.113.1'] } }).dns
  const lan = config.lans[0]
  if (lan?.dhcp !== undefined) {
    lan.dhcp.dns = ['192.168.1.53']
    lan.dhcp.ntp = ['192.168.1.1']
  }
  if (config.system !== undefined) {
    config.system.ntpServers = ['192.168.1.123', 'pool.ntp.example']
  }
  expect(move(config, '192.168.2.1/24')).toEqual([])
  expect(lan?.ipv4).toBe('192.168.2.1/24')
  expect(lan?.dhcp?.range).toEqual(['192.168.2.100', '192.168.2.200'])
  expect(lan?.dhcp?.static.map((lease) => lease.ip)).toEqual(['192.168.2.10'])
  expect(lan?.dhcp?.dns).toEqual(['192.168.2.53'])
  expect(lan?.dhcp?.ntp).toEqual(['192.168.2.1'])
  expect(config.firewall?.portForwards[0]?.to).toBe('192.168.2.2')
  expect(config.dns?.records[0]?.address).toBe('192.168.2.10')
  expect(config.dns?.upstreams).toEqual(['192.168.2.53', '203.0.113.1'])
  expect(config.system?.ntpServers).toEqual(['192.168.2.123', 'pool.ntp.example'])
  // What is not an address in the old subnet is as it was.
  expect(lan?.dhcp?.static[0]?.mac).toBe('52:54:00:fe:10:10')
  expect(config.firewall?.portForwards[0]?.name).toBe('lan-http')
})

test('an address still inside the new subnet stays', () => {
  const config = labConfig()
  const before = clone(ConfigSchema, config)
  expect(move(config, '192.168.1.1/23')).toEqual([])
  before.lans[0]!.ipv4 = '192.168.1.1/23'
  expect(equals(ConfigSchema, config, before)).toBe(true)
})

test('an address left outside moves by its distance from the start', () => {
  const config = labConfig()
  expect(move(config, '192.168.1.129/25')).toEqual([])
  // .100 lay outside 192.168.1.128/25 and takes the place 100 from its start; .200 is inside.
  expect(config.lans[0]?.dhcp?.range).toEqual(['192.168.1.228', '192.168.1.200'])
  // .10 goes to .138 and the forward's .2 to .130.
  expect(config.lans[0]?.dhcp?.static[0]?.ip).toBe('192.168.1.138')
  expect(config.firewall?.portForwards[0]?.to).toBe('192.168.1.130')
})

test('an address with no place is left and reported', () => {
  const config = labConfig()
  const lan = config.lans[0]!
  lan.ipv4 = '192.168.0.1/23'
  lan.dhcp!.range = ['192.168.0.100', '192.168.0.200']
  lan.dhcp!.static[0]!.ip = '192.168.1.50'
  config.firewall!.portForwards[0]!.to = '192.168.1.2'
  const unfit = move(config, '192.168.0.1/24')
  expect(unfit).toEqual([
    { path: 'lans[0].dhcp.static[0].ip', value: '192.168.1.50' },
    { path: 'firewall.port_forwards[0].to', value: '192.168.1.2' },
  ])
  expect(lan.dhcp!.static[0]!.ip).toBe('192.168.1.50')
  expect(config.firewall!.portForwards[0]!.to).toBe('192.168.1.2')
  // What still fits is where it was.
  expect(lan.dhcp!.range).toEqual(['192.168.0.100', '192.168.0.200'])
})

test('what was the router’s own address follows the router', () => {
  const config = labConfig()
  const lan = config.lans[0]!
  lan.dhcp!.dns = ['192.168.1.1']
  config.dns = create(ConfigSchema, { dns: { records: [{ name: 'router', address: '192.168.1.1' }] } }).dns
  // The router moves within its own subnet: nothing else does.
  expect(move(config, '192.168.1.254/24')).toEqual([])
  expect(lan.dhcp!.dns).toEqual(['192.168.1.254'])
  expect(config.dns?.records[0]?.address).toBe('192.168.1.254')
  expect(lan.dhcp!.range).toEqual(['192.168.1.100', '192.168.1.200'])
})

test("a rule's target moves as an address, a range and a block", () => {
  const rules = (targets: string[]) => {
    const config = labConfig()
    config.firewall!.rules = create(ConfigSchema, {
      firewall: { rules: targets.map((to, n) => ({ name: `rule${n}`, from: 'wan', to, proto: 'tcp', ports: ['443'] })) },
    }).firewall!.rules
    return config
  }
  const config = rules(['192.168.1.20', '192.168.1.10-192.168.1.20', '192.168.1.0/24', '192.168.1.64/26', '2001:db8:1:1::10', '192.168.9.0/24', 'lan1'])
  expect(move(config, '192.168.2.1/24')).toEqual([])
  expect(config.firewall!.rules.map((rule) => rule.to)).toEqual([
    '192.168.2.20',
    '192.168.2.10-192.168.2.20',
    '192.168.2.0/24',
    '192.168.2.64/26',
    '2001:db8:1:1::10',
    '192.168.9.0/24',
    'lan1',
  ])

  // The old subnet itself becomes the new one, whatever its size.
  const widened = rules(['192.168.1.0/24'])
  expect(move(widened, '192.168.4.1/22')).toEqual([])
  expect(widened.firewall!.rules[0]?.to).toBe('192.168.4.0/22')

  // A range moves whole or not at all, and a smaller block must still be a block inside.
  const halved = rules(['192.168.1.100-192.168.1.200', '192.168.1.0/25', '192.168.1.192/26', '192.168.1.200-192.168.1.250'])
  expect(move(halved, '192.168.1.129/25')).toEqual([{ path: 'firewall.rules[0].to', value: '192.168.1.100-192.168.1.200' }])
  expect(halved.firewall!.rules.map((rule) => rule.to)).toEqual([
    // No place for both ends: left whole.
    '192.168.1.100-192.168.1.200',
    // The lower half goes where an address at its start would: onto the new subnet.
    '192.168.1.128/25',
    // Already inside: where they were.
    '192.168.1.192/26',
    '192.168.1.200-192.168.1.250',
  ])

  // A block that would no longer be a block has no place.
  const quartered = rules(['192.168.1.0/25'])
  // (The lab's pool has none either in a subnet a quarter the size; this looks at the rule.)
  expect(move(quartered, '192.168.1.193/26').filter((left) => left.path.startsWith('firewall.rules'))).toEqual([
    { path: 'firewall.rules[0].to', value: '192.168.1.0/25' },
  ])
  expect(quartered.firewall!.rules[0]?.to).toBe('192.168.1.0/25')
})

test('another LAN, the WAN side and every IPv6 address are left alone', () => {
  const config = labConfig()
  const wan = create(ConfigSchema, {
    wans: [{ name: 'wan1', port: 'p1', priority: 20, kind: { case: 'static', value: { address: '192.168.1.5/24', gateway: '192.168.1.254', dns: ['192.168.1.53'] } } }],
    lans: [{ name: 'guest', ports: ['p3'], ipv4: '192.168.3.1/24', ipv6: '2001:db8:1:3::1/64', dhcp: { range: ['192.168.3.100', '192.168.3.200'] } }],
    publicIpv4: [{ prefix: '198.51.100.0/29' }],
  })
  config.wans.push(...wan.wans)
  config.lans.push(...wan.lans)
  config.publicIpv4 = wan.publicIpv4
  config.firewall!.portForwards[0]!.address = '198.51.100.2'
  const before = clone(ConfigSchema, config)
  expect(move(config, '192.168.2.1/24')).toEqual([])
  // The other LAN, whole.
  expect(equals(LanSchema, config.lans[1]!, before.lans[1]!)).toBe(true)
  // A static WAN's own address and gateway are the ISP's side, even when they look like the LAN's.
  const fixed = config.wans[1]!.kind
  expect(fixed.case === 'static' && fixed.value.address).toBe('192.168.1.5/24')
  expect(fixed.case === 'static' && fixed.value.gateway).toBe('192.168.1.254')
  // Its resolvers are carried: an address in the LAN is a device on the LAN.
  expect(fixed.case === 'static' && fixed.value.dns).toEqual(['192.168.2.53'])
  expect(config.publicIpv4[0]?.prefix).toBe('198.51.100.0/29')
  expect(config.firewall!.portForwards[0]!.address).toBe('198.51.100.2')
  expect(config.lans[1]?.ipv6).toBe('2001:db8:1:3::1/64')
})

/** The lab's config with a second LAN, `guest`, that has a pool, a reservation, a rule and a record of its own, and hands out a DNS server that sits on lan0. */
function twoLans(): Config {
  const config = labConfig()
  const more = create(ConfigSchema, {
    lans: [
      {
        name: 'guest',
        ports: ['p1'],
        ipv4: '192.168.3.1/24',
        dhcp: { range: ['192.168.3.100', '192.168.3.200'], static: [{ mac: '02:00:00:aa:03:10', ip: '192.168.3.10', hostname: 'tv' }], dns: ['192.168.1.53'], ntp: ['192.168.3.1'] },
      },
    ],
    firewall: { rules: [{ name: 'cameras', from: 'wan', to: '192.168.3.64/26', proto: 'tcp', ports: ['554'] }] },
    dns: { records: [{ name: 'tv', address: '192.168.3.10' }] },
  })
  config.lans.push(...more.lans)
  config.firewall!.rules = more.firewall!.rules
  config.dns = more.dns
  return config
}

test("a LAN's own pool follows only its own move", () => {
  const config = twoLans()
  const [lan0, guest] = [config.lans[0]!, config.lans[1]!]
  // lan0 is given a subnet that guest is in: for a moment the two are in one, as they are
  // half way through being swapped.
  lan0.ipv4 = '192.168.3.1/24'
  expect(renumber(config, '192.168.1.1/24', '192.168.3.1/24', 'lan0')).toEqual([])
  expect(lan0.dhcp!.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(lan0.dhcp!.static[0]!.ip).toBe('192.168.3.10')
  // Guest's own are where they were, and the server it hands out, which sits on lan0, followed lan0.
  expect(guest.dhcp!.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(guest.dhcp!.static[0]!.ip).toBe('192.168.3.10')
  expect(guest.dhcp!.dns).toEqual(['192.168.3.53'])

  // Guest moves out: its own pool and reservation go with it, and lan0's, which now lie in
  // the subnet guest is leaving, stay.
  guest.ipv4 = '192.168.1.1/24'
  expect(renumber(config, '192.168.3.1/24', '192.168.1.1/24', 'guest')).toEqual([])
  expect(guest.dhcp!.range).toEqual(['192.168.1.100', '192.168.1.200'])
  expect(guest.dhcp!.static[0]!.ip).toBe('192.168.1.10')
  expect(lan0.dhcp!.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(lan0.dhcp!.static[0]!.ip).toBe('192.168.3.10')
  // Without an owner every address of the subnet is carried, as before.
  const plain = twoLans()
  plain.lans[0]!.ipv4 = '192.168.3.1/24'
  renumber(plain, '192.168.1.1/24', '192.168.3.1/24')
  plain.lans[1]!.ipv4 = '192.168.1.1/24'
  renumber(plain, '192.168.3.1/24', '192.168.1.1/24')
  expect(plain.lans[0]!.dhcp!.range).toEqual(['192.168.1.100', '192.168.1.200'])
})

test('two LANs swap their subnets, and what pointed into each still does', () => {
  // Half way through, both LANs are in one subnet, and an address there says nothing of
  // which LAN it belongs to. What tells them apart is the config the draft was read from:
  // the LAN a field points into there is the one it belongs to, wherever an earlier move of
  // this draft has carried it since.
  const base = twoLans()
  const config = twoLans()
  const [lan0, guest] = [config.lans[0]!, config.lans[1]!]
  lan0.ipv4 = '192.168.3.1/24'
  expect(renumber(config, '192.168.1.1/24', '192.168.3.1/24', 'lan0', base)).toEqual([])
  guest.ipv4 = '192.168.1.1/24'
  expect(renumber(config, '192.168.3.1/24', '192.168.1.1/24', 'guest', base)).toEqual([])

  // lan0 and all that pointed into it are in 192.168.3.0/24.
  expect(lan0.dhcp!.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(lan0.dhcp!.static[0]!.ip).toBe('192.168.3.10')
  expect(config.firewall!.portForwards[0]!.to).toBe('192.168.3.2')
  expect(guest.dhcp!.dns).toEqual(['192.168.3.53'])
  // Guest and all that pointed into it are in 192.168.1.0/24: its rule, its record, and its
  // own router handed out as the time server.
  expect(guest.dhcp!.range).toEqual(['192.168.1.100', '192.168.1.200'])
  expect(guest.dhcp!.static[0]!.ip).toBe('192.168.1.10')
  expect(config.firewall!.rules[0]!.to).toBe('192.168.1.64/26')
  expect(config.dns!.records[0]!.address).toBe('192.168.1.10')
  expect(guest.dhcp!.ntp).toEqual(['192.168.1.1'])

  // The LAN that arrived moves on while the other stays: what came with it goes with it,
  // and what was the resident's is left.
  const again = twoLans()
  again.lans[0]!.ipv4 = '192.168.3.1/24'
  renumber(again, '192.168.1.1/24', '192.168.3.1/24', 'lan0', base)
  again.lans[0]!.ipv4 = '192.168.5.1/24'
  expect(renumber(again, '192.168.3.1/24', '192.168.5.1/24', 'lan0', base)).toEqual([])
  expect(again.lans[0]!.dhcp!.range).toEqual(['192.168.5.100', '192.168.5.200'])
  expect(again.firewall!.portForwards[0]!.to).toBe('192.168.5.2')
  expect(again.lans[1]!.dhcp!.dns).toEqual(['192.168.5.53'])
  expect(again.lans[1]!.dhcp!.range).toEqual(['192.168.3.100', '192.168.3.200'])
  expect(again.firewall!.rules[0]!.to).toBe('192.168.3.64/26')
  expect(again.dns!.records[0]!.address).toBe('192.168.3.10')
  expect(again.lans[1]!.dhcp!.ntp).toEqual(['192.168.3.1'])
})

test('in a shared subnet a field is known by the names above it, not by its place', () => {
  // A LAN between the two is removed in the same draft, so guest is the third LAN as the
  // router has it and the second in the draft. The server it hands out is its own.
  const base = twoLans()
  base.lans.splice(1, 0, ...create(ConfigSchema, { lans: [{ name: 'mid', ports: ['p4'], ipv4: '192.168.2.1/24', dhcp: { dns: ['192.168.1.53'] } }] }).lans)
  base.lans[2]!.dhcp!.dns = ['192.168.3.53']
  const config = clone(ConfigSchema, base)
  config.lans.splice(1, 1)
  const [lan0, guest] = [config.lans[0]!, config.lans[1]!]
  lan0.ipv4 = '192.168.3.1/24'
  expect(renumber(config, '192.168.1.1/24', '192.168.3.1/24', 'lan0', base)).toEqual([])
  guest.ipv4 = '192.168.1.1/24'
  expect(renumber(config, '192.168.3.1/24', '192.168.1.1/24', 'guest', base)).toEqual([])
  // Its own server went with it. By place, it would have been taken for the server that
  // the removed LAN handed out, which sat on lan0, and left behind.
  expect(guest.dhcp!.dns).toEqual(['192.168.1.53'])
  expect(config.firewall!.portForwards[0]!.to).toBe('192.168.3.2')
})

test('in a shared subnet a field that was pointed elsewhere by hand is no longer the other LAN\'s', () => {
  // As the router has it, guest hands out a server on lan0. In this draft it hands out its
  // own router. What the router's config says of the field is not what the field holds, so
  // it is not lan0's to keep: it follows guest.
  const base = twoLans()
  const config = twoLans()
  const [lan0, guest] = [config.lans[0]!, config.lans[1]!]
  guest.dhcp!.dns = ['192.168.3.1']
  lan0.ipv4 = '192.168.3.1/24'
  renumber(config, '192.168.1.1/24', '192.168.3.1/24', 'lan0', base)
  expect(guest.dhcp!.dns).toEqual(['192.168.3.1'])
  guest.ipv4 = '192.168.1.1/24'
  expect(renumber(config, '192.168.3.1/24', '192.168.1.1/24', 'guest', base)).toEqual([])
  expect(guest.dhcp!.dns).toEqual(['192.168.1.1'])
  // And the forward into lan0, which holds what lan0's move made of it, stayed with lan0.
  expect(config.firewall!.portForwards[0]!.to).toBe('192.168.3.2')
})

test('moving there and back changes nothing', () => {
  const config = labConfig()
  const before = clone(ConfigSchema, config)
  expect(move(config, '192.168.2.1/24')).toEqual([])
  expect(equals(ConfigSchema, config, before)).toBe(false)
  expect(move(config, '192.168.1.1/24')).toEqual([])
  expect(equals(ConfigSchema, config, before)).toBe(true)
})

test('an address that is not valid, before or after, carries nothing', () => {
  const config = labConfig()
  const before = clone(ConfigSchema, config)
  expect(renumber(config, '192.168.1.1/24', '192.168.2')).toEqual([])
  expect(renumber(config, '', '192.168.2.1/24')).toEqual([])
  expect(renumber(config, '192.168.1.1/24', '192.168.1.1/24')).toEqual([])
  expect(equals(ConfigSchema, config, before)).toBe(true)
})

/** Every string and repeated-string field under a message, by its path without indices. */
function stringFields(schema: DescMessage, under = ''): string[] {
  return schema.fields.flatMap((field) => {
    const path = under === '' ? field.name : `${under}.${field.name}`
    if (field.fieldKind === 'scalar') {
      return field.scalar === ScalarType.STRING ? [path] : []
    }
    if (field.fieldKind === 'message') {
      return stringFields(field.message, path)
    }
    if (field.fieldKind === 'list') {
      if (field.listKind === 'message') {
        return stringFields(field.message, path)
      }
      return field.listKind === 'scalar' && field.scalar === ScalarType.STRING ? [path] : []
    }
    if (field.fieldKind === 'map') {
      throw new Error(`${path} is a map: the rule that carries addresses does not look inside one`)
    }
    return []
  })
}

test('every string field of the config is classified', () => {
  const inSchema = stringFields(ConfigSchema).sort()
  expect(inSchema.length).toBeGreaterThan(30)
  expect(Object.keys(STRING_FIELDS).sort()).toEqual(inSchema)
  // The ones that are carried, and the one that is a rule's target.
  const of = (kind: string) => Object.keys(STRING_FIELDS).filter((path) => STRING_FIELDS[path] === kind).sort()
  expect(of('carried')).toEqual(
    ['dns.records.address', 'dns.upstreams', 'firewall.port_forwards.to', 'lans.dhcp.dns', 'lans.dhcp.ntp', 'system.ntp_servers', 'wans.static.dns'].sort(),
  )
  // A LAN's own: they follow that LAN and no other.
  expect(of('own')).toEqual(['lans.dhcp.range', 'lans.dhcp.static.ip'])
  expect(of('target')).toEqual(['firewall.rules.to'])
  expect(STRING_FIELDS['lans.ipv4']).toBe('left')
})
