// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the dialog lists before an apply (SPEC §8.4): every difference between the config as
// the router has it and the draft, each named as the page that edits it names it. The last
// test holds it to the schema: no leaf of the config can differ and go unlisted.

import { clone, ConfigSchema, create, ScalarType, WanSchema, type Config, type DescField, type DescMessage } from '@openfeo/client'
import { expect, test } from 'vitest'

import { changes, type Change } from '../src/model/changes'
import { renumber } from '../src/model/renumber'
import { labConfig } from './fixtures'

/** The lab's config with `edit` done to it, against the lab's config. */
function after(edit: (draft: Config) => void, base: Config = labConfig()): Change[] {
  const draft = clone(ConfigSchema, base)
  edit(draft)
  return changes(base, draft)
}

/** A config whose one WAN is PPPoE on a tagged port, carrying IPv6. */
function pppoeConfig(): Config {
  const config = labConfig()
  config.wans = create(ConfigSchema, {
    wans: [
      {
        name: 'wan0',
        port: 'p0',
        vlan: 911,
        priority: 10,
        kind: { case: 'pppoe', value: { username: 'openfeo@isp.example' } },
        ipv6: { prefix: '2001:db8:1::/48' },
      },
    ],
  }).wans
  return config
}

const pppoe = (config: Config) => {
  const kind = config.wans[0]!.kind
  if (kind.case !== 'pppoe') {
    throw new Error('not PPPoE')
  }
  return kind.value
}

test('two configs that are equal have no changes', () => {
  expect(changes(labConfig(), labConfig())).toEqual([])
  expect(changes(pppoeConfig(), pppoeConfig())).toEqual([])
  // A copy is equal too.
  const config = labConfig()
  expect(changes(config, clone(ConfigSchema, config))).toEqual([])
})

test('each setting of a WAN is one change, named as the page names it', () => {
  const table: [(draft: Config) => void, Change][] = [
    [(d) => (pppoe(d).username = 'other@isp.example'), { subject: 'wan0', what: 'username', before: 'openfeo@isp.example', after: 'other@isp.example' }],
    [(d) => (pppoe(d).service = 'fibre'), { subject: 'wan0', what: 'service name', before: 'none', after: 'fibre' }],
    [(d) => (pppoe(d).ac = 'bras-1'), { subject: 'wan0', what: 'access concentrator', before: 'none', after: 'bras-1' }],
    [(d) => (d.wans[0]!.port = 'p1'), { subject: 'wan0', what: 'port', before: 'p0', after: 'p1' }],
    [(d) => (d.wans[0]!.vlan = 0), { subject: 'wan0', what: 'VLAN tag', before: '911', after: 'none' }],
    [(d) => (d.wans[0]!.priority = 20), { subject: 'wan0', what: 'priority', before: '10', after: '20' }],
    [(d) => (d.wans[0]!.ipv6 = undefined), { subject: 'wan0', what: 'IPv6', before: 'on', after: 'off' }],
    [(d) => (d.wans[0]!.ipv6!.prefix = ''), { subject: 'wan0', what: 'routed prefix', before: '2001:db8:1::/48', after: 'none' }],
    [(d) => (d.wans[0]!.ipv6!.pdHint = 60), { subject: 'wan0', what: 'prefix length to ask for', before: 'none', after: '60' }],
    [(d) => (d.wans[0]!.ipv6!.gateway = 'fe80::1'), { subject: 'wan0', what: 'IPv6 gateway', before: 'none', after: 'fe80::1' }],
  ]
  for (const [edit, change] of table) {
    expect(after(edit, pppoeConfig()), change.what).toEqual([change])
  }

  // The settings of a DHCP WAN, on the lab's.
  expect(after((d) => {
    const kind = d.wans[0]!.kind
    if (kind.case === 'dhcp') {
      kind.value.hostname = ''
      kind.value.vendorClass = 'isp-cpe'
    }
  })).toEqual([
    { subject: 'wan0', what: 'hostname sent', before: 'openfeo-lab', after: 'none' },
    { subject: 'wan0', what: 'vendor class sent', before: 'none', after: 'isp-cpe' },
  ])

  // A type changed: the type, then what was typed for the new one. What the old one had goes with it.
  expect(
    after((d) => {
      d.wans[0]!.kind = create(WanSchema, {
        kind: { case: 'static', value: { address: '203.0.113.10/24', gateway: '203.0.113.1', dns: ['203.0.113.1', '203.0.113.2'] } },
      }).kind
    }),
  ).toEqual([
    { subject: 'wan0', what: 'type', before: 'DHCP', after: 'Static' },
    { subject: 'wan0', what: 'address', before: 'none', after: '203.0.113.10/24' },
    { subject: 'wan0', what: 'gateway', before: 'none', after: '203.0.113.1' },
    { subject: 'wan0', what: 'DNS servers', before: 'none', after: '203.0.113.1, 203.0.113.2' },
  ])

  // IPv6 switched on: that, and what was typed for it.
  expect(after((d) => (d.wans[0]!.ipv6 = create(WanSchema, { ipv6: { prefix: '2001:db8:1::/48' } }).ipv6))).toEqual([
    { subject: 'wan0', what: 'IPv6', before: 'off', after: 'on' },
    { subject: 'wan0', what: 'routed prefix', before: 'none', after: '2001:db8:1::/48' },
  ])
  // "disabled" spelt out is off, as absent is: saying so is no change of IPv6, but it is a difference.
  const spelt = after((d) => (d.wans[0]!.ipv6 = create(WanSchema, { ipv6: { mode: 'disabled' } }).ipv6))
  expect(spelt).toHaveLength(1)
  expect(spelt[0]?.subject).toBe('wans[0].ipv6.mode')
})

test('each setting of a LAN is one change; a pool is one and the reservations are one', () => {
  const table: [(draft: Config) => void, Change][] = [
    [(d) => d.lans[0]!.ports.push('p1'), { subject: 'lan0', what: 'ports', before: 'p2', after: 'p2, p1' }],
    [(d) => (d.lans[0]!.ports = []), { subject: 'lan0', what: 'ports', before: 'p2', after: 'none' }],
    [
      (d) => (d.lans[0]!.dhcp!.range = ['192.168.1.50', '192.168.1.220']),
      { subject: 'lan0', what: 'pool', before: '192.168.1.100 – 192.168.1.200', after: '192.168.1.50 – 192.168.1.220' },
    ],
    [(d) => (d.lans[0]!.dhcp!.leaseSecs = 3600), { subject: 'lan0', what: 'lease time', before: '12 hours', after: '1 hour' }],
    [(d) => (d.lans[0]!.dhcp!.dns = ['192.168.1.53', '203.0.113.1']), { subject: 'lan0', what: 'DNS servers handed out', before: 'the router', after: '192.168.1.53, 203.0.113.1' }],
    [(d) => (d.lans[0]!.dhcp!.ntp = ['192.168.1.123']), { subject: 'lan0', what: 'NTP servers handed out', before: 'the router', after: '192.168.1.123' }],
    [(d) => (d.lans[0]!.ipv6 = 'none'), { subject: 'lan0', what: 'IPv6', before: 'on', after: 'off' }],
    [(d) => (d.lans[0]!.ipv6 = '2001:db8:1:1::1/64'), { subject: 'lan0', what: 'routed /64', before: 'none', after: '2001:db8:1:1::1/64' }],
    [(d) => (d.lans[0]!.ra = false), { subject: 'lan0', what: 'router advertisements', before: 'on', after: 'off' }],
    [(d) => (d.lans[0]!.ipv6Index = 7), { subject: 'lan0', what: 'subnet number', before: 'none', after: '7' }],
    [(d) => (d.lans[0]!.reaches = ['none']), { subject: 'lan0', what: 'may reach', before: 'wan', after: 'none' }],
  ]
  for (const [edit, change] of table) {
    expect(after(edit), `${change.what} ${change.after}`).toEqual([change])
  }
  // A lease time left to the router's default is the default, said either way.
  expect(after((d) => (d.lans[0]!.dhcp!.leaseSecs = 0))).toHaveLength(1)
  expect(after((d) => (d.lans[0]!.dhcp!.leaseSecs = 0))[0]?.subject).toBe('lans[0].dhcp.lease_secs')

  // The reservations together are one change, saying what happened to how many.
  const reserve = (d: Config, mac: string, ip: string, hostname: string) =>
    d.lans[0]!.dhcp!.static.push(create(ConfigSchema, { lans: [{ dhcp: { static: [{ mac, ip, hostname }] } }] }).lans[0]!.dhcp!.static[0]!)
  expect(after((d) => reserve(d, '02:00:00:aa:01:22', '192.168.1.20', 'printer'))).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 added' }])
  expect(after((d) => (d.lans[0]!.dhcp!.static = []))).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 removed' }])
  expect(after((d) => (d.lans[0]!.dhcp!.static[0]!.hostname = 'store'))).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 changed' }])
  // An address alone, with the LAN where it was, is a change and not a move.
  expect(after((d) => (d.lans[0]!.dhcp!.static[0]!.ip = '192.168.1.11'))).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 changed' }])
  expect(
    after((d) => {
      d.lans[0]!.dhcp!.static[0]!.hostname = 'store'
      reserve(d, '02:00:00:aa:01:22', '192.168.1.20', 'printer')
      reserve(d, '02:00:00:aa:01:23', '192.168.1.21', 'camera')
    }),
  ).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '2 added, 1 changed' }])
  // One matched by its client identifier is the same one when the identifier is.
  const byId = labConfig()
  byId.lans[0]!.dhcp!.static[0]!.mac = ''
  byId.lans[0]!.dhcp!.static[0]!.clientId = '01020000aa0110'
  expect(after((d) => (d.lans[0]!.dhcp!.static[0]!.ip = '192.168.1.12'), byId)).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 changed' }])
})

test('a password is said to have changed and never what to', () => {
  const found = after((d) => (pppoe(d).password = 'a-typed-secret'), pppoeConfig())
  expect(found).toEqual([{ subject: 'wan0', what: 'password', before: '', after: 'changed' }])
  expect(JSON.stringify(found)).not.toContain('a-typed-secret')
  // Nor on a WAN that becomes PPPoE, nor on one that is added.
  const switched = after((d) => {
    d.wans[0]!.kind = create(WanSchema, { kind: { case: 'pppoe', value: { username: 'openfeo@isp.example', password: 'a-typed-secret' } } }).kind
    d.wans.push(create(WanSchema, { name: 'wan1', port: 'p1', vlan: 911, kind: { case: 'pppoe', value: { username: 'two@isp.example', password: 'another-typed-secret' } } }))
  })
  expect(switched).toEqual([
    { subject: 'wan0', what: 'type', before: 'DHCP', after: 'PPPoE' },
    { subject: 'wan0', what: 'username', before: 'none', after: 'openfeo@isp.example' },
    { subject: 'wan0', what: 'password', before: '', after: 'changed' },
    { subject: 'wan1', what: 'WAN', before: '', after: 'added: PPPoE on p1.911' },
  ])
  expect(JSON.stringify(switched)).not.toContain('typed-secret')
})

test('a renumbered LAN lists its address, its pool, its reservations as moved, and the forward that followed', () => {
  const found = after((d) => {
    const from = d.lans[0]!.ipv4
    d.lans[0]!.ipv4 = '192.168.2.1/24'
    renumber(d, from, '192.168.2.1/24')
  })
  expect(found).toEqual([
    { subject: 'lan0', what: 'address', before: '192.168.1.1/24', after: '192.168.2.1/24' },
    { subject: 'lan0', what: 'pool', before: '192.168.1.100 – 192.168.1.200', after: '192.168.2.100 – 192.168.2.200' },
    { subject: 'lan0', what: 'reservations', before: '', after: '1 moved into the new subnet' },
    { subject: 'port forward lan-http', what: 'target', before: '192.168.1.2', after: '192.168.2.2' },
  ])
})

test('what a renumbering carried elsewhere is listed by what it is', () => {
  const base = labConfig()
  const more = create(ConfigSchema, {
    firewall: { rules: [{ name: 'cameras', from: 'wan', to: '192.168.1.64/26', proto: 'tcp', ports: ['554'] }] },
    dns: { records: [{ name: 'nas', address: '192.168.1.10' }], upstreams: ['192.168.1.53'] },
  })
  base.firewall!.rules = more.firewall!.rules
  base.dns = more.dns
  const found = after((d) => {
    d.lans[0]!.ipv4 = '192.168.2.1/24'
    renumber(d, '192.168.1.1/24', '192.168.2.1/24')
  }, base)
  expect(found.slice(3)).toEqual([
    { subject: 'port forward lan-http', what: 'target', before: '192.168.1.2', after: '192.168.2.2' },
    { subject: 'rule cameras', what: 'target', before: '192.168.1.64/26', after: '192.168.2.64/26' },
    { subject: 'dns.upstreams', what: '', before: '192.168.1.53', after: '192.168.2.53' },
    { subject: 'DNS record nas', what: 'address', before: '192.168.1.10', after: '192.168.2.10' },
  ])
})

test('a WAN or a LAN added or removed is one change that says what it is', () => {
  expect(
    after((d) => {
      d.wans.push(create(WanSchema, { name: 'wan1', port: 'p1', vlan: 911, priority: 20, kind: { case: 'pppoe', value: { username: 'two@isp.example' } } }))
      d.lans.push(create(ConfigSchema, { lans: [{ name: 'guest', ports: ['p3'], ipv4: '192.168.3.1/24', dhcp: { range: ['192.168.3.100', '192.168.3.200'] } }] }).lans[0]!)
    }),
  ).toEqual([
    { subject: 'wan1', what: 'WAN', before: '', after: 'added: PPPoE on p1.911' },
    { subject: 'guest', what: 'LAN', before: '', after: 'added: 192.168.3.1/24 on p3' },
  ])
  expect(
    after((d) => {
      d.wans = []
      d.lans = []
    }),
  ).toEqual([
    { subject: 'wan0', what: 'WAN', before: 'DHCP on p0', after: 'removed' },
    { subject: 'lan0', what: 'LAN', before: '192.168.1.1/24 on p2', after: 'removed' },
  ])
  // One that is new and still empty says so.
  expect(after((d) => d.lans.push(create(ConfigSchema, { lans: [{ name: 'guest' }] }).lans[0]!))).toEqual([
    { subject: 'guest', what: 'LAN', before: '', after: 'added: no address on no ports' },
  ])
  // Those that stay come first, in the draft's order; those that went, after.
  const two = labConfig()
  two.wans.push(create(WanSchema, { name: 'wan1', port: 'p1', priority: 20, kind: { case: 'dhcp', value: {} } }))
  expect(
    after((d) => {
      d.wans.shift()
      d.wans[0]!.priority = 5
    }, two).map((change) => [change.subject, change.what]),
  ).toEqual([
    ['wan1', 'priority'],
    ['wan0', 'WAN'],
  ])
})

test('a DHCP server turned off says what goes with it', () => {
  expect(after((d) => (d.lans[0]!.dhcp = undefined))).toEqual([{ subject: 'lan0', what: 'DHCP server', before: 'on', after: 'off; its pool and 1 reservation go' }])
  const three = labConfig()
  three.lans[0]!.dhcp!.static.push(...create(ConfigSchema, { lans: [{ dhcp: { static: [{ mac: '02:00:00:aa:01:22', ip: '192.168.1.20' }] } }] }).lans[0]!.dhcp!.static)
  expect(after((d) => (d.lans[0]!.dhcp = undefined), three)[0]?.after).toBe('off; its pool and 2 reservations go')
  const bare = labConfig()
  bare.lans[0]!.dhcp!.static = []
  expect(after((d) => (d.lans[0]!.dhcp = undefined), bare)[0]?.after).toBe('off; its pool goes')

  // Turned on: that, its pool, and what else was set for it.
  const off = labConfig()
  off.lans[0]!.dhcp = undefined
  expect(changes(off, labConfig())).toEqual([
    { subject: 'lan0', what: 'DHCP server', before: 'off', after: 'on' },
    { subject: 'lan0', what: 'pool', before: 'none', after: '192.168.1.100 – 192.168.1.200' },
    { subject: 'lan0', what: 'reservations', before: '', after: '1 added' },
  ])
})

test('a difference no page shows is listed by its path', () => {
  expect(after((d) => (d.firewall!.wanPing = false))).toEqual([{ subject: 'firewall.wan_ping', what: '', before: 'true', after: 'false' }])
  expect(after((d) => (d.firewall!.portForwards[0]!.port = 2223))).toEqual([{ subject: 'firewall.port_forwards[0].port', what: '', before: '2222', after: '2223' }])
  expect(after((d) => (d.system!.hostname = 'edge'))).toEqual([{ subject: 'system.hostname', what: '', before: 'openfeo', after: 'edge' }])
  // Something gone altogether: what it was, and that it is no more.
  expect(after((d) => (d.firewall!.portForwards = []))).toEqual([
    { subject: 'firewall.port_forwards[0].name', what: '', before: 'lan-http', after: 'none' },
    { subject: 'firewall.port_forwards[0].proto', what: '', before: 'tcp', after: 'none' },
    { subject: 'firewall.port_forwards[0].port', what: '', before: '2222', after: 'none' },
    { subject: 'firewall.port_forwards[0].to', what: '', before: '192.168.1.2', after: 'none' },
    { subject: 'firewall.port_forwards[0].to_port', what: '', before: '8080', after: 'none' },
  ])
})

test('the admin’s hash is never listed', () => {
  // It is not sent and not taken (SPEC §8.3): a draft that carries one changes nothing.
  expect(after((d) => (d.admin = create(ConfigSchema, { admin: { passwordHash: '$argon2id$not-a-real-hash' } }).admin))).toEqual([])
})

/** A step from a message to one of its fields: by name, and into the first element of a list. */
type Step = { field: DescField }

/** Every leaf field under a message, as the steps that lead to it. */
function leaves(schema: DescMessage, under: Step[] = [], depth = 0): Step[][] {
  return schema.fields.flatMap((field) => {
    const here = [...under, { field }]
    const message = field.fieldKind === 'message' ? field.message : field.fieldKind === 'list' && field.listKind === 'message' ? field.message : undefined
    return message === undefined ? [here] : depth > 6 ? [] : leaves(message, here, depth + 1)
  })
}

/** Change the one leaf the steps lead to, making whatever stands on the way that is not there. */
function alter(config: Config, steps: Step[]): void {
  let holder = config as unknown as Record<string, unknown>
  for (const [at, { field }] of steps.entries()) {
    const last = at === steps.length - 1
    let owner = holder
    let slot = field.localName
    if (field.oneof !== undefined) {
      const group = holder[field.oneof.localName] as { case?: string; value?: unknown }
      if (group.case !== field.localName) {
        holder[field.oneof.localName] = { case: field.localName, value: last ? undefined : create(field.message as DescMessage) }
      }
      owner = holder[field.oneof.localName] as Record<string, unknown>
      slot = 'value'
    }
    if (!last) {
      if (field.fieldKind === 'list') {
        const list = owner[slot] as unknown[]
        if (list.length === 0) {
          list.push(create(field.message as DescMessage))
        }
        holder = list[0] as Record<string, unknown>
      } else {
        owner[slot] ??= create(field.message as DescMessage)
        holder = owner[slot] as Record<string, unknown>
      }
      continue
    }
    const scalar = field.fieldKind === 'scalar' || (field.fieldKind === 'list' && field.listKind === 'scalar') ? field.scalar : undefined
    const other = (value: unknown): unknown => (scalar === ScalarType.STRING ? `${String(value ?? '')}x` : scalar === ScalarType.BOOL ? value !== true : Number(value ?? 0) + 1)
    if (field.fieldKind === 'list') {
      ;(owner[slot] as unknown[]).push(other(undefined))
    } else {
      owner[slot] = other(owner[slot])
    }
  }
}

test('nothing an apply would alter is left out', () => {
  const all = leaves(ConfigSchema)
  expect(all.length).toBeGreaterThan(50)
  const name = (steps: Step[]) => steps.map((step) => step.field.name).join('.')
  for (const base of [labConfig(), pppoeConfig()]) {
    for (const steps of all) {
      if (name(steps) === 'admin.password_hash') {
        continue
      }
      const draft = clone(ConfigSchema, base)
      alter(draft, steps)
      expect(changes(base, draft).length, name(steps)).toBeGreaterThan(0)
    }
  }
})
