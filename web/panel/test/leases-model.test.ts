// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { clone, ConfigSchema, create, LeaseSchema, type Config, type Lease } from '@openfeo/client'
import { expect, test } from 'vitest'

import { ago, leaseKey, leaseRows, matches, newestFirst, perLan, reserve, reserved, until } from '../src/model/leases'
import { labConfig, NOW } from './fixtures'

function lease(address: string, joined: number, more: Partial<Pick<Lease, 'lan' | 'mac' | 'hostname'>> = {}): Lease {
  return create(LeaseSchema, {
    lan: more.lan ?? 'lan0',
    address,
    mac: more.mac ?? `02:00:00:00:00:${address.split('.').at(-1)?.padStart(2, '0') ?? '00'}`,
    hostname: more.hostname ?? '',
    joinedUnix: BigInt(joined),
    expiresUnix: BigInt(joined + 43_200),
  })
}

test('the newest come first, and equal times keep one order', () => {
  const table = [
    lease('192.168.1.131', 100),
    lease('192.168.1.143', 900),
    lease('192.168.20.107', 500, { lan: 'iot' }),
    lease('192.168.1.120', 500),
    lease('192.168.1.110', 500),
  ]
  const order = (leases: Lease[]) => newestFirst(leases).map((each) => each.address)
  expect(order(table)).toEqual(['192.168.1.143', '192.168.20.107', '192.168.1.110', '192.168.1.120', '192.168.1.131'])
  expect(order([...table].reverse())).toEqual(order(table))
  // Addresses are ordered as addresses, not as text.
  expect(order([lease('192.168.1.9', 1), lease('192.168.1.10', 1)])).toEqual(['192.168.1.9', '192.168.1.10'])
  expect(table.map((each) => each.address)[0]).toBe('192.168.1.131')
})

test('a filter finds a lease by its address, its name or its MAC, in either case', () => {
  const plug = lease('192.168.1.143', 1, { hostname: 'plug-kitchen', mac: '02:00:00:3a:11:9e' })
  expect(matches(plug, '')).toBe(true)
  expect(matches(plug, '  ')).toBe(true)
  expect(matches(plug, '1.143')).toBe(true)
  expect(matches(plug, 'KITCHEN')).toBe(true)
  expect(matches(plug, '3A:11')).toBe(true)
  expect(matches(plug, ' kitchen ')).toBe(true)
  expect(matches(plug, 'lan0')).toBe(false)
  expect(matches(plug, 'printer')).toBe(false)
})

test('a device with no name is not found by "none"', () => {
  // The page writes "none given" where there is no name; that is the page's word, not the device's.
  expect(matches(lease('192.168.1.120', 1), 'none')).toBe(false)
})

test('the filter is text, not a pattern', () => {
  const plug = lease('192.168.1.143', 1, { hostname: 'plug-kitchen' })
  expect(matches(plug, '.*')).toBe(false)
  expect(matches(plug, '1.14')).toBe(true)
  expect(matches(plug, '1x14')).toBe(false)
  expect(matches(plug, '(')).toBe(false)
  expect(matches(plug, 'plug[')).toBe(false)
})

test('each LAN has its count, in the order the LANs are given', () => {
  const table = [lease('192.168.1.143', 1), lease('192.168.20.107', 1, { lan: 'iot' }), lease('192.168.1.120', 1)]
  expect(perLan(table, ['lan0', 'iot', 'guest'])).toEqual([
    { lan: 'lan0', count: 2 },
    { lan: 'iot', count: 1 },
    { lan: 'guest', count: 0 },
  ])
})

test('how long ago, by its largest unit', () => {
  expect(ago(0)).toBe('just now')
  expect(ago(59)).toBe('just now')
  expect(ago(60)).toBe('1 min ago')
  expect(ago(119)).toBe('1 min ago')
  expect(ago(120)).toBe('2 min ago')
  expect(ago(3_599)).toBe('59 min ago')
  expect(ago(3_600)).toBe('1 h ago')
  expect(ago(86_399)).toBe('23 h ago')
  expect(ago(86_400)).toBe('1 d ago')
  expect(ago(3 * 86_400 + 5)).toBe('3 d ago')
})

test('a time ahead of the clock is just now', () => {
  // A lease file written under a right clock and read while the clock is still the build's.
  expect(ago(-30)).toBe('just now')
  expect(ago(-86_400)).toBe('just now')
  expect(ago(Number.NaN)).toBe('just now')
})

test('how long until, by its two largest units', () => {
  expect(until(0)).toBe('expired')
  expect(until(-5)).toBe('expired')
  expect(until(30)).toBe('in under a minute')
  expect(until(240)).toBe('in 4 min')
  expect(until(43_080)).toBe('in 11 h 58 min')
  expect(until(25_320)).toBe('in 7 h 02 min')
  expect(until(3_600)).toBe('in 1 h 00 min')
  expect(until(3 * 86_400)).toBe('in 3 d')
  expect(until(86_400 + 7_200)).toBe('in 1 d 2 h')
})

test('ages are counted on the router’s clock', () => {
  // The functions take seconds, counted by the caller against the table's own clock, and no
  // `Date`: a browser whose clock is a day wrong still reads "2 min ago".
  const table = { timeUnix: 1_800_000_000n, carriedOnSecs: 5 }
  const plug = lease('192.168.1.143', 1_799_999_885)
  const routerNow = Number(table.timeUnix) + table.carriedOnSecs
  expect(ago(routerNow - Number(plug.joinedUnix))).toBe('2 min ago')
  expect(until(Number(plug.expiresUnix) - routerNow)).toBe('in 11 h 58 min')
})

test('a row is told from every other by its LAN, its MAC and its address', () => {
  expect(leaseKey(lease('192.168.1.143', 1, { mac: '02:00:00:3A:11:9E' }))).toBe('lan0 02:00:00:3a:11:9e 192.168.1.143')
})

/** The lab's config with a second LAN that has no DHCP server. */
function config(): Config {
  const made = labConfig()
  const lan0 = made.lans[0]
  if (lan0 !== undefined) {
    const quiet = clone(ConfigSchema, made).lans[0]
    if (quiet !== undefined) {
      quiet.name = 'quiet'
      quiet.dhcp = undefined
      made.lans.push(quiet)
    }
  }
  return made
}

test('whether a lease is reserved, by what the router has and what the draft has', () => {
  const base = config()
  const draft = clone(ConfigSchema, base)
  const plug = lease('192.168.1.143', 1, { mac: '02:00:00:3A:11:9E', hostname: 'plug-kitchen' })
  expect(reserved(plug, base, draft)).toBe('no')
  // The router's own reservation, whatever case its MAC is written in.
  const nas = lease('192.168.1.10', 1, { mac: '52:54:00:FE:10:10', hostname: 'nas' })
  expect(reserved(nas, base, draft)).toBe('applied')
  // In the draft and not yet the router's.
  reserve(draft, base, plug)
  expect(reserved(plug, base, draft)).toBe('draft')
  // Taken out of the draft again on LAN & DHCP: it is offered again.
  const removed = clone(ConfigSchema, base)
  removed.lans[0]?.dhcp?.static.splice(0, 1)
  expect(reserved(nas, base, removed)).toBe('no')
})

test('no Reserve where the draft cannot take one', () => {
  const base = config()
  const plug = lease('192.168.1.143', 1, { mac: '02:00:00:3a:11:9e' })
  expect(reserved(plug, base, null)).toBe('unavailable')
  // Its LAN is gone from the draft.
  const gone = clone(ConfigSchema, base)
  gone.lans.splice(0, 1)
  expect(reserved(plug, base, gone)).toBe('unavailable')
  // Its LAN has no DHCP server in the draft.
  expect(reserved(lease('192.168.1.143', 1, { lan: 'quiet' }), base, clone(ConfigSchema, base))).toBe('unavailable')
  // Its MAC is reserved for another address, or its address for another MAC.
  const nasMoved = lease('192.168.1.144', 1, { mac: '52:54:00:fe:10:10' })
  expect(reserved(nasMoved, base, clone(ConfigSchema, base))).toBe('unavailable')
  const squatter = lease('192.168.1.10', 1, { mac: '02:00:00:00:00:77' })
  expect(reserved(squatter, base, clone(ConfigSchema, base))).toBe('unavailable')
})

test('Reserve puts the MAC, the address and the name into that LAN’s reservations and nowhere else', () => {
  const base = config()
  const draft = clone(ConfigSchema, base)
  reserve(draft, base, lease('192.168.1.143', 1, { mac: '02:00:00:3a:11:9e', hostname: 'plug-kitchen' }))
  const added = draft.lans[0]?.dhcp?.static.at(-1)
  expect([added?.mac, added?.ip, added?.hostname, added?.clientId]).toEqual(['02:00:00:3a:11:9e', '192.168.1.143', 'plug-kitchen', ''])
  expect(draft.lans[0]?.dhcp?.static).toHaveLength(2)
  expect(draft.lans[1]?.dhcp).toBeUndefined()
  // A device that gave no name is reserved with none.
  reserve(draft, base, lease('192.168.1.150', 1))
  expect(draft.lans[0]?.dhcp?.static.at(-1)?.hostname).toBe('')
})

test('reserving twice adds one', () => {
  const base = config()
  const draft = clone(ConfigSchema, base)
  const plug = lease('192.168.1.143', 1, { mac: '02:00:00:3a:11:9e' })
  reserve(draft, base, plug)
  reserve(draft, base, plug)
  expect(draft.lans[0]?.dhcp?.static).toHaveLength(2)
  // Nor is anything added for a lease that cannot be reserved.
  reserve(draft, base, lease('192.168.1.143', 1, { lan: 'quiet' }))
  reserve(draft, base, lease('192.168.1.10', 1, { mac: '02:00:00:00:00:77' }))
  expect(draft.lans[0]?.dhcp?.static).toHaveLength(2)
})

test('a row says its ages on the router’s clock and its exact times on the browser’s', () => {
  // The router's clock is a year behind the browser's: the ages do not notice, and the exact
  // times are counted back from the browser's now by the router's own measure.
  const routerClock = Math.floor(NOW.getTime() / 1000) - 31_536_000
  const plug = lease('192.168.1.143', routerClock - 125, { hostname: 'plug-kitchen', mac: '02:00:00:3A:11:9E' })
  const unnamed = lease('192.168.20.107', routerClock - 2 * 86_400 - 60, { lan: 'iot' })
  const rows = leaseRows([plug, unnamed], routerClock, NOW, (_, joinedSecsAgo) => joinedSecsAgo !== undefined && joinedSecsAgo < 180)
  expect(rows[0]).toEqual({
    key: 'lan0 02:00:00:3a:11:9e 192.168.1.143',
    joined: '2 min ago',
    joinedAt: '19:40:25',
    address: '192.168.1.143',
    name: 'plug-kitchen',
    named: 'yes',
    mac: '02:00:00:3A:11:9E',
    lan: 'lan0',
    expires: 'in 11 h 57 min',
    expiresAt: '11 Nov 07:40',
    fresh: 'yes',
  })
  expect(rows[1]).toMatchObject({ joined: '2 d ago', joinedAt: '8 Nov 19:41', name: 'none given', named: '', lan: 'iot', fresh: '' })
  // Until the router has said what time it is, there is no age to say.
  const waiting = leaseRows([plug], undefined, NOW, () => true)
  expect(waiting[0]).toMatchObject({ joined: '—', joinedAt: '', expires: '—', expiresAt: '', fresh: 'yes' })
})
