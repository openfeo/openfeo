// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Routes page makes of the router's dump (SPEC §8.4): which routes a person reads,
// in what order, and whose each one is.

import { create, RouteKind, RouteSchema, type Route } from '@openfeo/client'
import { expect, test } from 'vitest'

import { routeRows } from '../src/model/routes'
import { state } from './fixtures'

type Init = Partial<Pick<Route, 'v6' | 'table' | 'destination' | 'gateway' | 'interface' | 'protocol' | 'metric' | 'kind'>>

function route(init: Init): Route {
  return create(RouteSchema, { table: 'main', protocol: 'openfeo', kind: RouteKind.UNICAST, ...init })
}

const DEFAULT4 = route({ gateway: '203.0.113.1', interface: 'ppp-wan0', metric: 10 })
const PEER = route({ destination: '203.0.113.1/32', interface: 'ppp-wan0', protocol: 'kernel' })
const LAN0 = route({ destination: '192.168.1.0/24', interface: 'br-lan0', protocol: 'kernel' })
const IOT = route({ destination: '192.168.20.0/24', interface: 'br-iot', protocol: 'kernel' })

const destinations = (routes: Route[], v6 = false) => routeRows(routes, state(), v6).map((row) => row.destination)
const only = (init: Init, v6 = false) => {
  const rows = routeRows([route(init)], state(), v6)
  expect(rows).toHaveLength(1)
  return rows[0]!
}

test('the page shows main and the WANs’ own tables, and not the kernel’s', () => {
  const routes = [
    LAN0,
    // The kernel's own entries: its table, and its kind wherever it is.
    route({ table: 'local', destination: '192.168.1.1/32', interface: 'br-lan0', protocol: 'kernel', kind: RouteKind.LOCAL }),
    route({ table: 'local', destination: '192.168.1.255/32', interface: 'br-lan0', protocol: 'kernel' }),
    route({ destination: '192.168.1.0/32', interface: 'br-lan0', protocol: 'kernel', kind: RouteKind.LOCAL }),
    // What every interface has.
    route({ destination: '224.0.0.0/4', interface: 'br-lan0', protocol: 'kernel' }),
    route({ v6: true, destination: 'fe80::/64', interface: 'br-lan0', protocol: 'kernel' }),
    route({ v6: true, destination: 'ff00::/8', interface: 'br-lan0', protocol: 'kernel' }),
    route({ v6: true, destination: '2001:db8:1:1::/64', interface: 'br-lan0', protocol: 'kernel' }),
  ]
  expect(destinations(routes)).toEqual(['192.168.1.0/24'])
  expect(destinations(routes, true)).toEqual(['2001:db8:1:1::/64'])
})

test('the default route is called default, and main comes first', () => {
  const routes = [
    route({ table: '53', destination: '198.51.100.0/24', interface: 'br-lan0' }),
    route({ table: 'wan0', gateway: '203.0.113.1', interface: 'ppp-wan0' }),
    IOT,
    LAN0,
    DEFAULT4,
    PEER,
  ]
  const rows = routeRows(routes, state(), false)
  // Main, its default first and the rest as the router sent them; then the WAN's own; then any other.
  expect(rows.map((row) => row.destination)).toEqual(['default', '192.168.20.0/24', '192.168.1.0/24', '203.0.113.1/32', 'default', '198.51.100.0/24'])
  expect(new Set(rows.map((row) => row.key)).size).toBe(rows.length)
})

test('via is the gateway, the link, or a refusal', () => {
  expect([only(DEFAULT4).via, only(DEFAULT4).how]).toEqual(['203.0.113.1', 'gateway'])
  expect([only(LAN0).via, only(LAN0).how]).toEqual(['on the link', 'link'])
  for (const kind of [RouteKind.UNREACHABLE, RouteKind.BLACKHOLE, RouteKind.PROHIBIT]) {
    const refused = only({ destination: '198.51.100.0/24', kind })
    expect([refused.via, refused.how, refused.interface]).toEqual(['refused', 'refused', ''])
  }
})

test('a route belongs to whoever’s interface it leaves by', () => {
  expect(only(DEFAULT4).belongsTo).toBe('wan0')
  expect(only(PEER).belongsTo).toBe('wan0')
  expect(only(LAN0).belongsTo).toBe('lan0')
  expect(only(IOT).belongsTo).toBe('iot')
  expect(only(IOT).interface).toBe('br-iot')
})

test('a route in a WAN’s own table belongs to that WAN, and says the table', () => {
  expect(only({ table: 'wan0', gateway: '203.0.113.1', interface: 'ppp-wan0' }).belongsTo).toBe('wan0, its own table')
  // Whatever it leaves by, and when it refuses.
  expect(only({ table: 'wan0', kind: RouteKind.UNREACHABLE }).belongsTo).toBe('wan0, its own table')
})

test('a refused block inside a WAN’s prefix is the part no LAN uses', () => {
  const whole = only({ v6: true, destination: '2001:db8:1::/48', kind: RouteKind.BLACKHOLE }, true)
  expect([whole.via, whole.belongsTo]).toEqual(['refused', 'wan0, the part of its prefix no LAN uses'])
  const part = only({ v6: true, destination: '2001:db8:1:ff00::/56', kind: RouteKind.UNREACHABLE }, true)
  expect(part.belongsTo).toBe('wan0, the part of its prefix no LAN uses')
  // A block that only holds the prefix, or lies beside it, is not a part of it.
  expect(only({ v6: true, destination: '2001:db8::/32', kind: RouteKind.BLACKHOLE }, true).belongsTo).toBe('—')
  expect(only({ v6: true, destination: '2001:db8:2::/48', kind: RouteKind.BLACKHOLE }, true).belongsTo).toBe('—')
})

test('a route that is nobody’s says so with a dash', () => {
  expect(only({ destination: '198.51.100.0/24', gateway: '192.0.2.9', interface: 'tun7' }).belongsTo).toBe('—')
  expect(only({ kind: RouteKind.UNREACHABLE, metric: 1000 }).belongsTo).toBe('—')
})
