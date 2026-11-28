// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The Routes page (SPEC §8.4), in the shell at /routes: the router's dump as a person reads
// it, read when the page opens and again whenever the router's state changes.

import { create, ErrorCode, RouteKind, RouteSchema, RouterError, type Route } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, expect, test } from 'vitest'

import type { FakeRouter } from './fake-router'
import { state } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

type Init = Partial<Pick<Route, 'v6' | 'table' | 'destination' | 'gateway' | 'interface' | 'protocol' | 'metric' | 'kind'>>
const route = (init: Init): Route => create(RouteSchema, { table: 'main', protocol: 'kernel', kind: RouteKind.UNICAST, ...init })

const ROUTES: Route[] = [
  route({ gateway: '203.0.113.1', interface: 'ppp-wan0', protocol: 'openfeo', metric: 10 }),
  route({ destination: '203.0.113.1/32', interface: 'ppp-wan0' }),
  route({ destination: '192.168.1.0/24', interface: 'br-lan0' }),
  route({ destination: '192.168.20.0/24', interface: 'br-iot' }),
  route({ table: 'local', destination: '192.168.1.1/32', interface: 'br-lan0', kind: RouteKind.LOCAL }),
  route({ v6: true, gateway: 'fe80::1', interface: 'ppp-wan0', protocol: 'openfeo' }),
  route({ v6: true, destination: '2001:db8:1:1::/64', interface: 'br-lan0' }),
  route({ v6: true, destination: '2001:db8:1::/48', protocol: 'openfeo', kind: RouteKind.BLACKHOLE }),
  route({ v6: true, destination: 'fe80::/64', interface: 'br-lan0' }),
]
const ONLY_V4 = ROUTES.filter((each) => !each.v6)

async function page(routes: FakeRouter['routesNow'] = ROUTES) {
  const router = signedIn()
  router.routesNow = routes
  const made = await panelAt('/routes', router)
  router.push('state', state())
  await flushPromises()
  return made
}

const cells = (wrapper: VueWrapper) => wrapper.findAll('.routes__table tbody tr').map((row) => row.findAll('td').map((cell) => cell.text()))
const family = (wrapper: VueWrapper, label: string) => {
  const found = wrapper.findAll('.ofo-seg button').find((button) => button.text() === label)
  if (found === undefined) {
    throw new Error(`no choice of ${label}`)
  }
  return found
}

/** A promise a test settles when it chooses. */
function later<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((yes) => {
    resolve = yes
  })
  return { promise, resolve }
}

afterEach(() => {
  unmountAll()
})

test('the page reads the routes when it opens and shows the IPv4 ones', async () => {
  const { wrapper, router, errors } = await page()
  expect(router.calls.dumpRoutes).toBe(1)
  expect(wrapper.find('h1').text()).toBe('Routes')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('Where the router sends traffic for each destination, as it is now.')
  const choice = wrapper.find('.ofo-seg')
  expect(choice.attributes('aria-label')).toBe('Family')
  expect(choice.findAll('button').map((button) => [button.text(), button.attributes('aria-pressed')])).toEqual([
    ['IPv4', 'true'],
    ['IPv6', 'false'],
  ])
  expect(wrapper.findAll('.routes__table th').map((head) => head.text())).toEqual(['Destination', 'Via', 'Interface', 'Belongs to'])
  expect(cells(wrapper)).toEqual([
    ['default', '203.0.113.1', 'ppp-wan0', 'wan0'],
    ['203.0.113.1/32', 'on the link', 'ppp-wan0', 'wan0'],
    ['192.168.1.0/24', 'on the link', 'br-lan0', 'lan0'],
    ['192.168.20.0/24', 'on the link', 'br-iot', 'iot'],
  ])
  // What is on the link is said quietly; a gateway and a destination are in mono.
  const first = wrapper.findAll('.routes__table tbody tr')[1]?.findAll('td') ?? []
  expect(first[1]?.find('.ofo-muted').text()).toBe('on the link')
  expect(wrapper.find('.routes__note').text()).toBe('A view: the routes follow from the WAN and LAN settings, and there is nothing to edit here.')
  expect(wrapper.find('.ofo-savebar').exists()).toBe(false)
  expect(errors).toEqual([])
})

test('choosing IPv6 shows the other family without asking again', async () => {
  const { wrapper, router } = await page()
  await family(wrapper, 'IPv6').trigger('click')
  expect(cells(wrapper)).toEqual([
    ['default', 'fe80::1', 'ppp-wan0', 'wan0'],
    ['2001:db8:1:1::/64', 'on the link', 'br-lan0', 'lan0'],
    ['2001:db8:1::/48', 'refused', '', 'wan0, the part of its prefix no LAN uses'],
  ])
  expect(router.calls.dumpRoutes).toBe(1)
  await family(wrapper, 'IPv4').trigger('click')
  expect(cells(wrapper)).toHaveLength(4)
})

test('a family with no routes says so', async () => {
  const { wrapper } = await page(ONLY_V4)
  await family(wrapper, 'IPv6').trigger('click')
  expect(wrapper.find('.routes__table').exists()).toBe(false)
  expect(wrapper.find('.routes__none').text()).toBe('No IPv6 routes.')
  // The choice and the sentence about the page stay.
  expect(wrapper.find('.ofo-seg').exists()).toBe(true)
  expect(wrapper.find('.routes__note').exists()).toBe(true)
  await family(wrapper, 'IPv4').trigger('click')
  expect(wrapper.find('.routes__none').exists()).toBe(false)
})

test('the routes are read again when the state changes', async () => {
  const { wrapper, router } = await page()
  router.routesNow = ONLY_V4.slice(2)
  // The same state again is no change.
  router.push('state', state())
  await flushPromises()
  expect(router.calls.dumpRoutes).toBe(1)
  const changed = state()
  changed.generation = 43n
  router.push('state', changed)
  await flushPromises()
  expect(router.calls.dumpRoutes).toBe(2)
  expect(cells(wrapper).map((row) => row[0])).toEqual(['192.168.1.0/24', '192.168.20.0/24'])
})

test('an older answer does not replace a newer one', async () => {
  const first = later<Route[]>()
  const second = later<Route[]>()
  const answers = [first.promise, second.promise]
  const { wrapper, router } = await page(() => answers.shift() ?? Promise.resolve([]))
  expect(wrapper.find('.routes__waiting').exists()).toBe(true)
  const changed = state()
  changed.generation = 43n
  router.push('state', changed)
  await flushPromises()
  expect(router.calls.dumpRoutes).toBe(2)
  second.resolve(ONLY_V4.slice(2))
  await flushPromises()
  expect(cells(wrapper).map((row) => row[0])).toEqual(['192.168.1.0/24', '192.168.20.0/24'])
  // The answer to the first question arrives last, and is about a router that has changed since.
  first.resolve(ONLY_V4)
  await flushPromises()
  expect(cells(wrapper).map((row) => row[0])).toEqual(['192.168.1.0/24', '192.168.20.0/24'])
})

test('a dump that fails says so and can be tried again', async () => {
  const { wrapper, router } = await page(new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost'))
  expect(wrapper.find('.routes__failed').text()).toContain('The routes could not be read from the router.')
  expect(wrapper.find('.routes__table').exists()).toBe(false)
  router.routesNow = ROUTES
  const again = wrapper.findAll('.routes__failed button').find((button) => button.text() === 'Try again')
  await again?.trigger('click')
  await flushPromises()
  expect(wrapper.find('.routes__failed').exists()).toBe(false)
  expect(cells(wrapper)).toHaveLength(4)
  // A later read that fails leaves what was read before on screen, and says so.
  router.routesNow = new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
  const changed = state()
  changed.generation = 43n
  router.push('state', changed)
  await flushPromises()
  expect(wrapper.find('.routes__failed').exists()).toBe(true)
  expect(cells(wrapper)).toHaveLength(4)
})
