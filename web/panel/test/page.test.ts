// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create, StateSchema } from '@openfeo/client'
import { THEME_KEY } from '@openfeo/ui'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import Dashboard from '../src/pages/Dashboard.vue'
import { ROUTER, SESSION, useSession } from '../src/session'
import { FakeRouter } from './fake-router'
import { counters, event, NOW, state } from './fixtures'

const wrappers: VueWrapper[] = []

async function dashboard() {
  const router = new FakeRouter()
  router.authenticated = true
  router.connection = 'open'
  const session = useSession(router)
  await session.refresh()
  const wrapper = mount(Dashboard, {
    global: { provide: { [ROUTER as symbol]: router, [SESSION as symbol]: session } },
    attachTo: document.body,
  })
  wrappers.push(wrapper)
  await flushPromises()
  return { wrapper, router, session }
}

async function loaded() {
  const made = await dashboard()
  const { router } = made
  router.push('state', state())
  router.push('counters', counters(1_000n, [['ppp-wan0', 0n, 0n], ['br-lan0', 0n, 0n]]))
  router.push('counters', counters(2_000n, [['ppp-wan0', 51_575_000n, 4_775_000n], ['br-lan0', 4_737_500n, 51_137_500n]]))
  router.push('events', event('wan.wan0.down', { reason: 'keepalive lost' }, new Date(2026, 10, 7, 21, 3, 19)))
  router.push('events', event('wan.wan0.up', {}, new Date(2026, 10, 7, 21, 3, 22)))
  router.push('events', event('lan.lan0.lease.granted', { address: '192.168.1.23', host: 'pixel-8' }, new Date(2026, 10, 10, 19, 42, 7)))
  await flushPromises()
  return made
}

/** What the system says it prefers, for the theme the switch starts from. */
let systemPrefersLight = false

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
  systemPrefersLight = false
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query.includes('light') && systemPrefersLight }))
})
afterEach(() => {
  for (const wrapper of wrappers.splice(0)) {
    wrapper.unmount()
  }
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

test('before the first state there are skeletons and no numbers', async () => {
  const { wrapper } = await dashboard()
  expect(wrapper.find('h1').text()).toBe('Dashboard')
  expect(wrapper.findAll('.ofo-skel').length).toBeGreaterThan(8)
  expect(wrapper.find('.ofo-stat__value').exists()).toBe(false)
  expect(wrapper.find('.ofo-iface__name').exists()).toBe(false)
  expect(wrapper.find('.ofo-port').exists()).toBe(false)
  // The bars sit inside the frames the real things will have: four tiles, three cards.
  expect(wrapper.findAll('.ofo-stat')).toHaveLength(4)
  expect(wrapper.findAll('.ofo-iface')).toHaveLength(3)
  expect(wrapper.find('.ofo-pagehead__sub').exists()).toBe(false)
  // The frames are there already, so nothing jumps when the state arrives.
  expect(wrapper.findAll('.ofo-card__title').map((title) => title.text())).toEqual(['Ports', 'Addresses', 'Recent events'])
  // The router's name is known before login, so the top bar has it at once.
  expect(wrapper.find('.ofo-topbar__host').text()).toBe('openfeo.home.arpa')
})

test('with the fixture state it shows the headline, four tiles, three cards, four ports, the addresses and the events', async () => {
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-skel').exists()).toBe(false)
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('wan0 up since 7 Nov 09:14 · 14 clients on 2 LANs')
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 4h')

  const tiles = wrapper.findAll('.ofo-stat')
  expect(tiles.map((tile) => tile.find('.ofo-stat__label').text())).toEqual(['Download', 'Upload', 'Clients', 'Connections'])
  expect(tiles[0]?.find('.ofo-stat__value').text()).toBe('412.6Mbit/s')
  expect(tiles[1]?.find('.ofo-stat__value').text()).toBe('38.2Mbit/s')
  expect(tiles[2]?.find('.ofo-stat__value').text()).toBe('14')
  expect(tiles[2]?.find('.ofo-stat__foot').text()).toBe('11 on lan0 · 3 on iot')
  expect(tiles[3]?.find('.ofo-stat__value').text()).toBe('1842')
  expect(tiles[0]?.find('svg.ofo-spark--s1').exists()).toBe(true)
  expect(tiles[1]?.find('svg.ofo-spark--s2').exists()).toBe(true)

  const cards = wrapper.findAll('.ofo-iface')
  expect(cards.map((card) => card.find('.ofo-iface__name').text())).toEqual(['wan0', 'lan0', 'iot'])
  expect(cards.map((card) => card.classes().includes('ofo-iface--active'))).toEqual([true, false, false])
  expect(cards[0]?.find('.ofo-pill--ok').text()).toBe('Up')
  expect(cards[0]?.find('.ofo-iface__rx').text()).toBe('↓ 412.6 Mbit/s')
  expect(cards[1]?.find('.ofo-iface__tx').text()).toBe('↑ 409.1 Mbit/s')
  expect(cards[2]?.find('.ofo-iface__rx').text()).toBe('↓ —')

  expect(wrapper.findAll('.ofo-port').map((port) => port.find('.ofo-port__speed').text())).toEqual(['2.5G', '2.5G', '—', '1G'])
  expect(wrapper.findAll('.ofo-port')[0]?.classes()).toContain('ofo-port--wan')

  const addresses = wrapper.findAll('.dash__addresses tbody tr')
  expect(addresses).toHaveLength(7)
  expect(addresses[0]?.findAll('td').map((cell) => cell.text())).toEqual(['ppp-wan0', '203.0.113.100 peer 203.0.113.1', 'PPP'])
  // An interface is named once, on its first row.
  expect(addresses[1]?.findAll('td')[0]?.text()).toBe('')
  expect(addresses[4]?.findAll('td')[2]?.text()).toBe('Delegated prefix · deprecated')
  expect(wrapper.find('.dash__addresses').text()).not.toContain('fe80')

  const events = wrapper.findAll('.dash__events tbody tr')
  expect(events.map((row) => row.findAll('td').map((cell) => cell.text()))).toEqual([
    ['19:42:07', 'lan0 leased 192.168.1.23 to pixel-8.'],
    ['7 Nov 21:03', 'wan0 up.'],
    ['7 Nov 21:03', 'wan0 down: keepalive lost.'],
  ])
  expect(events[0]?.findAll('code').map((code) => code.text())).toEqual(['lan0', '192.168.1.23', 'pixel-8'])
  // Nothing leads onward until the Logs page exists.
  expect(wrapper.find('.dash__events a').exists()).toBe(false)
})

test('the sidebar holds the dashboard alone, and marks it', async () => {
  const { wrapper } = await loaded()
  const items = wrapper.findAll('.ofo-nav__item')
  expect(items.map((item) => item.text())).toEqual(['Dashboard'])
  expect(items[0]?.attributes('aria-current')).toBe('page')
  expect(wrapper.find('.ofo-nav__group').exists()).toBe(false)
})

test('a router that has seen nothing happen says so', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  await flushPromises()
  expect(wrapper.find('.dash__events').text()).toBe('Nothing has happened since the router started.')
})

test('the uptime keeps counting between the router’s words', async () => {
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 4h')
  await vi.advanceTimersByTimeAsync(3_600_000)
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 5h')
})

test('an event stamped before the clock was set is shown when it happened, not on the day the image was built', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  // Four seconds after boot, by a clock that was still the build's.
  router.push('events', event('wan.wan0.up', {}, new Date(2026, 9, 1, 12, 0, 0), 4_000n))
  await flushPromises()
  expect(wrapper.find('.dash__events td').text()).toBe('7 Nov 15:42')
})

test('before the clock is synced the events show the uptime', async () => {
  const { wrapper, router } = await dashboard()
  const unsynced = state()
  if (unsynced.system !== undefined) {
    unsynced.system.timeSynced = false
  }
  router.push('state', unsynced)
  router.push('events', event('wan.wan0.up', {}, NOW, 192_000n))
  await flushPromises()
  expect(wrapper.find('.dash__events td').text()).toBe('up 3m 12s')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('wan0 up · 14 clients on 2 LANs')
})

test('a refused config is said above everything, with its violations', async () => {
  const { wrapper, router } = await dashboard()
  const refused = state()
  refused.system = create(StateSchema, {
    system: {
      hostname: 'openfeo',
      domain: 'home.arpa',
      version: '0.4.0',
      configProblem: {
        reason: 'invalid (2 errors)',
        violations: [
          { path: 'lans[0].ipv4', code: 'cidr', message: 'not an address with a prefix length' },
          { path: 'wans[0].port', code: 'port', message: 'no such port' },
        ],
      },
    },
  }).system
  router.push('state', refused)
  await flushPromises()
  const banner = wrapper.find('.ofo-banner--warn')
  expect(banner.exists()).toBe(true)
  expect(banner.find('.ofo-banner__title').text()).toBe('config.toml was refused')
  expect(banner.text()).toContain('invalid (2 errors)')
  expect(banner.findAll('li').map((item) => item.text())).toEqual([
    'lans[0].ipv4: not an address with a prefix length',
    'wans[0].port: no such port',
  ])
  expect(banner.findAll('li code').map((code) => code.text())).toEqual(['lans[0].ipv4', 'wans[0].port'])
  expect(banner.text()).toContain('The router is running on first-boot defaults.')
  // It is the first thing on the page.
  expect(wrapper.find('.dash').element.firstElementChild).toBe(banner.element)
  expect((await loaded()).wrapper.find('.ofo-banner').exists()).toBe(false)
})

test('a lost connection is said, and the rates and connections become dashes', async () => {
  const { wrapper, router } = await loaded()
  router.setConnection('reconnecting')
  await flushPromises()
  const banner = wrapper.find('.ofo-banner--danger')
  expect(banner.text()).toBe('The connection to the router was lost at 19:42:30. Retrying.')
  expect(banner.attributes('role')).toBe('alert')
  const tiles = wrapper.findAll('.ofo-stat')
  expect(tiles[0]?.find('.ofo-stat__value').text()).toBe('—')
  expect(tiles[1]?.find('.ofo-stat__value').text()).toBe('—')
  expect(tiles[3]?.find('.ofo-stat__value').text()).toBe('—')
  expect(wrapper.findAll('.ofo-iface__rx').map((rx) => rx.text())).toEqual(['↓ —', '↓ —', '↓ —'])
  // What is not a rate stays: it was true when last heard.
  expect(tiles[2]?.find('.ofo-stat__value').text()).toBe('14')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toContain('wan0 up since')
  router.setConnection('open')
  await flushPromises()
  expect(wrapper.find('.ofo-banner--danger').exists()).toBe(false)
})

test('Log out logs out', async () => {
  const { wrapper, router } = await loaded()
  const button = wrapper.findAll('.ofo-topbar__end button').find((each) => each.text() === 'Log out')
  expect(button).toBeDefined()
  await button?.trigger('click')
  await flushPromises()
  expect(router.calls.logout).toBe(1)
})

test('choosing a theme applies and stores it', async () => {
  const { wrapper } = await loaded()
  const toggle = wrapper.find('.ofo-topbar__end button[aria-label]')
  expect(toggle.attributes('aria-label')).toBe('Use light theme')
  await toggle.trigger('click')
  expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  expect(window.localStorage.getItem(THEME_KEY)).toBe('light')
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  await wrapper.find('.ofo-topbar__end button[aria-label]').trigger('click')
  expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
})

test('a theme chosen before is the one the switch starts from', async () => {
  window.localStorage.setItem(THEME_KEY, 'light')
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
})

test('with no theme chosen the switch starts from what the system prefers, and stores nothing', async () => {
  systemPrefersLight = true
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  expect(window.localStorage.getItem(THEME_KEY)).toBeNull()
  expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
})

test('with storage blocked the dashboard still comes up, and a theme can be chosen for this page', async () => {
  const real = Object.getOwnPropertyDescriptor(window, 'localStorage')
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    get: () => {
      throw new DOMException('The operation is insecure.', 'SecurityError')
    },
  })
  try {
    const { wrapper } = await loaded()
    expect(wrapper.find('h1').text()).toBe('Dashboard')
    await wrapper.find('.ofo-topbar__end button[aria-label]').trigger('click')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  } finally {
    if (real !== undefined) {
      Object.defineProperty(window, 'localStorage', real)
    }
  }
})

test('leaving the page lets go of the router', async () => {
  const { wrapper, router } = await loaded()
  wrapper.unmount()
  wrappers.length = 0
  expect(router.open('state')).toHaveLength(0)
  expect(router.open('counters')).toHaveLength(0)
  expect(router.open('events')).toHaveLength(0)
})
