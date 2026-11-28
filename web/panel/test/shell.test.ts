// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The shell every page behind the login sits in (SPEC §8.4): the sidebar, the top bar, what
// is said above every page, and one set of ears on the router whichever page is shown.

import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { LIVE, type LiveData } from '../src/live'
import { NOW, state } from './fixtures'
import { panelAt, unmountAll } from './mounting'

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
})
afterEach(() => {
  unmountAll()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

test('the sidebar lists the dashboard, then Network with its pages in the order they are built', async () => {
  const { wrapper, errors } = await panelAt('/')
  const nav = wrapper.find('nav.ofo-nav')
  // In the order they stand: an item, the group's name, its two items.
  expect(nav.findAll('.ofo-nav__item, .ofo-nav__group').map((entry) => entry.text())).toEqual(['Dashboard', 'Network', 'WAN', 'LAN & DHCP', 'Leases', 'Firewall', 'DNS', 'Routes', 'Router', 'Ports', 'System'])
  expect(nav.findAll('.ofo-nav__item').map((item) => item.attributes('href'))).toEqual(['/', '/wan', '/lan', '/leases', '/firewall', '/dns', '/routes', '/ports', '/system'])
  expect(nav.findAll('.ofo-nav__group').map((group) => group.text())).toEqual(['Network', 'Router'])
  expect(errors).toEqual([])
})

test('the entry of the page being shown is the current one', async () => {
  const current = (wrapper: Awaited<ReturnType<typeof panelAt>>['wrapper']) =>
    wrapper
      .findAll('.ofo-nav__item')
      .filter((item) => item.attributes('aria-current') === 'page')
      .map((item) => item.text())
  expect(current((await panelAt('/')).wrapper)).toEqual(['Dashboard'])
  expect(current((await panelAt('/wan')).wrapper)).toEqual(['WAN'])
  expect(current((await panelAt('/lan/lan0')).wrapper)).toEqual(['LAN & DHCP'])
  expect(current((await panelAt('/leases')).wrapper)).toEqual(['Leases'])
  expect(current((await panelAt('/firewall')).wrapper)).toEqual(['Firewall'])
  expect(current((await panelAt('/dns')).wrapper)).toEqual(['DNS'])
  expect(current((await panelAt('/routes')).wrapper)).toEqual(['Routes'])
  expect(current((await panelAt('/ports')).wrapper)).toEqual(['Ports'])
  expect(current((await panelAt('/system')).wrapper)).toEqual(['System'])
})

test('a click in the sidebar changes the page without a reload', async () => {
  const { wrapper, routes, errors } = await panelAt('/')
  expect(wrapper.find('h1').text()).toBe('Dashboard')
  const shell = wrapper.find('.ofo-shell').element
  const item = wrapper.findAll('.ofo-nav__item').find((each) => each.text() === 'LAN & DHCP')
  await item?.trigger('click')
  await flushPromises()
  expect(routes.currentRoute.value.path).toBe('/lan')
  expect(wrapper.find('h1').text()).toBe('LAN & DHCP')
  // The shell is the one that was there: only the page inside it changed.
  expect(wrapper.find('.ofo-shell').element).toBe(shell)
  expect(errors).toEqual([])
})

test('the top bar and the lost-connection banner are on every page', async () => {
  for (const path of ['/', '/wan', '/lan']) {
    const { wrapper, router } = await panelAt(path)
    router.push('state', state())
    await flushPromises()
    expect(wrapper.find('.ofo-topbar__host').text(), path).toBe('openfeo.home.arpa')
    expect(wrapper.find('.ofo-topbar__meta').text(), path).toBe('0.4.0 · up 3d 4h')
    expect(wrapper.findAll('.ofo-topbar__end button').some((button) => button.text() === 'Log out'), path).toBe(true)
    expect(wrapper.find('.ofo-banner--danger').exists(), path).toBe(false)
    router.setConnection('reconnecting')
    await flushPromises()
    expect(wrapper.find('.ofo-banner--danger').text(), path).toBe('The connection to the router was lost at 19:42:30. Retrying.')
    unmountAll()
  }
})

test('a refused config is said on every page', async () => {
  const { wrapper, router } = await panelAt('/wan')
  const refused = state()
  if (refused.system !== undefined) {
    refused.system.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid (1 error)', violations: [] }
  }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.ofo-banner--warn .ofo-banner__title').text()).toBe('config.toml was refused')
})

test('the router is listened to once, whichever page is shown', async () => {
  const { router, routes } = await panelAt('/')
  const open = () => (['state', 'leases', 'counters', 'events'] as const).map((topic) => router.open(topic).length)
  expect(open()).toEqual([1, 1, 1, 1])
  await routes.push('/wan')
  await flushPromises()
  await routes.push('/lan/lan0')
  await flushPromises()
  await routes.push('/')
  await flushPromises()
  expect(open()).toEqual([1, 1, 1, 1])
  // And none was closed and opened again on the way.
  expect(router.listening).toHaveLength(4)
})

test('an address of no page goes to the dashboard', async () => {
  for (const path of ['/nothing', '/wan/wan0/more', '/lan/a/b']) {
    const { wrapper, routes } = await panelAt(path)
    expect(routes.currentRoute.value.path, path).toBe('/')
    expect(wrapper.find('h1').text(), path).toBe('Dashboard')
    unmountAll()
  }
})

test('a router that was asked to restart and stays away is said to be away', async () => {
  const { wrapper, router, store } = await panelAt('/system')
  router.push('state', state())
  await flushPromises()
  const said = () => wrapper.findAll('.said .ofo-banner').map((banner) => banner.text())
  const live = (wrapper.findComponent({ name: 'Shell' }).vm.$ as unknown as { provides: Record<symbol, unknown> }).provides[LIVE as symbol] as LiveData
  expect(store().pending.value).toBeUndefined()
  live.restart()
  router.setConnection('reconnecting')
  await flushPromises()
  expect(said()).toEqual(['The router is restarting. You log in again when it is back.'])
  await vi.advanceTimersByTimeAsync(119_000)
  expect(said()).toEqual(['The router is restarting. You log in again when it is back.'])
  // Two minutes on it should have been back: the page says since when it has heard nothing.
  await vi.advanceTimersByTimeAsync(2_000)
  expect(said()).toEqual(['The router was asked to restart at 19:42:30 and has not answered since.'])
})
