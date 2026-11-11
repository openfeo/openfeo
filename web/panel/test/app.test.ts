// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import App from '../src/App.vue'
import { panelRoutes } from '../src/routes'
import { ROUTER, SESSION, useSession } from '../src/session'
import { FakeRouter } from './fake-router'
import { state } from './fixtures'

const wrappers: VueWrapper[] = []

/** The whole panel as main.ts assembles it, at an address, on a scripted router. */
async function panel(router: FakeRouter, path = '/') {
  window.history.replaceState(null, '', path)
  const session = useSession(router)
  const routes = panelRoutes(session)
  const errors: unknown[] = []
  const wrapper = mount(App, {
    global: {
      plugins: [routes],
      provide: { [ROUTER as symbol]: router, [SESSION as symbol]: session },
      config: { errorHandler: (error) => errors.push(error) },
    },
    attachTo: document.body,
  })
  wrappers.push(wrapper)
  await routes.isReady()
  await session.refresh()
  await flushPromises()
  return { wrapper, session, routes, errors }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
})
afterEach(() => {
  for (const wrapper of wrappers.splice(0)) {
    wrapper.unmount()
  }
  vi.unstubAllGlobals()
  vi.useRealTimers()
  window.history.replaceState(null, '', '/')
})

test('a first visit to a router with no password is the first-password screen, and the dashboard is never set up', async () => {
  // The address is / before anyone knows which screen this is. The dashboard must not be
  // made for that moment: it would try to subscribe with no session.
  const router = new FakeRouter()
  router.statusNow = { ...router.statusNow, needsPassword: true }
  const { wrapper, routes, errors } = await panel(router)
  expect(errors).toEqual([])
  expect(wrapper.find('h1').text()).toBe('Set the admin password')
  expect(routes.currentRoute.value.path).toBe('/first-password')
  expect(router.listening).toHaveLength(0)
})

test('a visit with no session is the login screen, whatever address was asked for', async () => {
  for (const path of ['/', '/first-password', '/some/page/of/a/later/part']) {
    const { wrapper, routes, errors } = await panel(new FakeRouter(), path)
    expect(errors, path).toEqual([])
    expect(wrapper.find('h1').text(), path).toBe('Log in')
    expect(routes.currentRoute.value.path, path).toBe('/login')
  }
})

test('a visit with a session is the dashboard, and a gate address is corrected to it', async () => {
  for (const path of ['/', '/login']) {
    const router = new FakeRouter()
    router.authenticated = true
    router.connection = 'open'
    const { wrapper, routes, errors } = await panel(router, path)
    expect(errors, path).toEqual([])
    expect(wrapper.find('h1').text(), path).toBe('Dashboard')
    expect(routes.currentRoute.value.path, path).toBe('/')
    expect(router.open('state').length, path).toBeGreaterThan(0)
  }
})

test('logging in leads to the dashboard, and a session that ends leads back with the reason', async () => {
  const router = new FakeRouter()
  const { wrapper, routes, errors } = await panel(router)
  await wrapper.find('input').setValue('a password of some length')
  await wrapper.find('form').trigger('submit')
  await flushPromises()
  expect(wrapper.find('h1').text()).toBe('Dashboard')
  expect(routes.currentRoute.value.path).toBe('/')
  router.push('state', state())
  await flushPromises()
  expect(wrapper.find('.ofo-pagehead__sub').text()).toContain('wan0 up')

  router.endSession('revoked')
  await flushPromises()
  expect(wrapper.find('h1').text()).toBe('Log in')
  expect(wrapper.find('.gate__why').text()).toBe('This session was ended from elsewhere. Log in again.')
  expect(routes.currentRoute.value.path).toBe('/login')
  expect(errors).toEqual([])
})

test('until the router has answered there is a skeleton, and when it does not answer that is said', async () => {
  const router = new FakeRouter()
  router.unreachable = true
  const { wrapper, errors } = await panel(router)
  expect(wrapper.text()).toBe('The router is not answering. Retrying.')
  expect(wrapper.find('[role="status"]').exists()).toBe(true)
  router.unreachable = false
  await vi.advanceTimersByTimeAsync(5_000)
  await flushPromises()
  expect(wrapper.find('h1').text()).toBe('Log in')
  expect(errors).toEqual([])
})
