// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { ErrorCode, RouterError } from '@openfeo/client'
import { THEME_KEY } from '@openfeo/ui'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { Component } from 'vue'

import themeScript from '../public/theme.js?raw'
import ConfigUnreadable from '../src/pages/ConfigUnreadable.vue'
import FirstPassword from '../src/pages/FirstPassword.vue'
import Login from '../src/pages/Login.vue'
import { ROUTER, SESSION, useSession } from '../src/session'
import { FakeRouter } from './fake-router'

const wrappers: VueWrapper[] = []

async function page(component: Component, router = new FakeRouter(), before?: (session: ReturnType<typeof useSession>) => void) {
  const session = useSession(router)
  await session.refresh()
  before?.(session)
  const wrapper = mount(component, {
    global: { provide: { [ROUTER as symbol]: router, [SESSION as symbol]: session } },
    attachTo: document.body,
  })
  wrappers.push(wrapper)
  return { wrapper, router, session }
}

async function type(wrapper: VueWrapper, values: string[]) {
  const inputs = wrapper.findAll('input')
  for (const [at, value] of values.entries()) {
    await inputs[at]?.setValue(value)
  }
}

const submit = async (wrapper: VueWrapper) => {
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}
const button = (wrapper: VueWrapper) => wrapper.find('button[type="submit"]')

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  for (const wrapper of wrappers.splice(0)) {
    wrapper.unmount()
  }
  vi.useRealTimers()
})

function needsPassword() {
  const router = new FakeRouter()
  router.statusNow = { ...router.statusNow, needsPassword: true }
  return router
}

test('the first-password screen says what it is for, in the words agreed', async () => {
  const { wrapper } = await page(FirstPassword, needsPassword())
  expect(wrapper.find('h1').text()).toBe('Set the admin password')
  expect(wrapper.text()).toContain('This router has no password yet. Set one now: until you do, anyone on the LAN can.')
  expect(wrapper.findAll('.ofo-field__label').map((label) => label.text())).toEqual(['New password', 'Repeat password'])
  expect(wrapper.find('.ofo-field__help').text()).toBe('12 characters or more.')
  expect(button(wrapper).text()).toBe('Set password')
  expect(button(wrapper).classes()).toContain('ofo-btn--primary')
  expect(wrapper.findAll('input').map((input) => [input.attributes('type'), input.attributes('autocomplete')])).toEqual([
    ['password', 'new-password'],
    ['password', 'new-password'],
  ])
  expect(wrapper.find('img[alt="OpenFeO"]').exists()).toBe(true)
})

test('the password is sent exactly as typed', async () => {
  const { wrapper, router, session } = await page(FirstPassword, needsPassword())
  const typed = '  spaced out pass  '
  await type(wrapper, [typed, typed])
  await submit(wrapper)
  expect(router.calls.setInitialPassword).toEqual([typed])
  expect(session.screen.value).toBe('dashboard')
})

test('the button says Setting… and cannot be pressed twice', async () => {
  const router = needsPassword()
  const release = router.hold()
  const { wrapper, session } = await page(FirstPassword, router)
  await type(wrapper, ['correct horse battery', 'correct horse battery'])
  await submit(wrapper)
  expect(button(wrapper).text()).toBe('Setting…')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(true)
  await submit(wrapper)
  expect(router.calls.setInitialPassword).toHaveLength(1)
  expect(session.screen.value).toBe('first-password')
  release()
  await flushPromises()
  expect(session.screen.value).toBe('dashboard')
})

test('a problem with the password is said at its field, and nothing is sent', async () => {
  const { wrapper, router } = await page(FirstPassword, needsPassword())
  // Nothing is said before the person has tried.
  expect(wrapper.find('.ofo-field--error').exists()).toBe(false)
  await type(wrapper, ['too short', 'too short'])
  await submit(wrapper)
  const fields = wrapper.findAll('.ofo-field')
  expect(fields[0]?.classes()).toContain('ofo-field--error')
  expect(fields[0]?.find('.ofo-field__help').text()).toBe('12 characters or more.')
  expect(fields[1]?.classes()).not.toContain('ofo-field--error')

  await type(wrapper, ['correct horse battery', 'correct horse batterx'])
  await submit(wrapper)
  expect(wrapper.findAll('.ofo-field')[0]?.classes()).not.toContain('ofo-field--error')
  expect(wrapper.findAll('.ofo-field')[1]?.find('.ofo-field__help').text()).toBe('The two passwords differ.')
  expect(router.calls.setInitialPassword).toEqual([])
  // Mending it clears the complaint as it is typed.
  await type(wrapper, ['correct horse battery', 'correct horse battery'])
  expect(wrapper.find('.ofo-field--error').exists()).toBe(false)
})

test('the fingerprint is shown in two lines of sixteen pairs', async () => {
  const { wrapper } = await page(FirstPassword, needsPassword())
  expect(wrapper.text()).toContain('Certificate fingerprint (SHA-256)')
  const lines = wrapper.findAll('.fp__value span').map((line) => line.text())
  expect(lines).toEqual([
    '00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F',
    '10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F',
  ])
  expect(wrapper.text()).toContain("The router's console prints the same fingerprint. If the two differ, this is not your router.")
})

test('a password set by someone else meanwhile sends this client to log in, saying so', async () => {
  const router = needsPassword()
  router.refuse = new RouterError(ErrorCode.FAILED_PRECONDITION, 'a password is already set')
  const { wrapper, session } = await page(FirstPassword, router)
  router.statusNow = { ...router.statusNow, needsPassword: false }
  await type(wrapper, ['correct horse battery', 'correct horse battery'])
  await submit(wrapper)
  expect(session.screen.value).toBe('login')
  expect(session.notice.value).toBe('A password was set a moment ago. Log in with it.')
})

test('a router that stops answering while the password is set says so and lets the person try again', async () => {
  const router = needsPassword()
  router.refuse = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  const { wrapper, session } = await page(FirstPassword, router)
  await type(wrapper, ['correct horse battery', 'correct horse battery'])
  await submit(wrapper)
  expect(wrapper.find('[role="alert"]').text()).toBe('The router is not answering. Try again.')
  expect(button(wrapper).text()).toBe('Set password')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(false)
  expect(session.screen.value).toBe('first-password')
})

test("the login screen names the router and sends the password as typed", async () => {
  const { wrapper, router, session } = await page(Login)
  expect(wrapper.find('.gate__host').text()).toBe('openfeo.home.arpa')
  expect(wrapper.find('.gate__host').classes()).toContain('ofo-mono')
  expect(wrapper.find('h1').text()).toBe('Log in')
  expect(wrapper.find('.ofo-field__label').text()).toBe('Password')
  expect(wrapper.find('input').attributes('autocomplete')).toBe('current-password')
  expect(button(wrapper).text()).toBe('Log in')
  await type(wrapper, [' the password, spaces and all '])
  await submit(wrapper)
  expect(router.calls.login).toEqual([' the password, spaces and all '])
  expect(session.screen.value).toBe('dashboard')
})

test('a router with no domain is named by its hostname alone', async () => {
  const router = new FakeRouter()
  router.statusNow = { ...router.statusNow, domain: '' }
  const { wrapper } = await page(Login, router)
  expect(wrapper.find('.gate__host').text()).toBe('openfeo')
})

test('a wrong password says so and counts the wait down with the button disabled', async () => {
  const router = new FakeRouter()
  router.refuse = new RouterError(ErrorCode.UNAUTHENTICATED, 'wrong password', { retryAfterSecs: 8 })
  const { wrapper } = await page(Login, router)
  await type(wrapper, ['hunter2hunter2'])
  await submit(wrapper)
  const help = () => wrapper.find('.ofo-field__help').text()
  expect(wrapper.find('.ofo-field').classes()).toContain('ofo-field--error')
  expect(help()).toBe('Wrong password. Next attempt in 8 s.')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(true)
  await vi.advanceTimersByTimeAsync(1_000)
  expect(help()).toBe('Wrong password. Next attempt in 7 s.')
  await vi.advanceTimersByTimeAsync(6_000)
  expect(help()).toBe('Wrong password. Next attempt in 1 s.')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(true)
  await vi.advanceTimersByTimeAsync(1_000)
  expect(help()).toBe('Wrong password.')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(false)
  // The count stops at nothing.
  await vi.advanceTimersByTimeAsync(5_000)
  expect(help()).toBe('Wrong password.')
  // While it waits, pressing Enter sends nothing.
  expect(router.calls.login).toHaveLength(1)
})

test('a wrong password with no wait says only that', async () => {
  const router = new FakeRouter()
  router.refuse = new RouterError(ErrorCode.UNAUTHENTICATED, 'wrong password')
  const { wrapper } = await page(Login, router)
  await type(wrapper, ['hunter2hunter2'])
  await submit(wrapper)
  expect(wrapper.find('.ofo-field__help').text()).toBe('Wrong password.')
  expect((button(wrapper).element as HTMLButtonElement).disabled).toBe(false)
})

test('an attempt made too soon says how long, and nothing is sent while it waits', async () => {
  const router = new FakeRouter()
  router.refuse = new RouterError(ErrorCode.RESOURCE_EXHAUSTED, 'wait 3 s before trying again', { retryAfterSecs: 3 })
  const { wrapper } = await page(Login, router)
  await type(wrapper, ['hunter2hunter2'])
  await submit(wrapper)
  expect(wrapper.find('.ofo-field__help').text()).toBe('Next attempt in 3 s.')
  await submit(wrapper)
  expect(router.calls.login).toHaveLength(1)
  await vi.advanceTimersByTimeAsync(3_000)
  expect(wrapper.find('.ofo-field--error').exists()).toBe(false)
  router.refuse = null
  await submit(wrapper)
  expect(router.calls.login).toHaveLength(2)
})

test('a router that does not answer a login says so', async () => {
  const router = new FakeRouter()
  router.refuse = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  const { wrapper } = await page(Login, router)
  await type(wrapper, ['hunter2hunter2'])
  await submit(wrapper)
  expect(wrapper.find('.ofo-field__help').text()).toBe('The router is not answering. Try again.')
})

test('the reason the session ended is said on the login screen', async () => {
  const lapsed = await page(Login, new FakeRouter(), (session) => (session.ended.value = 'lapsed'))
  expect(lapsed.wrapper.find('.gate__why').text()).toBe('Your session ended. Log in again.')
  const revoked = await page(Login, new FakeRouter(), (session) => (session.ended.value = 'revoked'))
  expect(revoked.wrapper.find('.gate__why').text()).toBe('This session was ended from elsewhere. Log in again.')
  const left = await page(Login, new FakeRouter(), (session) => (session.ended.value = 'logout'))
  expect(left.wrapper.find('.gate__why').exists()).toBe(false)
  const fresh = await page(Login)
  expect(fresh.wrapper.find('.gate__why').exists()).toBe(false)
  const told = await page(Login, new FakeRouter(), (session) => {
    session.notice.value = 'A password was set a moment ago. Log in with it.'
  })
  expect(told.wrapper.find('.gate__why').text()).toBe('A password was set a moment ago. Log in with it.')
})

test('both screens link to the licences', async () => {
  for (const component of [FirstPassword, Login]) {
    const { wrapper } = await page(component, needsPassword())
    const link = wrapper.find('a[href="/licences.txt"]')
    expect(link.exists()).toBe(true)
    expect(link.text()).toBe('Licences')
  }
})

test('a config file that cannot be read is said, and nothing is offered', async () => {
  const { wrapper } = await page(ConfigUnreadable)
  expect(wrapper.find('h1').text()).toBe('The config file cannot be read')
  expect(wrapper.text()).toContain(
    '/state/config.toml is not valid TOML. The router is running on first-boot defaults and nobody can log in until the file is fixed or removed from the console.',
  )
  expect(wrapper.find('code').text()).toBe('/state/config.toml')
  expect(wrapper.find('input').exists()).toBe(false)
  expect(wrapper.find('button').exists()).toBe(false)
})

test('theme.js and the ui package agree on the key', () => {
  // The script runs before the page's own code, so that a chosen theme is there at first paint.
  expect(themeScript).toContain(`'${THEME_KEY}'`)
  expect(themeScript).toContain('data-theme')
})
