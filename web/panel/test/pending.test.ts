// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What is said above every page about a change of config (SPEC §8.4): that one is waiting,
// how long is left on the router's own clock, and afterwards what became of it.

import { clone, ConfigEffectKind, ConfigSchema, create, ErrorCode, RouterError, StateSchema, type Config } from '@openfeo/client'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import PendingBanner from '../src/parts/PendingBanner.vue'
import type { FakeRouter } from './fake-router'
import { event, NOW, pendingState, routerConfig, state, UPTIME_SECS } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

async function page(path = '/lan', prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config: routerConfig(), tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt(path, router)
  router.push('state', state())
  await flushPromises()
  return made
}

const waiting = (wrapper: VueWrapper) => wrapper.find('.pending')
const notice = (wrapper: VueWrapper) => wrapper.find('.notice')
const button = (within: { findAll: VueWrapper['findAll'] }, text: string) => within.findAll('button').find((each) => each.text() === text)
const RESTARTS = [{ subject: 'lan0', kind: ConfigEffectKind.LAN_DHCP_RESTARTS }]

/** Change the pool's end and apply it through the store: this tab's own change, now pending. */
async function applied(made: Awaited<ReturnType<typeof page>>, agoSecs = 13) {
  const { wrapper, router, store } = made
  await fieldLabelled(wrapper, 'Pool end').find('input').setValue('192.168.1.220')
  const after = clone(ConfigSchema, store().draft.value!)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store().apply((await store().review())!, false)
  router.configNow = { config: after, tag: 't2', confirmSecs: 120 }
  router.push('state', pendingState(agoSecs, 120, RESTARTS))
  await flushPromises()
  return after
}

/** The change is gone from the state, the router's config is this, and it says why. */
async function settled(router: FakeRouter, config: Config, tag: string, topic: string, fields: Record<string, string> = {}) {
  router.configNow = { config: clone(ConfigSchema, config), tag, confirmSecs: 120 }
  router.push('state', state())
  router.push('events', event(topic, fields, NOW))
  await flushPromises()
}

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

test('a pending change is said on every page, with the time left', async () => {
  for (const path of ['/', '/wan', '/lan']) {
    const { wrapper, router } = await page(path)
    expect(waiting(wrapper).exists(), path).toBe(false)
    router.push('state', pendingState(13))
    await flushPromises()
    const banner = waiting(wrapper)
    expect(banner.classes(), path).toContain('ofo-banner--warn')
    expect(banner.find('.ofo-banner__title').text(), path).toBe('A change is waiting for you to confirm')
    expect(banner.find('.pending__said').text(), path).toBe('Applied at 19:42. The router goes back to how it was in 1:47 unless you confirm.')
    expect(banner.find('[role="timer"]').text(), path).toBe('1:47')
    expect(banner.find('[role="timer"]').classes(), path).toContain('ofo-mono')
    const buttons = banner.findAll('.ofo-row button')
    expect(buttons.map((each) => each.text()), path).toEqual(['Revert now', 'Confirm'])
    expect(buttons[0]?.classes(), path).toContain('ofo-btn--ghost')
    expect(buttons[1]?.classes(), path).toContain('ofo-btn--primary')
    // It is above the page, and does not announce itself anew each second.
    expect(wrapper.find('.ofo-shell__content').element.firstElementChild?.contains(banner.element), path).toBe(true)
    expect(banner.attributes('role'), path).toBe('group')
    // Gone from the state, gone from the page.
    router.push('state', state())
    await flushPromises()
    expect(waiting(wrapper).exists(), path).toBe(false)
    unmountAll()
  }
})

test("the countdown is the router's clock, not the browser's", async () => {
  // This browser's clock is an hour ahead of the truth. The time left is what the router's
  // uptime says it is; only "applied at" is told by the clock the person is looking at.
  vi.setSystemTime(new Date(NOW.getTime() + 3_600_000))
  const { wrapper, router } = await page('/')
  router.push('state', pendingState(13))
  await flushPromises()
  expect(waiting(wrapper).find('[role="timer"]').text()).toBe('1:47')
  expect(waiting(wrapper).find('.pending__said').text()).toContain('Applied at 20:42.')
})

test('the time left counts down each second and stops at zero', async () => {
  const { wrapper, router } = await page('/')
  router.push('state', pendingState(13))
  await flushPromises()
  const left = () => waiting(wrapper).find('[role="timer"]').text()
  await vi.advanceTimersByTimeAsync(1_000)
  expect(left()).toBe('1:46')
  await vi.advanceTimersByTimeAsync(46_000)
  expect(left()).toBe('1:00')
  await vi.advanceTimersByTimeAsync(55_000)
  expect(left()).toBe('0:05')
  await vi.advanceTimersByTimeAsync(5_000)
  expect(left()).toBe('0:00')
  // Until the router says the change is gone, it is still said, at nothing left.
  await vi.advanceTimersByTimeAsync(3_000)
  expect(left()).toBe('0:00')
  expect(waiting(wrapper).exists()).toBe(true)
  // What the router says next is the truth, whatever was counted here.
  router.push('state', pendingState(100))
  await flushPromises()
  expect(left()).toBe('0:20')
})

test('a tab that slept past the window shows no negative time', async () => {
  const { wrapper, router } = await page('/')
  router.push('state', pendingState(13))
  await flushPromises()
  await vi.advanceTimersByTimeAsync(600_000)
  expect(waiting(wrapper).find('[role="timer"]').text()).toBe('0:00')
  expect(waiting(wrapper).text()).not.toContain('-')
})

test("without the router's uptime the banner gives no time", () => {
  const pending = pendingState(13).system!.pendingConfig!
  const banner = mount(PendingBanner, { props: { pending, sinceBootMs: undefined, now: NOW, busy: false } })
  expect(banner.find('.pending__said').text()).toBe('The router goes back to how it was unless you confirm.')
  expect(banner.find('[role="timer"]').exists()).toBe(false)
  // With it: the time left, and when it was applied by this clock.
  const timed = mount(PendingBanner, { props: { pending, sinceBootMs: UPTIME_SECS * 1000 + 7_000, now: new Date(NOW.getTime() + 7_000), busy: false } })
  expect(timed.find('.pending__said').text()).toBe('Applied at 19:42. The router goes back to how it was in 1:40 unless you confirm.')
})

test("what changed is the router's account of it", async () => {
  const { wrapper, router } = await page('/')
  router.push(
    'state',
    pendingState(13, 120, [
      { subject: 'lan0', kind: ConfigEffectKind.LAN_ADDRESS_MOVES },
      { subject: 'wan0', kind: ConfigEffectKind.WAN_RECONNECTS },
    ]),
  )
  await flushPromises()
  const what = waiting(wrapper).find('details')
  expect(what.find('summary').text()).toBe('What changed')
  expect((what.element as HTMLDetailsElement).open).toBe(false)
  expect(what.findAll('li').map((item) => item.text())).toEqual(['lan0 moves: its devices need new addresses.', 'wan0 drops and comes back.'])
  // A change that interrupted nothing says that.
  router.push('state', pendingState(13))
  await flushPromises()
  expect(waiting(wrapper).find('details').text()).toContain('Nothing was interrupted.')
})

test('confirm and revert now ask the router, and both are disabled meanwhile', async () => {
  const { wrapper, router } = await page('/')
  router.push('state', pendingState(13))
  await flushPromises()
  const buttons = () => waiting(wrapper).findAll('.ofo-row button')
  const disabled = () => buttons().map((each) => (each.element as HTMLButtonElement).disabled)
  expect(disabled()).toEqual([false, false])

  let letGo = router.holdCall('confirm')
  await button(waiting(wrapper), 'Confirm')?.trigger('click')
  await flushPromises()
  expect(router.calls.confirm).toBe(1)
  expect(disabled()).toEqual([true, true])
  letGo()
  await flushPromises()
  expect(disabled()).toEqual([false, false])

  letGo = router.holdCall('revert')
  await button(waiting(wrapper), 'Revert now')?.trigger('click')
  await flushPromises()
  expect(router.calls.revert).toBe(1)
  expect(disabled()).toEqual([true, true])
  letGo()
  await flushPromises()
  expect(disabled()).toEqual([false, false])
  expect(notice(wrapper).exists()).toBe(false)
})

test("a refusal is said in the router's words", async () => {
  const { wrapper, router } = await page('/')
  router.push('state', pendingState(13))
  await flushPromises()
  router.confirmRefusal = new RouterError(ErrorCode.INTERNAL, 'config.toml could not be written: no space left on the device')
  await button(waiting(wrapper), 'Confirm')?.trigger('click')
  await flushPromises()
  expect(notice(wrapper).classes()).toContain('ofo-banner--danger')
  expect(notice(wrapper).find('.notice__said').text()).toBe('config.toml could not be written: no space left on the device')
  expect(notice(wrapper).attributes('role')).toBe('alert')
  // The change is still waiting, and still says so.
  expect(waiting(wrapper).exists()).toBe(true)
})

test('a change that ran out says so, and that the draft is kept', async () => {
  const made = await page()
  const { wrapper, router, store } = made
  await applied(made)
  expect(waiting(wrapper).exists()).toBe(true)
  expect(store().changes.value).toEqual([])
  await settled(router, routerConfig(), 't1', 'config.reverted', { why: 'timeout' })
  expect(waiting(wrapper).exists()).toBe(false)
  expect(notice(wrapper).classes()).toContain('ofo-banner--info')
  expect(notice(wrapper).find('.ofo-banner__title').text()).toBe('The router went back to how it was')
  expect(notice(wrapper).find('.notice__said').text()).toBe('The change applied at 19:42 was not confirmed in time. Your changes are still here as a draft.')
  // And they are: the bar counts them again.
  expect(wrapper.find('.ofo-savebar').text()).toContain('1 change not applied yet')
  expect((fieldLabelled(wrapper, 'Pool end').find('input').element as HTMLInputElement).value).toBe('192.168.1.220')
})

test('a change reverted by hand, and one changed elsewhere, each say so', async () => {
  const made = await page()
  await applied(made)
  await settled(made.router, routerConfig(), 't1', 'config.reverted', { why: 'asked' })
  expect(notice(made.wrapper).find('.notice__said').text()).toBe('The change applied at 19:42 was reverted. Your changes are still here as a draft.')
  unmountAll()

  // Another session's change, seen from a tab that changed nothing: no draft to speak of.
  const other = await page('/')
  const theirs = routerConfig()
  theirs.lans[0]!.dhcp!.leaseSecs = 3600
  other.router.configNow = { config: theirs, tag: 't2', confirmSecs: 120 }
  other.router.push('state', pendingState(13))
  await flushPromises()
  await settled(other.router, routerConfig(), 't1', 'config.reverted', { why: 'timeout' })
  expect(notice(other.wrapper).find('.notice__said').text()).toBe('The change applied at 19:42 was not confirmed in time.')
  // With no word of why, and no time: only that it is not in force.
  other.store().notice.value = { kind: 'reverted', why: 'unknown', appliedAt: null, draftKept: true }
  await flushPromises()
  expect(notice(other.wrapper).find('.notice__said').text()).toBe('The change is not in force. Your changes are still here as a draft.')
  other.store().notice.value = { kind: 'reverted', why: 'timeout', appliedAt: null, draftKept: false }
  await flushPromises()
  expect(notice(other.wrapper).find('.notice__said').text()).toBe('The change was not confirmed in time.')
  unmountAll()

  // The config changed under a draft that has changes of its own.
  const mine = await page()
  await fieldLabelled(mine.wrapper, 'Pool end').find('input').setValue('192.168.1.220')
  mine.router.configNow = { config: theirs, tag: 't2', confirmSecs: 120 }
  mine.router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  expect(notice(mine.wrapper).classes()).toContain('ofo-banner--info')
  expect(notice(mine.wrapper).find('.notice__said').text()).toBe(
    "The router's config was changed from another session. Your changes are kept: look through them before you apply.",
  )
})

test('the tab the router moved away from says where to find it', async () => {
  const { wrapper, store } = await page()
  store().notice.value = { kind: 'moved', name: 'openfeo.home.arpa', address: '192.168.2.1' }
  await flushPromises()
  expect(notice(wrapper).classes()).toContain('ofo-banner--info')
  expect(notice(wrapper).find('.ofo-banner__title').text()).toBe('The router is moving')
  expect(notice(wrapper).find('.notice__said').text()).toBe(
    'Renew your DHCP lease, or change your static address, then open https://openfeo.home.arpa or https://192.168.2.1.',
  )
  const links = notice(wrapper).findAll('a')
  expect(links.map((link) => link.attributes('href'))).toEqual(['https://openfeo.home.arpa', 'https://192.168.2.1'])
  expect(links.map((link) => link.text())).toEqual(['https://openfeo.home.arpa', 'https://192.168.2.1'])
  // A LAN that is gone leaves no address: the name alone.
  store().notice.value = { kind: 'moved', name: 'openfeo.home.arpa', address: '' }
  await flushPromises()
  expect(notice(wrapper).find('.notice__said').text()).toBe('Renew your DHCP lease, or change your static address, then open https://openfeo.home.arpa.')
  expect(notice(wrapper).findAll('a')).toHaveLength(1)
})

test('a notice can be dismissed', async () => {
  const { wrapper, store, routes } = await page()
  store().notice.value = { kind: 'changed-elsewhere' }
  await flushPromises()
  // It is there on every page until it is.
  await routes.push('/')
  await flushPromises()
  expect(notice(wrapper).exists()).toBe(true)
  await button(notice(wrapper), 'Dismiss')?.trigger('click')
  expect(notice(wrapper).exists()).toBe(false)
  expect(store().notice.value).toBeNull()
})

test('a state that carries no change is no banner, whatever else it carries', async () => {
  const { wrapper, router } = await page('/')
  const quiet = create(StateSchema, { system: { hostname: 'openfeo', uptimeSecs: 5n } })
  router.push('state', quiet)
  await flushPromises()
  expect(waiting(wrapper).exists()).toBe(false)
  expect(notice(wrapper).exists()).toBe(false)
})
