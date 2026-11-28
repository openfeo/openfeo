// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The System page (SPEC §8.4), in the shell at /system: the router's name, its clock and time
// servers, the password, restarting, and what it is running.

import { ErrorCode, RouterError, type Config, type State } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, pendingState, routerConfig, state } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

async function page(config: Config = routerConfig(), first: State | null = state(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt('/system', router)
  if (first !== null) {
    router.push('state', first)
  }
  await flushPromises()
  return made
}

const bar = (wrapper: VueWrapper) => wrapper.find('.ofo-savebar')
const section = (wrapper: VueWrapper, title: string) => {
  const found = wrapper.findAll('.ofo-formsec').find((each) => each.find('.ofo-formsec__title').text() === title)
  if (found === undefined) {
    throw new Error(`no section ${title}`)
  }
  return found
}
const box = (wrapper: VueWrapper, label: string) => fieldLabelled(wrapper, label).find('input')
const type = async (wrapper: VueWrapper, label: string, text: string) => {
  await box(wrapper, label).setValue(text)
  await box(wrapper, label).trigger('blur')
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  window.sessionStorage.clear()
  vi.stubGlobal('matchMedia', () => ({ matches: false }))
})
afterEach(() => {
  unmountAll()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

test('the page is in the navigation under Router and has the save bar', async () => {
  const { wrapper, errors } = await page()
  const nav = wrapper.find('nav.ofo-nav')
  expect(nav.findAll('.ofo-nav__group').map((group) => group.text())).toEqual(['Network', 'Router'])
  // Router's group comes after Network's pages, and System is the last entry in it.
  const entries = nav.findAll('.ofo-nav__item, .ofo-nav__group').map((entry) => entry.text())
  expect(entries.indexOf('Router')).toBeGreaterThan(entries.indexOf('DNS'))
  expect(entries.slice(entries.indexOf('Router')).at(-1)).toBe('System')
  const entry = wrapper.findAll('.ofo-nav__item').find((item) => item.text() === 'System')
  expect(entry?.attributes('href')).toBe('/system')
  expect(entry?.attributes('aria-current')).toBe('page')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('The router’s name, clock, password and software.')
  expect(wrapper.findAll('.ofo-formsec__title').map((title) => title.text())).toEqual(['Name', 'Time', 'Password', 'Restart', 'About'])
  expect(bar(wrapper).exists()).toBe(false)
  await type(wrapper, 'Hostname', 'edge')
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(errors).toEqual([])
})

test('the name section says where the panel is', async () => {
  const { wrapper } = await page()
  expect(section(wrapper, 'Name').find('.ofo-formsec__text').text()).toBe(
    'The panel is at openfeo.home.arpa. Changing either gives the router a new certificate, so your browser will ask about it once more.',
  )
  expect(fieldLabelled(wrapper, 'Domain').find('.ofo-field__help').text()).toBe('Every local name is under it.')
})

test('hostname and domain are settings like any other', async () => {
  const { wrapper, store } = await page()
  await type(wrapper, 'Hostname', 'edge')
  expect(store().draft.value!.system!.hostname).toBe('edge')
  expect(store().changes.value).toEqual([{ subject: 'The router', what: 'hostname', before: 'openfeo', after: 'edge' }])
  expect(fieldLabelled(wrapper, 'Hostname').find('.ofo-field__help').text()).toBe('Was openfeo.')
  await type(wrapper, 'Domain', 'lan.example')
  expect(store().changes.value.map((change) => `${change.subject} ${change.what}`)).toEqual(['The router hostname', 'The router domain'])
  // The section goes on saying where the panel is now: the name changes when it is applied.
  expect(section(wrapper, 'Name').find('.ofo-formsec__text').text()).toContain('The panel is at openfeo.home.arpa.')
  // What the page can tell of a name is said once the field is left.
  await type(wrapper, 'Hostname', 'my router')
  expect(fieldLabelled(wrapper, 'Hostname').find('[role="alert"]').text()).toBe('Letters, digits and hyphens, 63 at most.')
  await type(wrapper, 'Domain', 'home..arpa')
  expect(fieldLabelled(wrapper, 'Domain').find('[role="alert"]').text()).toBe('Names separated by dots, such as home.arpa.')
})

test('what the router refuses of a name is said at its field', async () => {
  const { wrapper, router, store } = await page()
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'system.hostname', code: 'invalid_hostname', message: 'not a DNS label' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'system.ntp_servers[1]', code: 'invalid_hostname', message: 'not a host name' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'system.timezone', code: 'unknown', message: 'no such zone' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  expect(fieldLabelled(wrapper, 'Hostname').find('[role="alert"]').text()).toBe('not a DNS label')
  expect(fieldLabelled(wrapper, 'Time servers').find('[role="alert"]').text()).toBe('not a host name')
  // What no field is for is listed above, by its path.
  expect(wrapper.find('.refused').findAll('li').map((item) => item.text())).toEqual(['system.timezone: no such zone'])
})

test('the pill says whether the clock was set', async () => {
  const { wrapper, router } = await page()
  const time = () => section(wrapper, 'Time')
  expect(time().find('.ofo-formsec__text').text()).toBe('The panel shows times in your browser’s time zone.')
  expect(time().find('.ofo-pill').text()).toBe('Synced')
  expect(time().find('.ofo-pill').classes()).toContain('ofo-pill--ok')
  expect(time().find('.clock').text()).toBe('Synced The router’s clock was set from the internet.')
  // It follows the router.
  const unset = state()
  unset.system!.timeSynced = false
  router.push('state', unset)
  await flushPromises()
  expect(time().find('.ofo-pill').text()).toBe('Not set yet')
  expect(time().find('.ofo-pill').classes()).toContain('ofo-pill--warn')
  expect(time().find('.clock').text()).toBe('Not set yet The router has not had the time from the internet yet. Times from before it has are counted from when the router started.')
})

test('until the router has said, the page claims nothing of its clock or of what it runs', async () => {
  const { wrapper } = await page(routerConfig(), null)
  expect(section(wrapper, 'Time').find('.clock').exists()).toBe(false)
  expect(section(wrapper, 'About').find('dl').exists()).toBe(false)
})

test('the time servers are a list typed with commas', async () => {
  const { wrapper, store } = await page()
  expect(fieldLabelled(wrapper, 'Time servers').find('.ofo-field__help').text()).toBe('Names or addresses, separated by commas.')
  await box(wrapper, 'Time servers').setValue('0.pool.ntp.org, ')
  expect((box(wrapper, 'Time servers').element as HTMLInputElement).value).toBe('0.pool.ntp.org, ')
  await type(wrapper, 'Time servers', '0.pool.ntp.org, 203.0.113.1')
  expect(store().draft.value!.system!.ntpServers).toEqual(['0.pool.ntp.org', '203.0.113.1'])
  expect(store().changes.value).toEqual([{ subject: 'The router', what: 'time servers', before: 'none', after: '0.pool.ntp.org, 203.0.113.1' }])
  await type(wrapper, 'Time servers', 'not a name')
  expect(fieldLabelled(wrapper, 'Time servers').find('[role="alert"]').text()).toBe('not a name is not a name or an address.')
})

test('about says what the router runs, and links to the notices', async () => {
  const found = state()
  found.system!.tlsFingerprint = '6F:1C:9E:02'
  const { wrapper } = await page(routerConfig(), found)
  const about = section(wrapper, 'About')
  expect(about.findAll('dt').map((term) => term.text())).toEqual(['Version', 'Running for', 'Certificate', 'Licences'])
  expect(about.findAll('dd').map((value) => value.text())).toEqual(['0.4.0', '3d 4h', 'SHA-256 6F:1C:9E:02', 'Open-source notices'])
  // What a machine wrote is in mono.
  expect(about.findAll('dd').map((value) => value.classes().includes('ofo-mono'))).toEqual([true, false, true, false])
  const notices = about.find('dd a')
  expect(notices.attributes('href')).toBe('/licences.txt')
})

test('system.timezone is sent back as it came', async () => {
  const config = routerConfig()
  config.system!.timezone = 'Europe/London'
  const { wrapper, store } = await page(config)
  await type(wrapper, 'Hostname', 'edge')
  await type(wrapper, 'Time servers', '203.0.113.1')
  expect(store().draft.value!.system!.timezone).toBe('Europe/London')
})

test('a config the router refused is shown and its settings cannot be changed', async () => {
  const { wrapper, router } = await page()
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toContain('The router refused its config file')
  for (const label of ['Hostname', 'Domain', 'Time servers']) {
    expect((box(wrapper, label).element as HTMLInputElement).disabled, label).toBe(true)
  }
  expect(bar(wrapper).exists()).toBe(false)
})

// ---- The password: a call of its own, outside the draft ----

const OLD = 'the password in use now'
const NEW = 'a new password of length'
const button = (wrapper: VueWrapper, text: string) => {
  const found = wrapper.findAll('button').find((each) => each.text() === text)
  if (found === undefined) {
    throw new Error(`no button ${text}`)
  }
  return found
}
const disabled = (wrapper: VueWrapper, text: string) => (button(wrapper, text).element as HTMLButtonElement).disabled
/** Fill the three fields in, leaving each as a person does. */
async function fill(wrapper: VueWrapper, current: string, next: string, again: string = next) {
  await type(wrapper, 'Current password', current)
  await type(wrapper, 'New password', next)
  await type(wrapper, 'New password again', again)
}
const typedIn = (wrapper: VueWrapper) => ['Current password', 'New password', 'New password again'].map((label) => (box(wrapper, label).element as HTMLInputElement).value)
const alertAt = (wrapper: VueWrapper, label: string) => fieldLabelled(wrapper, label).find('[role="alert"]')

test('the password is changed by a call of its own', async () => {
  const { wrapper, router, store } = await page()
  const password = section(wrapper, 'Password')
  expect(password.find('.ofo-formsec__text').text()).toBe('Changing it takes effect at once and logs out every other session.')
  expect(password.findAll('.ofo-field__label').map((label) => label.text())).toEqual(['Current password', 'New password', 'New password again'])
  expect(password.findAll('input').map((input) => [input.attributes('type'), input.attributes('autocomplete')])).toEqual([
    ['password', 'current-password'],
    ['password', 'new-password'],
    ['password', 'new-password'],
  ])
  expect(fieldLabelled(wrapper, 'New password').find('.ofo-field__help').text()).toBe('At least 12 characters.')
  await fill(wrapper, OLD, NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(router.calls.changePassword).toEqual([[OLD, NEW]])
  // Done: the fields are empty and the page says what happened.
  expect(typedIn(wrapper)).toEqual(['', '', ''])
  expect(password.find('.changed').text()).toBe('The password was changed. Every other session was logged out.')
  // It was never a change of config: nothing to apply.
  expect(store().changes.value).toEqual([])
  expect(bar(wrapper).exists()).toBe(false)
})

test('what is typed for a password is kept nowhere', async () => {
  const { wrapper, routes, store } = await page()
  await fill(wrapper, OLD, NEW, 'a second new password')
  const kept = () =>
    JSON.stringify([
      store().draft.value,
      store().base.value,
      store().violations.value,
      store().notice.value,
      Object.entries(window.sessionStorage),
      Object.entries(window.localStorage),
    ])
  for (const secret of [OLD, NEW, 'a second new password']) {
    expect(kept(), secret).not.toContain(secret)
  }
  expect(store().changes.value).toEqual([])
  // Leaving the page forgets them.
  await routes.push('/dns')
  await flushPromises()
  await routes.push('/system')
  await flushPromises()
  expect(typedIn(wrapper)).toEqual(['', '', ''])
})

test('what the page knows of a new password is said when its field is left', async () => {
  const { wrapper, router } = await page()
  await box(wrapper, 'New password').setValue('short')
  expect(alertAt(wrapper, 'New password').exists()).toBe(false)
  await box(wrapper, 'New password').trigger('blur')
  expect(alertAt(wrapper, 'New password').text()).toBe('12 characters or more.')
  await type(wrapper, 'New password', NEW)
  expect(alertAt(wrapper, 'New password').exists()).toBe(false)
  await type(wrapper, 'New password again', 'another password entirely')
  expect(alertAt(wrapper, 'New password again').text()).toBe('The two passwords differ.')
  // Pressed as it is, nothing is asked of the router.
  await type(wrapper, 'Current password', OLD)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(router.calls.changePassword).toEqual([])
  // And pressed with nothing typed, each field that needs something says so.
  unmountAll()
  const empty = await page()
  await button(empty.wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(empty.router.calls.changePassword).toEqual([])
  expect(alertAt(empty.wrapper, 'New password').text()).toBe('12 characters or more.')
})

test('a wrong current password is said at its field, and the others are left as typed', async () => {
  // Review Focus 4.
  const { wrapper, router } = await page(routerConfig(), state(), (fake) => {
    fake.changeRefusal = new RouterError(ErrorCode.INVALID_ARGUMENT, 'the old password is wrong')
  })
  await fill(wrapper, 'not the password', NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(alertAt(wrapper, 'Current password').text()).toBe('That is not the current password.')
  expect(typedIn(wrapper)).toEqual(['not the password', NEW, NEW])
  expect(section(wrapper, 'Password').find('.changed').exists()).toBe(false)
  // Typing the current password again takes what was said of it away.
  router.changeRefusal = null
  await type(wrapper, 'Current password', OLD)
  expect(alertAt(wrapper, 'Current password').exists()).toBe(false)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(router.calls.changePassword).toEqual([
    ['not the password', NEW],
    [OLD, NEW],
  ])
  expect(section(wrapper, 'Password').find('.changed').exists()).toBe(true)
})

test('a wait is counted down at the field and the button is held for it', async () => {
  const { wrapper, router } = await page(routerConfig(), state(), (fake) => {
    fake.changeRefusal = new RouterError(ErrorCode.RESOURCE_EXHAUSTED, 'try again later', { retryAfterSecs: 4 })
  })
  await fill(wrapper, OLD, NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(alertAt(wrapper, 'Current password').text()).toBe('Too many tries. Wait 4 s.')
  expect(disabled(wrapper, 'Change password')).toBe(true)
  await vi.advanceTimersByTimeAsync(2_000)
  expect(alertAt(wrapper, 'Current password').text()).toBe('Too many tries. Wait 2 s.')
  // Pressing does nothing while it counts.
  await button(wrapper, 'Change password').trigger('click')
  expect(router.calls.changePassword).toHaveLength(1)
  await vi.advanceTimersByTimeAsync(2_000)
  expect(disabled(wrapper, 'Change password')).toBe(false)
  expect(alertAt(wrapper, 'Current password').exists()).toBe(false)
  // A wrong password that earns a wait says both.
  router.changeRefusal = new RouterError(ErrorCode.INVALID_ARGUMENT, 'the old password is wrong', { retryAfterSecs: 2 })
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(alertAt(wrapper, 'Current password').text()).toBe('That is not the current password. Wait 2 s.')
  expect(disabled(wrapper, 'Change password')).toBe(true)
})

test('the wait a wrong password earns is said for as long as the button is held', async () => {
  // Review Focus 4: retyping takes "that is not the password" away, since it was said of
  // what was there; the wait is still the router's, and a held button says why it is held.
  const { wrapper, router } = await page(routerConfig(), state(), (fake) => {
    fake.changeRefusal = new RouterError(ErrorCode.INVALID_ARGUMENT, 'the old password is wrong', { retryAfterSecs: 8 })
  })
  await fill(wrapper, 'not the password', NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(alertAt(wrapper, 'Current password').text()).toBe('That is not the current password. Wait 8 s.')
  await type(wrapper, 'Current password', OLD)
  expect(alertAt(wrapper, 'Current password').text()).toBe('Wait 8 s before trying again.')
  expect(disabled(wrapper, 'Change password')).toBe(true)
  await vi.advanceTimersByTimeAsync(5_000)
  expect(alertAt(wrapper, 'Current password').text()).toBe('Wait 3 s before trying again.')
  expect(disabled(wrapper, 'Change password')).toBe(true)
  await vi.advanceTimersByTimeAsync(3_000)
  expect(alertAt(wrapper, 'Current password').exists()).toBe(false)
  expect(disabled(wrapper, 'Change password')).toBe(false)
  router.changeRefusal = null
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(router.calls.changePassword.at(-1)).toEqual([OLD, NEW])
  expect(section(wrapper, 'Password').find('.changed').exists()).toBe(true)
})

test('a double press sends one call', async () => {
  const { wrapper, router } = await page()
  await fill(wrapper, OLD, NEW)
  const release = router.holdCall('changePassword')
  await button(wrapper, 'Change password').trigger('click')
  await button(wrapper, 'Change password').trigger('click')
  expect(disabled(wrapper, 'Change password')).toBe(true)
  release()
  await flushPromises()
  expect(router.calls.changePassword).toHaveLength(1)
  expect(disabled(wrapper, 'Change password')).toBe(false)
})

test('while a change waits to be confirmed the password cannot be changed, and the page says why', async () => {
  const { wrapper, router } = await page(routerConfig(), pendingState(13))
  const password = section(wrapper, 'Password')
  expect(password.find('.held').text()).toBe('A change of config is waiting to be confirmed. Confirm or revert it first.')
  expect(disabled(wrapper, 'Change password')).toBe(true)
  await fill(wrapper, OLD, NEW)
  await button(wrapper, 'Change password').trigger('click')
  expect(router.calls.changePassword).toEqual([])
  // Once the change is settled, the button is offered again.
  router.push('state', state())
  await flushPromises()
  expect(password.find('.held').exists()).toBe(false)
  expect(disabled(wrapper, 'Change password')).toBe(false)
  // A router that refuses for that reason all the same is given the same words.
  router.changeRefusal = new RouterError(ErrorCode.FAILED_PRECONDITION, 'a change of config is pending; confirm or revert it before changing the password')
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(password.find('.failed').text()).toBe('A change of config is waiting to be confirmed. Confirm or revert it first.')
})

test('what the router said of a waiting change is said once, and goes when the change is settled', async () => {
  // The router knew of a change this page had not yet heard of.
  const { wrapper, router } = await page(routerConfig(), state(), (fake) => {
    fake.changeRefusal = new RouterError(ErrorCode.FAILED_PRECONDITION, 'a change of config is pending; confirm or revert it before changing the password')
  })
  const password = section(wrapper, 'Password')
  const WAITING = 'A change of config is waiting to be confirmed. Confirm or revert it first.'
  await fill(wrapper, OLD, NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(password.find('.failed').text()).toBe(WAITING)
  // The state catches up: the sentence is where the held button is explained, and nowhere else.
  router.push('state', pendingState(13))
  await flushPromises()
  expect(password.find('.held').text()).toBe(WAITING)
  expect(password.find('.failed').exists()).toBe(false)
  // Settled: nothing is waiting, and nothing says so.
  router.push('state', state())
  await flushPromises()
  expect(password.find('.held').exists()).toBe(false)
  expect(password.find('.failed').exists()).toBe(false)
  expect(disabled(wrapper, 'Change password')).toBe(false)
})

test('anything else the router says of a password change is said under the button', async () => {
  const { wrapper } = await page(routerConfig(), state(), (fake) => {
    fake.changeRefusal = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  })
  await fill(wrapper, OLD, NEW)
  await button(wrapper, 'Change password').trigger('click')
  await flushPromises()
  expect(section(wrapper, 'Password').find('.failed').text()).toBe('the router did not answer')
  expect(typedIn(wrapper)).toEqual([OLD, NEW, NEW])
})

// ---- Restart: asked first, and a call of its own ----

const dialog = (wrapper: VueWrapper) => wrapper.find('.ofo-dialog')
const said = (wrapper: VueWrapper) => wrapper.findAll('.said .ofo-banner').map((banner) => banner.text())

test('the dialog says what a restart loses', async () => {
  // Review Focus 3.
  const { wrapper, router, store } = await page()
  const restart = section(wrapper, 'Restart')
  expect(restart.find('.ofo-formsec__text').text()).toBe('Everything goes offline for about a minute. You log in again when it is back.')
  expect(button(wrapper, 'Restart the router').classes()).toContain('ofo-btn--danger')
  const lines = async () => {
    await button(wrapper, 'Restart the router').trigger('click')
    const found = dialog(wrapper)
      .findAll('.ofo-dialog__text')
      .map((line) => line.text())
    await button(wrapper, 'Cancel').trigger('click')
    return found
  }
  await button(wrapper, 'Restart the router').trigger('click')
  expect(dialog(wrapper).find('.ofo-dialog__title').text()).toBe('Restart openfeo.home.arpa?')
  expect(dialog(wrapper).attributes('role')).toBe('alertdialog')
  expect(dialog(wrapper).findAll('button').map((each) => each.text())).toEqual(['Cancel', 'Restart'])
  await button(wrapper, 'Cancel').trigger('click')
  expect(dialog(wrapper).exists()).toBe(false)
  // Nothing in hand.
  expect(await lines()).toEqual(['Every device loses the internet for about a minute.'])
  // A draft with one change, then with two.
  store().edit((draft) => (draft.system!.hostname = 'edge'))
  await flushPromises()
  expect(await lines()).toEqual(['Every device loses the internet for about a minute.', '1 change that is not applied yet is lost.'])
  store().edit((draft) => (draft.system!.domain = 'lan.example'))
  await flushPromises()
  expect(await lines()).toEqual(['Every device loses the internet for about a minute.', '2 changes that are not applied yet are lost.'])
  // A change waiting to be confirmed, with the draft still in hand.
  router.push('state', pendingState(13))
  await flushPromises()
  expect(await lines()).toEqual([
    'Every device loses the internet for about a minute.',
    'The change that is waiting to be confirmed goes back to how it was.',
    '2 changes that are not applied yet are lost.',
  ])
  expect(router.calls.reboot).toBe(0)
})

test('Cancel asks nothing of the router', async () => {
  const { wrapper, router } = await page()
  await button(wrapper, 'Restart the router').trigger('click')
  await button(wrapper, 'Cancel').trigger('click')
  await flushPromises()
  expect(router.calls.reboot).toBe(0)
  expect(said(wrapper)).toEqual([])
})

test('after a restart the page waits and then asks for the password', async () => {
  // Review Focus 5.
  const { wrapper, router, routes } = await page()
  await button(wrapper, 'Restart the router').trigger('click')
  await button(wrapper, 'Restart').trigger('click')
  await flushPromises()
  expect(router.calls.reboot).toBe(1)
  expect(dialog(wrapper).exists()).toBe(false)
  expect(said(wrapper)).toEqual(['The router is restarting. You log in again when it is back.'])
  // It cannot be asked twice.
  expect(disabled(wrapper, 'Restart the router')).toBe(true)
  // The socket goes with the router: the page says the same, not that the connection was lost.
  router.setConnection('reconnecting')
  await flushPromises()
  expect(said(wrapper)).toEqual(['The router is restarting. You log in again when it is back.'])
  // The router answers again and knows no session: the login screen.
  router.endSession('lapsed')
  await flushPromises()
  expect(wrapper.find('h1').text()).toBe('Log in')
  expect(routes.currentRoute.value.path).toBe('/login')
})

test('a restart the router refuses is said and nothing is marked', async () => {
  const { wrapper, router } = await page(routerConfig(), state(), (fake) => {
    fake.rebootRefusal = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  })
  await button(wrapper, 'Restart the router').trigger('click')
  await button(wrapper, 'Restart').trigger('click')
  await flushPromises()
  expect(router.calls.reboot).toBe(1)
  expect(dialog(wrapper).find('[role="alert"]').text()).toBe('the router did not answer')
  expect(said(wrapper)).toEqual([])
  // A double press while it is asked sends one call.
  router.rebootRefusal = null
  const release = router.holdCall('reboot')
  await button(wrapper, 'Restart').trigger('click')
  await button(wrapper, 'Restart').trigger('click')
  release()
  await flushPromises()
  expect(router.calls.reboot).toBe(2)
})
