// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The System page (SPEC §8.4), in the shell at /system: the router's name, its clock and time
// servers, the password, restarting, and what it is running.

import { type Config, type State } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, routerConfig, state } from './fixtures'
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
  // Router's group comes after Network's pages, and System is in it.
  expect(nav.findAll('.ofo-nav__item, .ofo-nav__group').map((entry) => entry.text()).slice(-2)).toEqual(['Router', 'System'])
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
