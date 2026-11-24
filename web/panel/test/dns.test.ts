// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The DNS page (SPEC §8.4), in the shell at /dns: the owner's resolvers and whether the WAN's
// are used too, with the resolvers in use now; local names as a table edited in place; and
// the names let through the rebinding guard, under Advanced.

import { create, ConfigSchema, StateSchema, type Config, type State } from '@openfeo/client'
import { flushPromises, type DOMWrapper, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, routerConfig, state } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

/** The router's config with these DNS settings. */
function withDns(dns: NonNullable<Parameters<typeof create<typeof ConfigSchema>>[1]>['dns']): Config {
  const config = routerConfig()
  config.dns = create(ConfigSchema, { dns }).dns
  return config
}

/** The fixture's state with these resolvers in use. */
function using(resolvers: { address: string; wan: string }[]): State {
  const found = state()
  found.dns = create(StateSchema, { dns: { resolvers } }).dns
  return found
}

async function page(config: Config = routerConfig(), first: State | null = using([{ address: '203.0.113.53', wan: 'wan0' }])) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  const made = await panelAt('/dns', router)
  if (first !== null) {
    router.push('state', first)
  }
  await flushPromises()
  return made
}

const bar = (wrapper: VueWrapper) => wrapper.find('.ofo-savebar')
const box = (wrapper: VueWrapper, label: string) => fieldLabelled(wrapper, label).find('input')
const type = async (wrapper: VueWrapper, label: string, text: string) => {
  await box(wrapper, label).setValue(text)
  await box(wrapper, label).trigger('blur')
}
const names = (wrapper: VueWrapper) => wrapper.findAll('table.names tbody tr')
const values = (row: DOMWrapper<Element>) => row.findAll('input').map((input) => (input.element as HTMLInputElement).value)
const typeIn = async (row: DOMWrapper<Element>, at: number, text: string) => {
  await row.findAll('input')[at]?.setValue(text)
  await row.findAll('input')[at]?.trigger('blur')
}
const press = async (wrapper: VueWrapper, text: string) => {
  const button = wrapper.findAll('button').find((each) => each.text() === text)
  if (button === undefined) {
    throw new Error(`no button ${text}`)
  }
  await button.trigger('click')
  await flushPromises()
}
const toggle = (wrapper: VueWrapper) => {
  const found = wrapper.findAll('.ofo-toggle').find((each) => each.text() === 'Also use the resolvers the WAN gives')
  if (found === undefined) {
    throw new Error('no toggle')
  }
  return found.find('input')
}
const inUse = (wrapper: VueWrapper) => wrapper.find('.dns__inuse')
const refuse = (router: FakeRouter, violations: [path: string, message: string][]) => {
  router.validation = {
    violations: violations.map(([path, message]) => ({ $typeName: 'openfeo.v1.ConfigViolation' as const, path, code: 'invalid', message })),
    effects: [],
    caller: undefined,
  }
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

test('the page is in the navigation and has the save bar', async () => {
  const { wrapper, errors } = await page()
  const entry = wrapper.findAll('.ofo-nav__item').find((item) => item.text() === 'DNS')
  expect(entry?.attributes('href')).toBe('/dns')
  expect(entry?.attributes('aria-current')).toBe('page')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('How names are looked up for every device on your network.')
  expect(wrapper.findAll('.ofo-formsec__title').map((title) => title.text())).toEqual(['Resolvers', 'Local names', 'Protection'])
  expect(bar(wrapper).exists()).toBe(false)
  await type(wrapper, 'Your own resolvers', '9.9.9.9')
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(errors).toEqual([])
})

test('the resolvers are a list typed with commas', async () => {
  const { wrapper, store } = await page()
  expect(fieldLabelled(wrapper, 'Your own resolvers').find('.ofo-field__help').text()).toBe('Asked first, in this order. Leave empty to use only the ones the WAN gives.')
  await box(wrapper, 'Your own resolvers').setValue('9.9.9.9, ')
  // What is typed stays as typed, comma in mid-air and all, while it means the same list.
  expect((box(wrapper, 'Your own resolvers').element as HTMLInputElement).value).toBe('9.9.9.9, ')
  expect(store().draft.value!.dns!.upstreams).toEqual(['9.9.9.9'])
  await type(wrapper, 'Your own resolvers', '9.9.9.9, 2001:db8::53')
  expect(store().draft.value!.dns!.upstreams).toEqual(['9.9.9.9', '2001:db8::53'])
  expect(store().changes.value).toEqual([{ subject: 'DNS', what: 'your own resolvers', before: 'none', after: '9.9.9.9, 2001:db8::53' }])
  // What the page can tell is not an address is said, the field having been left.
  await type(wrapper, 'Your own resolvers', '9.9.9.9, nope')
  expect(fieldLabelled(wrapper, 'Your own resolvers').find('[role="alert"]').text()).toBe('nope is not an address.')
  // Emptied, a router that had no DNS settings has none again.
  await type(wrapper, 'Your own resolvers', '')
  expect(store().draft.value!.dns).toBeUndefined()
  expect(store().changes.value).toEqual([])
})

test('the toggle is one change, and putting it back is none', async () => {
  const { wrapper, store } = await page()
  expect((toggle(wrapper).element as HTMLInputElement).checked).toBe(true)
  await toggle(wrapper).setValue(false)
  expect(store().draft.value!.dns!.useWanDns).toBe(false)
  expect(store().changes.value).toEqual([{ subject: 'DNS', what: 'the WAN’s resolvers too', before: 'not set', after: 'no' }])
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  await toggle(wrapper).setValue(true)
  expect(store().changes.value).toEqual([])
  expect(bar(wrapper).exists()).toBe(false)
  unmountAll()
  // A config that says no shows the switch off.
  const off = await page(withDns({ useWanDns: false }))
  expect((toggle(off.wrapper).element as HTMLInputElement).checked).toBe(false)
})

test('in use now says each resolver and where it came from', async () => {
  const { wrapper, router } = await page(
    routerConfig(),
    using([
      { address: '198.51.100.53', wan: '' },
      { address: '203.0.113.53', wan: 'wan0' },
      { address: '203.0.113.54', wan: 'wan0' },
    ]),
  )
  expect(inUse(wrapper).text()).toBe('In use now: 198.51.100.53 yours; 203.0.113.53, 203.0.113.54 from wan0.')
  // The addresses are a machine's, in mono.
  expect(inUse(wrapper).findAll('.ofo-mono').map((mono) => mono.text())).toEqual(['198.51.100.53', '203.0.113.53, 203.0.113.54'])
  // It is what the router says, and follows it without a reload.
  router.push('state', using([{ address: '203.0.113.53', wan: 'wan0' }]))
  await flushPromises()
  expect(inUse(wrapper).text()).toBe('In use now: 203.0.113.53 from wan0.')
  router.push('state', using([]))
  await flushPromises()
  expect(inUse(wrapper).text()).toBe('In use now: none. Names outside your network cannot be looked up.')
})

test('until the router has said, nothing is claimed to be in use', async () => {
  const { wrapper } = await page(routerConfig(), null)
  expect(inUse(wrapper).exists()).toBe(false)
})

test('a local name is added, filled in and removed', async () => {
  const { wrapper, store } = await page(withDns({ records: [{ name: 'www', address: '192.168.1.10' }] }))
  expect(wrapper.findAll('table.names thead th').map((th) => th.text())).toEqual(['Name', 'Address', ''])
  expect(names(wrapper).map(values)).toEqual([['www', '192.168.1.10']])
  await press(wrapper, 'Add name')
  const added = () => names(wrapper)[1]!
  expect(values(added())).toEqual(['', ''])
  // A row just added says nothing yet, though it has no name.
  expect(added().find('[role="alert"]').exists()).toBe(false)
  await typeIn(added(), 0, 'www')
  await typeIn(added(), 1, '192.168.1.11')
  expect(added().find('[role="alert"]').text()).toBe('This name already has an IPv4 address.')
  await typeIn(added(), 1, '2001:db8:1:1::10')
  expect(added().find('[role="alert"]').exists()).toBe(false)
  expect(store().changes.value).toEqual([{ subject: 'DNS record www', what: '', before: '', after: 'added: 2001:db8:1:1::10' }])
  // The address the router has is said under one that was changed.
  await typeIn(names(wrapper)[0]!, 1, '192.168.1.12')
  expect(names(wrapper)[0]!.find('.ofo-field__help').text()).toBe('Was 192.168.1.10.')
  await added().find('button').trigger('click')
  await names(wrapper)[0]!.find('button').trigger('click')
  expect(names(wrapper)).toHaveLength(0)
  expect(store().changes.value).toEqual([{ subject: 'DNS record www', what: '', before: '192.168.1.10', after: 'removed' }])
})

test('the note says what the first name becomes', async () => {
  const note = (wrapper: VueWrapper) => wrapper.find('.names__note').text()
  const none = await page()
  expect(note(none.wrapper)).toBe('A name with no dot is under home.arpa: www is www.home.arpa. One name may have an IPv4 and an IPv6 address.')
  unmountAll()
  const some = withDns({ records: [{ name: 'nas.example.org', address: '192.168.1.10' }, { name: 'Media', address: '192.168.1.11' }] })
  some.system!.domain = 'lan.example'
  const named = await page(some)
  expect(note(named.wrapper)).toBe('A name with no dot is under lan.example: media is media.lan.example. One name may have an IPv4 and an IPv6 address.')
  // The names are a machine's, in mono.
  expect(named.wrapper.findAll('.names__note .ofo-mono').map((mono) => mono.text())).toEqual(['lan.example', 'media', 'media.lan.example'])
})

test('Advanced is open when a name is let through', async () => {
  const closed = await page()
  const advanced = (wrapper: VueWrapper) => wrapper.find('details')
  expect(advanced(closed.wrapper).attributes('open')).toBeUndefined()
  unmountAll()
  const { wrapper, store } = await page(withDns({ rebindAllow: ['plex.direct'] }))
  expect(advanced(wrapper).attributes('open')).toBeDefined()
  expect((box(wrapper, 'Names let through').element as HTMLInputElement).value).toBe('plex.direct')
  expect(fieldLabelled(wrapper, 'Names let through').find('.ofo-field__help').text()).toBe('A name here, and everything under it, may answer with a private address.')
  await type(wrapper, 'Names let through', 'plex.direct, example.org')
  expect(store().draft.value!.dns!.rebindAllow).toEqual(['plex.direct', 'example.org'])
  expect(store().changes.value).toEqual([{ subject: 'DNS', what: 'names let through', before: 'plex.direct', after: 'plex.direct, example.org' }])
})

test('what the router refuses is said at the field it names', async () => {
  const { wrapper, router, store } = await page(withDns({ upstreams: ['203.0.113.53', '203.0.113.54'], records: [{ name: 'www', address: '192.168.1.10' }, { name: 'nas', address: '192.168.1.11' }] }))
  refuse(router, [
    ['dns.upstreams[1]', 'not a unicast address'],
    ['dns.records[0].address', 'inside no LAN'],
    ['dns.records[1]', 'the router answers this name itself'],
    ['dns.rebind_allow[0]', 'not a name'],
  ])
  expect(await store().review()).toBeNull()
  await flushPromises()
  expect(fieldLabelled(wrapper, 'Your own resolvers').find('[role="alert"]').text()).toBe('not a unicast address')
  expect(names(wrapper)[0]!.findAll('td')[1]?.find('[role="alert"]').text()).toBe('inside no LAN')
  // What no field is for is listed above, by its path.
  expect(wrapper.find('.refused').findAll('li').map((item) => item.text())).toEqual(['dns.records[1]: the router answers this name itself'])
  // What is wrong under Advanced opens it.
  expect(wrapper.find('details').attributes('open')).toBeDefined()
  expect(fieldLabelled(wrapper, 'Names let through').find('[role="alert"]').text()).toBe('not a name')
  await type(wrapper, 'Your own resolvers', '203.0.113.53')
  expect(fieldLabelled(wrapper, 'Your own resolvers').find('[role="alert"]').exists()).toBe(false)
})

test('dns.blocklists is sent back as it came', async () => {
  // No page edits it; the panel drops nothing it does not show.
  const { wrapper, store } = await page(withDns({ blocklists: ['kept'], upstreams: ['203.0.113.53'] }))
  await type(wrapper, 'Your own resolvers', '')
  await toggle(wrapper).setValue(false)
  await press(wrapper, 'Add name')
  expect(store().draft.value!.dns!.blocklists).toEqual(['kept'])
})

test('a config the router refused is shown and cannot be changed', async () => {
  const { wrapper, router } = await page(withDns({ records: [{ name: 'www', address: '192.168.1.10' }] }))
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toContain('The router refused its config file')
  const shown = wrapper.find('.page')
  expect(shown.findAll('input').every((input) => (input.element as HTMLInputElement).disabled)).toBe(true)
  expect(shown.findAll('button').every((button) => (button.element as HTMLButtonElement).disabled)).toBe(true)
})
