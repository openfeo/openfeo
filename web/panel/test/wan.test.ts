// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The WAN page (SPEC §8.4), in the shell at /wan, on a router whose one WAN is PPPoE on a
// tagged port and carries IPv6.

import { clone, ConfigSchema, create, WanSchema, type Config } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, routerConfig, state } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

/** The panel at a WAN page address, on the fixture's router (or `config`), its state heard. */
async function page(path = '/wan', config: Config = routerConfig(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt(path, router)
  router.push('state', state())
  await flushPromises()
  return made
}

/** The fixture's config with a second WAN, DHCP on a port of its own, that the state knows nothing of. */
function twoWans(): Config {
  const config = routerConfig()
  config.lans[0]!.ports = ['p1', 'p3']
  config.wans.push(create(WanSchema, { name: 'wan1', port: 'p2', priority: 20, kind: { case: 'dhcp', value: { hostname: 'openfeo-two' } } }))
  return config
}

const tabs = (wrapper: VueWrapper) => wrapper.findAll('[role="tab"]')
const sections = (wrapper: VueWrapper) => wrapper.findAll('.ofo-formsec')
const labels = (within: { findAll: VueWrapper['findAll'] }) => within.findAll('.ofo-field__label').map((label) => label.text())
const input = (within: { findAll: VueWrapper['findAll'] }, label: string) => fieldLabelled(within, label).find('input')
const type = async (within: { findAll: VueWrapper['findAll'] }, label: string, text: string) => {
  await input(within, label).setValue(text)
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

test('a tab per WAN with its phase, and the address chooses which is shown', async () => {
  const { wrapper, routes, errors } = await page('/wan', twoWans())
  expect(wrapper.find('h1').text()).toBe('WAN')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('How the router reaches the internet.')
  expect(wrapper.find('.ofo-pagehead__actions button').text()).toBe('Add WAN')
  const [first, second] = tabs(wrapper)
  expect(tabs(wrapper)).toHaveLength(2)
  // The one the router is running says how it is doing; the other has nothing to say.
  expect(first?.text()).toContain('wan0')
  expect(first?.find('.ofo-pill').classes()).toEqual(['ofo-pill', 'ofo-pill--ok'])
  expect(first?.find('.ofo-pill').text()).toBe('up')
  expect(second?.text()).toBe('wan1')
  expect(second?.find('.ofo-pill').exists()).toBe(false)
  // /wan shows the first.
  expect(first?.attributes('aria-selected')).toBe('true')
  expect((input(wrapper, 'Username').element as HTMLInputElement).value).toBe('openfeo@isp.example')
  const panel = wrapper.find('[role="tabpanel"]')
  expect(panel.attributes('id')).toBe(first?.attributes('aria-controls'))

  // A click on a tab shows that WAN, and the address says which.
  await second?.trigger('click')
  await flushPromises()
  expect(routes.currentRoute.value.path).toBe('/wan/wan1')
  expect(tabs(wrapper)[1]?.attributes('aria-selected')).toBe('true')
  expect(wrapper.text()).toContain('Nothing to fill in: the address, gateway and DNS servers come from the ISP.')
  expect(errors).toEqual([])
  unmountAll()

  // The address alone chooses, and a name that is no WAN's shows the first.
  const direct = await page('/wan/wan1', twoWans())
  expect(tabs(direct.wrapper)[1]?.attributes('aria-selected')).toBe('true')
  unmountAll()
  const unknown = await page('/wan/nothing', twoWans())
  expect(tabs(unknown.wrapper)[0]?.attributes('aria-selected')).toBe('true')
  expect(unknown.errors).toEqual([])
})

test("each type shows its own fields and no other's", async () => {
  const { wrapper } = await page()
  const titles = sections(wrapper).map((section) => section.find('.ofo-formsec__title').text())
  expect(titles).toEqual(['Connection', 'Port', 'IPv6'])
  expect(sections(wrapper).map((section) => section.find('.ofo-formsec__text').text())).toEqual([
    'How this WAN gets its address from your ISP.',
    "Where the ISP's cable goes, and the VLAN it expects.",
    'Whether this WAN carries IPv6, and the prefix your LANs take theirs from.',
  ])
  const connection = () => sections(wrapper)[0]!
  const choices = connection().findAll('.ofo-choice')
  expect(connection().find('legend').text()).toBe('Type')
  expect(choices.map((choice) => choice.text())).toEqual(['DHCPThe ISP hands out the address.', 'PPPoEYou log in with an account.', 'StaticYou type the address.'])
  expect(choices.map((choice) => (choice.find('input').element as HTMLInputElement).checked)).toEqual([false, true, false])

  expect(labels(connection())).toEqual(['Type', 'Username', 'Password', 'Service name', 'Access concentrator'])
  expect(fieldLabelled(connection(), 'Service name').find('.ofo-field__help').text()).toBe('Only connect to this service. Leave empty for any.')
  expect(fieldLabelled(connection(), 'Access concentrator').find('.ofo-field__help').text()).toBe('Only connect to this one. Leave empty for any.')

  await choices[2]?.find('input').setValue(true)
  expect(labels(connection())).toEqual(['Type', 'Address', 'Gateway', 'DNS servers'])
  expect(fieldLabelled(connection(), 'Address').find('.ofo-field__help').text()).toBe("The address and the size of the ISP's subnet.")
  expect(fieldLabelled(connection(), 'DNS servers').find('.ofo-field__help').text()).toBe('One or more, separated by commas.')
  expect(connection().find('details').exists()).toBe(false)

  await connection().findAll('.ofo-choice')[0]?.find('input').setValue(true)
  expect(labels(connection())).toEqual(['Type', 'Hostname sent', 'Vendor class sent'])
  expect(connection().text()).toContain('Nothing to fill in: the address, gateway and DNS servers come from the ISP.')
  expect(fieldLabelled(connection(), 'Hostname sent').find('.ofo-field__help').text()).toBe('Option 12. Leave empty to send none.')
  expect(fieldLabelled(connection(), 'Vendor class sent').find('.ofo-field__help').text()).toBe('Option 60, for ISPs that ask for one.')

  // The other two sections are the same for every type.
  expect(labels(sections(wrapper)[1]!)).toEqual(['Port', 'VLAN tag', 'Priority'])
  expect(fieldLabelled(wrapper, 'VLAN tag').find('.ofo-field__help').text()).toBe('1 to 4094. Leave empty for a line with no tag.')
  expect(fieldLabelled(wrapper, 'Priority').find('.ofo-field__help').text()).toBe('The lowest number wins when more than one WAN is up.')
  expect(labels(sections(wrapper)[2]!)).toEqual(['Routed prefix', 'Prefix length to ask for', 'Gateway'])
  expect(sections(wrapper)[2]!.find('.ofo-toggle').text()).toBe('IPv6')
  expect(fieldLabelled(wrapper, 'Routed prefix').find('.ofo-field__help').text()).toBe(
    'A fixed prefix your ISP routes to you, such as 2001:db8:1::/48. Leave empty to ask the ISP for one.',
  )
  expect(fieldLabelled(wrapper, 'Prefix length to ask for').find('.ofo-field__help').text()).toBe('48 to 64, when no prefix is typed.')
  expect(fieldLabelled(wrapper, 'Prefix length to ask for').find('input').attributes('placeholder')).toBe('56')
  expect(fieldLabelled(sections(wrapper)[2]!, 'Gateway').find('.ofo-field__help').text()).toBe('Leave empty to learn it from the ISP.')

  // Back to PPPoE: what the router has for it is there again.
  await connection().findAll('.ofo-choice')[1]?.find('input').setValue(true)
  expect((input(connection(), 'Username').element as HTMLInputElement).value).toBe('openfeo@isp.example')
})

test('the password field is empty and says it is unchanged; typing one is a change that names no value', async () => {
  const { wrapper, store } = await page('/wan', twoWans())
  const password = () => fieldLabelled(wrapper, 'Password')
  const box = () => password().find('input')
  expect(box().attributes('type')).toBe('password')
  expect((box().element as HTMLInputElement).value).toBe('')
  expect(box().attributes('placeholder')).toBe('Unchanged')
  expect(password().find('.ofo-field__help').text()).toBe('Kept on the router and never shown. Type a new one to change it.')
  expect(store().changes.value).toEqual([])

  await box().setValue('a-typed-secret')
  expect(store().changes.value).toEqual([{ subject: 'wan0', what: 'password', before: '', after: 'changed' }])
  // It is in the field it was typed in and nowhere else on the page: not said back, in no
  // other field. (The test's DOM writes a field's value out with its markup; a browser does not.)
  expect(wrapper.text()).not.toContain('a-typed-secret')
  expect(wrapper.html().split('a-typed-secret')).toHaveLength(2)
  expect(wrapper.findAll('input').filter((each) => (each.element as HTMLInputElement).value === 'a-typed-secret')).toHaveLength(1)
  expect(password().find('.ofo-field__help').text()).toBe('Kept on the router and never shown. Type a new one to change it.')
  await box().setValue('')
  expect(store().changes.value).toEqual([])

  // A WAN that is not PPPoE on the router has no password to leave unchanged.
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  await wrapper.findAll('.ofo-choice')[1]?.find('input').setValue(true)
  expect(box().attributes('placeholder')).toBeUndefined()
  expect(password().find('.ofo-field__help').text()).toBe("The account's password.")
})

test('the password field is empty again after an apply', async () => {
  const { wrapper, router, store } = await page()
  const box = () => fieldLabelled(wrapper, 'Password').find('input')
  await box().setValue('a-typed-secret')
  router.applyAnswer = { answered: true, tag: 't1' }
  const review = await store().review()
  expect(review).not.toBeNull()
  await store().apply(review!, false)
  await flushPromises()
  // It was sent, and is not shown back.
  const sent = router.calls.apply[0]!.config.wans[0]!.kind
  expect(sent.case === 'pppoe' && sent.value.password).toBe('a-typed-secret')
  expect((box().element as HTMLInputElement).value).toBe('')
  expect(box().attributes('placeholder')).toBe('Unchanged')
  expect(wrapper.html()).not.toContain('a-typed-secret')
  expect(store().changes.value).toEqual([])
})

test('a field that differs says what it was', async () => {
  const { wrapper } = await page()
  const help = (label: string) => fieldLabelled(wrapper, label).find('.ofo-field__help').text()
  expect(help('VLAN tag')).toBe('1 to 4094. Leave empty for a line with no tag.')
  await type(wrapper, 'VLAN tag', '')
  expect(help('VLAN tag')).toBe('1 to 4094. Leave empty for a line with no tag. Was 911.')
  await type(wrapper, 'VLAN tag', '911')
  expect(help('VLAN tag')).toBe('1 to 4094. Leave empty for a line with no tag.')
  await type(wrapper, 'Service name', 'fibre')
  expect(help('Service name')).toBe('Only connect to this service. Leave empty for any. Was empty.')
  await type(wrapper, 'Username', 'other@isp.example')
  expect(help('Username')).toBe('Was openfeo@isp.example.')
  await type(wrapper, 'Priority', '20')
  expect(help('Priority')).toBe('The lowest number wins when more than one WAN is up. Was 10.')
  // The port is a choice, and says the same.
  const port = fieldLabelled(wrapper, 'Port')
  expect(port.findAll('option').map((option) => option.text())).toEqual([
    'p0 · 2500 Mbit/s · link up',
    'p1 · 2500 Mbit/s · link up · in lan0',
    'p2 · no link · in lan0',
    'p3 · 1000 Mbit/s · link up · in lan0, iot',
  ])
  await port.find('select').setValue('p2')
  expect(port.find('.ofo-field__help').text()).toBe('Was p0.')
  // A password never says what it was.
  await type(wrapper, 'Password', 'a-typed-secret')
  expect(help('Password')).not.toContain('Was')
})

test('a tag out of range is said when the field is left, not before', async () => {
  const { wrapper, store } = await page()
  const field = () => fieldLabelled(wrapper, 'VLAN tag')
  await type(wrapper, 'VLAN tag', '5000')
  expect(field().classes()).not.toContain('ofo-field--error')
  expect(field().find('[role="alert"]').exists()).toBe(false)
  await field().find('input').trigger('blur')
  expect(field().classes()).toContain('ofo-field--error')
  expect(field().find('[role="alert"]').text()).toBe('1 to 4094.')
  expect(field().find('input').attributes('aria-invalid')).toBe('true')
  // The tab says there is something to look at.
  expect(tabs(wrapper)[0]?.find('.ofo-pill').classes()).toEqual(['ofo-pill', 'ofo-pill--danger'])
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('problem')
  // Once left, it is checked as it is put right.
  await type(wrapper, 'VLAN tag', '100')
  expect(field().classes()).not.toContain('ofo-field--error')
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('up')
  // Only digits get into a number's field.
  await type(wrapper, 'VLAN tag', '12a')
  expect((field().find('input').element as HTMLInputElement).value).toBe('12')
  expect(store().draft.value!.wans[0]!.vlan).toBe(12)
})

test("the router's violation is shown at its field, and one with no field at the top", async () => {
  const { wrapper, router, store } = await page()
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].pppoe.username', code: 'empty', message: 'an account name is needed' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].static.dns[1]', code: 'address', message: 'not an address' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0]', code: 'kind', message: 'a WAN is one kind' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].ipv6', code: 'ipv6', message: 'only one WAN may carry IPv6' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'firewall.port_forwards[0].to', code: 'outside', message: 'the target is in no LAN' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[1].ipv4', code: 'overlap', message: 'overlaps lan0' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  const username = fieldLabelled(wrapper, 'Username')
  expect(username.classes()).toContain('ofo-field--error')
  expect(username.find('[role="alert"]').text()).toBe('an account name is needed')
  // What has no field on this tab is listed at its top, by its path and in the router's words.
  const atTop = wrapper.find('[role="tabpanel"] .refused')
  expect(atTop.findAll('li').map((item) => item.text())).toEqual(['wans[0]: a WAN is one kind', 'wans[0].ipv6: only one WAN may carry IPv6'])
  expect(atTop.findAll('li code').map((code) => code.text())).toEqual(['wans[0]', 'wans[0].ipv6'])
  // What is not about a WAN at all is above the page.
  const above = wrapper.findAll('.refused').find((list) => !list.element.closest('[role="tabpanel"]'))
  expect(above?.findAll('li').map((item) => item.text())).toEqual(['firewall.port_forwards[0].to: the target is in no LAN', 'lans[1].ipv4: overlaps lan0'])
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('problem')

  // A violation at a field of another type shows when that type's fields do.
  await wrapper.findAll('.ofo-choice')[2]?.find('input').setValue(true)
  expect(fieldLabelled(wrapper, 'DNS servers').find('[role="alert"]').text()).toBe('not an address')
  await wrapper.findAll('.ofo-choice')[1]?.find('input').setValue(true)

  // Putting a field right takes its message away; the rest stay until the router is asked again.
  await type(wrapper, 'Username', 'openfeo@isp.example')
  expect(fieldLabelled(wrapper, 'Username').classes()).not.toContain('ofo-field--error')
  expect(wrapper.find('[role="tabpanel"] .refused').exists()).toBe(true)
  router.validation = { violations: [], effects: [], caller: undefined }
  await store().review()
  await flushPromises()
  expect(wrapper.find('.refused').exists()).toBe(false)
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('up')
})

test('what the router refuses on a WAN that is not shown is said above the page', async () => {
  // Two WANs on one port: the router says so at the later one, whichever was just edited.
  const { wrapper, router, store } = await page('/wan', twoWans())
  await fieldLabelled(wrapper, 'Port').find('select').setValue('p2')
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[1].port', code: 'port_used_twice', message: '"p2" is already assigned' }],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  // Nothing on the tab that is shown is wrong, and the refusal is still on the page.
  expect(wrapper.find('[role="tabpanel"] .ofo-field--error').exists()).toBe(false)
  const above = () => wrapper.findAll('.refused').find((list) => !list.element.closest('[role="tabpanel"]'))
  expect(above()?.findAll('li').map((item) => item.text())).toEqual(['wans[1].port: "p2" is already assigned'])
  expect(tabs(wrapper)[1]?.find('.ofo-pill').text()).toBe('problem')
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(fieldLabelled(wrapper, 'Port').find('[role="alert"]').text()).toBe('"p2" is already assigned')
  expect(above()).toBeUndefined()
})

test('removing a WAN takes with it what was said of the WANs whose places change', async () => {
  const { wrapper, router, store } = await page('/wan', twoWans())
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[1].port', code: 'port_used_twice', message: '"p2" is already assigned' }],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  expect(tabs(wrapper)[1]?.find('.ofo-pill').text()).toBe('problem')
  // wan0 goes: wan1 is the first WAN now, and what was said of a second is said of none.
  await wrapper.findAll('button').find((button) => button.text() === 'Remove wan0')?.trigger('click')
  await flushPromises()
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['wan1'])
  expect(wrapper.find('.refused').exists()).toBe(false)
  expect(wrapper.find('[role="tabpanel"] .ofo-field--error').exists()).toBe(false)
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
  expect(store().violations.value).toEqual([])
})

test('a WAN added under the name of one that was removed starts from nothing', async () => {
  // What was typed for a type that was switched away from is kept under the WAN's name, a
  // typed password with it. It goes when the WAN does.
  const { wrapper, store } = await page('/wan/wan1', twoWans())
  const choose = async (at: number) => {
    await wrapper.findAll('.ofo-choice')[at]?.find('input').setValue(true)
  }
  await choose(1)
  await type(wrapper, 'Username', 'second@isp.example')
  await type(wrapper, 'Password', 'a-typed-secret')
  await choose(2)
  await wrapper.findAll('button').find((button) => button.text() === 'Remove wan1')?.trigger('click')
  await flushPromises()

  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  await wrapper.find('.ofo-dialog input').setValue('wan1')
  await wrapper.findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  await flushPromises()
  await choose(1)
  expect((input(wrapper, 'Username').element as HTMLInputElement).value).toBe('')
  const account = store().draft.value!.wans[1]!.kind
  expect(account.case === 'pppoe' && account.value.password).toBe('')
  expect(wrapper.html()).not.toContain('a-typed-secret')
})

test('advanced opens for a field that is set', async () => {
  const closed = await page()
  const groups = () => closed.wrapper.findAll('details.ofo-adv')
  expect(groups()).toHaveLength(2)
  expect(groups().map((group) => (group.element as HTMLDetailsElement).open)).toEqual([false, false])
  // Or for one with a problem.
  closed.router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].ipv6.pd_hint', code: 'range', message: '48 to 64' }],
    effects: [],
    caller: undefined,
  }
  await closed.store().review()
  await flushPromises()
  expect(groups().map((group) => (group.element as HTMLDetailsElement).open)).toEqual([false, true])
  unmountAll()

  const config = routerConfig()
  const kind = config.wans[0]!.kind
  if (kind.case === 'pppoe') {
    kind.value.ac = 'bras-1'
  }
  const open = await page('/wan', config)
  expect(open.wrapper.findAll('details.ofo-adv').map((group) => (group.element as HTMLDetailsElement).open)).toEqual([true, false])
})

test('Add WAN asks for a name, adds a tab and shows it; Remove takes the WAN away', async () => {
  const { wrapper, routes, store, errors } = await page()
  const dialog = () => wrapper.find('.ofo-dialog')
  expect(dialog().exists()).toBe(false)
  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  expect(dialog().attributes('role')).toBe('dialog')
  expect(dialog().find('.ofo-dialog__title').text()).toBe('Add a WAN')
  expect(labels(dialog())).toEqual(['Name'])
  expect(dialog().findAll('.ofo-dialog__foot button').map((button) => button.text())).toEqual(['Cancel', 'Add'])
  // The name is the field the dialog opens on.
  expect(document.activeElement).toBe(dialog().find('input').element)

  // A name already in use, by a WAN or a LAN, is refused where it is typed.
  await dialog().find('input').setValue('lan0')
  await dialog().findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  expect(dialog().find('[role="alert"]').text()).toBe('lan0 is already in use.')
  expect(store().draft.value!.wans).toHaveLength(1)
  await dialog().find('input').setValue('wan-too-long')
  await dialog().find('input').trigger('keydown', { key: 'Enter' })
  expect(dialog().find('[role="alert"]').text()).toBe('1 to 11 characters: a to z, 0 to 9, - and _, starting with a letter or a digit.')

  await dialog().find('input').setValue('wan1')
  await dialog().find('input').trigger('keydown', { key: 'Enter' })
  await flushPromises()
  expect(dialog().exists()).toBe(false)
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['wan0 up', 'wan1'])
  expect(routes.currentRoute.value.path).toBe('/wan/wan1')
  expect(tabs(wrapper)[1]?.attributes('aria-selected')).toBe('true')
  // It starts as DHCP, ten above the highest priority, on a port still to be chosen: every one is in use.
  expect(wrapper.text()).toContain('Nothing to fill in')
  expect((input(wrapper, 'Priority').element as HTMLInputElement).value).toBe('20')
  expect((fieldLabelled(wrapper, 'Port').find('select').element as HTMLSelectElement).value).toBe('')
  expect(fieldLabelled(wrapper, 'Port').findAll('option')[0]?.text()).toBe('Choose a port')
  expect(store().changes.value).toEqual([{ subject: 'wan1', what: 'WAN', before: '', after: 'added: DHCP on no port' }])
  // A WAN that is only a draft has nothing that it "was".
  await type(wrapper, 'Priority', '30')
  expect(fieldLabelled(wrapper, 'Priority').find('.ofo-field__help').text()).toBe('The lowest number wins when more than one WAN is up.')

  // Remove is at the foot, and names what it removes.
  const remove = () => wrapper.findAll('button').find((button) => button.text().startsWith('Remove'))
  expect(remove()?.text()).toBe('Remove wan1')
  await remove()?.trigger('click')
  await flushPromises()
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['wan0 up'])
  expect(routes.currentRoute.value.path).toBe('/wan/wan0')
  expect(store().changes.value).toEqual([])

  // Cancel, and Esc, add nothing.
  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  await dialog().find('input').setValue('wan2')
  await dialog().findAll('.ofo-dialog__foot button')[0]?.trigger('click')
  expect(dialog().exists()).toBe(false)
  expect(tabs(wrapper)).toHaveLength(1)
  expect(errors).toEqual([])
})

test('with IPv6 off the prefix fields are gone, and on again they are as they were', async () => {
  const { wrapper, store } = await page()
  const v6 = () => sections(wrapper)[2]!
  const toggle = () => v6().find('.ofo-toggle input')
  expect((toggle().element as HTMLInputElement).checked).toBe(true)
  await type(v6(), 'Gateway', 'fe80::1')
  await toggle().setValue(false)
  expect(labels(v6())).toEqual([])
  expect(v6().find('details').exists()).toBe(false)
  expect(store().changes.value).toEqual([{ subject: 'wan0', what: 'IPv6', before: 'on', after: 'off' }])
  await toggle().setValue(true)
  expect(labels(v6())).toEqual(['Routed prefix', 'Prefix length to ask for', 'Gateway'])
  expect((input(v6(), 'Routed prefix').element as HTMLInputElement).value).toBe('2001:db8:1::/48')
  expect((input(v6(), 'Gateway').element as HTMLInputElement).value).toBe('fe80::1')
  expect(store().changes.value).toEqual([{ subject: 'wan0', what: 'IPv6 gateway', before: 'none', after: 'fe80::1' }])
})

test('nothing can be changed on a router running on defaults, and the page says why', async () => {
  const { wrapper, router, store } = await page()
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid (1 error)', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toBe('The router refused its config file and runs on defaults. Mend or remove the file to change settings here.')
  const controls = wrapper.findAll('[role="tabpanel"] input, [role="tabpanel"] select')
  expect(controls.length).toBeGreaterThan(8)
  expect(controls.every((control) => (control.element as HTMLInputElement).disabled)).toBe(true)
  expect((wrapper.find('.ofo-pagehead__actions button').element as HTMLButtonElement).disabled).toBe(true)
  const remove = wrapper.findAll('button').find((button) => button.text().startsWith('Remove'))
  expect((remove?.element as HTMLButtonElement).disabled).toBe(true)
  // The tabs still show each WAN: looking is not changing.
  expect((tabs(wrapper)[0]?.element as HTMLButtonElement).disabled).toBe(false)
  expect(store().changes.value).toEqual([])
})

test('before the config has been read the page waits, and a router with no WAN says so', async () => {
  const router = signedIn()
  router.configNow = { config: routerConfig(), tag: 't1', confirmSecs: 120 }
  const letGo = router.holdCall('config')
  const waiting = await panelAt('/wan', router)
  expect(waiting.wrapper.find('h1').text()).toBe('WAN')
  expect(waiting.wrapper.find('.ofo-skel').exists()).toBe(true)
  expect(waiting.wrapper.find('[role="tab"]').exists()).toBe(false)
  letGo()
  await flushPromises()
  expect(waiting.wrapper.find('.ofo-skel').exists()).toBe(false)
  expect(tabs(waiting.wrapper)).toHaveLength(1)
  unmountAll()

  const none = clone(ConfigSchema, routerConfig())
  none.wans = []
  const empty = await page('/wan', none)
  expect(empty.wrapper.find('[role="tab"]').exists()).toBe(false)
  expect(empty.wrapper.text()).toContain('No WAN is set up.')
  expect(empty.errors).toEqual([])
})
