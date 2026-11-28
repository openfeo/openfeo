// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The Firewall page (SPEC §8.4), in the shell at /firewall: which network may reach which,
// port forwards and rules as tables edited in place, and whether the router answers ping.

import { create, ConfigSchema, type Config } from '@openfeo/client'
import { flushPromises, type DOMWrapper, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, routerConfig, state } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

async function page(config: Config = routerConfig(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt('/firewall', router)
  router.push('state', state())
  await flushPromises()
  return made
}

/** A config with a rule beside the fixture's forward. */
function withRule(): Config {
  const config = routerConfig()
  config.firewall!.rules = create(ConfigSchema, {
    firewall: { rules: [{ name: 'web6', from: 'wan', to: '2001:db8:1:1::10', proto: 'tcp', ports: ['80', '443'] }] },
  }).firewall!.rules
  return config
}

const bar = (wrapper: VueWrapper) => wrapper.find('.ofo-savebar')
const grid = (wrapper: VueWrapper) => wrapper.find('table.reach')
/** The tick named so, wherever it is in the grid. */
const tick = (wrapper: VueWrapper, name: string) => {
  const found = grid(wrapper).find(`input[aria-label="${name}"]`)
  if (!found.exists()) {
    throw new Error(`no tick ${name}`)
  }
  return found
}
const ticked = (wrapper: VueWrapper, name: string) => (tick(wrapper, name).element as HTMLInputElement).checked
const forwards = (wrapper: VueWrapper) => wrapper.findAll('table.fwd tbody tr')
const rules = (wrapper: VueWrapper) => wrapper.findAll('table.rules tbody tr')
const heads = (wrapper: VueWrapper, table: string) => wrapper.findAll(`table.${table} thead th`).map((th) => th.text())
/** The controls of a row, in the order of its columns. */
const controls = (row: DOMWrapper<Element>) => row.findAll('input, select')
const values = (row: DOMWrapper<Element>) => controls(row).map((control) => (control.element as HTMLInputElement | HTMLSelectElement).value)
/** Type into a row's control and leave it, as a person does. */
const type = async (row: DOMWrapper<Element>, at: number, text: string) => {
  await controls(row)[at]?.setValue(text)
  await controls(row)[at]?.trigger('blur')
}
const press = async (wrapper: VueWrapper, text: string) => {
  const button = wrapper.findAll('button').find((each) => each.text() === text)
  if (button === undefined) {
    throw new Error(`no button ${text}`)
  }
  await button.trigger('click')
  await flushPromises()
}
const what = (changes: { subject: string; what: string }[]) => changes.map((change) => `${change.subject} ${change.what}`.trim())
const refuse = (router: FakeRouter, path: string, message: string) => {
  router.validation = { violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path, code: 'invalid', message }], effects: [], caller: undefined }
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
  const { wrapper, store, errors } = await page()
  const entry = wrapper.findAll('.ofo-nav__item').find((item) => item.text() === 'Firewall')
  expect(entry?.attributes('href')).toBe('/firewall')
  expect(entry?.attributes('aria-current')).toBe('page')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('What may reach what. Nothing on the internet gets in unless you say so here.')
  expect(wrapper.findAll('.ofo-formsec__title').map((title) => title.text())).toEqual(['Between networks', 'Port forwards', 'Rules', 'The router itself'])
  // No change yet, so no bar; one tick and it is there.
  expect(bar(wrapper).exists()).toBe(false)
  await tick(wrapper, 'iot may reach lan0').setValue(true)
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  expect(store().changes.value).toHaveLength(1)
  expect(errors).toEqual([])
})

test('the grid shows what each LAN may reach, and a tick is one change', async () => {
  const config = routerConfig()
  config.lans[0]!.reaches = ['wan', 'iot']
  const { wrapper, store } = await page(config)
  expect(heads(wrapper, 'reach')).toEqual(['From', 'Internet', 'lan0', 'iot'])
  const names = grid(wrapper)
    .findAll('tbody tr')
    .map((row) => row.find('td').text())
  expect(names).toEqual(['lan0', 'iot'])
  expect([ticked(wrapper, 'lan0 may reach the internet'), ticked(wrapper, 'lan0 may reach iot')]).toEqual([true, true])
  expect([ticked(wrapper, 'iot may reach the internet'), ticked(wrapper, 'iot may reach lan0')]).toEqual([true, false])
  // A LAN's own cell has no tick: a dash.
  expect(grid(wrapper).findAll('input')).toHaveLength(4)
  expect(grid(wrapper).findAll('tbody tr')[0]?.findAll('td')[2]?.text()).toBe('—')

  await tick(wrapper, 'iot may reach lan0').setValue(true)
  expect(store().draft.value!.lans[1]!.reaches).toEqual(['wan', 'lan0'])
  expect(store().changes.value).toEqual([{ subject: 'iot', what: 'may reach', before: 'the internet', after: 'the internet, lan0' }])
  await tick(wrapper, 'iot may reach the internet').setValue(false)
  expect(store().draft.value!.lans[1]!.reaches).toEqual(['lan0'])
})

test('opening the page changes nothing', async () => {
  // Review Focus 1: a LAN whose list is empty in the file reaches the internet alone.
  const config = routerConfig()
  config.lans[0]!.reaches = []
  const { wrapper, store } = await page(config)
  expect(ticked(wrapper, 'lan0 may reach the internet')).toBe(true)
  expect(store().changes.value).toEqual([])
  expect(bar(wrapper).exists()).toBe(false)
  await tick(wrapper, 'lan0 may reach the internet').setValue(false)
  expect(store().draft.value!.lans[0]!.reaches).toEqual(['none'])
  expect(bar(wrapper).text()).toContain('1 change not applied yet')
  await tick(wrapper, 'lan0 may reach the internet').setValue(true)
  expect(store().draft.value!.lans[0]!.reaches).toEqual([])
  expect(bar(wrapper).exists()).toBe(false)
})

test('a forward is added, filled in and removed', async () => {
  const { wrapper, store } = await page()
  expect(heads(wrapper, 'fwd')).toEqual(['Name', 'Protocol', 'Port', 'To address', 'To port', ''])
  expect(forwards(wrapper).map(values)).toEqual([['lan-http', 'tcp', '8080', '192.168.1.10', '']])
  // To port's placeholder is the port: empty means the same one.
  expect(controls(forwards(wrapper)[0]!)[4]?.attributes('placeholder')).toBe('8080')

  await press(wrapper, 'Add forward')
  const added = () => forwards(wrapper)[1]!
  expect(values(added())).toEqual(['', 'tcp', '', '', ''])
  await type(added(), 0, 'nas-ssh')
  await controls(added())[1]?.setValue('udp')
  await type(added(), 2, '2222')
  await type(added(), 3, '192.168.1.10')
  await type(added(), 4, '22')
  const made = store().draft.value!.firewall!.portForwards[1]!
  expect([made.name, made.proto, made.port, made.to, made.toPort]).toEqual(['nas-ssh', 'udp', 2222, '192.168.1.10', 22])
  expect(store().changes.value).toEqual([{ subject: 'port forward nas-ssh', what: '', before: '', after: 'added: UDP 2222 to 192.168.1.10:22' }])
  // An empty To port is written 0: the same port.
  await type(added(), 4, '')
  expect(store().draft.value!.firewall!.portForwards[1]!.toPort).toBe(0)

  await added().find('button').trigger('click')
  expect(forwards(wrapper)).toHaveLength(1)
  expect(store().changes.value).toEqual([])
})

test('what is wrong is said when the field is left, not while it is typed', async () => {
  const { wrapper } = await page()
  await press(wrapper, 'Add forward')
  const row = () => forwards(wrapper)[1]!
  const said = () => row().findAll('[role="alert"]').map((alert) => alert.text())
  // A row that has just been added says nothing yet, though it has no name and no port.
  expect(said()).toEqual([])
  await controls(row())[0]?.setValue('lan-http')
  expect(said()).toEqual([])
  await controls(row())[0]?.trigger('blur')
  expect(said()).toEqual(['Another forward has this name.'])
  await type(row(), 2, '70000')
  expect(said()).toEqual(['Another forward has this name.', 'A port from 1 to 65535.'])
  await type(row(), 3, 'nas')
  expect(said()).toContain('An IPv4 address.')
  await type(row(), 0, 'nas-ssh')
  await type(row(), 2, '2222')
  await type(row(), 3, '192.168.1.10')
  expect(said()).toEqual([])
})

test('removing a row takes what was said of it with it', async () => {
  const { wrapper, router, store } = await page(withRule())
  await press(wrapper, 'Add forward')
  await type(forwards(wrapper)[1]!, 2, '70000')
  expect(forwards(wrapper)[1]!.find('[role="alert"]').exists()).toBe(true)
  refuse(router, 'firewall.port_forwards[1].to', 'a forward needs a target')
  expect(await store().review()).toBeNull()
  // The first row goes: the one that was second is now first, and nothing said of the second
  // place is said of whatever comes to stand there.
  await forwards(wrapper)[0]!.find('button').trigger('click')
  await press(wrapper, 'Add forward')
  expect(forwards(wrapper)).toHaveLength(2)
  expect(forwards(wrapper)[1]!.find('[role="alert"]').exists()).toBe(false)
  expect(store().violations.value).toEqual([])
})

test('what the router refuses is said at the cell it names', async () => {
  const { wrapper, router, store } = await page(withRule())
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'firewall.port_forwards[0].port', code: 'reserved', message: 'port 8080 is in use' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'firewall.rules[0].ports[1]', code: 'invalid', message: 'not a port' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'firewall.rules[0]', code: 'invalid', message: 'a rule into the LAN it starts from' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[1].reaches', code: 'unknown', message: 'no such LAN' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  const cell = (row: DOMWrapper<Element>, at: number) => row.findAll('td')[at]!
  expect(cell(forwards(wrapper)[0]!, 2).find('[role="alert"]').text()).toBe('port 8080 is in use')
  expect(cell(rules(wrapper)[0]!, 4).find('[role="alert"]').text()).toBe('not a port')
  // What no cell is for is listed above, by its path.
  expect(wrapper.find('.refused').findAll('li').map((item) => item.text())).toEqual(['firewall.rules[0]: a rule into the LAN it starts from'])
  // And what is said of a LAN's ticks is said under the grid, by the LAN's name.
  expect(wrapper.find('.reach__said [role="alert"]').text()).toBe('iot: no such LAN')
  // Changing the cell takes what was said of it away; the rest stays.
  await type(forwards(wrapper)[0]!, 2, '8081')
  expect(cell(forwards(wrapper)[0]!, 2).find('[role="alert"]').exists()).toBe(false)
  await tick(wrapper, 'iot may reach lan0').setValue(true)
  expect(wrapper.find('.reach__said [role="alert"]').exists()).toBe(false)
  expect(store().violations.value.map((violation) => violation.path)).toEqual(['firewall.rules[0].ports[1]', 'firewall.rules[0]'])
})

test('a rule’s From offers the internet and each LAN', async () => {
  const { wrapper, store } = await page(withRule())
  expect(heads(wrapper, 'rules')).toEqual(['Name', 'From', 'To', 'Protocol', 'Ports', ''])
  expect(rules(wrapper).map(values)).toEqual([['web6', 'wan', '2001:db8:1:1::10', 'tcp', '80, 443']])
  const from = controls(rules(wrapper)[0]!)[1]!
  expect(from.findAll('option').map((option) => [option.attributes('value'), option.text()])).toEqual([
    ['wan', 'Internet'],
    ['lan0', 'lan0'],
    ['iot', 'iot'],
  ])
  await from.setValue('iot')
  expect(store().draft.value!.firewall!.rules[0]!.from).toBe('iot')
  await press(wrapper, 'Add rule')
  expect(values(rules(wrapper)[1]!)).toEqual(['', 'wan', '', 'tcp', ''])
  await type(rules(wrapper)[1]!, 4, '1000-1010, 443')
  expect(store().draft.value!.firewall!.rules[1]!.ports).toEqual(['1000-1010', '443'])
  // What was typed stays as it was typed, comma and all, while it means the same list.
  await controls(rules(wrapper)[1]!)[4]?.setValue('1000-1010, 443, ')
  expect((controls(rules(wrapper)[1]!)[4]?.element as HTMLInputElement).value).toBe('1000-1010, 443, ')
  await rules(wrapper)[1]!.find('button').trigger('click')
  expect(rules(wrapper)).toHaveLength(1)
})

test('ports on a rule made ICMP are said to be wrong, not thrown away', async () => {
  const { wrapper, store } = await page(withRule())
  const row = () => rules(wrapper)[0]!
  await controls(row())[3]?.setValue('icmp')
  expect(store().draft.value!.firewall!.rules[0]!.ports).toEqual(['80', '443'])
  // A choice is made, not typed: what it makes wrong is said at once, at the field it is about.
  expect(row().findAll('td')[4]?.find('[role="alert"]').text()).toBe('Ports go with TCP and UDP only.')
  await type(row(), 4, '')
  expect(row().find('[role="alert"]').exists()).toBe(false)
  await type(row(), 4, '90-80')
  await controls(row())[3]?.setValue('tcp')
  expect(row().findAll('td')[4]?.find('[role="alert"]').text()).toBe('Ports are numbers from 1 to 65535, or ranges such as 1000-1010.')
})

test('with a public block a forward says which address it listens on', async () => {
  const config = routerConfig()
  config.publicIpv4 = create(ConfigSchema, { publicIpv4: [{ prefix: '198.51.100.0/29' }] }).publicIpv4
  const { wrapper, store } = await page(config)
  expect(heads(wrapper, 'fwd')).toEqual(['Name', 'Protocol', 'Port', 'To address', 'To port', 'Listens on', ''])
  await type(forwards(wrapper)[0]!, 5, '198.51.100.2')
  expect(store().draft.value!.firewall!.portForwards[0]!.address).toBe('198.51.100.2')
  expect(wrapper.text()).toContain('Listens on: an address of your public block; empty for the WAN’s own.')
  // Without one the column is not there, and neither is the line about it.
  unmountAll()
  const plain = await page()
  expect(heads(plain.wrapper, 'fwd')).not.toContain('Listens on')
  expect(plain.wrapper.text()).not.toContain('Listens on:')
  expect(plain.wrapper.text()).toContain('To port: leave empty for the same port.')
})

test('the toggle writes wan_ping', async () => {
  const { wrapper, store } = await page()
  const toggle = wrapper.findAll('.ofo-toggle').find((each) => each.text() === 'Answer ping from the internet')
  expect(toggle).toBeDefined()
  const input = toggle!.find('input')
  expect((input.element as HTMLInputElement).checked).toBe(false)
  await input.setValue(true)
  expect(store().draft.value!.firewall!.wanPing).toBe(true)
  expect(what(store().changes.value)).toEqual(['The router answers ping from the internet'])
  await input.setValue(false)
  expect(store().changes.value).toEqual([])
})

test('a router with no firewall settings gains them and loses them without a trace', async () => {
  const config = routerConfig()
  config.firewall = undefined
  const { wrapper, store } = await page(config)
  expect(forwards(wrapper)).toHaveLength(0)
  expect(wrapper.find('table.fwd').exists()).toBe(false)
  await press(wrapper, 'Add forward')
  expect(forwards(wrapper)).toHaveLength(1)
  await forwards(wrapper)[0]!.find('button').trigger('click')
  expect(store().draft.value!.firewall).toBeUndefined()
  expect(store().changes.value).toEqual([])
  await press(wrapper, 'Add rule')
  await rules(wrapper)[0]!.find('button').trigger('click')
  expect(store().changes.value).toEqual([])
})

test('a config the router refused is shown and cannot be changed', async () => {
  const { wrapper, router } = await page(withRule())
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toContain('The router refused its config file')
  const page_ = wrapper.find('.page')
  expect(page_.findAll('input, select').every((control) => (control.element as HTMLInputElement).disabled)).toBe(true)
  expect(page_.findAll('button').every((button) => (button.element as HTMLButtonElement).disabled)).toBe(true)
  expect(bar(wrapper).exists()).toBe(false)
})
