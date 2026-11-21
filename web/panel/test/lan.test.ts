// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The LAN & DHCP page (SPEC §8.4), in the shell at /lan, on a router with a LAN across three
// ports and a second LAN that is a VLAN of one of them.

import { create, ConfigSchema, type Config } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { event, NOW, routerConfig, state } from './fixtures'
import { fieldLabelled, panelAt, signedIn, unmountAll } from './mounting'

async function page(path = '/lan', config: Config = routerConfig(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt(path, router)
  router.push('state', state())
  await flushPromises()
  return made
}

type Within = { findAll: VueWrapper['findAll'] }
const tabs = (wrapper: VueWrapper) => wrapper.findAll('[role="tab"]')
const section = (wrapper: VueWrapper, title: string) => {
  const found = wrapper.findAll('.ofo-formsec').find((each) => each.find('.ofo-formsec__title').text() === title)
  if (found === undefined) {
    throw new Error(`no section ${title}`)
  }
  return found
}
const labels = (within: Within) => within.findAll('.ofo-field__label').map((label) => label.text())
const box = (within: Within, label: string) => fieldLabelled(within, label).find('input')
const valueOf = (within: Within, label: string) => (box(within, label).element as HTMLInputElement).value
const help = (within: Within, label: string) => fieldLabelled(within, label).find('.ofo-field__help').text()
/** Type into a field and leave it, as a person does. */
const type = async (within: Within, label: string, text: string) => {
  await box(within, label).setValue(text)
  await box(within, label).trigger('blur')
}
const rows = (wrapper: VueWrapper) => wrapper.findAll('table.res tbody tr')
const cells = (wrapper: VueWrapper) => rows(wrapper).map((row) => row.findAll('input').map((input) => (input.element as HTMLInputElement).value))
const what = (changes: { subject: string; what: string }[]) => changes.map((change) => `${change.subject} ${change.what}`)

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

test('a tab per LAN with its clients, and the address chooses which is shown', async () => {
  const { wrapper, routes, errors } = await page()
  expect(wrapper.find('h1').text()).toBe('LAN & DHCP')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('The networks behind the router, and the addresses it hands out.')
  expect(wrapper.find('.ofo-pagehead__actions button').text()).toBe('Add LAN')
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['lan0 11 clients', 'iot 3 clients'])
  expect(tabs(wrapper).map((tab) => tab.find('.ofo-tabs__count').text())).toEqual(['11 clients', '3 clients'])
  expect(tabs(wrapper)[0]?.attributes('aria-selected')).toBe('true')
  expect(wrapper.findAll('.ofo-formsec__title').map((title) => title.text())).toEqual(['Network', 'DHCP', 'Reservations', 'IPv6'])
  expect(wrapper.findAll('.ofo-formsec__text').map((text) => text.text())).toEqual([
    "The router's own address on this LAN, the size of the subnet, and the ports that belong to it.",
    'The addresses the router hands out on this LAN, and what it tells each device.',
    'Devices that always get the same address, and the name they are found by.',
    'Whether this LAN carries IPv6 and tells devices about it.',
  ])
  expect(valueOf(wrapper, 'Router address')).toBe('192.168.1.1')

  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(routes.currentRoute.value.path).toBe('/lan/iot')
  expect(valueOf(wrapper, 'Router address')).toBe('192.168.20.1')
  expect(errors).toEqual([])
  unmountAll()

  const direct = await page('/lan/iot')
  expect(tabs(direct.wrapper)[1]?.attributes('aria-selected')).toBe('true')
  unmountAll()
  const unknown = await page('/lan/nothing')
  expect(tabs(unknown.wrapper)[0]?.attributes('aria-selected')).toBe('true')
  // One client is one client, and a LAN the router is not yet running has none to count.
  unmountAll()
  const one = await page('/lan', routerConfig(), () => undefined)
  const single = state()
  single.lans[1]!.leases = 1
  single.lans.shift()
  one.router.push('state', single)
  await flushPromises()
  expect(tabs(one.wrapper).map((tab) => tab.text())).toEqual(['lan0', 'iot 1 client'])
})

test("changing the router's address carries the pool and the reservations, and each says what it was", async () => {
  const { wrapper, store } = await page()
  const network = () => section(wrapper, 'Network')
  const dhcp = () => section(wrapper, 'DHCP')
  expect(labels(network())).toEqual(['Router address', 'Subnet size', 'Ports'])
  expect(labels(dhcp())).toEqual(['Pool start', 'Pool end', 'Lease time', 'DNS servers handed out', 'NTP servers handed out'])
  expect(help(dhcp(), 'DNS servers handed out')).toBe('Leave empty for the router itself.')
  expect(box(dhcp(), 'NTP servers handed out').attributes('placeholder')).toBe('The router')

  // While it is being typed nothing moves; when the field is left, everything in the subnet does.
  await box(network(), 'Router address').setValue('192.168.2.1')
  expect(valueOf(dhcp(), 'Pool start')).toBe('192.168.1.100')
  expect(store().changes.value).toEqual([])
  await box(network(), 'Router address').trigger('blur')
  expect(store().draft.value!.lans[0]!.ipv4).toBe('192.168.2.1/24')
  expect(help(network(), 'Router address')).toBe('Was 192.168.1.1.')
  expect(help(network(), 'Subnet size')).toBe('192.168.2.1 to 192.168.2.254.')
  expect(valueOf(dhcp(), 'Pool start')).toBe('192.168.2.100')
  expect(help(dhcp(), 'Pool start')).toBe('Was 192.168.1.100. Moved with the subnet.')
  expect(valueOf(dhcp(), 'Pool end')).toBe('192.168.2.249')
  expect(help(dhcp(), 'Pool end')).toBe('Was 192.168.1.249. Moved with the subnet.')
  expect(cells(wrapper)).toEqual([
    ['nas', '52:54:00:fe:10:10', '192.168.2.10'],
    ['printer', '52:54:00:fe:10:11', '192.168.2.11'],
  ])
  expect(rows(wrapper)[0]?.findAll('.ofo-field__help').map((said) => said.text())).toEqual(['Was 192.168.1.10. Moved with the subnet.'])
  expect(what(store().changes.value)).toEqual(['lan0 address', 'lan0 pool', 'lan0 reservations', 'port forward lan-http target'])

  // An address then changed by hand says what it was, and no longer that it moved.
  await type(dhcp(), 'Pool start', '192.168.2.50')
  expect(help(dhcp(), 'Pool start')).toBe('Was 192.168.1.100.')
  // The address may be typed with its size.
  await type(network(), 'Router address', '192.168.4.1/23')
  expect(store().draft.value!.lans[0]!.ipv4).toBe('192.168.4.1/23')
  expect(valueOf(network(), 'Router address')).toBe('192.168.4.1')
  expect((fieldLabelled(network(), 'Subnet size').find('select').element as HTMLSelectElement).value).toBe('23')
  expect(help(network(), 'Subnet size')).toBe('192.168.4.1 to 192.168.5.254. Was /24.')

  // One that is not an address yet is said when the field is left, and moves nothing.
  await type(network(), 'Router address', '192.168.4')
  expect(fieldLabelled(network(), 'Router address').find('[role="alert"]').text()).toBe('Not an IPv4 address.')
  expect(store().draft.value!.lans[0]!.ipv4).toBe('192.168.4.1/23')
})

test('an address that is half typed outlives a read of the config', async () => {
  // A config event, or the socket opening again, makes the panel read the config. With no
  // changes in the draft, that used to count as another draft and wipe the field.
  const { wrapper, router, store } = await page()
  await box(wrapper, 'Router address').setValue('192.168.9')
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  expect(router.calls.config).toBe(2)
  expect(valueOf(wrapper, 'Router address')).toBe('192.168.9')
  expect(store().changes.value).toEqual([])
})

test('an address with no place in the new subnet is marked at its field', async () => {
  const config = routerConfig()
  config.dns = create(ConfigSchema, { dns: { records: [{ name: 'nas', address: '192.168.1.200' }] } }).dns
  const { wrapper, store } = await page('/lan', config)
  const size = () => fieldLabelled(section(wrapper, 'Network'), 'Subnet size').find('select')
  await size().setValue('25')
  await flushPromises()
  expect(store().draft.value!.lans[0]!.ipv4).toBe('192.168.1.1/25')
  // The pool's end has no place among 126 addresses, and says so where it is; its start still fits.
  const end = () => fieldLabelled(wrapper, 'Pool end')
  expect(end().classes()).toContain('ofo-field--error')
  expect(end().find('[role="alert"]').text()).toBe('Has no place in 192.168.1.0/25.')
  expect(valueOf(wrapper, 'Pool end')).toBe('192.168.1.249')
  expect(fieldLabelled(wrapper, 'Pool start').find('[role="alert"]').exists()).toBe(false)
  // The reservations still fit and say nothing.
  expect(rows(wrapper)[0]?.find('[role="alert"]').exists()).toBe(false)
  // What is on no page yet is listed above this one, by its path.
  const above = wrapper.find('.unfit')
  expect(above.findAll('li').map((item) => item.text())).toEqual(['dns.records[0].address: 192.168.1.200'])
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('problem')

  // Put right by hand, the field says nothing more, and the tab has nothing to point at.
  await type(wrapper, 'Pool end', '192.168.1.120')
  expect(end().find('[role="alert"]').exists()).toBe(false)
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
  expect(wrapper.find('.unfit').exists()).toBe(true)
  // Discarding takes all of it away.
  store().discard()
  await flushPromises()
  expect(wrapper.find('.unfit').exists()).toBe(false)
  expect(wrapper.find('[role="tabpanel"] [role="alert"]').exists()).toBe(false)
})

test('a pool that a move left the wrong way round says so at once', async () => {
  // Into the upper half of the subnet: the pool's start is carried up past its end, which
  // has a place where it is. No field of the pool was touched, and it is said all the same.
  const config = routerConfig()
  config.lans[0]!.dhcp!.range = ['192.168.1.100', '192.168.1.200']
  const { wrapper } = await page('/lan', config)
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
  await type(wrapper, 'Router address', '192.168.1.129/25')
  expect(valueOf(wrapper, 'Pool start')).toBe('192.168.1.228')
  expect(valueOf(wrapper, 'Pool end')).toBe('192.168.1.200')
  expect(fieldLabelled(wrapper, 'Pool start').find('[role="alert"]').text()).toBe('The pool starts after it ends.')
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('problem')

  // The same by the size alone.
  const high = routerConfig()
  high.lans[0]!.ipv4 = '192.168.1.250/24'
  high.lans[0]!.dhcp!.range = ['192.168.1.100', '192.168.1.200']
  unmountAll()
  const other = await page('/lan', high)
  await fieldLabelled(other.wrapper, 'Subnet size').find('select').setValue('25')
  expect(valueOf(other.wrapper, 'Pool start')).toBe('192.168.1.228')
  expect(fieldLabelled(other.wrapper, 'Pool start').find('[role="alert"]').text()).toBe('The pool starts after it ends.')
})

test('the subnet size says the range it gives', async () => {
  const { wrapper, store } = await page()
  const size = () => fieldLabelled(wrapper, 'Subnet size')
  expect((size().find('select').element as HTMLSelectElement).value).toBe('24')
  expect(size().findAll('option').map((option) => option.text()).slice(7, 10)).toEqual(['/23 · 510 addresses', '/24 · 254 addresses', '/25 · 126 addresses'])
  expect(size().find('.ofo-field__help').text()).toBe('192.168.1.1 to 192.168.1.254.')
  await size().find('select').setValue('23')
  await flushPromises()
  expect(store().draft.value!.lans[0]!.ipv4).toBe('192.168.1.1/23')
  expect(size().find('.ofo-field__help').text()).toBe('192.168.0.1 to 192.168.1.254. Was /24.')
  // Nothing had to move: the subnet grew around what was there.
  expect(what(store().changes.value)).toEqual(['lan0 address'])
})

test('a port is ticked into the LAN and out of it; a tagged member cannot be changed', async () => {
  const config = routerConfig()
  config.lans[0]!.ports = ['p1', 'p3']
  const { wrapper, store } = await page('/lan', config)
  const ports = () => section(wrapper, 'Network').findAll('.ofo-choice')
  expect(section(wrapper, 'Network').find('legend').text()).toBe('Ports')
  expect(ports().map((port) => port.text())).toEqual(['p1', 'p2free', 'p3'])
  expect(ports().map((port) => (port.find('input').element as HTMLInputElement).checked)).toEqual([true, false, true])
  await ports()[1]?.find('input').setValue(true)
  expect(store().draft.value!.lans[0]!.ports).toEqual(['p1', 'p3', 'p2'])
  expect(ports().map((port) => port.text())).toEqual(['p1', 'p2', 'p3'])
  await ports()[0]?.find('input').setValue(false)
  expect(store().draft.value!.lans[0]!.ports).toEqual(['p3', 'p2'])
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'ports', before: 'p1, p3', after: 'p3, p2' }])
  expect(ports().map((port) => port.text())).toEqual(['p1free', 'p2', 'p3'])

  // The VLAN's own member is listed, ticked, and not to be changed here; the port lan0 let go is on offer.
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(ports().map((port) => port.text())).toEqual(['p1free', 'p3.20tagged: set in the config file'])
  const tagged = ports()[1]?.find('input').element as HTMLInputElement
  expect(tagged.checked).toBe(true)
  expect(tagged.disabled).toBe(true)
})

test('with the DHCP server off its fields and the reservations are gone, and on again they are back', async () => {
  const { wrapper, store } = await page()
  const toggle = () => section(wrapper, 'DHCP').find('.ofo-toggle input')
  expect(section(wrapper, 'DHCP').find('.ofo-toggle').text()).toBe('DHCP server')
  await type(wrapper, 'Pool end', '192.168.1.220')
  await toggle().setValue(false)
  expect(labels(section(wrapper, 'DHCP'))).toEqual([])
  expect(wrapper.findAll('.ofo-formsec__title').map((title) => title.text())).toEqual(['Network', 'DHCP', 'IPv6'])
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'DHCP server', before: 'on', after: 'off; its pool and 2 reservations go' }])
  await toggle().setValue(true)
  expect(valueOf(wrapper, 'Pool end')).toBe('192.168.1.220')
  expect(rows(wrapper)).toHaveLength(2)
  expect(what(store().changes.value)).toEqual(['lan0 pool'])
})

test('a reservation is added, edited and removed in place', async () => {
  const { wrapper, store } = await page()
  const reservations = () => section(wrapper, 'Reservations')
  expect(reservations().findAll('th').map((head) => head.text())).toEqual(['Name', 'MAC address', 'Address', ''])
  expect(cells(wrapper)).toEqual([
    ['nas', '52:54:00:fe:10:10', '192.168.1.10'],
    ['printer', '52:54:00:fe:10:11', '192.168.1.11'],
  ])
  expect(rows(wrapper)[0]?.findAll('input').map((input) => input.classes().includes('ofo-input--sm'))).toEqual([true, true, true])

  // Added: a row to fill in.
  const add = reservations().findAll('button').find((button) => button.text() === 'Add reservation')
  await add?.trigger('click')
  expect(rows(wrapper)).toHaveLength(3)
  const fresh = () => rows(wrapper)[2]!.findAll('input')
  expect(fresh().map((input) => input.attributes('placeholder'))).toEqual(['Optional', '02:00:00:00:00:00', '192.168.1.'])
  await fresh()[0]?.setValue('camera')
  await fresh()[1]?.setValue('02:00:00:aa:01:30')
  await fresh()[2]?.setValue('192.168.1.30')
  // Edited: the first one's address.
  await rows(wrapper)[0]?.findAll('input')[2]?.setValue('192.168.1.12')
  expect(rows(wrapper)[0]?.find('.ofo-field__help').text()).toBe('Was 192.168.1.10.')
  // Removed: the second.
  await rows(wrapper)[1]?.findAll('button').find((button) => button.text() === 'Remove')?.trigger('click')
  expect(cells(wrapper)).toEqual([
    ['nas', '52:54:00:fe:10:10', '192.168.1.12'],
    ['camera', '02:00:00:aa:01:30', '192.168.1.30'],
  ])
  // All three are one change.
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 added, 1 removed, 1 changed' }])
  expect(store().draft.value!.lans[0]!.dhcp!.static.map((lease) => lease.hostname)).toEqual(['nas', 'camera'])
})

test('removing a reservation takes with it what was said of the rows whose places change', async () => {
  // What the router refused is kept by the row's number. With a row gone, the rows after it
  // each have another number, and what was said of row 2 must not be said of what was row 3.
  const config = routerConfig()
  config.lans[0]!.dhcp!.static.push(
    ...create(ConfigSchema, {
      lans: [
        {
          dhcp: {
            static: [
              { mac: '52:54:00:fe:10:12', ip: '192.168.1.12', hostname: 'tv' },
              { mac: '52:54:00:fe:10:13', ip: '192.168.1.13', hostname: 'desk' },
            ],
          },
        },
      ],
    }).lans[0]!.dhcp!.static,
  )
  const { wrapper, router, store } = await page('/lan', config)
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[0].ip', code: 'pool', message: 'inside the pool' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[2].ip', code: 'twice', message: 'reserved twice' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  const said = () => rows(wrapper).map((row) => row.find('[role="alert"]').exists() && row.find('[role="alert"]').text())
  expect(said()).toEqual(['inside the pool', false, 'reserved twice', false])

  await rows(wrapper)[1]?.findAll('button').find((button) => button.text() === 'Remove')?.trigger('click')
  // The row before the one that went keeps what was said of it; no row after it says anything.
  expect(cells(wrapper).map((row) => row[0])).toEqual(['nas', 'tv', 'desk'])
  expect(said()).toEqual(['inside the pool', false, false])
  expect(store().violations.value.map((violation) => violation.path)).toEqual(['lans[0].dhcp.static[0].ip'])

  await rows(wrapper)[0]?.findAll('button').find((button) => button.text() === 'Remove')?.trigger('click')
  expect(said()).toEqual([false, false])
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
})

test('a reservation by client identifier is shown, kept, and can only be removed', async () => {
  // The router wants a MAC on every reservation and matches by the identifier when there is
  // one: such a reservation has both.
  const config = routerConfig()
  const lease = config.lans[0]!.dhcp!.static[1]!
  lease.clientId = '01020000aa0122'
  const { wrapper, store } = await page('/lan', config)
  const row = () => rows(wrapper)[1]!
  // Its identifier stands where the MAC would be, as a machine wrote it, with the MAC said
  // beneath; nothing in the row is a field to change.
  expect(row().find('code.ofo-mono').text()).toBe('01020000aa0122')
  expect(row().findAll('td')[1]?.find('.ofo-field__help').text()).toBe('Matched by this client identifier. Its MAC address is 52:54:00:fe:10:11.')
  // The reservation beside it, matched by its MAC, is an ordinary row.
  expect(rows(wrapper)[0]!.find('code').exists()).toBe(false)
  expect(rows(wrapper)[0]!.findAll('input')).toHaveLength(3)
  expect(row().findAll('input').map((input) => (input.element as HTMLInputElement).disabled)).toEqual([true, true])
  expect(row().findAll('input').map((input) => (input.element as HTMLInputElement).value)).toEqual(['printer', '192.168.1.11'])
  // Other edits leave it as it is.
  await rows(wrapper)[0]?.findAll('input')[0]?.setValue('store')
  expect(store().draft.value!.lans[0]!.dhcp!.static[1]).toEqual(config.lans[0]!.dhcp!.static[1])
  // A renumbering still carries it.
  await type(wrapper, 'Router address', '192.168.2.1')
  expect(store().draft.value!.lans[0]!.dhcp!.static[1]!.ip).toBe('192.168.2.11')
  expect(store().draft.value!.lans[0]!.dhcp!.static[1]!.clientId).toBe('01020000aa0122')
  await row().findAll('button').find((button) => button.text() === 'Remove')?.trigger('click')
  expect(rows(wrapper)).toHaveLength(1)
})

test('a MAC address is checked when its field is left', async () => {
  const { wrapper, router, store } = await page()
  const mac = () => rows(wrapper)[0]!.findAll('td')[1]!
  await mac().find('input').setValue('52:54:00:fe:10')
  expect(mac().classes()).not.toContain('ofo-field--error')
  await mac().find('input').trigger('blur')
  expect(mac().classes()).toContain('ofo-field--error')
  expect(mac().find('[role="alert"]').text()).toBe('A MAC address is six pairs of hex digits, such as 02:00:00:aa:01:10.')
  expect(tabs(wrapper)[0]?.find('.ofo-pill').text()).toBe('problem')
  await mac().find('input').setValue('52-54-00-FE-10-10')
  expect(mac().classes()).not.toContain('ofo-field--error')

  // An address outside the subnet is said the same way, and so is what the router says of a row.
  const address = () => rows(wrapper)[0]!.findAll('td')[2]!
  await address().find('input').setValue('192.168.9.10')
  await address().find('input').trigger('blur')
  expect(address().find('[role="alert"]').text()).toBe('Not in 192.168.1.0/24.')
  await address().find('input').setValue('192.168.1.10')
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[1].ip', code: 'twice', message: 'reserved twice' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[0]', code: 'match', message: 'a reservation matches by MAC or by client identifier' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.range', code: 'router', message: 'the router is inside the pool' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].ports[1]', code: 'port', message: 'no such port' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].port', code: 'port', message: 'in use by lan0' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  expect(rows(wrapper)[1]!.findAll('td')[2]!.find('[role="alert"]').text()).toBe('reserved twice')
  expect(rows(wrapper)[0]!.findAll('td')[0]!.find('[role="alert"]').text()).toBe('a reservation matches by MAC or by client identifier')
  expect(fieldLabelled(wrapper, 'Pool start').find('[role="alert"]').text()).toBe('the router is inside the pool')
  // What has no field is at the top of the tab, and what is another page's above the page.
  expect(wrapper.find('[role="tabpanel"] .refused').findAll('li').map((item) => item.text())).toEqual(['lans[0].ports[1]: no such port'])
  const above = wrapper.findAll('.refused').find((list) => !list.element.closest('[role="tabpanel"]'))
  expect(above?.findAll('li').map((item) => item.text())).toEqual(['wans[0].port: in use by lan0'])
})

test('what the router refuses on a LAN that is not shown is said above the page', async () => {
  // A clash between two LANs is reported at the later one, which is often not the tab that
  // is open: pressing Apply changes must not look like nothing happened.
  const { wrapper, router, store } = await page()
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[1].ipv4', code: 'overlap', message: 'overlaps lan0 (192.168.1.1/24)' }],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  const above = () => wrapper.findAll('.refused').find((list) => !list.element.closest('[role="tabpanel"]'))
  expect(above()?.findAll('li').map((item) => item.text())).toEqual(['lans[1].ipv4: overlaps lan0 (192.168.1.1/24)'])
  expect(tabs(wrapper)[1]?.find('.ofo-pill').text()).toBe('problem')
  // On its own tab it is at its field, and no longer above the page.
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(fieldLabelled(wrapper, 'Router address').find('[role="alert"]').text()).toBe('overlaps lan0 (192.168.1.1/24)')
  expect(above()).toBeUndefined()
})

test('Other… takes the lease time in seconds', async () => {
  const { wrapper, store } = await page()
  const lease = () => fieldLabelled(wrapper, 'Lease time').find('select')
  // The router's config names none: twelve hours.
  expect((lease().element as HTMLSelectElement).value).toBe('43200')
  expect(fieldLabelled(wrapper, 'Lease time').findAll('option').map((option) => option.text())).toEqual(['1 hour', '12 hours', '1 day', '1 week', 'Other…'])
  expect(labels(section(wrapper, 'DHCP'))).not.toContain('Seconds')
  await lease().setValue('3600')
  await flushPromises()
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'lease time', before: '12 hours', after: '1 hour' }])
  expect(fieldLabelled(wrapper, 'Lease time').find('.ofo-field__help').text()).toBe('Was 12 hours.')
  // Twelve hours again is the router's own "none named": no change at all.
  await lease().setValue('43200')
  await flushPromises()
  expect(store().changes.value).toEqual([])

  await lease().setValue('other')
  await flushPromises()
  expect(labels(section(wrapper, 'DHCP'))).toContain('Seconds')
  expect(valueOf(wrapper, 'Seconds')).toBe('43200')
  await type(wrapper, 'Seconds', '7200')
  expect(store().draft.value!.lans[0]!.dhcp!.leaseSecs).toBe(7200)
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'lease time', before: '12 hours', after: '2 hours' }])
  await type(wrapper, 'Seconds', '30')
  expect(fieldLabelled(wrapper, 'Seconds').find('[role="alert"]').text()).toBe('At least 60 seconds.')
  // A time that is none of the four shows as Other from the start.
  unmountAll()
  const odd = routerConfig()
  odd.lans[0]!.dhcp!.leaseSecs = 900
  const other = await page('/lan', odd)
  expect((fieldLabelled(other.wrapper, 'Lease time').find('select').element as HTMLSelectElement).value).toBe('other')
  expect(valueOf(other.wrapper, 'Seconds')).toBe('900')
})

test('a LAN that a forward points into cannot be removed, and the page says what is in the way', async () => {
  const { wrapper, store } = await page()
  const remove = () => wrapper.findAll('button').find((button) => button.text().startsWith('Remove lan0') || button.text().startsWith('Remove iot'))
  expect(remove()?.text()).toBe('Remove lan0')
  expect((remove()?.element as HTMLButtonElement).disabled).toBe(true)
  expect(wrapper.find('.page__foot').text()).toContain('Cannot be removed yet: port forward lan-http points into it.')
  await remove()?.trigger('click')
  expect(store().draft.value!.lans).toHaveLength(2)

  // The other LAN has nothing pointing at it.
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(remove()?.text()).toBe('Remove iot')
  expect((remove()?.element as HTMLButtonElement).disabled).toBe(false)
  expect(wrapper.find('.page__foot').text()).not.toContain('Cannot be removed')
})

test('Add LAN asks for a name and adds an empty LAN; Remove takes one away', async () => {
  const config = routerConfig()
  config.lans[0]!.ports = ['p1', 'p3']
  const { wrapper, routes, store, errors } = await page('/lan', config)
  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  const dialog = () => wrapper.find('.ofo-dialog')
  expect(dialog().find('.ofo-dialog__title').text()).toBe('Add a LAN')
  // Twelve characters are a LAN's limit, and a WAN's name is taken too.
  await dialog().find('input').setValue('lan-too-long1')
  await dialog().findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  expect(dialog().find('[role="alert"]').text()).toBe('1 to 12 characters: a to z, 0 to 9, - and _, starting with a letter or a digit.')
  await dialog().find('input').setValue('wan0')
  await dialog().findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  expect(dialog().find('[role="alert"]').text()).toBe('wan0 is already in use.')
  await dialog().find('input').setValue('guest')
  await dialog().findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  await flushPromises()
  expect(dialog().exists()).toBe(false)
  expect(routes.currentRoute.value.path).toBe('/lan/guest')
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['lan0 11 clients', 'iot 3 clients', 'guest'])
  // It starts with nothing: no address, no ports, no DHCP server.
  expect(valueOf(wrapper, 'Router address')).toBe('')
  expect((section(wrapper, 'DHCP').find('.ofo-toggle input').element as HTMLInputElement).checked).toBe(false)
  expect(store().changes.value).toEqual([{ subject: 'guest', what: 'LAN', before: '', after: 'added: no address on no ports' }])

  // Given an address, a size and the one free port, and a DHCP server with the pool proposed for it.
  await fieldLabelled(wrapper, 'Subnet size').find('select').setValue('24')
  await type(wrapper, 'Router address', '192.168.3.1')
  expect(store().draft.value!.lans[2]!.ipv4).toBe('192.168.3.1/24')
  const ports = section(wrapper, 'Network').findAll('.ofo-choice')
  expect(ports.map((port) => port.text())).toEqual(['p2free'])
  await ports[0]?.find('input').setValue(true)
  await section(wrapper, 'DHCP').find('.ofo-toggle input').setValue(true)
  expect(valueOf(wrapper, 'Pool start')).toBe('192.168.3.100')
  expect(valueOf(wrapper, 'Pool end')).toBe('192.168.3.200')
  expect(store().changes.value).toEqual([{ subject: 'guest', what: 'LAN', before: '', after: 'added: 192.168.3.1/24 on p2' }])
  // A LAN that is only a draft has nothing that it "was".
  expect(fieldLabelled(wrapper, 'Router address').find('.ofo-field__help').exists()).toBe(false)

  const remove = wrapper.findAll('button').find((button) => button.text() === 'Remove guest')
  await remove?.trigger('click')
  await flushPromises()
  expect(tabs(wrapper)).toHaveLength(2)
  expect(routes.currentRoute.value.path).toBe('/lan/lan0')
  expect(store().changes.value).toEqual([])
  expect(errors).toEqual([])
})

test('removing a LAN takes with it what was said of the LANs whose places change', async () => {
  // No forward points into lan0 here, so it can go; iot is then the first LAN.
  const config = routerConfig()
  config.firewall!.portForwards = []
  const { wrapper, router, store } = await page('/lan/iot', config)
  // Half an address typed on iot and left there, and a refusal at iot's pool.
  await type(wrapper, 'Router address', '192.168.20')
  expect(fieldLabelled(wrapper, 'Router address').find('[role="alert"]').text()).toBe('Not an IPv4 address.')
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[1].dhcp.range', code: 'pool', message: 'the pool is not in the subnet' }],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()

  await tabs(wrapper)[0]?.trigger('click')
  await flushPromises()
  await wrapper.findAll('button').find((button) => button.text() === 'Remove lan0')?.trigger('click')
  await flushPromises()
  expect(tabs(wrapper).map((tab) => tab.text())).toEqual(['iot 3 clients'])
  // Nothing is said of a LAN 1 that is no longer there, above the page or on a tab.
  expect(wrapper.find('.refused').exists()).toBe(false)
  expect(store().violations.value).toEqual([])
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
  expect(valueOf(wrapper, 'Router address')).toBe('192.168.20.1')

  // And a LAN added now, which is LAN 1, does not start with what was typed for another.
  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  await wrapper.find('.ofo-dialog input').setValue('guest')
  await wrapper.findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  await flushPromises()
  expect(valueOf(wrapper, 'Router address')).toBe('')
  expect(fieldLabelled(wrapper, 'Router address').find('[role="alert"]').exists()).toBe(false)
  expect(tabs(wrapper)[1]?.find('.ofo-pill').exists()).toBe(false)
})

test('what was typed for a LAN that was removed does not come back under its name', async () => {
  // The DHCP server of a LAN whose server was switched off is kept under the LAN's name,
  // as it was typed. It goes when the LAN does: a LAN added under that name has, when its
  // server is switched on, what the router has for a LAN of that name and nothing typed.
  const { wrapper, store } = await page('/lan/iot')
  await type(wrapper, 'Pool end', '192.168.20.140')
  await section(wrapper, 'DHCP').find('.ofo-toggle input').setValue(false)
  await wrapper.findAll('button').find((button) => button.text() === 'Remove iot')?.trigger('click')
  await flushPromises()

  await wrapper.find('.ofo-pagehead__actions button').trigger('click')
  await wrapper.find('.ofo-dialog input').setValue('iot')
  await wrapper.findAll('.ofo-dialog__foot button')[1]?.trigger('click')
  await flushPromises()
  await type(wrapper, 'Router address', '192.168.20.1')
  await section(wrapper, 'DHCP').find('.ofo-toggle input').setValue(true)
  expect(store().draft.value!.lans[1]!.dhcp!.range).toEqual(['192.168.20.100', '192.168.20.149'])
})

test('unticking a port takes with it what was said of the ports', async () => {
  // A refusal at a port is kept by the port's place in the list, and the list has changed.
  const { wrapper, router, store } = await page()
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].ports[1]', code: 'port', message: 'no such port' }],
    effects: [],
    caller: undefined,
  }
  expect(await store().review()).toBeNull()
  await flushPromises()
  expect(wrapper.find('[role="tabpanel"] .refused').findAll('li').map((item) => item.text())).toEqual(['lans[0].ports[1]: no such port'])
  await section(wrapper, 'Network').findAll('.ofo-choice')[0]?.find('input').setValue(false)
  expect(wrapper.find('[role="tabpanel"] .refused').exists()).toBe(false)
  expect(tabs(wrapper)[0]?.find('.ofo-pill').exists()).toBe(false)
})

test('what the LAN may reach is a line, not a field', async () => {
  const config = routerConfig()
  config.lans[0]!.reaches = []
  config.lans[1]!.reaches = ['wan', 'lan0']
  const { wrapper } = await page('/lan', config)
  const line = () => section(wrapper, 'Network').find('.reach')
  expect(line().text()).toBe('May reach: wan. Changed on the Firewall page.')
  expect(line().find('input').exists()).toBe(false)
  await tabs(wrapper)[1]?.trigger('click')
  await flushPromises()
  expect(line().text()).toBe('May reach: wan, lan0. Changed on the Firewall page.')
})

test('IPv6 and its advertisements are switches, and the rest is under Advanced', async () => {
  const { wrapper, store } = await page()
  const v6 = () => section(wrapper, 'IPv6')
  const toggles = () => v6().findAll('.ofo-toggle')
  expect(toggles().map((toggle) => toggle.text())).toEqual(['IPv6', 'Router advertisements'])
  expect(toggles().map((toggle) => (toggle.find('input').element as HTMLInputElement).checked)).toEqual([true, true])
  expect(labels(v6())).toEqual(['Routed /64', 'Subnet number'])
  expect(help(v6(), 'Routed /64')).toBe("This LAN's own /64 inside the WAN's routed prefix.")
  expect(help(v6(), 'Subnet number')).toBe("This LAN's place in a prefix the ISP delegates.")
  // The number a LAN has when none is typed is its position: lan0 is the first.
  expect(box(v6(), 'Subnet number').attributes('placeholder')).toBe('1')
  expect((v6().find('details').element as HTMLDetailsElement).open).toBe(false)

  await toggles()[1]?.find('input').setValue(false)
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'router advertisements', before: 'on', after: 'off' }])
  await toggles()[1]?.find('input').setValue(true)
  expect(store().changes.value).toEqual([])
  await type(v6(), 'Subnet number', '7')
  expect(store().draft.value!.lans[0]!.ipv6Index).toBe(7)

  // Off writes "none" and takes the rest with it; on again is what the router has.
  await toggles()[0]?.find('input').setValue(false)
  expect(store().draft.value!.lans[0]!.ipv6).toBe('none')
  expect(labels(v6())).toEqual([])
  expect(toggles().map((toggle) => toggle.text())).toEqual(['IPv6'])
  expect(store().changes.value).toEqual([{ subject: 'lan0', what: 'IPv6', before: 'on', after: 'off' }])
  await toggles()[0]?.find('input').setValue(true)
  expect(store().changes.value).toEqual([])
})

test('nothing can be changed on a router running on defaults, and the page says why', async () => {
  const { wrapper, router, store } = await page()
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid (1 error)', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toBe('The router refused its config file and runs on defaults. Mend or remove the file to change settings here.')
  const controls = wrapper.findAll('[role="tabpanel"] input, [role="tabpanel"] select')
  expect(controls.length).toBeGreaterThan(15)
  expect(controls.every((control) => (control.element as HTMLInputElement).disabled)).toBe(true)
  const buttons = wrapper.findAll('.page button').filter((button) => button.attributes('role') !== 'tab')
  expect(buttons.map((button) => button.text())).toEqual(['Add LAN', 'Remove', 'Remove', 'Add reservation', 'Remove lan0'])
  expect(buttons.every((button) => (button.element as HTMLButtonElement).disabled)).toBe(true)
  // The reason is the one thing said at the foot: not what is in the way of a removal nobody can make.
  expect(wrapper.find('.page__foot').text()).toBe('Remove lan0')
  expect(store().changes.value).toEqual([])
})
