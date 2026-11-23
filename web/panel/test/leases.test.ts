// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The Leases page (SPEC §8.4), in the shell at /leases, on a router with two LANs that each
// hand out addresses.

import { create, LeasesSchema, type Config, type Leases } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import type { FakeRouter } from './fake-router'
import { NOW, routerConfig, state } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

const NOW_UNIX = Math.floor(NOW.getTime() / 1000)

type Row = [address: string, hostname: string, joinedSecsAgo: number, more?: { lan?: string; mac?: string }]

/** The lease table at NOW by the router's clock. */
function leases(rows: Row[], truncated = false): Leases {
  return create(LeasesSchema, {
    timeUnix: BigInt(NOW_UNIX),
    truncated,
    leases: rows.map(([address, hostname, ago, more]) => ({
      lan: more?.lan ?? 'lan0',
      address,
      mac: more?.mac ?? `02:00:00:00:00:${address.split('.').at(-1)?.padStart(2, '0').slice(-2) ?? '00'}`,
      hostname,
      joinedUnix: BigInt(NOW_UNIX - ago),
      expiresUnix: BigInt(NOW_UNIX - ago + 43_200),
    })),
  })
}

const TABLE: Row[] = [
  ['192.168.1.131', 'laptop', 2 * 86_400 + 60],
  ['192.168.1.143', 'plug-kitchen', 125, { mac: '02:00:00:3a:11:9e' }],
  ['192.168.20.107', '', 41 * 60, { lan: 'iot' }],
  ['192.168.1.142', 'phone', 5 * 3_600 + 9],
  ['192.168.20.101', 'camera-porch', 3 * 86_400, { lan: 'iot' }],
  // The router's own reservation, taken up.
  ['192.168.1.10', 'nas', 9 * 86_400, { mac: '52:54:00:FE:10:10' }],
]

async function page(table: Leases | null = leases(TABLE), config: Config = routerConfig(), prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  prepare(router)
  const made = await panelAt('/leases', router)
  router.push('state', state())
  if (table !== null) {
    router.push('leases', table)
  }
  await flushPromises()
  return made
}

const rows = (wrapper: VueWrapper) => wrapper.findAll('.leases__table tbody tr')
const cells = (wrapper: VueWrapper) => rows(wrapper).map((row) => row.findAll('td').map((cell) => cell.text()))
const addresses = (wrapper: VueWrapper) => rows(wrapper).map((row) => row.findAll('td')[1]?.text())
const rowOf = (wrapper: VueWrapper, address: string) => {
  const found = rows(wrapper).find((row) => row.findAll('td')[1]?.text() === address)
  if (found === undefined) {
    throw new Error(`no row for ${address}`)
  }
  return found
}
const filter = (wrapper: VueWrapper) => wrapper.find('.leases__filter')

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

test('every LAN’s leases in one table, newest first, with what can be done', async () => {
  const { wrapper, errors } = await page()
  expect(wrapper.find('h1').text()).toBe('Leases')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('Devices that took an address from the router, newest first.')
  expect(wrapper.findAll('.leases__table thead th').map((th) => th.text())).toEqual(['Joined', 'Address', 'Name', 'MAC', 'LAN', 'Expires', ''])
  expect(cells(wrapper)).toEqual([
    ['2 min ago', '192.168.1.143', 'plug-kitchen', '02:00:00:3a:11:9e', 'lan0', 'in 11 h 57 min', 'Reserve'],
    ['41 min ago', '192.168.20.107', 'none given', '02:00:00:00:00:07', 'iot', 'in 11 h 19 min', 'Reserve'],
    ['5 h ago', '192.168.1.142', 'phone', '02:00:00:00:00:42', 'lan0', 'in 6 h 59 min', 'Reserve'],
    ['2 d ago', '192.168.1.131', 'laptop', '02:00:00:00:00:31', 'lan0', 'expired', 'Reserve'],
    ['3 d ago', '192.168.20.101', 'camera-porch', '02:00:00:00:00:01', 'iot', 'expired', 'Reserve'],
    ['9 d ago', '192.168.1.10', 'nas', '52:54:00:FE:10:10', 'lan0', 'expired', 'Reserved'],
  ])
  const first = rows(wrapper)[0]?.findAll('td') ?? []
  // The exact times are the cells' titles, in the browser's zone.
  expect(first[0]?.find('span').attributes('title')).toBe('19:40:25')
  expect(first[5]?.find('span').attributes('title')).toBe('11 Nov 07:40')
  // Machine values are in mono, the MAC more quietly, and a name not given is the page's word.
  expect(first[1]?.classes()).toContain('ofo-mono')
  expect(first[3]?.classes()).toContain('ofo-mono')
  expect(first[3]?.find('.ofo-muted').exists()).toBe(true)
  expect(rows(wrapper)[1]?.findAll('td')[2]?.find('.ofo-muted').text()).toBe('none given')
  expect(first[6]?.classes()).toContain('ofo-num')
  expect(first[6]?.find('button').classes()).toEqual(['ofo-btn', 'ofo-btn--ghost', 'ofo-btn--sm'])
  // What the page is, said under it; the router's own domain is the example.
  expect(wrapper.find('.leases__help').text()).toBe(
    'A new row appears by itself when a device joins. A device with a name is also found as name.home.arpa. Reserve keeps this address for the device: it joins your other changes, to apply when you are ready. IPv6 devices choose their own addresses, so they are not listed.',
  )
  expect(wrapper.find('.leases__cut').exists()).toBe(false)
  expect(errors).toEqual([])
})

test('the filter narrows the rows as it is typed, by name, address or MAC', async () => {
  const { wrapper } = await page()
  expect(filter(wrapper).attributes('placeholder')).toBe('Filter by name, address or MAC')
  await filter(wrapper).setValue('KITCHEN')
  expect(addresses(wrapper)).toEqual(['192.168.1.143'])
  await filter(wrapper).setValue('168.20.')
  expect(addresses(wrapper)).toEqual(['192.168.20.107', '192.168.20.101'])
  await filter(wrapper).setValue('fe:10')
  expect(addresses(wrapper)).toEqual(['192.168.1.10'])
  await filter(wrapper).setValue('')
  expect(addresses(wrapper)).toHaveLength(6)
})

test('a filter that finds nothing says what it looked for, in the table', async () => {
  const { wrapper } = await page()
  await filter(wrapper).setValue(' zzz ')
  expect(rows(wrapper)).toHaveLength(1)
  const only = rows(wrapper)[0]
  expect(only?.findAll('td')).toHaveLength(1)
  expect(only?.find('td').attributes('colspan')).toBe('7')
  expect(only?.text()).toBe('No leases match zzz')
  expect(only?.find('code').text()).toBe('zzz')
  // It is not the empty state: that is for a router no device has asked yet.
  expect(wrapper.find('.ofo-empty').exists()).toBe(false)
})

test('a choice of LAN, with each one’s count, where more than one hands out addresses', async () => {
  const { wrapper, router } = await page()
  const choice = wrapper.find('.leases__tools .ofo-seg')
  expect(choice.attributes('aria-label')).toBe('LAN')
  expect(choice.findAll('button').map((button) => button.text())).toEqual(['All LANs', 'lan04', 'iot2'])
  expect(choice.findAll('button').map((button) => button.find('.ofo-tabs__count').exists())).toEqual([false, true, true])
  await choice.findAll('button')[2]?.trigger('click')
  expect(addresses(wrapper)).toEqual(['192.168.20.107', '192.168.20.101'])
  expect(wrapper.findAll('.leases__tools .ofo-seg button').map((button) => button.attributes('aria-pressed'))).toEqual(['false', 'false', 'true'])
  // The filter works within the LAN chosen, and says so when it finds nothing there.
  await filter(wrapper).setValue('kitchen')
  expect(rows(wrapper)[0]?.text()).toBe('No leases match kitchen on iot')
  await filter(wrapper).setValue('')
  // A LAN whose server is switched off is no longer a choice: the page shows them all again.
  const one = state()
  const iot = one.lans[1]
  if (iot !== undefined) {
    iot.dhcp = false
  }
  router.push('state', one)
  await flushPromises()
  expect(wrapper.find('.leases__tools .ofo-seg').exists()).toBe(false)
  expect(addresses(wrapper)).toHaveLength(6)
})

test('ages follow the router’s clock as it is carried on', async () => {
  const { wrapper } = await page()
  expect(rowOf(wrapper, '192.168.1.143').find('td').text()).toBe('2 min ago')
  await vi.advanceTimersByTimeAsync(60_000)
  expect(rowOf(wrapper, '192.168.1.143').find('td').text()).toBe('3 min ago')
  expect(rowOf(wrapper, '192.168.1.143').findAll('td')[5]?.text()).toBe('in 11 h 56 min')
})

test('Reserve puts a reservation among the changes, and the row says so', async () => {
  const { wrapper, store } = await page()
  expect(wrapper.find('.ofo-savebar').exists()).toBe(false)
  await rowOf(wrapper, '192.168.1.143').find('button').trigger('click')
  const added = store().draft.value?.lans[0]?.dhcp?.static.at(-1)
  expect([added?.mac, added?.ip, added?.hostname]).toEqual(['02:00:00:3a:11:9e', '192.168.1.143', 'plug-kitchen'])
  expect(store().draft.value?.lans[0]?.dhcp?.static).toHaveLength(3)
  const done = rowOf(wrapper, '192.168.1.143').findAll('td')[6]
  expect(done?.find('button').exists()).toBe(false)
  expect(done?.find('.ofo-pill--info').text()).toBe('Reserved, not applied yet')
  // The bar beneath the page counts it, and the dialog will list it, like any other change.
  expect(wrapper.find('.ofo-savebar').text()).toContain('1 change not applied yet')
  expect(store().changes.value.map((change) => `${change.subject} ${change.what}`)).toEqual(['lan0 reservations'])
  // A device with no name is reserved with none; one on another LAN, in that LAN.
  await rowOf(wrapper, '192.168.20.107').find('button').trigger('click')
  const iot = store().draft.value?.lans[1]?.dhcp?.static
  expect(iot?.map((each) => [each.mac, each.ip, each.hostname])).toEqual([['02:00:00:00:00:07', '192.168.20.107', '']])
  // Discarded, the offer is back.
  store().discard()
  await flushPromises()
  expect(rowOf(wrapper, '192.168.1.143').find('button').text()).toBe('Reserve')
})

test('what the router refuses is said on the page, so that Apply changes never looks dead', async () => {
  // The draft is the whole config: what the router finds wrong with it may be this page's
  // doing or another's, and either way a person who pressed Apply here is told here.
  const { wrapper, router } = await page()
  await rowOf(wrapper, '192.168.1.143').find('button').trigger('click')
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[2].hostname', code: 'duplicate_hostname', message: 'another reservation has this name' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0].port', code: 'port', message: 'no such port' },
    ],
    effects: [],
    caller: undefined,
  }
  expect(wrapper.find('.refused').exists()).toBe(false)
  await wrapper.find('.ofo-savebar').findAll('button').find((button) => button.text() === 'Apply changes')?.trigger('click')
  await flushPromises()
  expect(wrapper.find('[role="alertdialog"]').exists()).toBe(false)
  expect(wrapper.find('.refused').findAll('li').map((item) => item.text())).toEqual([
    'lans[0].dhcp.static[2].hostname: another reservation has this name',
    'wans[0].port: no such port',
  ])
})

test('a device whose name another reservation on its LAN already has is reserved without the name', async () => {
  // The router keeps a reservation's name to one device a LAN: two plugs of one make give
  // the same name, and a device that replaces another gives its predecessor's.
  const table = leases([
    ['192.168.1.143', 'printer', 125],
    ['192.168.1.144', 'NAS', 60],
  ])
  const { wrapper, store } = await page(table)
  await rowOf(wrapper, '192.168.1.143').find('button').trigger('click')
  await rowOf(wrapper, '192.168.1.144').find('button').trigger('click')
  const added = store().draft.value?.lans[0]?.dhcp?.static.slice(2)
  expect(added?.map((each) => [each.ip, each.hostname])).toEqual([
    ['192.168.1.143', ''],
    ['192.168.1.144', ''],
  ])
})

test('a reservation the router has reads Reserved, and one that cannot be made is not offered', async () => {
  const table = leases([
    ['192.168.1.10', 'nas', 60, { mac: '52:54:00:fe:10:10' }],
    // The printer's MAC, at an address that is not the one reserved for it.
    ['192.168.1.150', 'printer', 120, { mac: '52:54:00:fe:10:11' }],
    // A device squatting on the printer's reserved address.
    ['192.168.1.11', 'squatter', 180],
  ])
  const { wrapper } = await page(table)
  const last = (address: string) => rowOf(wrapper, address).findAll('td')[6]
  expect(last('192.168.1.10')?.find('.ofo-pill--info').text()).toBe('Reserved')
  expect(last('192.168.1.150')?.text()).toBe('')
  expect(last('192.168.1.11')?.text()).toBe('')
})

test('no Reserve on a router that takes no changes, and the page says why', async () => {
  const { wrapper, router } = await page()
  const refused = state()
  if (refused.system !== undefined) {
    refused.system.configProblem = { reason: 'config.toml: line 3: expected a table', violations: [] } as never
  }
  router.push('state', refused)
  await flushPromises()
  expect(wrapper.find('.readonly').text()).toBe('The router refused its config file and runs on defaults. Mend or remove the file to change settings here.')
  expect(wrapper.findAll('.leases__table button')).toHaveLength(0)
  // What is reserved is still said.
  expect(rowOf(wrapper, '192.168.1.10').findAll('td')[6]?.text()).toBe('Reserved')
})

test('a lease that arrives is marked new for a minute, and those there at first are not', async () => {
  const { wrapper, router } = await page()
  const marked = () => rows(wrapper).filter((row) => row.classes().includes('ofo-table__row--new')).map((row) => row.findAll('td')[1]?.text())
  // Even the one that joined two minutes ago: it was there when the page was opened.
  expect(marked()).toEqual([])
  router.push('leases', leases([...TABLE, ['192.168.1.144', 'thermostat', 2]]))
  await flushPromises()
  expect(addresses(wrapper)[0]).toBe('192.168.1.144')
  expect(marked()).toEqual(['192.168.1.144'])
  // A table that changes otherwise does not mark it again, nor unmark it.
  await vi.advanceTimersByTimeAsync(30_000)
  router.push('leases', leases([...TABLE.slice(1), ['192.168.1.144', 'thermostat', 32]]))
  await flushPromises()
  expect(marked()).toEqual(['192.168.1.144'])
  await vi.advanceTimersByTimeAsync(31_000)
  expect(marked()).toEqual([])
  // A device that left and comes back has arrived again.
  router.push('leases', leases([...TABLE, ['192.168.1.144', 'thermostat', 63]]))
  await flushPromises()
  expect(marked()).toEqual(['192.168.1.131'])
})

test('before the table has come the page waits, and with no lease yet it says what will appear', async () => {
  const { wrapper, router } = await page(null)
  expect(wrapper.find('.ofo-skel').exists()).toBe(true)
  expect(wrapper.find('.ofo-empty').exists()).toBe(false)
  expect(wrapper.find('.leases__table').exists()).toBe(false)
  router.push('leases', leases([]))
  await flushPromises()
  expect(wrapper.find('.ofo-skel').exists()).toBe(false)
  expect(wrapper.find('.ofo-empty__title').text()).toBe('No leases yet')
  expect(wrapper.find('.ofo-empty__text').text()).toBe('A device appears here when it takes an address from the router, such as a phone joining the Wi-Fi.')
  expect(wrapper.find('.leases__tools').exists()).toBe(false)
  // The first device to join after that has arrived while the page was open.
  router.push('leases', leases([['192.168.1.143', 'plug-kitchen', 1]]))
  await flushPromises()
  expect(rows(wrapper)[0]?.classes()).toContain('ofo-table__row--new')
})

test('a table that was cut says how many it shows', async () => {
  const { wrapper } = await page(leases(TABLE, true))
  expect(wrapper.find('.leases__cut').text()).toBe('The router holds more leases than it sends at once. These are the 6 that joined most recently.')
})
