// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The Ports page (SPEC §8.4), in the shell at /ports: the sockets on the box, what uses each,
// and the bytes each has carried since the router started.

import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, expect, test } from 'vitest'

import { counters, state } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

async function page(sample: ReturnType<typeof counters> | null = counters(5_000n, [['p0', 412_800_000_000n, 38_100_000_000n], ['p1', 31_000_000_000n, 388_400_000_000n], ['p2', 0n, 0n], ['p3', 7_240_000_000n, 24_500_000_000n]])) {
  const router = signedIn()
  const made = await panelAt('/ports', router)
  router.push('state', state())
  if (sample !== null) {
    router.push('counters', sample)
  }
  await flushPromises()
  return made
}

const rows = (wrapper: VueWrapper) => wrapper.findAll('.ports__table tbody tr')
const cells = (wrapper: VueWrapper) => rows(wrapper).map((row) => row.findAll('td').map((cell) => cell.text().replace(/\s+/g, ' ')))

afterEach(() => {
  unmountAll()
})

test('the page shows the strip and a row for each port', async () => {
  const { wrapper, router, errors } = await page()
  expect(wrapper.find('h1').text()).toBe('Ports')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('The sockets on the box, in the order they are on it.')
  expect(wrapper.findAll('.ofo-ports .ofo-port__name').map((name) => name.text())).toEqual(['p0', 'p1', 'p2', 'p3'])
  expect(wrapper.findAll('.ports__table th').map((head) => head.text())).toEqual(['Port', 'Link', 'Used by', 'MAC', 'Hardware', 'Received', 'Sent'])
  expect(cells(wrapper)).toEqual([
    ['p0', 'Up 2500 Mbit/s', 'wan0, tag 911', '52:54:00:12:34:00', 'pci-0000:01:00.0', '412.8 GB', '38.1 GB'],
    ['p1', 'Up 2500 Mbit/s', 'lan0', '52:54:00:12:34:01', 'pci-0000:02:00.0', '31.0 GB', '388.4 GB'],
    ['p2', 'No cable', 'lan0', '52:54:00:12:34:02', 'pci-0000:03:00.0', '0 B', '0 B'],
    ['p3', 'Up 1000 Mbit/s', 'lan0 · iot, tag 20', '52:54:00:12:34:03', 'pci-0000:04:00.0', '7.2 GB', '24.5 GB'],
  ])
  // A link's state is a word in a pill, the good one in its tone and the other in none.
  const pills = rows(wrapper).map((row) => row.find('.ofo-pill'))
  expect(pills.map((pill) => [pill.text(), pill.classes().includes('ofo-pill--ok')])).toEqual([
    ['Up', true],
    ['Up', true],
    ['No cable', false],
    ['Up', true],
  ])
  // What uses a port is a link to where the port is given to it.
  expect(rows(wrapper)[3]?.findAll('td')[2]?.findAll('a').map((link) => [link.text(), link.attributes('href')])).toEqual([
    ['lan0', '/lan/lan0'],
    ['iot', '/lan/iot'],
  ])
  expect(rows(wrapper)[0]?.find('td a').attributes('href')).toBe('/wan/wan0')
  expect(wrapper.find('.ports__note').text()).toBe(
    'A view: a port is given to a WAN or a LAN on that WAN’s or LAN’s own page. Received and Sent count from when the router started.',
  )
  expect(wrapper.find('.ofo-savebar').exists()).toBe(false)
  expect(router.calls.dumpRoutes).toBe(0)
  expect(errors).toEqual([])
})

test('a port nothing uses says so', async () => {
  const router = signedIn()
  const { wrapper } = await panelAt('/ports', router)
  const unused = state()
  unused.ports[2]!.uses = []
  router.push('state', unused)
  await flushPromises()
  expect(cells(wrapper)[2]?.[2]).toBe('Not in use')
  expect(rows(wrapper)[2]?.findAll('td')[2]?.find('a').exists()).toBe(false)
})

test('the counters move as samples come, and are a dash before the first', async () => {
  const { wrapper, router } = await page(null)
  expect(cells(wrapper).map((row) => [row[5], row[6]])).toEqual([
    ['—', '—'],
    ['—', '—'],
    ['—', '—'],
    ['—', '—'],
  ])
  const calls = router.calls.state
  router.push('counters', counters(5_000n, [['p0', 1_000n, 0n]]))
  await flushPromises()
  expect(cells(wrapper)[0]?.slice(5)).toEqual(['1.0 kB', '0 B'])
  router.push('counters', counters(6_000n, [['p0', 2_500_000n, 1_500n]]))
  await flushPromises()
  expect(cells(wrapper)[0]?.slice(5)).toEqual(['2.5 MB', '1.5 kB'])
  expect(router.calls.state).toBe(calls)
})

test('before the router has said anything the page waits', async () => {
  const { wrapper } = await panelAt('/ports', signedIn())
  expect(wrapper.find('.ports__waiting').exists()).toBe(true)
  expect(wrapper.find('.ports__table').exists()).toBe(false)
})
