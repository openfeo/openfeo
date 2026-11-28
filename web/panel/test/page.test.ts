// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create, ErrorCode, LeasesSchema, LinkHistorySchema, RouterError, StateSchema, type Leases, type LinkHistory } from '@openfeo/client'
import { THEME_KEY } from '@openfeo/ui'
import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { counters, event, NOW, state, UPTIME_SECS } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

const UPTIME_MS = UPTIME_SECS * 1000
/**
 * The router's clock when the browser's says NOW. It is a day behind, so that an age counted
 * on the browser's clock would be a day out: the pages count on the router's.
 */
const ROUTER_UNIX = Math.floor(NOW.getTime() / 1000) - 86_400

/** The lease table as the router has it when the browser's clock says NOW: each lease by its address, its name and how long ago it joined. */
function leases(rows: [address: string, hostname: string, joinedSecsAgo: number, lan?: string][]): Leases {
  return create(LeasesSchema, {
    timeUnix: BigInt(ROUTER_UNIX),
    leases: rows.map(([address, hostname, ago, lan]) => ({
      lan: lan ?? 'lan0',
      address,
      mac: `02:00:00:00:00:${address.split('.').at(-1)?.padStart(2, '0').slice(-2) ?? '00'}`,
      hostname,
      joinedUnix: BigInt(ROUTER_UNIX - ago),
      expiresUnix: BigInt(ROUTER_UNIX - ago + 43_200),
    })),
  })
}

/** What the router kept of a link: a sample a second for the `secs` seconds up to its uptime at NOW, at 8 Mbit/s down and 0.8 up. */
function kept(name: string, secs: number): LinkHistory {
  const seconds = Array.from({ length: secs + 1 }, (_, n) => UPTIME_SECS - secs + n)
  return create(LinkHistorySchema, {
    name,
    monotonicMs: seconds.map((second) => BigInt(second) * 1_000n),
    rxBytes: seconds.map((second) => BigInt(second) * 1_000_000n),
    txBytes: seconds.map((second) => BigInt(second) * 100_000n),
  })
}

/** The fixture's state with a second WAN, on a plain port. */
function twoWans() {
  const two = state()
  const first = two.wans[0]
  if (first !== undefined) {
    two.wans.push({ ...first, name: 'wan1', interface: 'p1', default4: false, default6: false })
  }
  return two
}

// The dashboard as it is reached: in the shell, at /. What the shell itself holds (the
// sidebar, the top bar, what is said above every page) is shell.test.ts's; the tests here
// that look at those are the ones part 1b wrote when the dashboard was the whole page.
function dashboard() {
  return panelAt('/')
}

async function loaded() {
  const made = await dashboard()
  const { router } = made
  router.push('state', state())
  router.push('counters', counters(1_000n, [['ppp-wan0', 0n, 0n], ['br-lan0', 0n, 0n]]))
  router.push('counters', counters(2_000n, [['ppp-wan0', 51_575_000n, 4_775_000n], ['br-lan0', 4_737_500n, 51_137_500n]]))
  router.push('events', event('wan.wan0.down', { reason: 'keepalive lost' }, new Date(2026, 10, 7, 21, 3, 19)))
  router.push('events', event('wan.wan0.up', {}, new Date(2026, 10, 7, 21, 3, 22)))
  router.push('events', event('lan.lan0.lease.granted', { address: '192.168.1.23', host: 'pixel-8' }, new Date(2026, 10, 10, 19, 42, 7)))
  router.push('leases', leases([['192.168.1.23', 'pixel-8', 23]]))
  await flushPromises()
  return made
}

/** What the system says it prefers, for the theme the switch starts from. */
let systemPrefersLight = false

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
  systemPrefersLight = false
  vi.stubGlobal('matchMedia', (query: string) => ({ matches: query.includes('light') && systemPrefersLight }))
})
afterEach(() => {
  unmountAll()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

test('before the first state there are skeletons and no numbers', async () => {
  const { wrapper } = await dashboard()
  expect(wrapper.find('h1').text()).toBe('Dashboard')
  expect(wrapper.findAll('.ofo-skel').length).toBeGreaterThan(8)
  expect(wrapper.find('.ofo-stat__value').exists()).toBe(false)
  expect(wrapper.find('.ofo-iface__name').exists()).toBe(false)
  expect(wrapper.find('.ofo-port').exists()).toBe(false)
  // The bars sit inside the frames the real things will have: four tiles, three cards.
  expect(wrapper.findAll('.ofo-stat')).toHaveLength(4)
  expect(wrapper.findAll('.ofo-iface')).toHaveLength(3)
  expect(wrapper.find('.ofo-pagehead__sub').exists()).toBe(false)
  // The frames are there already, so nothing jumps when the state arrives: a chart's among them.
  expect(wrapper.findAll('.ofo-card__title').map((title) => title.text())).toEqual(['Newest leases', 'Ports', 'Addresses', 'Recent events'])
  expect(wrapper.findAll('.ofo-chart')).toHaveLength(1)
  expect(wrapper.find('.ofo-chart svg').exists()).toBe(false)
  // The router's name is known before login, so the top bar has it at once.
  expect(wrapper.find('.ofo-topbar__host').text()).toBe('openfeo.home.arpa')
})

test('with the fixture state it shows the headline, four tiles, three cards, four ports, the addresses and the events', async () => {
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-skel').exists()).toBe(false)
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('wan0 up since 7 Nov 09:14 · 14 clients on 2 LANs')
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 4h')

  const tiles = wrapper.findAll('.ofo-stat')
  expect(tiles.map((tile) => tile.find('.ofo-stat__label').text())).toEqual(['Download', 'Upload', 'Clients', 'Connections'])
  expect(tiles[0]?.find('.ofo-stat__value').text()).toBe('412.6Mbit/s')
  expect(tiles[1]?.find('.ofo-stat__value').text()).toBe('38.2Mbit/s')
  expect(tiles[2]?.find('.ofo-stat__value').text()).toBe('14')
  expect(tiles[2]?.find('.ofo-stat__foot').text()).toBe('11 on lan0 · 3 on iot')
  expect(tiles[3]?.find('.ofo-stat__value').text()).toBe('1842')
  expect(tiles[0]?.find('svg.ofo-spark--s1').exists()).toBe(true)
  expect(tiles[1]?.find('svg.ofo-spark--s2').exists()).toBe(true)

  const cards = wrapper.findAll('.ofo-iface')
  expect(cards.map((card) => card.find('.ofo-iface__name').text())).toEqual(['wan0', 'lan0', 'iot'])
  expect(cards.map((card) => card.classes().includes('ofo-iface--active'))).toEqual([true, false, false])
  expect(cards[0]?.find('.ofo-pill--ok').text()).toBe('Up')
  expect(cards[0]?.find('.ofo-iface__rx').text()).toBe('↓ 412.6 Mbit/s')
  expect(cards[1]?.find('.ofo-iface__tx').text()).toBe('↑ 409.1 Mbit/s')
  expect(cards[2]?.find('.ofo-iface__rx').text()).toBe('↓ —')

  expect(wrapper.findAll('.ofo-port').map((port) => port.find('.ofo-port__speed').text())).toEqual(['2.5G', '2.5G', '—', '1G'])
  expect(wrapper.findAll('.ofo-port')[0]?.classes()).toContain('ofo-port--wan')

  const addresses = wrapper.findAll('.dash__addresses tbody tr')
  expect(addresses).toHaveLength(7)
  expect(addresses[0]?.findAll('td').map((cell) => cell.text())).toEqual(['ppp-wan0', '203.0.113.100 peer 203.0.113.1', 'PPP'])
  // An interface is named once, on its first row.
  expect(addresses[1]?.findAll('td')[0]?.text()).toBe('')
  expect(addresses[4]?.findAll('td')[2]?.text()).toBe('Delegated prefix · deprecated')
  expect(wrapper.find('.dash__addresses').text()).not.toContain('fe80')

  const events = wrapper.findAll('.dash__events tbody tr')
  expect(events.map((row) => row.findAll('td').map((cell) => cell.text()))).toEqual([
    ['19:42:07', 'lan0 leased 192.168.1.23 to pixel-8.'],
    ['7 Nov 21:03', 'wan0 up.'],
    ['7 Nov 21:03', 'wan0 down: keepalive lost.'],
  ])
  expect(events[0]?.findAll('code').map((code) => code.text())).toEqual(['lan0', '192.168.1.23', 'pixel-8'])
  // Nothing leads onward until the Logs page exists.
  expect(wrapper.find('.dash__events a').exists()).toBe(false)
})

test('a chart for each WAN, in config order, drawn back to before the page was opened', async () => {
  const router = signedIn()
  router.historyNow = [kept('ppp-wan0', 600), kept('p1', 600)]
  const { wrapper } = await panelAt('/', router)
  router.push('state', twoWans())
  await flushPromises()
  // From the top: the tiles, the charts, the interface cards.
  const blocks = wrapper.findAll('.dash > *').map((block) => block.classes().find((name) => ['ofo-grid', 'ofo-chart', 'ofo-card'].includes(name)))
  expect(blocks.slice(1, 5)).toEqual(['ofo-grid', 'ofo-chart', 'ofo-chart', 'ofo-grid'])
  const charts = wrapper.findAll('.ofo-chart')
  expect(charts.map((chart) => chart.find('h2').text())).toEqual(['wan0', 'wan1'])
  expect(charts[0]?.find('svg').attributes('aria-label')).toBe('Download and upload on wan0 over the last hour')
  // Ten minutes of the hour were kept by the router before this page asked: they are drawn.
  expect(charts[0]?.find('path.line.rx').attributes('d')).toMatch(/^M[\d.]+ [\d.]+ L/)
  expect(charts[1]?.find('path.line.rx').attributes('d')).toMatch(/^M/)
  // The unit is said once, in the legend; what is now is not known until two live samples are in.
  expect(charts[0]?.find('.ofo-chart__key--rx').text()).toBe('Download — Mbit/s')
  expect(charts[0]?.findAll('.ofo-chart__tick').map((tick) => tick.text())).toEqual(['18:50', '19:00', '19:10', '19:20', '19:30', '19:40'])
  const rx = (second: number) => BigInt(UPTIME_SECS + second) * 1_000_000n
  router.push('counters', counters(BigInt(UPTIME_MS + 1_000), [['ppp-wan0', rx(1), 0n]]))
  router.push('counters', counters(BigInt(UPTIME_MS + 2_000), [['ppp-wan0', rx(2), 0n]]))
  await flushPromises()
  expect(wrapper.findAll('.ofo-chart')[0]?.find('.ofo-chart__key--rx').text()).toBe('Download 8.0 Mbit/s')
  expect(wrapper.find('.ofo-chart__note').exists()).toBe(false)
})

test('the range is one choice for every chart, and the hour is where it opens', async () => {
  const router = signedIn()
  router.historyNow = [kept('ppp-wan0', 600), kept('p1', 600)]
  const { wrapper } = await panelAt('/', router)
  router.push('state', twoWans())
  await flushPromises()
  const pressed = () => wrapper.findAll('.ofo-chart .ofo-seg').map((choice) => choice.findAll('button').map((button) => button.attributes('aria-pressed')))
  expect(wrapper.findAll('.ofo-chart .ofo-seg button').map((button) => button.text())).toEqual(['5 min', '1 h', '5 min', '1 h'])
  expect(wrapper.find('.ofo-chart .ofo-seg').attributes('aria-label')).toBe('Range')
  expect(pressed()).toEqual([
    ['false', 'true'],
    ['false', 'true'],
  ])
  await wrapper.findAll('.ofo-chart')[1]?.findAll('.ofo-seg button')[0]?.trigger('click')
  expect(pressed()).toEqual([
    ['true', 'false'],
    ['true', 'false'],
  ])
  expect(wrapper.findAll('.ofo-chart svg').map((svg) => svg.attributes('aria-label'))).toEqual([
    'Download and upload on wan0 over the last five minutes',
    'Download and upload on wan1 over the last five minutes',
  ])
  expect(wrapper.findAll('.ofo-chart')[0]?.findAll('.ofo-chart__tick').map((tick) => tick.text())).toEqual(['19:38', '19:39', '19:40', '19:41', '19:42'])
})

test('the tiles say the hour’s peak, and their lines are filled from what the router kept', async () => {
  const router = signedIn()
  router.historyNow = [kept('ppp-wan0', 600)]
  const { wrapper } = await panelAt('/', router)
  router.push('state', state())
  await flushPromises()
  const tiles = wrapper.findAll('.ofo-stat')
  expect(tiles[0]?.find('.ofo-stat__foot').text()).toBe('peak 8.0 Mbit/s in the last hour')
  expect(tiles[1]?.find('.ofo-stat__foot').text()).toBe('peak 800.0 kbit/s in the last hour')
  // Sixty points already, before a single live sample.
  expect(tiles[0]?.find('svg.ofo-stat__spark path').attributes('d')?.split('L')).toHaveLength(60)
})

test('a WAN with nothing kept has an empty chart and dashes, and a history that could not be read is said', async () => {
  const router = signedIn()
  router.historyNow = new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
  const { wrapper } = await panelAt('/', router)
  router.push('state', state())
  await flushPromises()
  const chart = wrapper.find('.ofo-chart')
  expect(chart.find('.ofo-chart__note').text()).toBe('The last hour could not be read from the router. The line starts from when this page was opened.')
  expect(chart.find('path.line.rx').attributes('d')).toBe('')
  expect(chart.find('.ofo-chart__key--rx').text()).toBe('Download — bit/s')
  expect(chart.findAll('g.grid line')).toHaveLength(5)
})

test('a chart marks where its WAN came back', async () => {
  const router = signedIn()
  router.historyNow = [kept('ppp-wan0', 600)]
  const { wrapper } = await panelAt('/', router)
  router.push('state', state())
  router.push('events', event('wan.wan0.down', { reason: 'keepalive lost' }, new Date(NOW.getTime() - 12 * 60_000)))
  router.push('events', event('wan.wan0.up', {}, new Date(NOW.getTime() - 10 * 60_000)))
  await flushPromises()
  expect(wrapper.findAll('.ofo-chart g.event text').map((text) => text.text())).toEqual(['reconnected 19:32'])
})

test('the newest five leases, newest first, and a link to them all', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  // Before the table has come the card waits.
  await flushPromises()
  const card = () => wrapper.findAll('.ofo-card').find((each) => each.find('.ofo-card__title').text() === 'Newest leases')
  expect(card()?.find('.ofo-skel').exists()).toBe(true)
  router.push(
    'leases',
    leases([
      ['192.168.1.131', 'laptop', 2 * 86_400 + 60],
      ['192.168.1.143', 'plug-kitchen', 125],
      ['192.168.20.107', '', 41 * 60, 'iot'],
      ['192.168.1.142', 'phone', 5 * 3_600 + 9],
      ['192.168.20.101', 'camera-porch', 3 * 86_400, 'iot'],
      ['192.168.1.120', 'printer', 6 * 86_400],
      ['192.168.1.10', 'nas', 9 * 86_400],
    ]),
  )
  await flushPromises()
  expect(card()?.find('.ofo-skel').exists()).toBe(false)
  expect(card()?.findAll('thead th').map((th) => th.text())).toEqual(['Joined', 'Address', 'Name', 'MAC', 'LAN'])
  const rows = card()?.findAll('tbody tr') ?? []
  expect(rows.map((row) => row.findAll('td').map((cell) => cell.text()))).toEqual([
    ['2 min ago', '192.168.1.143', 'plug-kitchen', '02:00:00:00:00:43', 'lan0'],
    ['41 min ago', '192.168.20.107', 'none given', '02:00:00:00:00:07', 'iot'],
    ['5 h ago', '192.168.1.142', 'phone', '02:00:00:00:00:42', 'lan0'],
    ['2 d ago', '192.168.1.131', 'laptop', '02:00:00:00:00:31', 'lan0'],
    ['3 d ago', '192.168.20.101', 'camera-porch', '02:00:00:00:00:01', 'iot'],
  ])
  // The exact time is the cell's title, in the browser's zone; machine values are in mono.
  expect(rows[0]?.find('td span').attributes('title')).toBe('19:40:25')
  expect(rows[3]?.find('td span').attributes('title')).toBe('8 Nov 19:41')
  expect(rows[0]?.findAll('td')[1]?.classes()).toContain('ofo-mono')
  expect(rows[1]?.findAll('td')[2]?.find('.ofo-muted').text()).toBe('none given')
  const all = card()?.find('.ofo-card__head a')
  expect(all?.text()).toBe('All 7 leases')
  expect(all?.attributes('href')).toBe('/leases')
})

test('a row that has just joined is marked, for a minute', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  router.push('leases', leases([['192.168.1.143', 'plug-kitchen', 20], ['192.168.1.142', 'phone', 7_200]]))
  await flushPromises()
  const marked = () => wrapper.findAll('.dash__leases tbody tr').map((row) => row.classes().includes('ofo-table__row--new'))
  expect(marked()).toEqual([true, false])
  expect(wrapper.find('.dash__leases tbody tr td').text()).toBe('just now')
  // The router's clock is carried on by the browser's between two tables.
  await vi.advanceTimersByTimeAsync(45_000)
  expect(marked()).toEqual([false, false])
  expect(wrapper.find('.dash__leases tbody tr td').text()).toBe('1 min ago')
})

test('a row whose joined time is ahead of the router’s clock is not marked', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  // Leases read from a file written under a right clock, while the router's is still the build's.
  router.push('leases', leases([['192.168.1.143', 'plug-kitchen', -86_400], ['192.168.1.142', 'phone', -90_000]]))
  await flushPromises()
  const rows = wrapper.findAll('.dash__leases tbody tr')
  expect(rows.map((row) => row.find('td').text())).toEqual(['just now', 'just now'])
  expect(rows.map((row) => row.classes().includes('ofo-table__row--new'))).toEqual([false, false])
})

test('with no lease yet the card says so, and one lease is not "all 1 leases"', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  router.push('leases', leases([]))
  await flushPromises()
  const card = () => wrapper.findAll('.ofo-card').find((each) => each.find('.ofo-card__title').text() === 'Newest leases')
  expect(card()?.text()).toContain('No device has taken an address yet.')
  expect(card()?.find('table').exists()).toBe(false)
  expect(card()?.find('a').exists()).toBe(false)
  router.push('leases', leases([['192.168.1.143', 'plug-kitchen', 20]]))
  await flushPromises()
  expect(card()?.find('.ofo-card__head a').text()).toBe('1 lease')
})

test('the sidebar marks the dashboard', async () => {
  const { wrapper } = await loaded()
  const items = wrapper.findAll('.ofo-nav__item')
  expect(items[0]?.text()).toBe('Dashboard')
  // The dashboard's entry alone, whatever else the sidebar lists.
  expect(items.map((item) => item.attributes('aria-current')).filter((current) => current !== undefined)).toEqual(['page'])
  expect(items[0]?.attributes('aria-current')).toBe('page')
})

test('a router that has seen nothing happen says so', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  await flushPromises()
  expect(wrapper.find('.dash__events').text()).toBe('Nothing has happened since the router started.')
})

test('the uptime keeps counting between the router’s words', async () => {
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 4h')
  await vi.advanceTimersByTimeAsync(3_600_000)
  expect(wrapper.find('.ofo-topbar__meta').text()).toBe('0.4.0 · up 3d 5h')
})

test('an event stamped before the clock was set is shown when it happened, not on the day the image was built', async () => {
  const { wrapper, router } = await dashboard()
  router.push('state', state())
  // Four seconds after boot, by a clock that was still the build's.
  router.push('events', event('wan.wan0.up', {}, new Date(2026, 9, 1, 12, 0, 0), 4_000n))
  await flushPromises()
  expect(wrapper.find('.dash__events td').text()).toBe('7 Nov 15:42')
})

test('before the clock is synced the events show the uptime', async () => {
  const { wrapper, router } = await dashboard()
  const unsynced = state()
  if (unsynced.system !== undefined) {
    unsynced.system.timeSynced = false
  }
  router.push('state', unsynced)
  router.push('events', event('wan.wan0.up', {}, NOW, 192_000n))
  await flushPromises()
  expect(wrapper.find('.dash__events td').text()).toBe('up 3m 12s')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toBe('wan0 up · 14 clients on 2 LANs')
})

test('a refused config is said above everything, with its violations', async () => {
  const { wrapper, router } = await dashboard()
  const refused = state()
  refused.system = create(StateSchema, {
    system: {
      hostname: 'openfeo',
      domain: 'home.arpa',
      version: '0.4.0',
      configProblem: {
        reason: 'invalid (2 errors)',
        violations: [
          { path: 'lans[0].ipv4', code: 'cidr', message: 'not an address with a prefix length' },
          { path: 'wans[0].port', code: 'port', message: 'no such port' },
        ],
      },
    },
  }).system
  router.push('state', refused)
  await flushPromises()
  const banner = wrapper.find('.ofo-banner--warn')
  expect(banner.exists()).toBe(true)
  expect(banner.find('.ofo-banner__title').text()).toBe('config.toml was refused')
  expect(banner.text()).toContain('invalid (2 errors)')
  expect(banner.findAll('li').map((item) => item.text())).toEqual([
    'lans[0].ipv4: not an address with a prefix length',
    'wans[0].port: no such port',
  ])
  expect(banner.findAll('li code').map((code) => code.text())).toEqual(['lans[0].ipv4', 'wans[0].port'])
  expect(banner.text()).toContain('The router is running on first-boot defaults.')
  // It is the first thing on the page, above the dashboard itself.
  expect(wrapper.find('.ofo-shell__content').element.firstElementChild?.contains(banner.element)).toBe(true)
  expect(wrapper.find('.dash .ofo-banner').exists()).toBe(false)
  expect((await loaded()).wrapper.find('.ofo-banner').exists()).toBe(false)
})

test('a lost connection is said, and the rates and connections become dashes', async () => {
  const { wrapper, router } = await loaded()
  router.setConnection('reconnecting')
  await flushPromises()
  const banner = wrapper.find('.ofo-banner--danger')
  expect(banner.text()).toBe('The connection to the router was lost at 19:42:30. Retrying.')
  expect(banner.attributes('role')).toBe('alert')
  const tiles = wrapper.findAll('.ofo-stat')
  expect(tiles[0]?.find('.ofo-stat__value').text()).toBe('—')
  expect(tiles[1]?.find('.ofo-stat__value').text()).toBe('—')
  expect(tiles[3]?.find('.ofo-stat__value').text()).toBe('—')
  expect(wrapper.findAll('.ofo-iface__rx').map((rx) => rx.text())).toEqual(['↓ —', '↓ —', '↓ —'])
  // What is not a rate stays: it was true when last heard.
  expect(tiles[2]?.find('.ofo-stat__value').text()).toBe('14')
  expect(wrapper.find('.ofo-pagehead__sub').text()).toContain('wan0 up since')
  router.setConnection('open')
  await flushPromises()
  expect(wrapper.find('.ofo-banner--danger').exists()).toBe(false)
})

test('Log out logs out', async () => {
  const { wrapper, router } = await loaded()
  const button = wrapper.findAll('.ofo-topbar__end button').find((each) => each.text() === 'Log out')
  expect(button).toBeDefined()
  await button?.trigger('click')
  await flushPromises()
  expect(router.calls.logout).toBe(1)
})

test('choosing a theme applies and stores it', async () => {
  const { wrapper } = await loaded()
  const toggle = wrapper.find('.ofo-topbar__end button[aria-label]')
  expect(toggle.attributes('aria-label')).toBe('Use light theme')
  await toggle.trigger('click')
  expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  expect(window.localStorage.getItem(THEME_KEY)).toBe('light')
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  await wrapper.find('.ofo-topbar__end button[aria-label]').trigger('click')
  expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
})

test('a theme chosen before is the one the switch starts from', async () => {
  window.localStorage.setItem(THEME_KEY, 'light')
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
})

test('with no theme chosen the switch starts from what the system prefers, and stores nothing', async () => {
  systemPrefersLight = true
  const { wrapper } = await loaded()
  expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  expect(window.localStorage.getItem(THEME_KEY)).toBeNull()
  expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
})

test('with storage blocked the dashboard still comes up, and a theme can be chosen for this page', async () => {
  const real = Object.getOwnPropertyDescriptor(window, 'localStorage')
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    get: () => {
      throw new DOMException('The operation is insecure.', 'SecurityError')
    },
  })
  try {
    const { wrapper } = await loaded()
    expect(wrapper.find('h1').text()).toBe('Dashboard')
    await wrapper.find('.ofo-topbar__end button[aria-label]').trigger('click')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(wrapper.find('.ofo-topbar__end button[aria-label]').attributes('aria-label')).toBe('Use dark theme')
  } finally {
    if (real !== undefined) {
      Object.defineProperty(window, 'localStorage', real)
    }
  }
})

test('leaving the page lets go of the router', async () => {
  const { router } = await loaded()
  unmountAll()
  expect(router.open('state')).toHaveLength(0)
  expect(router.open('counters')).toHaveLength(0)
  expect(router.open('events')).toHaveLength(0)
})
