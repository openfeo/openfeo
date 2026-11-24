// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create, ErrorCode, LeasesSchema, LinkHistorySchema, RouterError, type LinkHistory } from '@openfeo/client'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { useLive } from '../src/live'
import { FakeRouter } from './fake-router'
import { counters, event, NOW, state } from './fixtures'

/** A link's history: a sample a second from `fromSecs` to `toSecs`, 125 000 bytes received in each. */
function hour(name: string, fromSecs: number, toSecs: number): LinkHistory {
  const seconds = Array.from({ length: toSecs - fromSecs + 1 }, (_, n) => fromSecs + n)
  return create(LinkHistorySchema, {
    name,
    monotonicMs: seconds.map((second) => BigInt(second) * 1_000n),
    rxBytes: seconds.map((second) => BigInt(second) * 125_000n),
    txBytes: seconds.map((second) => BigInt(second) * 12_500n),
  })
}

/** Let what was asked of the router be answered. */
const answered = () => vi.advanceTimersByTimeAsync(0)

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})
afterEach(() => {
  vi.useRealTimers()
})

function started() {
  const router = new FakeRouter()
  router.authenticated = true
  router.connection = 'open'
  const live = useLive(router)
  live.start()
  return { router, live }
}

test('it subscribes to state, leases, counters and every event the router keeps, and lets go on unmount', () => {
  const { router, live } = started()
  expect(router.open('state')).toHaveLength(1)
  expect(router.open('leases')).toHaveLength(1)
  expect(router.open('counters')).toHaveLength(1)
  expect(router.open('events')).toHaveLength(1)
  expect(router.open('events')[0]?.backlog).toBe(256)
  expect(live.state.value).toBeNull()
  expect(live.leases.value).toBeNull()
  expect(live.connection.value).toBe('open')
  live.stop()
  expect(router.open('state')).toHaveLength(0)
  expect(router.open('leases')).toHaveLength(0)
  expect(router.open('counters')).toHaveLength(0)
  expect(router.open('events')).toHaveLength(0)
  // And it no longer hears the connection.
  router.setConnection('reconnecting')
  expect(live.connection.value).toBe('open')
})

test('the state is the latest pushed', () => {
  const { router, live } = started()
  router.push('state', state())
  expect(live.state.value?.generation).toBe(42n)
  const next = state()
  next.generation = 43n
  router.push('state', next)
  expect(live.state.value?.generation).toBe(43n)
})

test('as many events are kept as the router keeps, newest first', () => {
  // The chart marks where a WAN came back within the hour, so the list is not cut at what
  // the dashboard shows of it.
  const { router, live } = started()
  for (let n = 1; n <= 260; n++) {
    router.push('events', event(`wan.wan0.${n % 2 === 0 ? 'up' : 'down'}`, { n: String(n) }))
  }
  expect(live.events.value).toHaveLength(256)
  expect(live.events.value.slice(0, 3).map((each) => each.fields.n)).toEqual(['260', '259', '258'])
  expect(live.events.value.at(-1)?.fields.n).toBe('5')
})

test('the lease table is kept and its clock carried on', () => {
  const { router, live } = started()
  expect(live.routerClock.value).toBeUndefined()
  const table = create(LeasesSchema, { timeUnix: 1_800_000_000n, leases: [{ lan: 'lan0', address: '192.168.1.143', joinedUnix: 1_799_999_880n }] })
  router.push('leases', table)
  expect(live.leases.value?.leases.map((lease) => lease.address)).toEqual(['192.168.1.143'])
  expect(live.routerClock.value).toBe(1_800_000_000)
  // Between two tables the router's clock is carried on by the time since the last arrived.
  vi.advanceTimersByTime(5_000)
  expect(live.routerClock.value).toBe(1_800_000_005)
  // The next table says the time itself, and it is taken as said.
  router.push('leases', create(LeasesSchema, { timeUnix: 1_800_000_100n }))
  expect(live.routerClock.value).toBe(1_800_000_100)
  expect(live.leases.value?.leases).toEqual([])
  // A browser clock set back holds the router's where it was.
  vi.setSystemTime(new Date(NOW.getTime() - 3_600_000))
  vi.advanceTimersByTime(1_000)
  expect(live.routerClock.value).toBe(1_800_000_100)
  live.stop()
})

test('the history is asked for once the state names a WAN, and the live samples follow it', async () => {
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 100, 200)]
  expect(router.calls.history).toEqual([])
  router.push('state', state())
  expect(router.calls.history).toEqual([['ppp-wan0']])
  await answered()
  expect(live.historyFailed.value).toBe(false)
  const kept = () => live.samples.value.get('ppp-wan0') ?? []
  expect(kept()).toHaveLength(101)
  expect([kept()[0]?.atMs, kept().at(-1)?.atMs]).toEqual([100_000, 200_000])
  // The state again asks nothing again.
  router.push('state', state())
  expect(router.calls.history).toHaveLength(1)
  // Each live sample of the WAN's link is added; other links are not kept.
  router.push('counters', counters(201_000n, [['ppp-wan0', 25_125_000n, 2_512_500n], ['br-lan0', 5n, 5n]]))
  expect(kept().at(-1)).toEqual({ atMs: 201_000, rxBytes: 25_125_000n, txBytes: 2_512_500n })
  expect(kept()).toHaveLength(102)
  expect([...live.samples.value.keys()]).toEqual(['ppp-wan0'])
  live.stop()
})

test('the sparkline is filled from the history at once', async () => {
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 100, 200)]
  router.push('state', state())
  expect(live.history.value).toEqual({ rx: [], tx: [] })
  await answered()
  expect(live.history.value.rx).toHaveLength(60)
  expect(live.history.value.rx.at(-1)).toBe(1_000_000)
  expect(live.history.value.tx.at(-1)).toBe(100_000)
  live.stop()
})

test('a history that cannot be read is said, and the live samples still gather', async () => {
  const { router, live } = started()
  router.historyNow = new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
  router.push('state', state())
  await answered()
  expect(live.historyFailed.value).toBe(true)
  router.push('counters', counters(201_000n, [['ppp-wan0', 1n, 1n]]))
  router.push('counters', counters(202_000n, [['ppp-wan0', 2n, 2n]]))
  expect(live.samples.value.get('ppp-wan0')?.map((sample) => sample.atMs)).toEqual([201_000, 202_000])
  // When the socket opens anew it is asked again, and an answer takes the word back.
  router.historyNow = [hour('ppp-wan0', 100, 200)]
  router.setConnection('reconnecting')
  router.setConnection('open')
  await answered()
  expect(live.historyFailed.value).toBe(false)
  expect(live.samples.value.get('ppp-wan0')).toHaveLength(103)
  live.stop()
})

test('a reconnect fills the time away and repeats nothing', async () => {
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 100, 200)]
  router.push('state', state())
  await answered()
  router.push('counters', counters(201_000n, [['ppp-wan0', 25_125_000n, 2_512_500n]]))
  // The socket is away for a minute; the router went on reading.
  router.setConnection('reconnecting')
  expect(live.samples.value.get('ppp-wan0')).toHaveLength(102)
  router.historyNow = [hour('ppp-wan0', 100, 260)]
  router.setConnection('open')
  expect(router.calls.history).toEqual([['ppp-wan0'], ['ppp-wan0']])
  // A live sample arrives before the answer does: it is not lost to it, nor counted twice.
  router.push('counters', counters(261_000n, [['ppp-wan0', 32_625_000n, 3_262_500n]]))
  await answered()
  const times = (live.samples.value.get('ppp-wan0') ?? []).map((sample) => sample.atMs)
  expect(times).toHaveLength(162)
  expect(times).toEqual(Array.from({ length: 162 }, (_, n) => (100 + n) * 1_000))
  live.stop()
})

test('samples of an earlier boot are dropped', async () => {
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 5_000, 5_100)]
  router.push('state', state())
  await answered()
  expect(live.samples.value.get('ppp-wan0')).toHaveLength(101)
  // The router restarted: its boot clock began again, and so did its counters.
  router.historyNow = [hour('ppp-wan0', 1, 8)]
  router.push('counters', counters(9_000n, [['ppp-wan0', 1_125_000n, 112_500n]]))
  expect(live.samples.value.get('ppp-wan0')?.map((sample) => sample.atMs)).toEqual([9_000])
  // The new boot's history is asked for, and joined on.
  expect(router.calls.history).toHaveLength(2)
  await answered()
  expect(live.samples.value.get('ppp-wan0')?.map((sample) => sample.atMs)).toEqual([1_000, 2_000, 3_000, 4_000, 5_000, 6_000, 7_000, 8_000, 9_000])
  live.stop()
})

test('a history from before the boot that the page now watches is not joined on', async () => {
  // The answer was on its way when the router restarted.
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 5_000, 5_100)]
  const letGo = router.holdCall('history')
  router.push('state', state())
  router.push('counters', counters(5_101_000n, [['ppp-wan0', 1n, 1n]]))
  router.historyNow = [hour('ppp-wan0', 1, 1)]
  router.push('counters', counters(2_000n, [['ppp-wan0', 2n, 2n]]))
  expect(router.calls.history).toHaveLength(2)
  letGo()
  await answered()
  const times = (live.samples.value.get('ppp-wan0') ?? []).map((sample) => sample.atMs)
  expect(times).toEqual([1_000, 2_000])
  live.stop()
})

test('an hour is kept and no more, and a WAN that is gone is forgotten', async () => {
  const { router, live } = started()
  router.historyNow = [hour('ppp-wan0', 1, 3_600)]
  router.push('state', state())
  await answered()
  expect(live.samples.value.get('ppp-wan0')).toHaveLength(3_600)
  router.push('counters', counters(3_700_000n, [['ppp-wan0', 462_500_000n, 46_250_000n]]))
  const kept = live.samples.value.get('ppp-wan0') ?? []
  expect([kept[0]?.atMs, kept.at(-1)?.atMs]).toEqual([100_000, 3_700_000])
  const none = state()
  none.wans = []
  router.push('state', none)
  expect([...live.samples.value.keys()]).toEqual([])
  live.stop()
})

test('a WAN whose interface has no name is not asked about, and nine WANs are asked about in two calls', async () => {
  const { router, live } = started()
  const many = state()
  const first = many.wans[0]
  if (first !== undefined) {
    // (The router names an interface for every WAN, a PPPoE WAN's between sessions too; an
    // empty name is no link to ask about.)
    many.wans = [
      ...Array.from({ length: 9 }, (_, n) => ({ ...first, name: `wan${n}`, interface: `p${n}` })),
      { ...first, name: 'wan9', interface: '' },
    ]
  }
  router.push('state', many)
  await answered()
  expect(router.calls.history).toEqual([
    ['p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7'],
    ['p8'],
  ])
  live.stop()
})

test("two counters samples make rates, and the default WAN's last sixty are kept", () => {
  const { router, live } = started()
  router.push('state', state())
  router.push('counters', counters(1_000n, [['ppp-wan0', 0n, 0n], ['br-lan0', 0n, 0n]]))
  // One sample is no rate; it does say how many connections are tracked.
  expect(live.rates.value).toBeNull()
  expect(live.conntrack.value).toEqual({ count: 1842, max: 262_144 })
  expect(live.history.value).toEqual({ rx: [], tx: [] })
  router.push('counters', counters(2_000n, [['ppp-wan0', 125_000n, 12_500n], ['br-lan0', 250_000n, 0n]]))
  expect(live.rates.value?.get('ppp-wan0')).toEqual({ name: 'ppp-wan0', rxBitsPerSec: 1_000_000, txBitsPerSec: 100_000 })
  expect(live.rates.value?.get('br-lan0')?.rxBitsPerSec).toBe(2_000_000)
  expect(live.history.value).toEqual({ rx: [1_000_000], tx: [100_000] })
  for (let n = 3; n <= 70; n++) {
    router.push('counters', counters(BigInt(n) * 1_000n, [['ppp-wan0', BigInt(n) * 125_000n, 0n]]))
  }
  expect(live.history.value.rx).toHaveLength(60)
  expect(live.history.value.tx).toHaveLength(60)
})

test('with no WAN there is no history, and the rates are still there', () => {
  const { router, live } = started()
  const none = state()
  none.wans = []
  router.push('state', none)
  router.push('counters', counters(1_000n, [['br-lan0', 0n, 0n]]))
  router.push('counters', counters(2_000n, [['br-lan0', 1_000n, 1_000n]]))
  expect(live.history.value).toEqual({ rx: [], tx: [] })
  expect(live.rates.value?.get('br-lan0')?.rxBitsPerSec).toBe(8_000)
})

test('a lost connection clears the rates and notes when, and its return clears the note', () => {
  const { router, live } = started()
  router.push('state', state())
  router.push('counters', counters(1_000n, [['ppp-wan0', 0n, 0n]]))
  router.push('counters', counters(2_000n, [['ppp-wan0', 125_000n, 0n]]))
  expect(live.lostAt.value).toBeNull()
  router.setConnection('reconnecting')
  expect(live.connection.value).toBe('reconnecting')
  expect(live.lostAt.value?.getTime()).toBe(NOW.getTime())
  // The numbers stop: they are not left at their last value as though still true.
  expect(live.rates.value).toBeNull()
  expect(live.conntrack.value).toBeNull()
  // What the router last said of itself stays on screen.
  expect(live.state.value?.generation).toBe(42n)
  // When it was lost does not move while it stays lost.
  vi.advanceTimersByTime(5_000)
  router.setConnection('reconnecting')
  expect(live.lostAt.value?.getTime()).toBe(NOW.getTime())

  router.setConnection('open')
  expect(live.lostAt.value).toBeNull()
  // The first sample after the gap is a new beginning, not a rate across the outage.
  router.push('counters', counters(60_000n, [['ppp-wan0', 9_000_000n, 0n]]))
  expect(live.rates.value).toBeNull()
  router.push('counters', counters(61_000n, [['ppp-wan0', 9_125_000n, 0n]]))
  expect(live.rates.value?.get('ppp-wan0')?.rxBitsPerSec).toBe(1_000_000)
})

test('told that events were lost, it asks for the backlog again and replaces its list', () => {
  const { router, live } = started()
  router.push('events', event('wan.wan0.up', { n: 'old' }))
  const before = router.open('events')[0]
  router.lose()
  expect(before?.closed).toBe(true)
  expect(router.open('events')).toHaveLength(1)
  expect(router.open('events')[0]?.backlog).toBe(256)
  expect(live.events.value).toEqual([])
  router.push('events', event('wan.wan0.down', { n: 'new' }))
  expect(live.events.value.map((each) => each.fields.n)).toEqual(['new'])
})

test('the clock ticks while it is listening, and the uptime moves on between the router\'s words', () => {
  const { router, live } = started()
  expect(live.now.value.getTime()).toBe(NOW.getTime())
  // Before the router has said anything there is no uptime to count from.
  expect(live.sinceBootMs.value).toBeUndefined()
  router.push('state', state())
  expect(live.sinceBootMs.value).toBe(273_600_000)
  vi.advanceTimersByTime(5_000)
  expect(live.now.value.getTime()).toBe(NOW.getTime() + 5_000)
  expect(live.sinceBootMs.value).toBe(273_605_000)
  // What the router says next is taken as it is said, not added to what was counted.
  const later = state()
  if (later.system !== undefined) {
    later.system.uptimeSecs = 273_700n
  }
  router.push('state', later)
  expect(live.sinceBootMs.value).toBe(273_700_000)
  live.stop()
  vi.advanceTimersByTime(5_000)
  expect(live.now.value.getTime()).toBe(NOW.getTime() + 5_000)
})

test('a browser clock set back does not take the uptime back', () => {
  const { router, live } = started()
  router.push('state', state())
  vi.setSystemTime(new Date(NOW.getTime() - 3_600_000))
  vi.advanceTimersByTime(1_000)
  expect(live.sinceBootMs.value).toBe(273_600_000)
  live.stop()
})
