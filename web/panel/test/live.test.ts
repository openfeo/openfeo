// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { useLive } from '../src/live'
import { FakeRouter } from './fake-router'
import { counters, event, NOW, state } from './fixtures'

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

test('it subscribes to state, counters and eight events of backlog, and lets go on unmount', () => {
  const { router, live } = started()
  expect(router.open('state')).toHaveLength(1)
  expect(router.open('counters')).toHaveLength(1)
  expect(router.open('events')).toHaveLength(1)
  expect(router.open('events')[0]?.backlog).toBe(8)
  expect(live.state.value).toBeNull()
  expect(live.connection.value).toBe('open')
  live.stop()
  expect(router.open('state')).toHaveLength(0)
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

test('the newest eight events are kept, newest first', () => {
  const { router, live } = started()
  for (let n = 1; n <= 10; n++) {
    router.push('events', event(`wan.wan0.${n % 2 === 0 ? 'up' : 'down'}`, { n: String(n) }))
  }
  expect(live.events.value).toHaveLength(8)
  expect(live.events.value.map((each) => each.fields.n)).toEqual(['10', '9', '8', '7', '6', '5', '4', '3'])
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
  expect(router.open('events')[0]?.backlog).toBe(8)
  expect(live.events.value).toEqual([])
  router.push('events', event('wan.wan0.down', { n: 'new' }))
  expect(live.events.value.map((each) => each.fields.n)).toEqual(['new'])
})
