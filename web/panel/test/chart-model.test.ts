// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import type { LinkRate, LinkSample } from '@openfeo/client'
import { expect, test } from 'vitest'

import { drawn, lastMinute, marks, OPENING, peak, RANGES, ticks } from '../src/model/chart'
import { BOOTED, event, NOW, UPTIME_SECS } from './fixtures'

const MBIT = 1_000_000

/**
 * A sample a second from `fromMs` to `toMs`, received at `rx(atMs)` bits per second over the
 * second that ends at each, and sent at a tenth of that. Seconds for which `there` is false
 * have no sample.
 */
function samples(fromMs: number, toMs: number, rx: (atMs: number) => number, there: (atMs: number) => boolean = () => true): LinkSample[] {
  const made: LinkSample[] = []
  let rxBytes = 0n
  let txBytes = 0n
  for (let atMs = fromMs; atMs <= toMs; atMs += 1_000) {
    if (atMs > fromMs) {
      rxBytes += BigInt(Math.round(rx(atMs) / 8))
      txBytes += BigInt(Math.round(rx(atMs) / 80))
    }
    if (there(atMs)) {
      made.push({ atMs, rxBytes, txBytes })
    }
  }
  return made
}

const live = (rx: number, tx: number): LinkRate => ({ name: 'ppp-wan0', rxBitsPerSec: rx, txBitsPerSec: tx })

test('the ranges are five minutes at a second and an hour at ten, and the hour is where it opens', () => {
  expect(RANGES.map((range) => [range.value, range.label, range.ms, range.bucketMs])).toEqual([
    ['5m', '5 min', 300_000, 1_000],
    ['1h', '1 h', 3_600_000, 10_000],
  ])
  expect(OPENING).toBe('1h')
})

test('five minutes are drawn a point a second, in one unit, with what is now in the legend', () => {
  const steady = samples(0, 400_000, () => 8 * MBIT)
  const found = drawn(steady, '5m', 400_000, live(412.6 * MBIT, 38.2 * MBIT))
  expect([found.from, found.to]).toEqual([100, 400])
  expect(found.unit).toBe('Mbit/s')
  expect(found.runs).toHaveLength(1)
  const [run] = found.runs
  expect(run).toHaveLength(300)
  expect(run?.[0]).toEqual({ at: 101, rx: 8, tx: 0.8 })
  expect(run?.at(-1)).toEqual({ at: 400, rx: 8, tx: 0.8 })
  // The legend's values are in the chart's unit, so that it is said once.
  expect(found.now).toEqual({ rx: '412.6', tx: '38.2' })
  expect(drawn(steady, '5m', 400_000, undefined).now).toEqual({ rx: '—', tx: '—' })
})

test('the hour is drawn in ten-second averages, and the ten seconds still under way are left out', () => {
  const steady = samples(0, 3_705_000, () => 8 * MBIT)
  const found = drawn(steady, '1h', 3_705_000, undefined)
  expect([found.from, found.to]).toEqual([105, 3705])
  const [run] = found.runs
  expect(found.runs).toHaveLength(1)
  // From the bucket that ends at 110 s to the one that ends at 3700 s.
  expect(run).toHaveLength(360)
  expect(run?.[0]).toEqual({ at: 110, rx: 8, tx: 0.8 })
  expect(run?.at(-1)).toEqual({ at: 3700, rx: 8, tx: 0.8 })
})

test('a stretch with no samples is a gap between two runs, in both views', () => {
  const holed = samples(0, 400_000, () => 8 * MBIT, (atMs) => atMs <= 300_000 || atMs > 330_000)
  const second = drawn(holed, '5m', 400_000, undefined).runs
  expect(second.map((run) => [run[0]?.at, run.at(-1)?.at])).toEqual([
    [101, 300],
    // The first sample after the hole has nothing to be measured from.
    [332, 400],
  ])
  const hour = drawn(holed, '1h', 400_000, undefined).runs
  expect(hour.map((run) => [run[0]?.at, run.at(-1)?.at])).toEqual([
    [10, 300],
    [340, 400],
  ])
})

test('the unit is the one the largest value is written in', () => {
  const quiet = drawn(
    samples(0, 60_000, () => 800),
    '5m',
    60_000,
    live(640, 80),
  )
  expect(quiet.unit).toBe('bit/s')
  expect(quiet.runs[0]?.[0]).toEqual({ at: 1, rx: 800, tx: 80 })
  expect(quiet.now).toEqual({ rx: '640.0', tx: '80.0' })
  // One busy second lifts the whole chart into its unit; the rest is small in it, not zero.
  const burst = drawn(
    samples(0, 60_000, (atMs) => (atMs === 30_000 ? 1_500 * MBIT : 8 * MBIT)),
    '5m',
    60_000,
    undefined,
  )
  expect(burst.unit).toBe('Gbit/s')
  expect(burst.runs[0]?.find((point) => point.at === 30)?.rx).toBe(1.5)
  expect(burst.runs[0]?.[0]?.rx).toBe(0.008)
  // What is now counts too: a rate above everything drawn does not read "1500.0 Mbit/s".
  expect(drawn(samples(0, 60_000, () => 8 * MBIT), '5m', 60_000, live(1_500 * MBIT, 0)).unit).toBe('Gbit/s')
  // Nothing to draw: the smallest unit.
  expect(drawn([], '1h', 60_000, undefined)).toMatchObject({ runs: [], unit: 'bit/s' })
})

test('the peak is the highest ten-second average of the hour, not the highest second', () => {
  const spiked = samples(0, 3_700_000, (atMs) => (atMs === 1_805_000 ? 80 * MBIT : 8 * MBIT))
  const found = peak(spiked, 3_700_000)
  // Nine seconds at 8 and one at 80.
  expect(found?.rx).toBeCloseTo(15.2 * MBIT, 0)
  expect(found?.tx).toBeCloseTo(1.52 * MBIT, 0)
  // It is the top of what the hour's chart draws.
  const hour = drawn(spiked, '1h', 3_700_000, undefined)
  const top = Math.max(...hour.runs.flatMap((run) => run.map((point) => point.rx)))
  expect(top).toBeCloseTo(15.2, 6)
  // A spike more than an hour ago is not this hour's.
  expect(peak(spiked, 1_805_000 + 3_600_000 + 10_000)?.rx).toBeCloseTo(8 * MBIT, 0)
  expect(peak([], 3_700_000)).toBeUndefined()
  expect(peak(samples(0, 5_000, () => 8 * MBIT), 5_000)).toBeUndefined()
})

test('ten seconds of which under half was read are not drawn, and are not the peak', () => {
  // The line is away from 300 s to 338 s (a PPPoE session ended and another began) and comes
  // back into a burst: the readings at 339 s and 340 s are all there is of their ten seconds.
  const burst = (atMs: number) => (atMs > 338_000 && atMs <= 340_000 ? 800 * MBIT : 8 * MBIT)
  const back = samples(0, 400_000, burst, (atMs) => atMs <= 300_000 || atMs >= 338_000)
  // Two seconds at 800 are not ten seconds at 800.
  expect(peak(back, 400_000)?.rx).toBeCloseTo(8 * MBIT, 0)
  const hour = drawn(back, '1h', 400_000, undefined)
  expect(hour.unit).toBe('Mbit/s')
  expect(hour.runs.map((run) => [run[0]?.at, run.at(-1)?.at])).toEqual([
    [10, 300],
    [350, 400],
  ])
  // Each second of it is still in the five minutes, where a second is a second.
  const second = drawn(back, '5m', 400_000, undefined)
  expect(Math.max(...second.runs.flatMap((run) => run.map((point) => point.rx)))).toBeCloseTo(800, 6)
  // Half of the ten seconds is enough: a line that came back at 334 s is drawn from 340 s.
  const sooner = samples(0, 400_000, () => 8 * MBIT, (atMs) => atMs <= 300_000 || atMs >= 334_000)
  expect(drawn(sooner, '1h', 400_000, undefined).runs.map((run) => run[0]?.at)).toEqual([10, 340])
  // The hour's first seconds after a boot follow the same rule.
  expect(peak(samples(7_000, 30_000, (atMs) => (atMs <= 10_000 ? 800 * MBIT : 8 * MBIT)), 30_000)?.rx).toBeCloseTo(8 * MBIT, 0)
})

const UPTIME_MS = UPTIME_SECS * 1000
const at = (minutesAgo: number) => new Date(NOW.getTime() - minutesAgo * 60_000)

test('a WAN that came back is marked with the time it did, and one that came up for the first time says so', () => {
  const events = [
    event('wan.wan0.up', {}, at(10)),
    event('wan.wan0.down', { reason: 'keepalive lost' }, at(12)),
    event('wan.wan1.up', {}, at(20)),
    event('lan.lan0.lease.granted', {}, at(25)),
    event('wan.wan0.up', {}, at(50)),
    event('wan.wan0.up', {}, at(90)),
  ]
  expect(marks(events, 'wan0', '1h', UPTIME_MS, UPTIME_MS, NOW)).toEqual([
    // Nothing says it had gone down before: it came up.
    { at: (UPTIME_MS - 50 * 60_000) / 1000, label: 'up 18:52' },
    { at: (UPTIME_MS - 10 * 60_000) / 1000, label: 'reconnected 19:32' },
  ])
  // In five minutes neither is in range; another WAN's are its own.
  expect(marks(events, 'wan0', '5m', UPTIME_MS, UPTIME_MS, NOW)).toEqual([])
  expect(marks(events, 'wan1', '1h', UPTIME_MS, UPTIME_MS, NOW)).toEqual([{ at: (UPTIME_MS - 20 * 60_000) / 1000, label: 'up 19:22' }])
  // The time is the browser's, counted back from now by the router's own clock; an event's
  // stamp may be the build's date. With no uptime to count by there is no time to say.
  const stamped = [event('wan.wan0.up', {}, new Date(2020, 0, 1), BigInt(UPTIME_MS - 60_000))]
  expect(marks(stamped, 'wan0', '5m', UPTIME_MS, UPTIME_MS, NOW)).toEqual([{ at: (UPTIME_MS - 60_000) / 1000, label: 'up 19:41' }])
  expect(marks(stamped, 'wan0', '5m', UPTIME_MS, undefined, NOW)).toEqual([{ at: (UPTIME_MS - 60_000) / 1000, label: 'up' }])
})

test('clock times run along the range: each minute for five, each ten for the hour', () => {
  // NOW is 19:42:30.
  expect(BOOTED.getTime()).toBe(NOW.getTime() - UPTIME_MS)
  expect(ticks('5m', UPTIME_MS, UPTIME_MS, NOW)).toEqual(
    ['19:38', '19:39', '19:40', '19:41', '19:42'].map((label, n) => ({ at: (UPTIME_MS - 270_000 + n * 60_000) / 1000, label })),
  )
  expect(ticks('1h', UPTIME_MS, UPTIME_MS, NOW)).toEqual(
    ['18:50', '19:00', '19:10', '19:20', '19:30', '19:40'].map((label, n) => ({ at: (UPTIME_MS - 3_150_000 + n * 600_000) / 1000, label })),
  )
  // The chart's edge a little behind the router's clock: the labels stay on the clock.
  expect(ticks('5m', UPTIME_MS - 2_000, UPTIME_MS, NOW).at(-1)).toEqual({ at: (UPTIME_MS - 30_000) / 1000, label: '19:42' })
  expect(ticks('5m', UPTIME_MS, undefined, NOW)).toEqual([])
})

test('the last minute of rates, for a tile’s line', () => {
  const steady = samples(0, 200_000, () => 8 * MBIT)
  const found = lastMinute(steady)
  expect(found.rx).toHaveLength(60)
  expect(found.tx).toHaveLength(60)
  expect(found.rx.at(-1)).toBe(8 * MBIT)
  expect(found.tx.at(-1)).toBe(0.8 * MBIT)
  expect(lastMinute(samples(0, 3_000, () => 8 * MBIT)).rx).toHaveLength(3)
  expect(lastMinute([])).toEqual({ rx: [], tx: [] })
})
