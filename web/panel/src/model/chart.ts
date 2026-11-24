// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What a WAN's chart draws (SPEC §8.4, §10): a link's samples as rates over a range, cut into
// runs at the gaps, in one unit; the hour's peak; where the WAN came back; and the clock
// along the bottom. Pure functions of what the router sent. The router's times are on its
// boot clock (`Counters.monotonicMs`, an event's `uptimeMs`); the clock on screen is the
// browser's, counted back from now by how long ago the router's clock says a thing was.

import { averaged, GAP_MS, ratesOver, type Event, type LinkRate, type LinkSample, type RatePoint } from '@openfeo/client'
import type { ChartMark, ChartPoint, ChartTick } from '@openfeo/ui'

import { DASH, hourMinute, rate, unitScale, type RateUnit } from './format'

export type Range = '5m' | '1h'

/** The two views: each second of five minutes, and an hour in ten-second averages. */
export const RANGES = [
  { value: '5m', label: '5 min', words: 'the last five minutes', ms: 300_000, bucketMs: 1_000, tickMs: 60_000 },
  { value: '1h', label: '1 h', words: 'the last hour', ms: 3_600_000, bucketMs: 10_000, tickMs: 600_000 },
] as const satisfies readonly { value: Range; label: string; words: string; ms: number; bucketMs: number; tickMs: number }[]

/** The view the dashboard opens with. */
export const OPENING: Range = '1h'

const HOUR = RANGES[1]

export function rangeOf(range: Range): (typeof RANGES)[number] {
  return RANGES.find((each) => each.value === range) ?? HOUR
}

/** How often the router reads a link's counters (SPEC §10). */
const READ_MS = 1_000

/**
 * A link's rates as one view draws them, up to `toMs`: each second's, or the mean of each
 * bucket that is complete (the one still under way would rise and fall as it fills) and of
 * which at least half was read: where the line had just come back, or the router had just
 * booted, a second or two would otherwise stand for ten.
 */
function points(samples: readonly LinkSample[], view: (typeof RANGES)[number], toMs: number): RatePoint[] {
  const fromMs = toMs - view.ms
  const rates = ratesOver(samples)
  const shown = view.bucketMs > READ_MS ? averaged(rates, view.bucketMs, Math.ceil(view.bucketMs / READ_MS / 2)) : rates
  return shown.filter((point) => point.atMs > fromMs && point.atMs <= toMs)
}

/** Cut where two points are further apart than the view's points ever are: a gap is drawn as a gap. */
function runsOf(shown: readonly RatePoint[], view: (typeof RANGES)[number]): RatePoint[][] {
  const gapMs = view.bucketMs > READ_MS ? view.bucketMs * 1.5 : GAP_MS
  const runs: RatePoint[][] = []
  let before: RatePoint | undefined
  for (const point of shown) {
    const run = runs.at(-1)
    if (run === undefined || before === undefined || point.atMs - before.atMs > gapMs) {
      runs.push([point])
    } else {
      run.push(point)
    }
    before = point
  }
  return runs
}

/** A chart's picture: what `OfoChart` is given. Its places along the range are seconds on the router's boot clock. */
export interface Drawn {
  runs: ChartPoint[][]
  from: number
  to: number
  /** The unit of every value, chosen from the largest. */
  unit: RateUnit
  /** The legend's values of the moment, in that unit; a dash without a rate. */
  now: { rx: string; tx: string }
}

/**
 * A link's samples as its chart draws them over `range`, ending at `toMs` on the router's
 * boot clock. Everything is in one unit, the one the largest value is written in (the largest
 * drawn or `live`, the rate of the moment), so that the unit is said once.
 */
export function drawn(samples: readonly LinkSample[], range: Range, toMs: number, live: LinkRate | undefined): Drawn {
  const view = rangeOf(range)
  const runs = runsOf(points(samples, view, toMs), view)
  const largest = Math.max(0, live?.rxBitsPerSec ?? 0, live?.txBitsPerSec ?? 0, ...runs.flatMap((run) => run.flatMap((point) => [point.rxBitsPerSec, point.txBitsPerSec])))
  const unit = rate(largest).unit
  const scale = unitScale(unit)
  const said = (bitsPerSec: number | undefined) => (bitsPerSec === undefined ? DASH : (bitsPerSec / scale).toFixed(1))
  return {
    runs: runs.map((run) => run.map((point) => ({ at: point.atMs / 1000, rx: point.rxBitsPerSec / scale, tx: point.txBitsPerSec / scale }))),
    from: (toMs - view.ms) / 1000,
    to: toMs / 1000,
    unit,
    now: { rx: said(live?.rxBitsPerSec), tx: said(live?.txBitsPerSec) },
  }
}

/**
 * The hour's peak, in bits per second: the highest ten-second average of the hour that ends at
 * `toMs`, each way. It is the top of what the hour's chart draws, so the two cannot disagree;
 * a burst shorter than ten seconds reads lower than it was, and ten seconds of which under
 * half was read are not counted. Nothing when the hour has no such ten seconds.
 */
export function peak(samples: readonly LinkSample[], toMs: number): { rx: number; tx: number } | undefined {
  const shown = points(samples, HOUR, toMs)
  if (shown.length === 0) {
    return undefined
  }
  return { rx: Math.max(...shown.map((point) => point.rxBitsPerSec)), tx: Math.max(...shown.map((point) => point.txBitsPerSec)) }
}

/** The browser's clock at a moment on the router's boot clock: now, less how long ago the router's clock says it was. */
function wall(atMs: number, sinceBootMs: number, now: Date): Date {
  return new Date(now.getTime() - (sinceBootMs - atMs))
}

/**
 * A mark where `wan` came up inside the range that ends at `toMs`: "reconnected 14:12" when
 * its going down is among the events, "up 14:12" when nothing says it had been up before.
 * `events` are what the router keeps (its last 256), in any order. The time is the browser's,
 * counted back by the router's uptime; with no uptime to count by, the mark has no time.
 */
export function marks(events: readonly Event[], wan: string, range: Range, toMs: number, sinceBootMs: number | undefined, now: Date): ChartMark[] {
  const fromMs = toMs - rangeOf(range).ms
  const downs = events.filter((event) => event.topic === `wan.${wan}.down`).map((event) => Number(event.uptimeMs))
  return events
    .filter((event) => event.topic === `wan.${wan}.up`)
    .map((event) => Number(event.uptimeMs))
    .filter((atMs) => atMs > fromMs && atMs <= toMs)
    .sort((a, b) => a - b)
    .map((atMs) => {
      const word = downs.some((down) => down < atMs) ? 'reconnected' : 'up'
      return { at: atMs / 1000, label: sinceBootMs === undefined ? word : `${word} ${hourMinute(wall(atMs, sinceBootMs, now))}` }
    })
}

/**
 * Clock times along the range that ends at `toMs`: each minute of five, each ten of the hour,
 * on the minute by the browser's clock. None while the router's uptime is not known.
 */
export function ticks(range: Range, toMs: number, sinceBootMs: number | undefined, now: Date): ChartTick[] {
  if (sinceBootMs === undefined) {
    return []
  }
  const view = rangeOf(range)
  const end = wall(toMs, sinceBootMs, now).getTime()
  const start = end - view.ms
  const every = view.tickMs / 60_000
  // The first minute at or after the start that is a multiple of the step, on the local clock.
  const first = new Date(start)
  first.setSeconds(0, 0)
  while (first.getTime() < start || first.getMinutes() % every !== 0) {
    first.setTime(first.getTime() + 60_000)
  }
  const found: ChartTick[] = []
  for (let at = first.getTime(); at <= end; at += view.tickMs) {
    found.push({ at: (toMs - (end - at)) / 1000, label: hourMinute(new Date(at)) })
  }
  return found
}

/** The last minute of a link's rates, oldest first, for a tile's line. */
export function lastMinute(samples: readonly LinkSample[]): { rx: number[]; tx: number[] } {
  const recent = ratesOver(samples).slice(-60)
  return { rx: recent.map((point) => point.rxBitsPerSec), tx: recent.map((point) => point.txBitsPerSec) }
}
