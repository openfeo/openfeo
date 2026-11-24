// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A chart's geometry (ThroughputChart.md): straight segments, a scale that stays still, and a
// gap that is left undrawn. It is given numbers and a width and gives back paths; it knows
// nothing of counters or of time, only of two values at a place along a range.

/** Two values at one place along the range. */
export interface ChartPoint {
  at: number
  rx: number
  tx: number
}

/** A dashed marker with a short label: a failover, a reconnect. */
export interface ChartMark {
  at: number
  label: string
}

/** A label along the range. */
export interface ChartTick {
  at: number
  label: string
}

/** The box's height, and where in it the plot lies: the top of the scale and zero. */
export const HEIGHT = 220
export const TOP = 12
export const BOTTOM = 196
/** The room at the right for the scale's labels. */
export const AXIS = 48

function round(value: number): string {
  return String(Math.round(value * 10) / 10)
}

/** How wide the plot is in a box `width` wide. */
export function plotWidth(width: number): number {
  return Math.max(0, width - AXIS)
}

/**
 * A round top for the scale at or above `max`: 1, 2 or 5 times a power of ten. It moves only
 * when the largest value crosses one of those, so the chart does not rescale with every
 * sample. 1 when there is nothing to scale to.
 */
export function ceiling(max: number): number {
  if (!Number.isFinite(max) || max <= 0) {
    return 1
  }
  const power = 10 ** Math.floor(Math.log10(max))
  for (const step of [1, 2, 5, 10]) {
    // (A product of floats may land a hair under the value it stands for.)
    const top = Number((step * power).toPrecision(12))
    if (top >= max) {
      return top
    }
  }
  return 10 * power
}

/** Five values from nothing to `top`, where the grid's lines go. */
export function levels(top: number): number[] {
  return [0, 0.25, 0.5, 0.75, 1].map((part) => Number((part * top).toPrecision(12)))
}

/** Where `at` lies across a plot `width` wide; `undefined` outside the range, or in a range with no length. */
export function across(at: number, from: number, to: number, width: number): number | undefined {
  if (!(to > from) || at < from || at > to) {
    return undefined
  }
  return ((at - from) / (to - from)) * plotWidth(width)
}

/** How high `value` lies: `top` at the top, nothing at the bottom, never outside. */
export function height(value: number, top: number): number {
  const part = Number.isFinite(value) && value > 0 && top > 0 ? Math.min(value / top, 1) : 0
  return BOTTOM - part * (BOTTOM - TOP)
}

/** Each run's points that lie in the range, as places in the box; a run with none is left out. */
function placed(
  runs: readonly (readonly ChartPoint[])[],
  series: 'rx' | 'tx',
  from: number,
  to: number,
  top: number,
  width: number,
): { x: number; y: number }[][] {
  return runs
    .map((run) =>
      run.flatMap((point) => {
        const x = across(point.at, from, to, width)
        return x === undefined ? [] : [{ x, y: height(point[series], top) }]
      }),
    )
    .filter((run) => run.length > 0)
}

/**
 * One `M … L …` for each run, in order. A gap lies between two runs and is not drawn; a run
 * with one point in the range is a short level stroke. Straight segments only: people read
 * exact drops here.
 */
export function linePath(
  runs: readonly (readonly ChartPoint[])[],
  series: 'rx' | 'tx',
  from: number,
  to: number,
  top: number,
  width: number,
): string {
  return placed(runs, series, from, to, top, width)
    .map((run) => {
      const [only] = run
      if (run.length === 1 && only !== undefined) {
        return `M${round(only.x - 1)} ${round(only.y)} L${round(only.x + 1)} ${round(only.y)}`
      }
      return run.map((point, i) => `${i === 0 ? 'M' : 'L'}${round(point.x)} ${round(point.y)}`).join(' ')
    })
    .join(' ')
}

/** The same runs closed down to the axis, for the fill. A run of one point has no area. */
export function areaPath(
  runs: readonly (readonly ChartPoint[])[],
  series: 'rx' | 'tx',
  from: number,
  to: number,
  top: number,
  width: number,
): string {
  return placed(runs, series, from, to, top, width)
    .filter((run) => run.length > 1)
    .map((run) => {
      const first = run[0]?.x ?? 0
      const last = run[run.length - 1]?.x ?? 0
      const line = run.map((point) => `L${round(point.x)} ${round(point.y)}`).join(' ')
      return `M${round(first)} ${BOTTOM} ${line} L${round(last)} ${BOTTOM} Z`
    })
    .join(' ')
}
