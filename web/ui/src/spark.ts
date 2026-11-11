// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A stat tile's sparkline: straight segments, no axes, no fill (the design system's rule:
// people read exact drops here, so nothing is smoothed).

const WIDTH = 180
const TOP = 2
const BOTTOM = 26

function round(value: number): string {
  return String(Math.round(value * 10) / 10)
}

/**
 * The path for a tile's samples in a `0 0 180 28` box: the oldest at the left edge, the
 * newest at the right, the largest at the top and zero at the bottom. One sample is a level
 * line; none is no path. A sample that is not a finite, positive number counts as zero.
 */
export function sparkPath(samples: readonly number[]): string {
  const values = samples.map((sample) => (Number.isFinite(sample) && sample > 0 ? sample : 0))
  if (values.length === 0) {
    return ''
  }
  const max = Math.max(...values, 0)
  const y = (value: number) => round(max === 0 ? BOTTOM : BOTTOM - (value / max) * (BOTTOM - TOP))
  if (values.length === 1) {
    const level = y(values[0] ?? 0)
    return `M0 ${level} L${WIDTH} ${level}`
  }
  const step = WIDTH / (values.length - 1)
  return values.map((value, i) => `${i === 0 ? 'M' : 'L'}${round(i * step)} ${y(value)}`).join(' ')
}
