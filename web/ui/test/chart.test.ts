// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { areaPath, ceiling, levels, linePath, type ChartPoint } from '../src/chart'

// The chart's geometry (ThroughputChart.md): a scale that stays still, straight segments, and
// a gap that is left undrawn. In a box 720 wide the plot runs from x 0 to 672 and from y 12
// (the top of the scale) to 196 (zero).

const WIDE = 720

test('the top of the scale is a round value at or above the largest', () => {
  expect(ceiling(0)).toBe(1)
  expect(ceiling(Number.NaN)).toBe(1)
  expect(ceiling(-3)).toBe(1)
  expect(ceiling(1)).toBe(1)
  expect(ceiling(38.2)).toBe(50)
  expect(ceiling(104)).toBe(200)
  expect(ceiling(918.2)).toBe(1000)
  expect(ceiling(1000)).toBe(1000)
  expect(ceiling(0.3)).toBe(0.5)
  expect(ceiling(2.0001)).toBe(5)
})

test('five levels from nothing to the top', () => {
  expect(levels(1000)).toEqual([0, 250, 500, 750, 1000])
  expect(levels(1)).toEqual([0, 0.25, 0.5, 0.75, 1])
})

const point = (at: number, rx: number, tx = 0): ChartPoint => ({ at, rx, tx })

test('a line runs from the left edge to the right, with the top of the scale at the top', () => {
  const runs = [[point(0, 0), point(50, 100), point(100, 50)]]
  expect(linePath(runs, 'rx', 0, 100, 100, WIDE)).toBe('M0 196 L336 12 L672 104')
  expect(linePath(runs, 'tx', 0, 100, 100, WIDE)).toBe('M0 196 L336 196 L672 196')
})

test('a gap between two runs is left undrawn, and nothing is curved', () => {
  const runs = [
    [point(0, 10), point(10, 10)],
    [point(60, 20), point(100, 20)],
  ]
  const path = linePath(runs, 'rx', 0, 100, 100, WIDE)
  expect(path).toBe('M0 177.6 L67.2 177.6 M403.2 159.2 L672 159.2')
  expect(path).not.toMatch(/[CSQTA]/i)
})

test('a value above the top is drawn at the top, and one that is no number at zero', () => {
  const runs = [[point(0, 500), point(100, Number.NaN)]]
  expect(linePath(runs, 'rx', 0, 100, 100, WIDE)).toBe('M0 12 L672 196')
})

test('what lies outside the range is not drawn, and a run of one point is a short level stroke', () => {
  const runs = [[point(-10, 10), point(50, 100), point(200, 10)]]
  expect(linePath(runs, 'rx', 0, 100, 100, WIDE)).toBe('M335 12 L337 12')
  expect(linePath([[point(-5, 1)]], 'rx', 0, 100, 100, WIDE)).toBe('')
  expect(linePath([], 'rx', 0, 100, 100, WIDE)).toBe('')
})

test('a range with no length draws nothing', () => {
  expect(linePath([[point(5, 1), point(5, 2)]], 'rx', 5, 5, 100, WIDE)).toBe('')
})

test('the fill closes each run down to the axis', () => {
  const runs = [
    [point(0, 100), point(50, 100)],
    [point(100, 50)],
  ]
  expect(areaPath(runs, 'rx', 0, 100, 100, WIDE)).toBe('M0 196 L0 12 L336 12 L336 196 Z')
})

test('the plot follows the width it is given', () => {
  expect(linePath([[point(0, 0), point(100, 100)]], 'rx', 0, 100, 100, 1048)).toBe('M0 196 L1000 12')
})
