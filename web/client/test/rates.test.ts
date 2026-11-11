// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create } from '@bufbuild/protobuf'
import { expect, test } from 'vitest'

import { CountersSchema, rates, type Counters } from '../src/index.js'

function sample(monotonicMs: bigint, links: [name: string, rx: bigint, tx: bigint][]): Counters {
  return create(CountersSchema, {
    monotonicMs,
    links: links.map(([name, rxBytes, txBytes]) => ({ name, rxBytes, txBytes })),
  })
}

test('two samples a second apart give bits per second', () => {
  const found = rates(sample(1_000n, [['wan0', 0n, 0n]]), sample(2_000n, [['wan0', 125_000n, 12_500n]]))
  expect(found).toEqual([{ name: 'wan0', rxBitsPerSec: 1_000_000, txBitsPerSec: 100_000 }])
})

test("the samples' own clock is used, not the caller's", () => {
  // A slow reader is sent only the latest sample, so two may be any time apart.
  const found = rates(sample(1_000n, [['wan0', 0n, 0n]]), sample(3_500n, [['wan0', 312_500n, 0n]]))
  expect(found).toEqual([{ name: 'wan0', rxBitsPerSec: 1_000_000, txBitsPerSec: 0 }])
})

test('a counter that went backwards is a rate of zero', () => {
  // An interface made anew (a PPP session, a bridge) starts counting again from nothing.
  const found = rates(sample(1_000n, [['ppp-wan0', 9_000_000n, 500n]]), sample(2_000n, [['ppp-wan0', 1_000n, 1_500n]]))
  expect(found).toEqual([{ name: 'ppp-wan0', rxBitsPerSec: 0, txBitsPerSec: 8_000 }])
})

test('a link in only one sample has no rate', () => {
  const found = rates(
    sample(1_000n, [
      ['wan0', 0n, 0n],
      ['gone', 5n, 5n],
    ]),
    sample(2_000n, [
      ['wan0', 1_000n, 1_000n],
      ['new', 7n, 7n],
    ]),
  )
  expect(found.map((rate) => rate.name)).toEqual(['wan0'])
})

test('samples out of order or at the same instant give nothing', () => {
  const earlier = sample(1_000n, [['wan0', 0n, 0n]])
  const later = sample(2_000n, [['wan0', 1_000n, 1_000n]])
  expect(rates(later, earlier)).toEqual([])
  expect(rates(later, later)).toEqual([])
})

test('counters past what a double holds exactly still give a true rate', () => {
  // 64-bit byte counters on a busy link pass 2^53; the difference is taken before the division.
  const base = 2n ** 60n
  const found = rates(sample(1_000n, [['wan0', base, base]]), sample(2_000n, [['wan0', base + 125_000n, base + 250_000n]]))
  expect(found).toEqual([{ name: 'wan0', rxBitsPerSec: 1_000_000, txBitsPerSec: 2_000_000 }])
})

test('the links keep the order the router gave them', () => {
  const found = rates(
    sample(0n, [
      ['p1', 0n, 0n],
      ['br-lan0', 0n, 0n],
      ['p0', 0n, 0n],
    ]),
    sample(1_000n, [
      ['p1', 1n, 1n],
      ['br-lan0', 1n, 1n],
      ['p0', 1n, 1n],
    ]),
  )
  expect(found.map((rate) => rate.name)).toEqual(['p1', 'br-lan0', 'p0'])
})
