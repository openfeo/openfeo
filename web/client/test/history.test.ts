// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create } from '@bufbuild/protobuf'
import { expect, test } from 'vitest'

import { averaged, CountersSchema, GAP_MS, LinkHistorySchema, rates, ratesOver, samplesOf, type LinkSample, type RatePoint } from '../src/index.js'

// The router keeps the last hour of each link's byte counters and computes no rates
// (SPEC §10). These make rates of that history by the rule the live samples are read by.

const sample = (atMs: number, rxBytes: bigint, txBytes: bigint): LinkSample => ({ atMs, rxBytes, txBytes })

test('a history is its three lists, zipped, oldest first', () => {
  const history = create(LinkHistorySchema, {
    name: 'p0',
    monotonicMs: [1_000n, 2_000n, 3_000n],
    rxBytes: [10n, 20n, 30n],
    txBytes: [1n, 2n],
  })
  // A list that is short gives no sample for what it lacks: nothing is made up.
  expect(samplesOf(history)).toEqual([sample(1_000, 10n, 1n), sample(2_000, 20n, 2n)])
  expect(samplesOf(create(LinkHistorySchema, { name: 'p0' }))).toEqual([])
})

test('a rate for each sample after the first, by the live rule', () => {
  const samples = [sample(1_000, 0n, 0n), sample(2_000, 125_000n, 12_500n), sample(3_500, 312_500n, 12_500n)]
  expect(ratesOver(samples)).toEqual([
    { atMs: 2_000, rxBitsPerSec: 1_000_000, txBitsPerSec: 100_000 },
    { atMs: 3_500, rxBitsPerSec: 1_000_000, txBitsPerSec: 0 },
  ])
  // The same numbers the live samples give.
  const counters = (at: LinkSample) =>
    create(CountersSchema, { monotonicMs: BigInt(at.atMs), links: [{ name: 'p0', rxBytes: at.rxBytes, txBytes: at.txBytes }] })
  const [first, second] = samples
  expect(rates(counters(first!), counters(second!))).toEqual([{ name: 'p0', rxBitsPerSec: 1_000_000, txBitsPerSec: 100_000 }])
  expect(ratesOver([])).toEqual([])
  expect(ratesOver([sample(1_000, 5n, 5n)])).toEqual([])
})

test('no rate across a gap', () => {
  // A PPPoE interface between sessions, or a read that failed: the time between is unknown,
  // not an average.
  expect(GAP_MS).toBe(5_000)
  const samples = [sample(1_000, 0n, 0n), sample(2_000, 1_000n, 0n), sample(8_000, 9_000n, 0n), sample(9_000, 10_000n, 0n)]
  expect(ratesOver(samples).map((point) => point.atMs)).toEqual([2_000, 9_000])
  // Exactly the limit apart is still one stretch.
  expect(ratesOver([sample(1_000, 0n, 0n), sample(6_000, 5_000n, 0n)])).toEqual([{ atMs: 6_000, rxBitsPerSec: 8_000, txBitsPerSec: 0 }])
})

test('no rate where a counter went backwards', () => {
  // An interface made anew starts counting from nothing: that second says nothing of the
  // line. Drawn as zero it would be a drop that did not happen.
  const samples = [sample(1_000, 9_000_000n, 500n), sample(2_000, 1_000n, 1_500n), sample(3_000, 2_000n, 2_500n)]
  expect(ratesOver(samples)).toEqual([{ atMs: 3_000, rxBitsPerSec: 8_000, txBitsPerSec: 8_000 }])
  const sent = [sample(1_000, 0n, 500n), sample(2_000, 1_000n, 0n)]
  expect(ratesOver(sent)).toEqual([])
})

test('no rate where time stood still or ran back', () => {
  // A reading that is not later than the one before is passed over, and the next is measured
  // from the one that stands: 3000 bytes in the half second from 2 s to 2.5 s.
  const samples = [sample(2_000, 0n, 0n), sample(2_000, 1_000n, 0n), sample(1_500, 2_000n, 0n), sample(2_500, 3_000n, 0n)]
  expect(ratesOver(samples)).toEqual([{ atMs: 2_500, rxBitsPerSec: 48_000, txBitsPerSec: 0 }])
})

test('buckets are aligned and averaged, and an empty one is absent', () => {
  const point = (atMs: number, rx: number): RatePoint => ({ atMs, rxBitsPerSec: rx, txBitsPerSec: rx / 10 })
  // A point a second from 1 s to 25 s, with 11 s to 20 s missing.
  const seconds = [...Array(25).keys()].map((n) => n + 1).filter((second) => second <= 10 || second > 20)
  const points = seconds.map((second) => point(second * 1_000, second * 100))
  expect(averaged(points, 10_000)).toEqual([
    // 1 s to 10 s: the mean of 100 to 1000.
    { atMs: 10_000, rxBitsPerSec: 550, txBitsPerSec: 55 },
    // 21 s to 25 s: the mean of 2100 to 2500, at the end of the bucket they lie in.
    { atMs: 30_000, rxBitsPerSec: 2_300, txBitsPerSec: 230 },
  ])
  // A point on a boundary closes the bucket it ends.
  expect(averaged([point(10_000, 7), point(10_001, 9)], 10_000).map((bucket) => [bucket.atMs, bucket.rxBitsPerSec])).toEqual([
    [10_000, 7],
    [20_000, 9],
  ])
  expect(averaged([], 10_000)).toEqual([])
  // A bucket of no length is no bucket: the points come back as they are.
  expect(averaged(points, 0)).toEqual(points)
})
