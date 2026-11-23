// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The router keeps the last hour of each link's byte counters, a sample a second, and
// computes no rates (SPEC §10). These make rates of that history by the rule `rates` reads
// two live samples by, so that a chart's past and its present agree; and they average those
// rates over buckets, for a view too long to draw each second of.

import type { LinkHistory } from './gen/openfeo/v1/state_pb.js'

/** One reading of a link's byte counters. */
export interface LinkSample {
  /** When it was read, in milliseconds on the router's boot clock (`Counters.monotonicMs`). */
  atMs: number
  rxBytes: bigint
  txBytes: bigint
}

/** A link's rates over one stretch between two samples. */
export interface RatePoint {
  /** When the later of its two samples was read. */
  atMs: number
  /** Received, in bits per second. */
  rxBitsPerSec: number
  /** Sent, in bits per second. */
  txBitsPerSec: number
}

/**
 * Samples further apart than this have no rate between them. The router reads once a second;
 * a longer silence is a link that was not there (a PPPoE interface between sessions) or reads
 * that failed, and what passed in it is unknown, not an average.
 */
export const GAP_MS = 5_000

/** A history's samples, oldest first. A list shorter than the others gives no sample for what it lacks. */
export function samplesOf(history: LinkHistory): LinkSample[] {
  const samples: LinkSample[] = []
  for (const [at, read] of history.monotonicMs.entries()) {
    const rxBytes = history.rxBytes[at]
    const txBytes = history.txBytes[at]
    if (rxBytes !== undefined && txBytes !== undefined) {
      samples.push({ atMs: Number(read), rxBytes, txBytes })
    }
  }
  return samples
}

/**
 * A rate for each sample after the first, from it and the one before. There is none where
 * time did not move on, none across a gap ({@link GAP_MS}), and none where a counter went
 * backwards: an interface made anew starts counting from nothing, and that second says
 * nothing of the line (live, it reads zero for a moment; drawn, zero would be a drop that
 * did not happen).
 */
export function ratesOver(samples: readonly LinkSample[]): RatePoint[] {
  const points: RatePoint[] = []
  let before: LinkSample | undefined
  for (const sample of samples) {
    if (before !== undefined) {
      const ms = sample.atMs - before.atMs
      if (!(ms > 0)) {
        // Out of order, or read twice: it is not a later reading, so the one before stands.
        continue
      }
      if (ms <= GAP_MS && sample.rxBytes >= before.rxBytes && sample.txBytes >= before.txBytes) {
        points.push({
          atMs: sample.atMs,
          rxBitsPerSec: (Number(sample.rxBytes - before.rxBytes) * 8_000) / ms,
          txBitsPerSec: (Number(sample.txBytes - before.txBytes) * 8_000) / ms,
        })
      }
    }
    before = sample
  }
  return points
}

/**
 * The mean of the points in each bucket that has any, placed at the bucket's end. Buckets are
 * `bucketMs` long and aligned to its multiples, each holding the points after its start up to
 * and at its end; one with no point is absent. With no length to a bucket the points come back
 * as they are.
 */
export function averaged(points: readonly RatePoint[], bucketMs: number): RatePoint[] {
  if (!(bucketMs > 0)) {
    return [...points]
  }
  const buckets = new Map<number, { rx: number; tx: number; count: number }>()
  for (const point of points) {
    const end = Math.ceil(point.atMs / bucketMs) * bucketMs
    const bucket = buckets.get(end) ?? { rx: 0, tx: 0, count: 0 }
    bucket.rx += point.rxBitsPerSec
    bucket.tx += point.txBitsPerSec
    bucket.count += 1
    buckets.set(end, bucket)
  }
  return [...buckets.entries()]
    .sort(([a], [b]) => a - b)
    .map(([atMs, bucket]) => ({ atMs, rxBitsPerSec: bucket.rx / bucket.count, txBitsPerSec: bucket.tx / bucket.count }))
}
