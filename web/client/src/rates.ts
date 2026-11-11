// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The router keeps no history and computes no rates (SPEC §10): it sends counters, each
// sample stamped with when it was read. Two samples and their own clock give a rate, which
// stays right when a slow reader is sent only the latest one.

import type { Counters } from './gen/openfeo/v1/state_pb.js'

export interface LinkRate {
  /** The link's name, as the kernel has it. */
  name: string
  /** Received, in bits per second. */
  rxBitsPerSec: number
  /** Sent, in bits per second. */
  txBitsPerSec: number
}

/** Bits per second for a byte counter that moved from `before` to `after` in `ms`. */
function bitsPerSec(before: bigint, after: bigint, ms: number): number {
  // A counter that went backwards belongs to an interface made anew: no rate for that second.
  return after < before ? 0 : (Number(after - before) * 8_000) / ms
}

/**
 * The rate of every link that is in both samples, in `next`'s order. Samples that are not
 * in order, or were read at the same instant, give nothing.
 */
export function rates(previous: Counters, next: Counters): LinkRate[] {
  const ms = Number(next.monotonicMs - previous.monotonicMs)
  if (!(ms > 0)) {
    return []
  }
  const before = new Map(previous.links.map((link) => [link.name, link]))
  const found: LinkRate[] = []
  for (const link of next.links) {
    const earlier = before.get(link.name)
    if (earlier !== undefined) {
      found.push({
        name: link.name,
        rxBitsPerSec: bitsPerSec(earlier.rxBytes, link.rxBytes, ms),
        txBitsPerSec: bitsPerSec(earlier.txBytes, link.txBytes, ms),
      })
    }
  }
  return found
}
