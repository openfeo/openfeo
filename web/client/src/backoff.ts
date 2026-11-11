// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// How long to wait before making a lost socket again: half a second, doubling to ten, and
// spread by chance down to half the step so that every tab does not come back at once.

const FIRST_MS = 500
const MOST_MS = 10_000

/**
 * The wait before attempt number `attempt` (0 is the first). `random` is in [0, 1): 1 would
 * give the whole step and 0 half of it.
 */
export function delayMs(attempt: number, random: number): number {
  const step = attempt >= 5 ? MOST_MS : Math.min(MOST_MS, FIRST_MS * 2 ** Math.max(0, attempt))
  return Math.round(step * (0.5 + random / 2))
}
