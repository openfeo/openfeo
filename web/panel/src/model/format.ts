// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// How the panel writes a number (the design system's voice): a unit always, rates to one
// decimal, and a dash where there is nothing to say rather than a zero that looks like a fact.

const RATE_UNITS = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'] as const
export type RateUnit = (typeof RATE_UNITS)[number]

/** What is shown where a number would be and there is none. */
export const DASH = '—'

/** A rate in the largest unit that keeps it under a thousand, to one decimal. */
export function rate(bitsPerSec: number): { value: string; unit: RateUnit } {
  if (!Number.isFinite(bitsPerSec) || bitsPerSec < 0) {
    return { value: DASH, unit: 'bit/s' }
  }
  let scaled = bitsPerSec
  let unit = 0
  // Judged as it will be written: 999.96 is "1000.0" to one decimal, which is the next unit's 1.0.
  while (unit < RATE_UNITS.length - 1 && Math.round(scaled * 10) / 10 >= 1000) {
    scaled /= 1000
    unit += 1
  }
  return { value: scaled.toFixed(1), unit: RATE_UNITS[unit] ?? 'bit/s' }
}

/** A length of time by its two largest units: `3d 4h`, `4h 12m`, `12m 5s`, `42s`. */
export function duration(secs: number): string {
  const whole = Number.isFinite(secs) && secs > 0 ? Math.floor(secs) : 0
  const days = Math.floor(whole / 86_400)
  const hours = Math.floor((whole % 86_400) / 3_600)
  const minutes = Math.floor((whole % 3_600) / 60)
  const seconds = whole % 60
  if (days > 0) {
    return `${days}d ${hours}h`
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`
  }
  return `${seconds}s`
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const two = (n: number) => String(n).padStart(2, '0')

/** A date and a time to the minute, in the reader's own zone: `7 Nov 09:14`. */
export function since(unixMs: bigint): string {
  const at = new Date(Number(unixMs))
  return `${at.getDate()} ${MONTHS[at.getMonth()] ?? ''} ${two(at.getHours())}:${two(at.getMinutes())}`
}

/** A time today as a clock to the second; any other day with its date, to the minute. */
export function clock(unixMs: bigint, now: Date): string {
  const at = new Date(Number(unixMs))
  const today = at.getFullYear() === now.getFullYear() && at.getMonth() === now.getMonth() && at.getDate() === now.getDate()
  return today ? `${two(at.getHours())}:${two(at.getMinutes())}:${two(at.getSeconds())}` : since(unixMs)
}

/**
 * What a port's label says beside its light, so that the light is never the only sign: its
 * speed, a dash with no cable, and `up` when it has a link whose speed the driver does not say.
 */
export function portSpeed(port: { carrier: boolean; speedMbps?: number | undefined }): string {
  if (!port.carrier) {
    return DASH
  }
  const mbps = port.speedMbps ?? 0
  if (mbps <= 0) {
    return 'up'
  }
  return mbps < 1000 ? `${mbps}M` : `${mbps / 1000}G`
}
