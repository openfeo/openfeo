// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Logs page works out (SPEC §8.4). The router answers the newest lines that match a
// level and a text, and pushes every line written after a subscription; the page joins the
// two, keeps a bounded number, marks where lines were skipped, and says when each was
// written. A line's number tells a repeat from a new line and an old line from a newer one.

import { LogLevel, type LogLine } from '@openfeo/client'

/** The most lines the page holds, shown or waiting. */
export const KEPT_LINES = 2000
/** How many lines one question asks for. */
export const PAGE_LINES = 200
/** How long after the last key a typed text is asked for. */
export const TYPING_MS = 300

/** What the page shows, top to bottom: a line, or a mark that lines were skipped there. */
export type Row = { kind: 'line'; line: LogLine } | { kind: 'gap'; key: string }

/** The router's two clocks as it last gave them (an answer or a batch carries both). */
export interface Clocks {
  uptimeMs: bigint
  timeUnixMs: bigint
}

const row = (line: LogLine): Row => ({ kind: 'line', line })

/** The number of the newest line in `rows`; 0 when there is none. */
function newest(rows: Row[]): bigint {
  for (let at = rows.length - 1; at >= 0; at--) {
    const each = rows[at]
    if (each?.kind === 'line') {
      return each.line.seq
    }
  }
  return 0n
}

/** `rows` no longer than `kept`, the oldest dropped; a mark left at the top is dropped too. */
function bounded(rows: Row[], kept: number): Row[] {
  let from = Math.max(0, rows.length - kept)
  while (rows[from]?.kind === 'gap' && from > 0) {
    from += 1
  }
  return from === 0 ? rows : rows.slice(from)
}

/**
 * What to show once the router has answered: its lines, then those that arrived live and are
 * newer. The page subscribes before it asks, so a line may come by both roads, and one that
 * came live is in the answer unless it was written after the router looked.
 */
export function joined(answer: LogLine[], live: LogLine[], kept = KEPT_LINES): Row[] {
  const last = answer.at(-1)?.seq ?? 0n
  return bounded([...answer, ...live.filter((line) => line.seq > last)].map(row), kept)
}

/** `rows` with `lines` after them: no line twice, and the oldest dropped beyond `kept`. */
export function appended(rows: Row[], lines: LogLine[], kept = KEPT_LINES): Row[] {
  const last = newest(rows)
  const fresh = lines.filter((line) => line.seq > last)
  return fresh.length === 0 ? rows : bounded([...rows, ...fresh.map(row)], kept)
}

/** `rows` with a mark at the end that lines were skipped here; never two marks together. */
export function gapped(rows: Row[]): Row[] {
  return rows.at(-1)?.kind === 'gap' ? rows : [...rows, { kind: 'gap', key: `gap-after-${String(newest(rows))}` }]
}

/**
 * What is shown once Follow is pressed: the rows that were held still, then what waited
 * meanwhile. Both are bounded alike, so when what waited was itself cut, nothing shown before
 * it is left: the top of the page is where what is kept ends, as it always is.
 */
export function resumed(shown: Row[], waiting: Row[], kept = KEPT_LINES): Row[] {
  if (waiting.length === 0) {
    return shown
  }
  // A mark that begins what waited would stand beside one that ends what is shown.
  const after = shown.at(-1)?.kind === 'gap' && waiting[0]?.kind === 'gap' ? waiting.slice(1) : waiting
  return bounded([...shown, ...after], kept)
}

/** `rows` with `lines` before them: the ones older than the oldest shown, and no line twice. */
export function preceded(rows: Row[], lines: LogLine[]): Row[] {
  const oldest = earlierThan(rows)
  const older = oldest === 0n ? lines : lines.filter((line) => line.seq < oldest)
  return older.length === 0 ? rows : [...older.map(row), ...rows]
}

/** How many lines `rows` holds, its marks aside. */
export function lineCount(rows: Row[]): number {
  return rows.reduce((count, each) => count + (each.kind === 'line' ? 1 : 0), 0)
}

/** The number of the oldest line in `rows`: what "before this" is, to ask for earlier lines. 0 when there is none. */
export function earlierThan(rows: Row[]): bigint {
  for (const each of rows) {
    if (each.kind === 'line') {
      return each.line.seq
    }
  }
  return 0n
}

/**
 * When a line was written. The router stamps a line with the time since it booted, which no
 * clock change moves, and says with every answer what both its clocks read now: the line is
 * as much older than that wall time as its stamp is behind that uptime. So a line written
 * before the clock was set shows the time it was truly written.
 */
export function writtenAt(line: LogLine, clocks: Clocks): Date {
  return new Date(Number(clocks.timeUnixMs - (clocks.uptimeMs - line.uptimeMs)))
}

/** A level as the word a line carries. A line of no level is as quiet as one can be. */
export function levelWord(level: LogLevel): 'error' | 'warn' | 'info' | 'debug' {
  switch (level) {
    case LogLevel.ERROR:
      return 'error'
    case LogLevel.WARN:
      return 'warn'
    case LogLevel.INFO:
      return 'info'
    default:
      return 'debug'
  }
}

const two = (n: number) => String(n).padStart(2, '0')

/** `14:03:05`, in the browser's zone: when a line was written, as the page says it. */
export function timeOfDay(at: Date): string {
  return `${two(at.getHours())}:${two(at.getMinutes())}:${two(at.getSeconds())}`
}

/** `<router>-log-20261128-143312.txt`: the router's name and when the file was made, in the browser's zone. */
export function fileName(hostname: string, at: Date): string {
  const day = `${String(at.getFullYear())}${two(at.getMonth() + 1)}${two(at.getDate())}`
  const time = `${two(at.getHours())}${two(at.getMinutes())}${two(at.getSeconds())}`
  return `${hostname === '' ? 'openfeo' : hostname}-log-${day}-${time}.txt`
}

/**
 * A line as the downloaded file has it: `2026-11-28T14:33:12.000Z info  api: login from …`.
 * The time is UTC, so that the file reads the same wherever it is opened; the level is padded
 * to the longest, so that the texts line up.
 */
export function fileLine(line: LogLine, clocks: Clocks): string {
  return `${writtenAt(line, clocks).toISOString()} ${levelWord(line.level).padEnd(5)} ${line.text}`
}
