// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Logs page works out (SPEC §8.4): how the lines the router answered and the lines
// it pushes are joined, what is kept, where a gap is marked, when a line was written, and the
// file a download saves.

import { create, LogLevel, LogLineSchema, type LogLine } from '@openfeo/client'
import { expect, test } from 'vitest'

import { appended, earlierThan, fileLine, fileName, gapped, joined, levelWord, lineCount, preceded, resumed, timeOfDay, writtenAt, type Row } from '../src/model/logs'

const line = (seq: number, text = `line ${String(seq)}`, level = LogLevel.INFO, uptimeMs = 1_000 * seq): LogLine =>
  create(LogLineSchema, { seq: BigInt(seq), uptimeMs: BigInt(uptimeMs), level, text })
const lines = (...seqs: number[]) => seqs.map((seq) => line(seq))
/** A row's number, or `gap`. */
const said = (rows: Row[]) => rows.map((row) => (row.kind === 'line' ? Number(row.line.seq) : 'gap'))

test('a line that came by both roads is shown once', () => {
  // The page subscribes first and asks second: what arrives meanwhile may be in the answer too.
  expect(said(joined(lines(38, 39, 40), lines(39, 40, 41)))).toEqual([38, 39, 40, 41])
  expect(said(joined(lines(38, 40), lines(41, 43)))).toEqual([38, 40, 41, 43])
  // Nothing matched when the router looked: whatever came live was written after.
  expect(said(joined([], lines(41, 42)))).toEqual([41, 42])
  expect(said(joined(lines(38), []))).toEqual([38])
  expect(joined([], [])).toEqual([])
  // A slow answer and a busy router: the bound holds here too, and the newest are kept.
  expect(said(joined(lines(1, 2, 3), lines(4, 5), 4))).toEqual([2, 3, 4, 5])
})

test('lines are appended once, and the oldest go beyond the bound', () => {
  const rows = joined(lines(1, 2, 3), [])
  expect(said(appended(rows, lines(3, 4)))).toEqual([1, 2, 3, 4])
  expect(said(appended(rows, lines(2)))).toEqual([1, 2, 3])
  expect(said(appended(rows, lines(4, 5, 6), 5))).toEqual([2, 3, 4, 5, 6])
  // A mark left at the top says nothing: what it stood between is gone.
  const marked = appended(gapped(joined(lines(1), [])), lines(5, 6))
  expect(said(marked)).toEqual([1, 'gap', 5, 6])
  expect(said(appended(marked, lines(7), 4))).toEqual([5, 6, 7])
  expect(said(appended(marked, lines(7), 3))).toEqual([5, 6, 7])
  // Nothing to add changes nothing, and the same rows are handed back.
  expect(appended(rows, [])).toBe(rows)
})

test('a gap is marked once', () => {
  const rows = joined(lines(1, 2), [])
  const once = gapped(rows)
  expect(said(once)).toEqual([1, 2, 'gap'])
  expect(gapped(once)).toBe(once)
  // Each mark has a name of its own, for the page to keep its place by.
  const twice = gapped(appended(once, lines(9)))
  expect(said(twice)).toEqual([1, 2, 'gap', 9, 'gap'])
  const keys = twice.flatMap((row) => (row.kind === 'gap' ? [row.key] : []))
  expect(new Set(keys).size).toBe(2)
  // Before any line, a mark says that the first lines were missed.
  expect(said(gapped([]))).toEqual(['gap'])
})

test('what waited while paused goes after what is shown', () => {
  const shown = joined(lines(1, 2), [])
  expect(said(resumed(shown, appended([], lines(3, 4))))).toEqual([1, 2, 3, 4])
  // A loss told while paused keeps its place among what waited; a mark is never doubled.
  const lossy = appended(gapped(appended([], lines(3))), lines(9))
  expect(said(resumed(shown, lossy))).toEqual([1, 2, 3, 'gap', 9])
  expect(said(resumed(gapped(shown), appended(gapped([]), lines(9))))).toEqual([1, 2, 'gap', 9])
  // The bound holds, the newest kept: the top of the page is where what is kept ends.
  expect(said(resumed(shown, appended([], lines(7, 8, 9)), 3))).toEqual([7, 8, 9])
  expect(resumed(shown, [])).toBe(shown)
  // What waited and is already shown is not shown again.
  expect(said(resumed(shown, appended([], lines(2, 3))))).toEqual([1, 2, 3])
  expect(resumed(shown, appended([], lines(1, 2)))).toBe(shown)
})

test('earlier lines go on top, once', () => {
  const shown = joined(lines(38, 39), [])
  expect(said(preceded(shown, lines(30, 31)))).toEqual([30, 31, 38, 39])
  // A line already shown, or newer than the oldest shown, is not an earlier one.
  expect(said(preceded(shown, lines(37, 38, 40)))).toEqual([37, 38, 39])
  expect(preceded(shown, [])).toBe(shown)
  expect(said(preceded([], lines(1, 2)))).toEqual([1, 2])
})

test('a time of day is hours, minutes and seconds', () => {
  expect(timeOfDay(new Date(2026, 10, 28, 14, 3, 5))).toBe('14:03:05')
  expect(timeOfDay(new Date(2026, 10, 28, 0, 0, 0))).toBe('00:00:00')
})

test('the lines are counted without their marks, and the oldest is known', () => {
  const rows = gapped(joined(lines(5, 6), []))
  expect(lineCount(rows)).toBe(2)
  expect(earlierThan(rows)).toBe(5n)
  expect(earlierThan(gapped([]))).toBe(0n)
})

test('a line’s time is counted back from the router’s two clocks', () => {
  const T = Date.UTC(2026, 10, 28, 14, 33, 12)
  const clocks = { uptimeMs: 600_000n, timeUnixMs: BigInt(T) }
  // Written a minute before the clocks were read: a minute before that wall time, whatever the
  // router's clock said when it was written.
  expect(writtenAt(line(1, 'x', LogLevel.INFO, 540_000), clocks).getTime()).toBe(T - 60_000)
  expect(writtenAt(line(1, 'x', LogLevel.INFO, 600_000), clocks).getTime()).toBe(T)
  // A line of the first second of the boot, on a router whose clock was set ten minutes later.
  expect(writtenAt(line(1, 'x', LogLevel.INFO, 800), clocks).getTime()).toBe(T - 599_200)
})

test('a level is said as a word', () => {
  expect([LogLevel.ERROR, LogLevel.WARN, LogLevel.INFO, LogLevel.DEBUG].map(levelWord)).toEqual(['error', 'warn', 'info', 'debug'])
  expect(levelWord(LogLevel.UNSPECIFIED)).toBe('debug')
})

test('the file is named for the router and the time', () => {
  expect(fileName('openfeo', new Date(2026, 10, 28, 14, 33, 12))).toBe('openfeo-log-20261128-143312.txt')
  expect(fileName('edge', new Date(2026, 0, 2, 3, 4, 5))).toBe('edge-log-20260102-030405.txt')
  // A router that has not said its name yet still gets a file.
  expect(fileName('', new Date(2026, 0, 2, 3, 4, 5))).toBe('openfeo-log-20260102-030405.txt')
})

test('the file has one line for each line', () => {
  const T = Date.UTC(2026, 10, 28, 14, 33, 12)
  const clocks = { uptimeMs: 600_000n, timeUnixMs: BigInt(T) }
  expect(fileLine(line(7, 'api: login from 192.168.1.142', LogLevel.INFO, 600_000), clocks)).toBe('2026-11-28T14:33:12.000Z info  api: login from 192.168.1.142')
  expect(fileLine(line(8, 'sntp: no answer from 203.0.113.1', LogLevel.ERROR, 599_500), clocks)).toBe('2026-11-28T14:33:11.500Z error sntp: no answer from 203.0.113.1')
  expect(fileLine(line(9, 'pppoe wan0: 3 echoes unanswered', LogLevel.WARN, 0), clocks)).toBe('2026-11-28T14:23:12.000Z warn  pppoe wan0: 3 echoes unanswered')
  // The router keeps a line to one line: what was a newline in a device's name arrives spelled out.
  const odd = fileLine(line(10, 'dhcp lan0: leased to plug\\nkitchen', LogLevel.DEBUG, 600_000), clocks)
  expect(odd).toBe('2026-11-28T14:33:12.000Z debug dhcp lan0: leased to plug\\nkitchen')
  expect(odd.split('\n')).toHaveLength(1)
})
