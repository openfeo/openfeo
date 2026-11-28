// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Ports page makes of the state and the counters (SPEC §8.4).

import { expect, test } from 'vitest'

import { portRows } from '../src/model/ports'
import { counters, state } from './fixtures'

const SAMPLE = counters(5_000n, [
  ['p0', 412_800_000_000n, 38_100_000_000n],
  ['p1', 31_000_000_000n, 388_400_000_000n],
  ['p2', 0n, 0n],
  ['br-lan0', 9n, 9n],
])

test('a row for each port, in port order', () => {
  const rows = portRows(state(), SAMPLE)
  expect(rows.map((row) => row.name)).toEqual(['p0', 'p1', 'p2', 'p3'])
  expect(rows.map((row) => [row.up, row.speed])).toEqual([
    [true, '2500 Mbit/s'],
    [true, '2500 Mbit/s'],
    [false, ''],
    [true, '1000 Mbit/s'],
  ])
  expect(rows[0]).toMatchObject({ mac: '52:54:00:12:34:00', hardware: 'pci-0000:01:00.0' })
  // A link that is up and whose driver says no speed is up, and no more is said.
  const quiet = state()
  quiet.ports[0]!.speedMbps = undefined
  expect(portRows(quiet, SAMPLE)[0]).toMatchObject({ up: true, speed: '' })
})

test('a use is a link to its WAN’s or LAN’s page, with its tag', () => {
  const rows = portRows(state(), SAMPLE)
  expect(rows[0]?.uses).toEqual([{ to: '/wan/wan0', name: 'wan0', tag: 911 }])
  expect(rows[1]?.uses).toEqual([{ to: '/lan/lan0', name: 'lan0', tag: 0 }])
  expect(rows[3]?.uses).toEqual([
    { to: '/lan/lan0', name: 'lan0', tag: 0 },
    { to: '/lan/iot', name: 'iot', tag: 20 },
  ])
  const unused = state()
  unused.ports[2]!.uses = []
  expect(portRows(unused, SAMPLE)[2]?.uses).toEqual([])
})

test('the counters are the port’s own link’s', () => {
  const rows = portRows(state(), SAMPLE)
  expect(rows.map((row) => [row.received, row.sent])).toEqual([
    ['412.8 GB', '38.1 GB'],
    ['31.0 GB', '388.4 GB'],
    ['0 B', '0 B'],
    // A port the sample does not name.
    ['—', '—'],
  ])
})

test('no sample yet is a dash', () => {
  expect(portRows(state(), null).map((row) => [row.received, row.sent])).toEqual([
    ['—', '—'],
    ['—', '—'],
    ['—', '—'],
    ['—', '—'],
  ])
})
