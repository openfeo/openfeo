// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A place in the config as the router writes one, and what is at or beneath another.

import { expect, test } from 'vitest'

import { fromItem, under } from '../src/model/path'

test('a path is under itself, a field of itself and an item of itself, and under no namesake', () => {
  expect(under('lans[0].dhcp.range', 'lans[0].dhcp.range')).toBe(true)
  expect(under('lans[0].dhcp.range[1]', 'lans[0].dhcp.range')).toBe(true)
  expect(under('lans[0].dhcp.static[2].ip', 'lans[0].dhcp')).toBe(true)
  expect(under('lans[0].dhcp.range_end', 'lans[0].dhcp.range')).toBe(false)
  expect(under('lans[10].ipv4', 'lans[1]')).toBe(false)
})

test('the items of a list from a place on are those whose places change when that one goes', () => {
  const list = 'lans[0].dhcp.static'
  expect(fromItem('lans[0].dhcp.static[0].ip', list, 1)).toBe(false)
  expect(fromItem('lans[0].dhcp.static[1]', list, 1)).toBe(true)
  expect(fromItem('lans[0].dhcp.static[1].ip', list, 1)).toBe(true)
  expect(fromItem('lans[0].dhcp.static[12].mac', list, 2)).toBe(true)
  // The list itself, another LAN's list and a field that only starts alike are not items of it.
  expect(fromItem('lans[0].dhcp.static', list, 0)).toBe(false)
  expect(fromItem('lans[1].dhcp.static[3].ip', list, 0)).toBe(false)
  expect(fromItem('lans[0].dhcp.statics[3]', list, 0)).toBe(false)
  // A list at the top, and items of items.
  expect(fromItem('lans[2].dhcp.static[0].ip', 'lans', 1)).toBe(true)
  expect(fromItem('lans[0].dhcp.static[5].ip', 'lans', 1)).toBe(false)
  expect(fromItem('wans[1].port', 'lans', 0)).toBe(false)
})
