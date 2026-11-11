// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { correction, PATHS } from '../src/routes'

test('a gate screen has one address, and any other is corrected to it', () => {
  expect(correction('login', '/login')).toBeNull()
  expect(correction('login', '/')).toBe('/login')
  expect(correction('login', '/first-password')).toBe('/login')
  expect(correction('first-password', '/')).toBe('/first-password')
  expect(correction('first-password', '/login')).toBe('/first-password')
  expect(correction('config-unreadable', '/login')).toBe('/config-unreadable')
  expect(correction('config-unreadable', '/config-unreadable')).toBeNull()
})

test('on the dashboard a gate address goes home, and any other stays where it is', () => {
  expect(correction('dashboard', '/')).toBeNull()
  expect(correction('dashboard', '/login')).toBe('/')
  expect(correction('dashboard', '/first-password')).toBe('/')
  expect(correction('dashboard', '/config-unreadable')).toBe('/')
  // A page a later part adds is the dashboard's neighbour, not a gate.
  expect(correction('dashboard', '/wan')).toBeNull()
})

test('every screen has an address of its own', () => {
  expect(new Set(Object.values(PATHS)).size).toBe(4)
  expect(PATHS.dashboard).toBe('/')
})
