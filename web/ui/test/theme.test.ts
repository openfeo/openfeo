// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { applyTheme, chooseTheme, storedTheme, systemTheme, THEME_KEY } from '../src/theme'

function storage(initial: Record<string, string> = {}) {
  const held = new Map(Object.entries(initial))
  return {
    getItem: (key: string) => held.get(key) ?? null,
    setItem: (key: string, value: string) => void held.set(key, value),
    held,
  }
}

test('a stored choice wins, anything else stored is no choice', () => {
  expect(THEME_KEY).toBe('openfeo.theme')
  expect(storedTheme(storage({ 'openfeo.theme': 'light' }))).toBe('light')
  expect(storedTheme(storage({ 'openfeo.theme': 'dark' }))).toBe('dark')
  expect(storedTheme(storage({ 'openfeo.theme': 'blue' }))).toBeNull()
  expect(storedTheme(storage())).toBeNull()
})

test('a store that throws is no choice', () => {
  const broken = {
    getItem: () => {
      throw new Error('storage is blocked')
    },
  }
  expect(storedTheme(broken)).toBeNull()
})

test('the system prefers light or it is dark', () => {
  expect(systemTheme(true)).toBe('light')
  expect(systemTheme(false)).toBe('dark')
})

test('applying no choice removes the attribute so the system decides', () => {
  const root = document.createElement('html')
  applyTheme(root, 'light')
  expect(root.getAttribute('data-theme')).toBe('light')
  applyTheme(root, 'dark')
  expect(root.getAttribute('data-theme')).toBe('dark')
  applyTheme(root, null)
  expect(root.hasAttribute('data-theme')).toBe(false)
})

test('choosing stores and applies', () => {
  const root = document.createElement('html')
  const store = storage()
  chooseTheme(root, store, 'light')
  expect(root.getAttribute('data-theme')).toBe('light')
  expect(store.held.get('openfeo.theme')).toBe('light')
})

test('choosing still applies when the choice cannot be stored', () => {
  const root = document.createElement('html')
  const broken = {
    setItem: () => {
      throw new Error('storage is full')
    },
  }
  chooseTheme(root, broken, 'light')
  expect(root.getAttribute('data-theme')).toBe('light')
})
