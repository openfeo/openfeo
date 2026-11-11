// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// @vitest-environment node
// (the files are read from disk)

import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { expect, test } from 'vitest'

const dir = fileURLToPath(new URL('../src/components/', import.meta.url))
const components = readdirSync(dir).filter((name) => name.endsWith('.vue'))

test('no component carries a style attribute', () => {
  // The router's content security policy refuses one (SPEC §8.3): a component styled that way
  // would look right in a test and wrong in the panel.
  expect(components.length).toBeGreaterThanOrEqual(17)
  for (const name of components) {
    const source = readFileSync(dir + name, 'utf8')
    expect(source, name).not.toMatch(/\sstyle=|:style=|v-bind:style=/)
    expect(source, name).not.toMatch(/<style/)
  }
})

test('every component is exported under its own name', () => {
  const index = readFileSync(fileURLToPath(new URL('../src/index.ts', import.meta.url)), 'utf8')
  for (const name of components) {
    const component = name.replace(/\.vue$/, '')
    expect(index, component).toContain(`export { default as ${component} } from './components/${name}'`)
  }
})
