// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// @vitest-environment node
// (the files are read from disk)

import { readdirSync, readFileSync, statSync } from 'node:fs'
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

/** Every text file under a directory of the package, by its path from the package. */
function texts(relative: string): string[] {
  const root = fileURLToPath(new URL(`../${relative}`, import.meta.url))
  if (!statSync(root).isDirectory()) {
    return [relative]
  }
  return readdirSync(root).flatMap((name) => (/\.(woff2|png)$/.test(name) ? [] : texts(`${relative}/${name}`)))
}

test('no hardware address in the package is one a maker was assigned', () => {
  // Every word in the repository is public (the project's rule): an example address is a
  // locally administered one, never one that could be a real device's. The design system's
  // files are copied in, so they are held to it here.
  const files = ['tokens.json', 'tokens.css', 'ofo.css', 'additions.css', 'docs', 'logos', 'src', 'test'].flatMap(texts)
  expect(files.length).toBeGreaterThan(40)
  for (const file of files) {
    const text = readFileSync(fileURLToPath(new URL(`../${file}`, import.meta.url)), 'utf8')
    for (const [mac] of text.matchAll(/\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g)) {
      const locallyAdministered = (Number.parseInt(mac.slice(0, 2), 16) & 0x02) !== 0
      expect(locallyAdministered, `${file}: ${mac}`).toBe(true)
    }
  }
})
