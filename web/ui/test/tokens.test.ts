// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// @vitest-environment node
// (the files are read from disk: under a DOM environment a module has no file address)

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { expect, test } from 'vitest'

import { render } from '../scripts/tokens.mjs'

const at = (name: string) => fileURLToPath(new URL(`../${name}`, import.meta.url))
const tokens: unknown = JSON.parse(readFileSync(at('tokens.json'), 'utf8'))
const tokensCss = readFileSync(at('tokens.css'), 'utf8')
const ofoCss = readFileSync(at('ofo.css'), 'utf8')

test('every variable the stylesheet uses is defined', () => {
  const used = new Set([...ofoCss.matchAll(/var\((--[a-z0-9-]+)/g)].map((match) => match[1]))
  expect(used.size).toBeGreaterThan(30)
  for (const name of used) {
    expect(tokensCss, name).toContain(`${name}:`)
  }
})

test('an alias becomes a var()', () => {
  const css = render(tokens)
  expect(css).toContain('--link:var(--info);')
  expect(css).toContain('--series-1:var(--oxide);')
  expect(css).not.toContain('{info}')
})

test('dark is the default, and light follows the system until the person chooses', () => {
  const css = render(tokens)
  expect(css).toMatch(/:root,\s*:root\[data-theme="dark"\]\s*\{[^}]*--ground:#0e1114;/)
  expect(css).toMatch(/:root\[data-theme="light"\]\s*\{[^}]*--ground:#f3f4f5;/)
  expect(css).toMatch(
    /@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme\]\)\s*\{[^}]*--ground:#f3f4f5;/,
  )
  // What does not change with the theme is said once.
  expect(css.match(/--space-4:16px;/g)).toHaveLength(1)
  expect(css.match(/--radius-md:6px;/g)).toHaveLength(1)
  expect(css.match(/--control-md:36px;/g)).toHaveLength(1)
  // The shadow does change with it.
  expect(css.match(/--shadow-pop:/g)).toHaveLength(3)
})

test('the light values are the same whether chosen or followed', () => {
  const css = render(tokens)
  const chosen = /:root\[data-theme="light"\]\s*\{([^}]*)\}/.exec(css)?.[1]
  const followed = /:root:not\(\[data-theme\]\)\s*\{([^}]*)\}/.exec(css)?.[1]
  expect(chosen).toBeDefined()
  expect(chosen?.replace(/\s+/g, '')).toBe(followed?.replace(/\s+/g, ''))
})

test('both fonts are declared from files that exist', () => {
  const css = render(tokens)
  const faces = [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].map((match) => match[1] ?? '')
  expect(faces).toHaveLength(2)
  for (const face of faces) {
    expect(face).toContain('font-display:swap;')
    const file = /url\("\.\/(fonts\/[^"]+\.woff2)"\) format\("woff2"\)/.exec(face)?.[1]
    expect(file, face).toBeDefined()
    expect(existsSync(at(file ?? '')), file).toBe(true)
  }
  expect(css).toContain('font-family:"Instrument Sans";')
  expect(css).toContain('font-weight:400 700;')
  expect(css).toContain('font-family:"JetBrains Mono";')
})

test('the file names its licence and says it is generated', () => {
  const head = render(tokens).split('\n').slice(0, 4).join('\n')
  expect(head).toContain('SPDX-License-Identifier: GPL-2.0-or-later')
  expect(head).toContain('Copyright (C) 2026 Andrew Newton')
  expect(head).toMatch(/generated/i)
})

test('tokens.css is what the script writes', () => {
  expect(tokensCss).toBe(render(tokens))
})
