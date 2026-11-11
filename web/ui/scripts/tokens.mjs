// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Write tokens.css from tokens.json (SPEC §8.4). tokens.json is the design system's own file,
// copied in unchanged; this turns it into the custom properties its stylesheet (ofo.css)
// reads. Dark is the default and light is its equal: light applies when the person chose it
// (`data-theme="light"` on the root) and, until they choose, when their system prefers it.
//
//   npm run tokens -w @openfeo/ui              writes tokens.css
//   npm run tokens -w @openfeo/ui -- --check   exits 1 when tokens.css is not what it would write

import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

/**
 * @typedef {{ name: string, value: string | { dark: string, light: string } }} Token
 * @typedef {{
 *   color: { tokens: Token[] },
 *   type: { fonts: { family: string, file: string, weight: string, style: string }[], families: Record<string, string> },
 *   spacing: { tokens: Token[] },
 *   radius: { tokens: Token[] },
 *   shadow: { tokens: Token[] },
 *   control: { tokens: Token[] },
 * }} Tokens
 */

/**
 * A token's value for a theme, with `{other}` turned into `var(--other)`.
 *
 * @param {Token} token
 * @param {'dark' | 'light'} theme
 */
function value(token, theme) {
  const raw = typeof token.value === 'string' ? token.value : token.value[theme]
  return raw.replace(/^\{([a-z0-9-]+)\}$/, 'var(--$1)')
}

/**
 * @param {string} selector
 * @param {[string, string][]} declarations
 * @param {string} indent
 */
function block(selector, declarations, indent = '') {
  const lines = declarations.map(([name, text]) => `${indent}  ${name}:${text};`)
  return `${indent}${selector} {\n${lines.join('\n')}\n${indent}}\n`
}

/**
 * The stylesheet for a tokens.json.
 *
 * @param {unknown} input
 * @returns {string}
 */
export function render(input) {
  const tokens = /** @type {Tokens} */ (input)
  /** @param {'dark' | 'light'} theme @returns {[string, string][]} */
  const themed = (theme) =>
    [...tokens.color.tokens, ...tokens.shadow.tokens].map((token) => [`--${token.name}`, value(token, theme)])
  /** @type {[string, string][]} */
  const fixed = [
    ...Object.entries(tokens.type.families).map(([name, stack]) => /** @type {[string, string]} */ ([`--font-${name}`, stack])),
    ...[...tokens.spacing.tokens, ...tokens.radius.tokens, ...tokens.control.tokens].map(
      (token) => /** @type {[string, string]} */ ([`--${token.name}`, value(token, 'dark')]),
    ),
  ]
  const faces = tokens.type.fonts.map((font) =>
    block('@font-face', [
      ['font-family', JSON.stringify(font.family)],
      ['src', `url("./${font.file}") format("woff2")`],
      ['font-weight', font.weight],
      ['font-style', font.style],
      ['font-display', 'swap'],
    ]),
  )
  return [
    '/* SPDX-License-Identifier: GPL-2.0-or-later */',
    '/* Copyright (C) 2026 Andrew Newton */',
    '/* Generated from tokens.json by scripts/tokens.mjs: change the tokens and run `npm run tokens`. */',
    '',
    ...faces,
    block(':root, :root[data-theme="dark"]', [...fixed, ...themed('dark')]),
    block(':root[data-theme="light"]', themed('light')),
    `@media (prefers-color-scheme: light) {\n${block(':root:not([data-theme])', themed('light'), '  ')}}\n`,
  ].join('\n')
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const source = new URL('../tokens.json', import.meta.url)
  const target = new URL('../tokens.css', import.meta.url)
  const css = render(JSON.parse(readFileSync(source, 'utf8')))
  if (process.argv.includes('--check')) {
    let held = ''
    try {
      held = readFileSync(target, 'utf8')
    } catch {
      // No file is a file that differs.
    }
    if (held !== css) {
      console.error('tokens: tokens.css is not what tokens.json gives; run `npm run tokens -w @openfeo/ui`')
      process.exit(1)
    }
    console.log('tokens: tokens.css is up to date')
  } else {
    writeFileSync(target, css)
    console.log('tokens: wrote tokens.css')
  }
}
