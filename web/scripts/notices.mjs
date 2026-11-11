// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The notices the panel ships (SPEC §13, §14): the licence text of every npm package that can
// reach the page and of the two fonts, as one text file the router serves at /licences.txt.
//
//   node web/scripts/notices.mjs <out-file>
//
// The packages are the ones the licence gate checks (lock.mjs). A package with no licence
// file stops the build: it is read by hand and dealt with, not shipped without its text.

import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { productionPackages } from './lock.mjs'

const RULE = '='.repeat(78)

/**
 * The file in a package's directory that holds its licence: `LICENSE`, `LICENCE` or
 * `COPYING` in any case and with any ending, a licence before anything else.
 *
 * @param {string[]} names
 * @returns {string | undefined}
 */
export function licenceFile(names) {
  const sorted = [...names].sort()
  return (
    sorted.find((name) => /^licen[cs]e([.-].*)?$/i.test(name)) ??
    sorted.find((name) => /^copying([.-].*)?$/i.test(name))
  )
}

/**
 * The bundled packages of a lockfile with their licence texts, read from `web`'s
 * `node_modules`, and the ones that have no licence file.
 *
 * @param {Parameters<typeof productionPackages>[0]} lock
 * @param {string} web
 * @param {Record<string, string>} kept paths of licence texts kept for packages that are
 *   published without one, by package name
 * @returns {{ packages: { name: string, version: string, license: string | undefined, text: string }[], missing: string[] }}
 */
export function gather(lock, web, kept) {
  const packages = []
  const missing = []
  for (const { name, version, license, path } of productionPackages(lock)) {
    const dir = join(web, path)
    let names = /** @type {string[]} */ ([])
    try {
      names = readdirSync(dir)
    } catch {
      // Not installed: reported as missing below.
    }
    const file = licenceFile(names)
    const from = file !== undefined ? join(dir, file) : kept[name]
    if (from === undefined) {
      missing.push(`${name}@${version}`)
    } else {
      packages.push({ name, version, license, text: readFileSync(from, 'utf8') })
    }
  }
  return { packages, missing }
}

/**
 * The notices file: the packages by name, then the fonts.
 *
 * @param {{ name: string, version: string, license: string | undefined, text: string }[]} packages
 * @param {{ name: string, text: string }[]} fonts
 * @returns {string}
 */
export function notices(packages, fonts) {
  const sorted = [...packages].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : 1,
  )
  const parts = [
    'OpenFeO panel: third-party notices',
    '',
    'The panel is part of OpenFeO and is licensed GPL-2.0-or-later. It is built with the',
    'packages below, some of which are in the page your browser runs, and it carries the two',
    'fonts that follow them. Each is given with its own licence.',
    '',
  ]
  for (const { name, version, license, text } of sorted) {
    parts.push(RULE, `${name} ${version}`, license ?? '', RULE, '', text.trim(), '')
  }
  for (const { name, text } of fonts) {
    parts.push(RULE, `${name} (font)`, 'OFL-1.1', RULE, '', text.trim(), '')
  }
  return parts.join('\n')
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const out = process.argv[2]
  if (out === undefined) {
    console.error('usage: node web/scripts/notices.mjs <out-file>')
    process.exit(2)
  }
  const web = fileURLToPath(new URL('..', import.meta.url))
  /** @type {{ texts: Record<string, string> }} */
  const { texts } = JSON.parse(readFileSync(join(web, 'scripts/licences.json'), 'utf8'))
  const kept = Object.fromEntries(Object.entries(texts).map(([name, file]) => [name, join(web, 'scripts', file)]))
  const { packages, missing } = gather(JSON.parse(readFileSync(join(web, 'package-lock.json'), 'utf8')), web, kept)
  if (missing.length > 0) {
    for (const id of missing) {
      console.error(`notices: ${id} has no licence file in node_modules; find its text and keep it under scripts/licence-texts (licences.json)`)
    }
    process.exit(1)
  }
  /** @type {{ type: { fonts: { family: string, file: string }[] } }} */
  const tokens = JSON.parse(readFileSync(join(web, 'ui/tokens.json'), 'utf8'))
  const fonts = tokens.type.fonts.map(({ family, file }) => ({
    name: family,
    text: readFileSync(join(web, 'ui', file.replace(/-Variable\.woff2$/, '-OFL.txt')), 'utf8'),
  }))
  writeFileSync(out, notices(packages, fonts))
  console.log(`notices: ${packages.length} packages and ${fonts.length} fonts in ${out}`)
}
