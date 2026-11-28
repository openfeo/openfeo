// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The notices the router ships (SPEC §13, §14), as one text file it serves at /licences.txt:
// the Rust crates in the binary (written by `cargo about`, scripts/rust-notices.sh), the C
// libraries linked into it (c-notices.json), every npm package that can reach the page, and
// the two fonts.
//
//   node web/scripts/notices.mjs --rust <cargo-about's-output> --c <nft-src-dir> <out-file>
//
// The packages are the ones the licence gate checks (lock.mjs). A package or a library with no
// licence text stops the build: it is read by hand and dealt with, not shipped without it.

import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { productionPackages } from './lock.mjs'

const RULE = '='.repeat(78)
/** Above and below the title of a part. */
const PART = '#'.repeat(78)

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
 * The C libraries' notices, in the order of `entries`. An entry names a library and its
 * licence, and says where its text is: `file`, a path in the library's source tree under
 * `srcDir` (as nft/fetch.sh leaves it, `<source>-<version>/`); `comment`, a source file there
 * whose first comment is the notice; or `kept`, a text under `keptDir`. Its version is the one
 * `sources` (nft/sources.txt) pins for its `source`, or its own `version` when it comes from
 * nowhere there; an entry `within` another's tree is said to be in it. Every library in
 * `sources` must have an entry of its own with a `file`.
 *
 * @param {{ name: string, source?: string, within?: boolean, version?: string, licence: string, file?: string, comment?: string, kept?: string }[]} entries
 * @param {string} sources
 * @param {string} srcDir
 * @param {string} keptDir
 * @returns {{ name: string, version: string, licence: string, text: string }[]}
 */
export function cNotices(entries, sources, srcDir, keptDir) {
  const pinned = new Map(
    sources
      .split('\n')
      .filter((line) => line.trim() !== '' && !line.startsWith('#'))
      .map((line) => /** @type {[string, string]} */ (line.split(/\s+/).slice(0, 2))),
  )
  for (const name of pinned.keys()) {
    if (!entries.some((entry) => entry.source === name && entry.file !== undefined && entry.within !== true)) {
      throw new Error(`notices: ${name} is built into the binary (nft/sources.txt) and has no notice of its own in c-notices.json`)
    }
  }
  return entries.map((entry) => {
    const pin = entry.source === undefined ? undefined : pinned.get(entry.source)
    if (entry.source !== undefined && pin === undefined) {
      throw new Error(`notices: ${entry.name} is said to come from ${entry.source}, which nft/sources.txt does not have`)
    }
    const version = pin === undefined ? (entry.version ?? '') : entry.within === true ? `(in ${entry.source} ${pin})` : pin
    const inTree = entry.file ?? entry.comment
    const from = inTree !== undefined ? join(srcDir, `${entry.source}-${pin}`, inTree) : join(keptDir, entry.kept ?? '')
    let text
    try {
      text = readFileSync(from, 'utf8')
    } catch {
      throw new Error(`notices: no notice for ${entry.name}: ${from} cannot be read`)
    }
    if (entry.comment !== undefined) {
      const comment = /\/\*([\s\S]*?)\*\//.exec(text)
      if (comment === null) {
        throw new Error(`notices: no notice for ${entry.name}: ${from} begins with no comment`)
      }
      text = (comment[1] ?? '')
        .split('\n')
        .map((line) => line.replace(/^ \* ?/, ''))
        .join('\n')
        .trim()
    }
    return { name: entry.name, version, licence: entry.licence, text }
  })
}

/**
 * The notices file: what `cargo about` wrote of the Rust crates, the C libraries, the npm
 * packages by name, then the fonts, each part under its title. A part with nothing in it is
 * left out.
 *
 * @param {{
 *   rust?: string,
 *   c?: { name: string, version: string, licence: string, text: string }[],
 *   packages?: { name: string, version: string, license: string | undefined, text: string }[],
 *   fonts?: { name: string, text: string }[],
 * }} parts
 * @returns {string}
 */
export function notices({ rust = '', c = [], packages = [], fonts = [] }) {
  const sorted = [...packages].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : 1,
  )
  const lines = [
    'OpenFeO: third-party notices',
    '',
    'OpenFeO is licensed GPL-2.0-or-later. Its binary is built with the Rust crates and the C',
    'libraries below, and the panel it serves with the npm packages and the two fonts that',
    'follow them, some of which are in the page your browser runs. Each is given with its own',
    'licence.',
    '',
  ]
  const title = (/** @type {string} */ text) => lines.push(PART, text, PART, '')
  if (rust.trim() !== '') {
    title('The router: Rust crates')
    lines.push(rust.replace(/\n+$/, ''), '')
  }
  if (c.length > 0) {
    title('The router: C libraries')
    for (const { name, version, licence, text } of c) {
      lines.push(RULE, `${name} ${version}`.trim(), licence, RULE, '', text.trim(), '')
    }
  }
  if (sorted.length > 0) {
    title('The panel: npm packages')
    for (const { name, version, license, text } of sorted) {
      lines.push(RULE, `${name} ${version}`, license ?? '', RULE, '', text.trim(), '')
    }
  }
  if (fonts.length > 0) {
    title('The panel: fonts')
    for (const { name, text } of fonts) {
      lines.push(RULE, `${name} (font)`, 'OFL-1.1', RULE, '', text.trim(), '')
    }
  }
  return lines.join('\n')
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2)
  /** @type {Record<string, string>} */
  const given = {}
  while (args[0]?.startsWith('--')) {
    const [flag, value] = args.splice(0, 2)
    given[String(flag)] = String(value)
  }
  const [out] = args
  const { '--rust': rustFile, '--c': srcDir } = given
  if (out === undefined || rustFile === undefined || srcDir === undefined || args.length !== 1) {
    console.error("usage: node web/scripts/notices.mjs --rust <cargo-about's-output> --c <nft-src-dir> <out-file>")
    process.exit(2)
  }
  const web = fileURLToPath(new URL('..', import.meta.url))
  const scripts = join(web, 'scripts')
  /** @type {{ texts: Record<string, string> }} */
  const { texts } = JSON.parse(readFileSync(join(scripts, 'licences.json'), 'utf8'))
  const kept = Object.fromEntries(Object.entries(texts).map(([name, file]) => [name, join(scripts, file)]))
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
  let c
  try {
    c = cNotices(
      JSON.parse(readFileSync(join(scripts, 'c-notices.json'), 'utf8')),
      readFileSync(join(web, '../nft/sources.txt'), 'utf8'),
      srcDir,
      scripts,
    )
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
  }
  const rust = readFileSync(rustFile, 'utf8')
  if (rust.trim() === '') {
    console.error(`notices: ${rustFile} is empty: cargo about wrote no notice (scripts/rust-notices.sh)`)
    process.exit(1)
  }
  writeFileSync(out, notices({ rust, c, packages, fonts }))
  console.log(`notices: the Rust crates, ${c.length} C libraries, ${packages.length} packages and ${fonts.length} fonts in ${out}`)
}
