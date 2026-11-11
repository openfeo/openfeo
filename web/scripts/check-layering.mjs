// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The rule between the three packages (SPEC §8.4), checked the way the Rust dependency rules
// are: the components know nothing of the API, the client has no UI in it, and the panel
// reaches the wire only through the client.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** @type {Record<string, { forbidden: (specifier: string) => string | null }>} */
const RULES = {
  client: {
    forbidden: (specifier) =>
      /^(vue|vue-router|pinia)($|\/)|^@vue\//.test(specifier)
        ? 'the client has no Vue in it'
        : /^@openfeo\/ui($|\/)/.test(specifier) || /(^|\/)(ui|panel)\/src\//.test(specifier)
          ? 'the client knows neither the components nor the panel'
          : null,
  },
  ui: {
    forbidden: (specifier) =>
      /^@openfeo\/client($|\/)|^@bufbuild\//.test(specifier) || /(^|\/)(client|panel)\/src\//.test(specifier)
        ? 'the components know nothing of the API'
        : null,
  },
  panel: {
    forbidden: (specifier) =>
      /^@openfeo\/client\/.+/.test(specifier) || /(^|\/)client\/src\//.test(specifier) || /^@bufbuild\//.test(specifier)
        ? 'the panel reaches the wire and its messages only through @openfeo/client'
        : null,
  },
}

/**
 * The source with its comments blanked out, strings left as they are.
 *
 * @param {string} source
 */
function withoutComments(source) {
  let out = ''
  let i = 0
  /** @type {string | null} */
  let quote = null
  while (i < source.length) {
    const ch = source[i]
    const next = source[i + 1]
    if (quote !== null) {
      out += ch
      if (ch === '\\') {
        out += next ?? ''
        i += 2
        continue
      }
      if (ch === quote) {
        quote = null
      }
      i += 1
    } else if (ch === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') {
        i += 1
      }
    } else if (ch === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2)
      i = end < 0 ? source.length : end + 2
      out += ' '
    } else {
      if (ch === "'" || ch === '"' || ch === '`') {
        quote = ch
      }
      out += ch
      i += 1
    }
  }
  return out
}

/**
 * Every module a source names: after `from`, in a bare `import '…'`, or in `import('…')`.
 *
 * @param {string} source
 * @returns {string[]}
 */
function specifiers(source) {
  const code = withoutComments(source)
  const found = []
  for (const pattern of [
    /\bfrom\s*(['"])([^'"\n]+)\1/g,
    /\bimport\s*(['"])([^'"\n]+)\1/g,
    /\bimport\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g,
  ]) {
    for (const match of code.matchAll(pattern)) {
      if (match[2] !== undefined) {
        found.push(match[2])
      }
    }
  }
  return found
}

/**
 * The imports that break the rule, one line each. `path` is relative to `web/` and its first
 * segment names the package.
 *
 * @param {{ path: string, source: string }[]} files
 * @returns {string[]}
 */
export function violations(files) {
  const found = []
  for (const { path, source } of files) {
    const rule = RULES[path.split('/')[0] ?? '']
    if (rule === undefined) {
      continue
    }
    for (const specifier of specifiers(source)) {
      const why = rule.forbidden(specifier)
      if (why !== null) {
        found.push(`${path}: imports '${specifier}': ${why}`)
      }
    }
  }
  return found
}

/**
 * @param {string} dir
 * @returns {string[]}
 */
function walk(dir) {
  let entries
  try {
    entries = readdirSync(dir)
  } catch {
    return []
  }
  return entries.flatMap((entry) => {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) {
      return entry === 'gen' || entry === 'node_modules' ? [] : walk(path)
    }
    return /\.(ts|vue)$/.test(entry) ? [path] : []
  })
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const web = fileURLToPath(new URL('..', import.meta.url))
  const files = Object.keys(RULES)
    .flatMap((name) => ['src', 'test', 'itest', 'e2e'].flatMap((dir) => walk(join(web, name, dir))))
    .map((path) => ({ path: relative(web, path), source: readFileSync(path, 'utf8') }))
  const found = violations(files)
  for (const line of found) {
    console.error(`layering: ${line}`)
  }
  if (found.length > 0) {
    process.exit(1)
  }
  console.log(`layering: ${files.length} files, the three packages keep to their sides`)
}
