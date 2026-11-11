// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What of the lockfile can reach the panel: every installed package that is not there for
// development only. That is more than the bundler ends up including (Vue's template compiler
// is a dependency of `vue` and is not shipped), which errs on the side of naming too many.

/**
 * @typedef {{ name: string, version: string, license: string | undefined, path: string }} Package
 */

/**
 * The packages of an npm lockfile (version 3) that are not development-only, not a workspace
 * and not a link to one, once each, sorted by name and then version.
 *
 * @param {{ packages?: Record<string, { version?: string, license?: string, dev?: boolean, link?: boolean }> }} lock
 * @returns {Package[]}
 */
export function productionPackages(lock) {
  const marker = 'node_modules/'
  /** @type {Map<string, Package>} */
  const found = new Map()
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    const at = path.lastIndexOf(marker)
    if (at < 0 || entry.link === true || entry.dev === true || entry.version === undefined) {
      continue
    }
    const name = path.slice(at + marker.length)
    const key = `${name}@${entry.version}`
    if (!found.has(key)) {
      found.set(key, { name, version: entry.version, license: entry.license, path })
    }
  }
  return [...found.values()].sort(
    (a, b) => compare(a.name, b.name) || compare(a.version, b.version),
  )
}

/**
 * @param {string} a
 * @param {string} b
 */
function compare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}
