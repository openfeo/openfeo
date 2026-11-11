// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The npm half of SPEC §14: every package that can reach the panel must carry a licence the
// project has accepted for the binary. The list is `deny.toml`'s, copied into
// `licences.json`; a test keeps the two the same.

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

import { productionPackages } from './lock.mjs'

/**
 * Whether an SPDX licence expression is met by the accepted identifiers: every term of an
 * `AND`, any term of an `OR`. An expression that does not parse is not accepted, and neither
 * is a licence with an exception (`WITH`) unless the whole of it is listed.
 *
 * @param {string} expression
 * @param {string[]} accepted
 */
export function satisfies(expression, accepted) {
  const tokens = expression.match(/\(|\)|[^\s()]+/g) ?? []
  let at = 0

  /** @returns {boolean | null} null when the expression does not parse */
  function either() {
    let result = both()
    while (result !== null && tokens[at] === 'OR') {
      at += 1
      const right = both()
      result = right === null ? null : result || right
    }
    return result
  }

  /** @returns {boolean | null} */
  function both() {
    let result = one()
    while (result !== null && tokens[at] === 'AND') {
      at += 1
      const right = one()
      result = right === null ? null : result && right
    }
    return result
  }

  /** @returns {boolean | null} */
  function one() {
    const token = tokens[at]
    if (token === undefined || token === ')' || token === 'AND' || token === 'OR' || token === 'WITH') {
      return null
    }
    at += 1
    if (token === '(') {
      const inner = either()
      if (inner === null || tokens[at] !== ')') {
        return null
      }
      at += 1
      return inner
    }
    if (tokens[at] === 'WITH') {
      const exception = tokens[at + 1]
      if (exception === undefined) {
        return null
      }
      at += 2
      return accepted.includes(`${token} WITH ${exception}`)
    }
    return accepted.includes(token)
  }

  const result = either()
  return result === true && at === tokens.length
}

/**
 * What is wrong with the packages' licences, one line each, in the order given.
 *
 * @param {{ name: string, version: string, license: string | undefined }[]} packages
 * @param {{ accepted: string[], overrides: Record<string, string> }} rules
 * @returns {string[]}
 */
export function problems(packages, rules) {
  const found = []
  for (const { name, version, license } of packages) {
    const id = `${name}@${version}`
    const licence = rules.overrides[id] ?? license
    if (licence === undefined || licence === '') {
      found.push(`${id}: the lockfile names no licence; read the package's and add an override`)
    } else if (!satisfies(licence, rules.accepted)) {
      found.push(`${id}: ${licence} is not a licence accepted for the binary (SPEC §14)`)
    }
  }
  return found
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const read = (/** @type {string} */ relative) =>
    JSON.parse(readFileSync(new URL(relative, import.meta.url), 'utf8'))
  const packages = productionPackages(read('../package-lock.json'))
  const found = problems(packages, read('./licences.json'))
  for (const line of found) {
    console.error(`licences: ${line}`)
  }
  if (found.length > 0) {
    process.exit(1)
  }
  console.log(`licences: ${packages.length} packages that can reach the panel, all accepted`)
}
