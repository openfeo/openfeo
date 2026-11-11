// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { problems, satisfies } from './check-licences.mjs'
import { productionPackages } from './lock.mjs'

test('an SPDX expression is satisfied term by term', () => {
  const accepted = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC']
  assert.ok(satisfies('MIT', accepted))
  assert.ok(satisfies('(Apache-2.0 AND BSD-3-Clause)', accepted))
  assert.ok(satisfies('(MIT OR GPL-3.0-only)', accepted))
  assert.ok(satisfies('MIT OR (GPL-3.0-only AND ISC)', accepted))
  assert.ok(!satisfies('(MIT AND GPL-3.0-only)', accepted))
  assert.ok(!satisfies('GPL-3.0-only', accepted))
  assert.ok(!satisfies('UNLICENSED', accepted))
  assert.ok(!satisfies('', accepted))
  assert.ok(!satisfies('(MIT', accepted), 'an expression that does not parse is not accepted')
  assert.ok(!satisfies('SEE LICENSE IN LICENSE.txt', accepted))
})

test('a bundled package with no licence, or one not accepted, is a problem that names it', () => {
  const found = problems(
    [
      { name: 'a', version: '1.0.0', license: undefined },
      { name: 'b', version: '2.0.0', license: 'GPL-3.0-only' },
      { name: 'c', version: '3.0.0', license: 'MIT' },
    ],
    { accepted: ['MIT'], overrides: {} },
  )
  assert.equal(found.length, 2)
  assert.match(found[0], /a@1\.0\.0/)
  assert.match(found[1], /b@2\.0\.0/)
})

test('an override settles a package the lockfile does not describe', () => {
  const packages = [{ name: 'a', version: '1.0.0', license: undefined }]
  assert.equal(problems(packages, { accepted: ['MIT'], overrides: { 'a@1.0.0': 'MIT' } }).length, 0)
  assert.equal(problems(packages, { accepted: ['MIT'], overrides: { 'a@2.0.0': 'MIT' } }).length, 1, 'another version')
  assert.equal(problems(packages, { accepted: ['MIT'], overrides: { 'a@1.0.0': 'GPL-3.0-only' } }).length, 1)
})

test('development packages and the workspaces themselves are not bundled', () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'openfeo-web' },
      client: { name: '@openfeo/client' },
      'node_modules/@openfeo/client': { resolved: 'client', link: true },
      'node_modules/vite': { version: '8.0.0', dev: true, license: 'MIT' },
      'node_modules/vue': { version: '3.5.0', license: 'MIT' },
      'node_modules/@bufbuild/protobuf': { version: '2.17.0', license: '(Apache-2.0 AND BSD-3-Clause)' },
      'node_modules/vue/node_modules/nested': { version: '1.2.3', license: 'ISC' },
      'node_modules/fsevents': { version: '2.0.0', dev: true, optional: true, license: 'MIT' },
    },
  }
  assert.deepEqual(
    productionPackages(lock).map((p) => `${p.name}@${p.version}`),
    ['@bufbuild/protobuf@2.17.0', 'nested@1.2.3', 'vue@3.5.0'],
  )
  assert.equal(productionPackages(lock)[0].path, 'node_modules/@bufbuild/protobuf')
})

test("the accepted list is deny.toml's", () => {
  const deny = readFileSync(new URL('../../deny.toml', import.meta.url), 'utf8')
  const section = deny.slice(deny.indexOf('[licenses]'))
  const start = section.indexOf('allow = [')
  const list = section.slice(start, section.indexOf('\n]', start))
  const allowed = [...list.matchAll(/^\s*"([^"]+)",/gm)].map((m) => m[1])
  assert.ok(allowed.includes('MIT') && allowed.length > 5, 'deny.toml was read')
  const { accepted } = JSON.parse(readFileSync(new URL('./licences.json', import.meta.url), 'utf8'))
  assert.deepEqual([...accepted].sort(), [...allowed].sort())
})
