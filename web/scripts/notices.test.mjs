// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { productionPackages } from './lock.mjs'
import { gather, licenceFile, notices } from './notices.mjs'

test('each bundled package appears once, by name, with its version, licence and text', () => {
  const out = notices(
    [
      { name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text of vue' },
      { name: '@bufbuild/protobuf', version: '2.17.0', license: '(Apache-2.0 AND BSD-3-Clause)', text: 'Apache text' },
    ],
    [],
  )
  assert.ok(out.indexOf('@bufbuild/protobuf 2.17.0') < out.indexOf('vue 3.5.0'), 'sorted by name')
  assert.ok(out.includes('(Apache-2.0 AND BSD-3-Clause)'))
  assert.equal(out.split('MIT text of vue').length, 2)
  assert.equal(out.split('vue 3.5.0').length, 2)
  assert.ok(out.startsWith('OpenFeO panel: third-party notices\n'))
})

test('the fonts follow the packages, each under its name', () => {
  const out = notices(
    [{ name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text' }],
    [{ name: 'Instrument Sans', text: 'SIL OPEN FONT LICENSE Version 1.1' }],
  )
  assert.match(out, /Instrument Sans[\s\S]*SIL OPEN FONT LICENSE Version 1\.1/)
  assert.ok(out.indexOf('vue 3.5.0') < out.indexOf('Instrument Sans'))
})

test('a licence file is found whatever its spelling, and a licence comes before a notice', () => {
  assert.equal(licenceFile(['index.js', 'LICENSE', 'README.md']), 'LICENSE')
  assert.equal(licenceFile(['license.md', 'package.json']), 'license.md')
  assert.equal(licenceFile(['LICENCE.txt']), 'LICENCE.txt')
  assert.equal(licenceFile(['COPYING']), 'COPYING')
  assert.equal(licenceFile(['NOTICE', 'LICENSE-MIT']), 'LICENSE-MIT')
  assert.equal(licenceFile(['README.md', 'licenses.js']), undefined)
})

test('a bundled package with no licence file is named, and the others are read', () => {
  const web = mkdtempSync(join(tmpdir(), 'notices-'))
  mkdirSync(join(web, 'node_modules/a'), { recursive: true })
  mkdirSync(join(web, 'node_modules/b'), { recursive: true })
  mkdirSync(join(web, 'node_modules/tool'), { recursive: true })
  writeFileSync(join(web, 'node_modules/a/LICENSE'), 'the text of a\n')
  writeFileSync(join(web, 'node_modules/b/index.js'), '')
  const lock = {
    packages: {
      '': {},
      'node_modules/a': { version: '1.0.0', license: 'MIT' },
      'node_modules/b': { version: '2.0.0', license: 'ISC' },
      'node_modules/tool': { version: '9.0.0', license: 'MIT', dev: true },
    },
  }
  const { packages, missing } = gather(lock, web, {})
  assert.deepEqual(missing, ['b@2.0.0'])
  assert.deepEqual(
    packages.map((p) => [p.name, p.text]),
    [['a', 'the text of a\n']],
  )
  // A package that is published without its licence has the text kept for it here.
  writeFileSync(join(web, 'kept-b.txt'), 'the text kept for b\n')
  const kept = gather(lock, web, { b: join(web, 'kept-b.txt') })
  assert.deepEqual(kept.missing, [])
  assert.deepEqual(
    kept.packages.map((p) => [p.name, p.text]),
    [
      ['a', 'the text of a\n'],
      ['b', 'the text kept for b\n'],
    ],
  )
  // A file in the package wins over one kept here.
  assert.equal(gather(lock, web, { a: join(web, 'kept-b.txt') }).packages[0].text, 'the text of a\n')
})

test('every text kept here is for a package that needs it', () => {
  // A kept text must not outlive the package it is for, nor the day its publisher starts
  // shipping the file: then the package's own text is the one to carry.
  const scripts = new URL('.', import.meta.url)
  const web = new URL('..', scripts)
  const { texts } = JSON.parse(readFileSync(new URL('licences.json', scripts), 'utf8'))
  const bundled = productionPackages(JSON.parse(readFileSync(new URL('package-lock.json', web), 'utf8')))
  assert.ok(Object.keys(texts).length > 0, 'the list of kept texts was read')
  for (const [name, file] of Object.entries(texts)) {
    const installed = bundled.filter((each) => each.name === name)
    assert.ok(installed.length > 0, `${name} is not among the packages that can reach the panel: its kept text can go`)
    for (const { path, version } of installed) {
      assert.equal(
        licenceFile(readdirSync(new URL(`${path}/`, web))),
        undefined,
        `${name}@${version} ships its own licence file now: its kept text can go`,
      )
    }
    assert.ok(readFileSync(new URL(file, scripts), 'utf8').length > 200, `${name}: ${file} is not a licence text`)
  }
})
