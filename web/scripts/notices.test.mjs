// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { productionPackages } from './lock.mjs'
import { cNotices, gather, licenceFile, notices } from './notices.mjs'

test('each bundled package appears once, by name, with its version, licence and text', () => {
  const out = notices({
    packages: [
      { name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text of vue' },
      { name: '@bufbuild/protobuf', version: '2.17.0', license: '(Apache-2.0 AND BSD-3-Clause)', text: 'Apache text' },
    ],
  })
  assert.ok(out.indexOf('@bufbuild/protobuf 2.17.0') < out.indexOf('vue 3.5.0'), 'sorted by name')
  assert.ok(out.includes('(Apache-2.0 AND BSD-3-Clause)'))
  assert.equal(out.split('MIT text of vue').length, 2)
  assert.equal(out.split('vue 3.5.0').length, 2)
  assert.ok(out.startsWith('OpenFeO: third-party notices\n'))
})

test('the fonts follow the packages, each under its name', () => {
  const out = notices({
    packages: [{ name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text' }],
    fonts: [{ name: 'Instrument Sans', text: 'SIL OPEN FONT LICENSE Version 1.1' }],
  })
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

// ---- The whole binary (SPEC §13): the Rust crates and the C libraries too ----

const SOURCES = `# name version url sha256
nftables 1.1.7 https://example.invalid/nftables.tar.xz 00
jansson 2.15.1 https://example.invalid/jansson.tar.gz 00
`

/** A tree as nft/fetch.sh leaves it, and a directory of kept texts. */
function trees() {
  const src = mkdtempSync(join(tmpdir(), 'c-src-'))
  mkdirSync(join(src, 'nftables-1.1.7/src'), { recursive: true })
  mkdirSync(join(src, 'jansson-2.15.1'), { recursive: true })
  writeFileSync(join(src, 'nftables-1.1.7/COPYING'), 'GPL text of nftables\n')
  writeFileSync(join(src, 'jansson-2.15.1/LICENSE'), 'MIT text of jansson\n')
  writeFileSync(
    join(src, 'nftables-1.1.7/src/mini-gmp.c'),
    '/* mini-gmp, a small one.\n\n   Either licence, as here.  */\n\n/* NOTE: not the notice. */\nint x;\n',
  )
  const kept = mkdtempSync(join(tmpdir(), 'c-kept-'))
  writeFileSync(join(kept, 'libc.txt'), 'MIT text of the libc\n')
  return { src, kept }
}

const ENTRIES = [
  { name: 'nftables', source: 'nftables', licence: 'GPL-2.0-only', file: 'COPYING' },
  { name: 'jansson', source: 'jansson', licence: 'MIT', file: 'LICENSE' },
]

test('the file covers the binary, in four parts', () => {
  const out = notices({
    rust: 'RULE\ntokio 1.0.0\nMIT\nRULE\n\nMIT text of tokio\n',
    c: [{ name: 'nftables', version: '1.1.7', licence: 'GPL-2.0-only', text: 'GPL text' }],
    packages: [{ name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text of vue' }],
    fonts: [{ name: 'Instrument Sans', text: 'OFL text' }],
  })
  assert.ok(out.startsWith('OpenFeO: third-party notices\n'))
  const at = ['The router: Rust crates', 'The router: C libraries', 'The panel: npm packages', 'The panel: fonts'].map((title) =>
    out.indexOf(`\n${title}\n`),
  )
  assert.ok(
    at.every((place) => place > 0),
    `every part has its title: ${at.join(' ')}`,
  )
  assert.deepEqual([...at].sort((a, b) => a - b), at, 'in that order')
  // The Rust part is what cargo about wrote, as it wrote it.
  assert.ok(out.includes('RULE\ntokio 1.0.0\nMIT\nRULE\n\nMIT text of tokio\n'))
  assert.ok(out.indexOf('tokio 1.0.0') < out.indexOf('nftables 1.1.7'))
  assert.match(out, /nftables 1\.1\.7\nGPL-2\.0-only\n=+\n\nGPL text\n/)
  assert.ok(out.indexOf('nftables 1.1.7') < out.indexOf('vue 3.5.0'))
  assert.ok(out.indexOf('vue 3.5.0') < out.indexOf('Instrument Sans (font)'))
})

test('a part with nothing in it has no title', () => {
  const out = notices({ packages: [{ name: 'vue', version: '3.5.0', license: 'MIT', text: 'MIT text' }] })
  assert.ok(out.includes('The panel: npm packages'))
  for (const title of ['The router: Rust crates', 'The router: C libraries', 'The panel: fonts']) {
    assert.ok(!out.includes(title), title)
  }
})

test('a C library has its version from the sources and its text from the tree', () => {
  const { src, kept } = trees()
  assert.deepEqual(cNotices(ENTRIES, SOURCES, src, kept), [
    { name: 'nftables', version: '1.1.7', licence: 'GPL-2.0-only', text: 'GPL text of nftables\n' },
    { name: 'jansson', version: '2.15.1', licence: 'MIT', text: 'MIT text of jansson\n' },
  ])
})

test('a notice kept in a comment is the comment, and one kept here is read from here', () => {
  const { src, kept } = trees()
  const found = cNotices(
    [
      ...ENTRIES,
      { name: 'mini-gmp', source: 'nftables', within: true, licence: 'LGPL-3.0-or-later OR GPL-2.0-or-later', comment: 'src/mini-gmp.c' },
      { name: 'a libc', version: '1.2.5', licence: 'MIT', kept: 'libc.txt' },
    ],
    SOURCES,
    src,
    kept,
  )
  assert.deepEqual(found.slice(2), [
    {
      name: 'mini-gmp',
      version: '(in nftables 1.1.7)',
      licence: 'LGPL-3.0-or-later OR GPL-2.0-or-later',
      // The first comment and nothing after it, without its marks.
      text: 'mini-gmp, a small one.\n\n   Either licence, as here.',
    },
    { name: 'a libc', version: '1.2.5', licence: 'MIT', text: 'MIT text of the libc\n' },
  ])
})

test('a library in the sources with no entry fails by name, and so does an entry whose text is not there', () => {
  const { src, kept } = trees()
  assert.throws(() => cNotices([ENTRIES[0]], SOURCES, src, kept), /jansson/)
  assert.throws(
    () => cNotices([...ENTRIES.slice(0, 1), { name: 'jansson', source: 'jansson', licence: 'MIT', file: 'COPYING' }], SOURCES, src, kept),
    /jansson.*COPYING/,
  )
  assert.throws(() => cNotices([...ENTRIES, { name: 'gone', source: 'gone', licence: 'MIT', file: 'LICENSE' }], SOURCES, src, kept), /gone/)
})

test('every library the binary builds has an entry', () => {
  const scripts = new URL('.', import.meta.url)
  const sources = readFileSync(new URL('../../nft/sources.txt', scripts), 'utf8')
  const entries = JSON.parse(readFileSync(new URL('c-notices.json', scripts), 'utf8'))
  const built = sources
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((line) => line.split(/\s+/)[0])
  assert.ok(built.length >= 4, 'nft/sources.txt was read')
  for (const name of built) {
    assert.ok(
      entries.some((entry) => entry.source === name && entry.file !== undefined && entry.within !== true),
      `${name} has no notice of its own in c-notices.json`,
    )
  }
  // A text kept here is a text: not a pointer to one.
  for (const entry of entries.filter((each) => each.kept !== undefined)) {
    assert.ok(readFileSync(new URL(entry.kept, scripts), 'utf8').length > 200, `${entry.name}: ${entry.kept} is not a licence text`)
    assert.ok(typeof entry.version === 'string' && entry.version !== '', `${entry.name} says which version its kept text is of`)
  }
})

// The pinned C sources, where `make nft-src` fetched them (the Makefile exports the place).
const NFT_SRC = process.env.OPENFEO_NFT_SRC ?? ''

test(
  'a C library whose source files name one licence is labelled with it',
  { skip: existsSync(NFT_SRC) ? false : 'the pinned C sources are not fetched (make nft-src, or run under make)' },
  () => {
    const scripts = new URL('.', import.meta.url)
    const sources = readFileSync(new URL('../../nft/sources.txt', scripts), 'utf8')
    const entries = JSON.parse(readFileSync(new URL('c-notices.json', scripts), 'utf8'))
    const pinned = new Map(
      sources
        .split('\n')
        .filter((line) => line !== '' && !line.startsWith('#'))
        .map((line) => line.split(/\s+/).slice(0, 2)),
    )
    let checked = 0
    for (const entry of entries.filter((each) => each.file !== undefined && each.within !== true)) {
      const dir = join(NFT_SRC, `${entry.source}-${pinned.get(entry.source)}`, 'src')
      const files = readdirSync(dir).filter((name) => name.endsWith('.c'))
      const named = files
        .map((name) => /SPDX-License-Identifier: ([A-Za-z0-9.+-]+)/.exec(readFileSync(join(dir, name), 'utf8'))?.[1])
        .filter((licence) => licence !== undefined)
      // Only where the sources speak, and with one voice: most of the files name a licence
      // and every one that does names the same. A tree that says little, or two things, is
      // labelled by what its project says of itself (docs/third-party.md).
      if (named.length * 2 > files.length && named.every((licence) => licence === named[0])) {
        assert.equal(entry.licence, named[0], `${entry.name}: its sources say ${named[0]}`)
        checked += 1
      }
    }
    assert.ok(checked > 0, 'no library names its licence in most of its source files: this test checks nothing')
  },
)
