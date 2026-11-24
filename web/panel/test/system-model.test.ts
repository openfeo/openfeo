// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the System page works out (SPEC §8.4): the router's name and whether a draft changes
// it, what the page can know is wrong with a name or a time server, and About's rows.

import { clone, ConfigSchema, create, SystemSchema, type Config } from '@openfeo/client'
import { expect, test } from 'vitest'

import { changes } from '../src/model/changes'
import { about, DEFAULT_HOSTNAME, renamedTo, routerName, settleSystem, systemProblems } from '../src/model/system'
import { routerConfig, state, UPTIME_SECS } from './fixtures'

test('the router’s name is its hostname under its domain, with the defaults for what is not set', () => {
  expect(DEFAULT_HOSTNAME).toBe('openfeo')
  const config = routerConfig()
  expect(routerName(config)).toBe('openfeo.home.arpa')
  config.system!.hostname = 'Edge'
  config.system!.domain = 'Lan.Example'
  expect(routerName(config)).toBe('edge.lan.example')
  config.system!.hostname = ''
  expect(routerName(config)).toBe('openfeo.lan.example')
  config.system = undefined
  expect(routerName(config)).toBe('openfeo.home.arpa')
})

test('a draft that changes either renames the router, and one that changes neither does not', () => {
  const base = routerConfig()
  const draft = (edit: (config: Config) => void) => {
    const made = clone(ConfigSchema, base)
    edit(made)
    return made
  }
  expect(renamedTo(base, draft((d) => (d.system!.hostname = 'edge')))).toEqual({ from: 'openfeo.home.arpa', to: 'edge.home.arpa' })
  expect(renamedTo(base, draft((d) => (d.system!.domain = 'lan.example')))).toEqual({ from: 'openfeo.home.arpa', to: 'openfeo.lan.example' })
  expect(renamedTo(base, draft(() => undefined))).toBeNull()
  expect(renamedTo(base, draft((d) => (d.system!.ntpServers = ['203.0.113.1'])))).toBeNull()
  // The default spelt out, or left out again, is the same name.
  expect(renamedTo(base, draft((d) => (d.system!.hostname = '')))).toBeNull()
  expect(renamedTo(base, draft((d) => (d.system = undefined)))).toBeNull()
  expect(renamedTo(base, draft((d) => (d.system!.hostname = 'OPENFEO')))).toBeNull()
  // Until the router's config is read there is nothing to compare with.
  expect(renamedTo(null, base)).toBeNull()
})

test('what the page knows of a name', () => {
  const problems = (init: Parameters<typeof create<typeof SystemSchema>>[1]) => systemProblems(create(SystemSchema, init))
  expect(problems({ hostname: 'openfeo', domain: 'home.arpa', ntpServers: ['0.pool.ntp.org', '203.0.113.1'] })).toEqual({})
  // Nothing typed is the router's default, not a mistake.
  expect(problems({})).toEqual({})
  expect(systemProblems(undefined)).toEqual({})
  for (const wrong of ['my router', 'a.b', '-edge', 'edge-', 'edge_1', 'x'.repeat(64)]) {
    expect(problems({ hostname: wrong }), wrong).toEqual({ hostname: 'Letters, digits and hyphens, 63 at most.' })
  }
  expect(problems({ hostname: 'x'.repeat(63) })).toEqual({})
  for (const wrong of ['.', 'home..arpa', '-bad.arpa', 'a.b.', '.home.arpa', 'home arpa', `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}`]) {
    expect(problems({ domain: wrong }), wrong).toEqual({ domain: 'Names separated by dots, such as home.arpa.' })
  }
  expect(problems({ domain: 'lan' })).toEqual({})
  expect(problems({ ntpServers: ['0.pool.ntp.org', 'not a name'] })).toEqual({ ntp_servers: 'not a name is not a name or an address.' })
  expect(problems({ ntpServers: ['2001:db8::1'] })).toEqual({ ntp_servers: '2001:db8::1 is not a name or an address.' })
})

test('system settings with nothing in them are taken out when the router has none', () => {
  const base = routerConfig()
  base.system = undefined
  const draft = clone(ConfigSchema, base)
  draft.system = create(SystemSchema, { hostname: 'edge' })
  settleSystem(draft, base)
  expect(draft.system?.hostname).toBe('edge')
  draft.system.hostname = ''
  settleSystem(draft, base)
  expect(draft.system).toBeUndefined()
  expect(changes(base, draft)).toEqual([])
})

test('about says the version, how long it has run and the fingerprint', () => {
  const found = state()
  found.system!.tlsFingerprint = '6F:1C:9E:02'
  expect(about(found, UPTIME_SECS * 1000)).toEqual([
    { label: 'Version', value: '0.4.0', mono: true },
    { label: 'Running for', value: '3d 4h', mono: false },
    { label: 'Certificate', value: 'SHA-256 6F:1C:9E:02', mono: true },
  ])
  // Until the uptime is counted here, what the router last said.
  expect(about(found, undefined)[1]).toEqual({ label: 'Running for', value: '3d 4h', mono: false })
})
