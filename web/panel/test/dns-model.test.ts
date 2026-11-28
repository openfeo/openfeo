// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the DNS page works out (SPEC §7.7, §8.4): what a local name becomes, what the page can
// know is wrong with one, the switch for the WAN's resolvers, and the resolvers in use.

import { clone, ConfigSchema, create, RecordSchema, StateSchema, type Config } from '@openfeo/client'
import { expect, test } from 'vitest'

import { changes } from '../src/model/changes'
import { becomes, DEFAULT_DOMAIN, domainOf, inUse, newRecord, recordProblems, setUsesWan, settleDns, usesWan } from '../src/model/dns'
import { routerConfig } from './fixtures'

test('a name with no dot is under the domain, and one with a dot stands', () => {
  expect(DEFAULT_DOMAIN).toBe('home.arpa')
  expect(becomes('www', 'home.arpa')).toBe('www.home.arpa')
  expect(becomes('WWW', 'home.arpa')).toBe('www.home.arpa')
  // A name that has a dot is taken as it is written: nothing to say of what it becomes.
  expect(becomes('nas.home.arpa', 'home.arpa')).toBeNull()
  expect(becomes('www.example', 'home.arpa')).toBeNull()
  // A dot at the end is the root's, not a label's.
  expect(becomes('www.', 'home.arpa')).toBeNull()
  expect(becomes('', 'home.arpa')).toBeNull()
  expect(becomes('  ', 'home.arpa')).toBeNull()

  const config = routerConfig()
  expect(domainOf(config)).toBe('home.arpa')
  config.system!.domain = 'Lan.Example'
  expect(domainOf(config)).toBe('lan.example')
  config.system!.domain = ''
  expect(domainOf(config)).toBe('home.arpa')
  config.system = undefined
  expect(domainOf(config)).toBe('home.arpa')
})

test('one name may have an address of each family and no more', () => {
  const record = (name: string, address: string) => create(RecordSchema, { name, address })
  const records = [record('www', '192.168.1.10'), record('www', '2001:db8:1:1::10'), record('www', '192.168.1.11'), record('media', '192.168.1.10'), record('WWW', '2001:db8:1:1::11')]
  expect(recordProblems(records, 0)).toEqual({ address: 'This name already has an IPv4 address.' })
  // Whatever its case: a name is a name.
  expect(recordProblems(records, 1)).toEqual({ address: 'This name already has an IPv6 address.' })
  expect(recordProblems(records, 2)).toEqual({ address: 'This name already has an IPv4 address.' })
  expect(recordProblems(records, 3)).toEqual({})
  expect(recordProblems([record('', '192.168.1.10')], 0)).toEqual({ name: 'Give it a name.' })
  expect(recordProblems([record('nas', 'nope')], 0)).toEqual({ address: 'An IPv4 or IPv6 address.' })
  expect(recordProblems([record('nas', '192.168.1.0/24')], 0)).toEqual({ address: 'An IPv4 or IPv6 address.' })
  // Nothing typed yet for the address is not a mistake of the page's to find.
  expect(recordProblems([record('nas', '')], 0)).toEqual({})
  const fresh = newRecord()
  expect([fresh.name, fresh.address]).toEqual(['', ''])
})

/** The router's config with `useWanDns` as given, and a draft of it. */
function pair(flag: boolean | undefined, upstreams: string[] = []): { base: Config; draft: Config } {
  const base = routerConfig()
  if (flag !== undefined || upstreams.length > 0) {
    base.dns = create(ConfigSchema, { dns: { upstreams } }).dns
    if (flag !== undefined) {
      base.dns!.useWanDns = flag
    }
  }
  return { base, draft: clone(ConfigSchema, base) }
}

test('the switch is on when the config does not say, and what is not said stays not said', () => {
  expect(usesWan(undefined)).toBe(true)
  expect(usesWan(create(ConfigSchema, { dns: {} }).dns)).toBe(true)
  expect(usesWan(create(ConfigSchema, { dns: { useWanDns: false } }).dns)).toBe(false)
  expect(usesWan(create(ConfigSchema, { dns: { useWanDns: true } }).dns)).toBe(true)

  // A router with no DNS settings at all: off writes it, on again leaves no trace.
  const none = pair(undefined)
  setUsesWan(none.draft, false, none.base)
  expect(none.draft.dns?.useWanDns).toBe(false)
  expect(changes(none.base, none.draft)).toEqual([{ subject: 'DNS', what: 'the WAN’s resolvers too', before: 'not set', after: 'no' }])
  setUsesWan(none.draft, true, none.base)
  expect(none.draft.dns).toBeUndefined()
  expect(changes(none.base, none.draft)).toEqual([])

  // One that has settings and does not say: back on is back to not saying.
  const unsaid = pair(undefined, ['203.0.113.53'])
  setUsesWan(unsaid.draft, false, unsaid.base)
  setUsesWan(unsaid.draft, true, unsaid.base)
  expect(unsaid.draft.dns?.useWanDns).toBeUndefined()
  expect(changes(unsaid.base, unsaid.draft)).toEqual([])

  // One that says yes stays saying yes; one that says no is switched on by saying yes.
  const said = pair(true)
  setUsesWan(said.draft, false, said.base)
  setUsesWan(said.draft, true, said.base)
  expect(said.draft.dns?.useWanDns).toBe(true)
  const off = pair(false)
  setUsesWan(off.draft, true, off.base)
  expect(off.draft.dns?.useWanDns).toBe(true)
  expect(changes(off.base, off.draft)).toEqual([{ subject: 'DNS', what: 'the WAN’s resolvers too', before: 'no', after: 'yes' }])
})

test('DNS settings with nothing in them are taken out when the router has none', () => {
  const { base, draft } = pair(undefined)
  draft.dns = create(ConfigSchema, { dns: { records: [{ name: 'nas', address: '192.168.1.10' }] } }).dns
  settleDns(draft, base)
  expect(draft.dns?.records).toHaveLength(1)
  draft.dns!.records = []
  settleDns(draft, base)
  expect(draft.dns).toBeUndefined()
  // A router that has the settings keeps them, empty or not.
  const kept = pair(undefined, ['203.0.113.53'])
  kept.draft.dns!.upstreams = []
  settleDns(kept.draft, kept.base)
  expect(kept.draft.dns).toBeDefined()
})

test('the resolvers in use are grouped by where they came from, in order', () => {
  const dns = (resolvers: { address: string; wan: string }[]) => create(StateSchema, { dns: { resolvers } }).dns
  expect(
    inUse(
      dns([
        { address: '198.51.100.53', wan: '' },
        { address: '203.0.113.53', wan: 'wan0' },
        { address: '203.0.113.54', wan: 'wan0' },
      ]),
    ),
  ).toEqual([
    { addresses: ['198.51.100.53'], from: 'yours' },
    { addresses: ['203.0.113.53', '203.0.113.54'], from: 'from wan0' },
  ])
  expect(inUse(dns([{ address: '9.9.9.9', wan: '' }, { address: '2001:db8::53', wan: '' }]))).toEqual([{ addresses: ['9.9.9.9', '2001:db8::53'], from: 'yours' }])
  // In the order asked, even where that goes back and forth.
  expect(inUse(dns([{ address: '203.0.113.53', wan: 'wan0' }, { address: '203.0.113.99', wan: 'wan1' }])).map((group) => group.from)).toEqual(['from wan0', 'from wan1'])
  expect(inUse(dns([]))).toEqual([])
  expect(inUse(undefined)).toEqual([])
})
