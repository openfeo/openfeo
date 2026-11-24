// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Firewall page works out (SPEC §8.4): the grid of which network may reach which,
// and what the page can know is wrong with a forward or a rule before the router is asked.

import { clone, ConfigSchema, create, PortForwardSchema, RuleSchema, type Config, type PortForward, type Rule } from '@openfeo/client'
import { expect, test } from 'vitest'

import { changes } from '../src/model/changes'
import {
  FORWARD_PROTOCOLS,
  forwardProblems,
  fromOptions,
  INTERNET,
  newForward,
  newRule,
  parsePorts,
  portsText,
  publicBlocks,
  reachGrid,
  RULE_PROTOCOLS,
  ruleProblems,
  setReach,
  setWanPing,
} from '../src/model/firewall'
import { routerConfig } from './fixtures'

/** The router's config and a draft of it, with `lan`'s list as given on both. */
function pair(reaches: Record<string, string[]>): { base: Config; draft: Config } {
  const base = routerConfig()
  for (const lan of base.lans) {
    lan.reaches = reaches[lan.name] ?? lan.reaches
  }
  return { base, draft: clone(ConfigSchema, base) }
}

const lanOf = (config: Config, name: string) => config.lans.find((lan) => lan.name === name)!

/** Tick or untick in the draft, as the page does. */
function tick(found: { base: Config; draft: Config }, lan: string, to: string, on: boolean): string[] {
  setReach(lanOf(found.draft, lan), to, on, found.draft, lanOf(found.base, lan))
  return lanOf(found.draft, lan).reaches
}

test('the grid has a row for each LAN and no tick for a LAN’s own cell', () => {
  const config = routerConfig()
  config.lans[0]!.reaches = ['wan', 'iot']
  expect(reachGrid(config)).toEqual([
    {
      lan: 'lan0',
      cells: [
        { to: 'wan', label: 'the internet', ticked: true, own: false },
        { to: 'lan0', label: 'lan0', ticked: false, own: true },
        { to: 'iot', label: 'iot', ticked: true, own: false },
      ],
    },
    {
      lan: 'iot',
      cells: [
        { to: 'wan', label: 'the internet', ticked: true, own: false },
        { to: 'lan0', label: 'lan0', ticked: false, own: false },
        { to: 'iot', label: 'iot', ticked: false, own: true },
      ],
    },
  ])
  expect(INTERNET).toBe('wan')
})

test('an empty list is the internet alone, and stays empty', () => {
  // Review Focus 1: `reaches = []` in the file means the internet alone (SPEC §7.5).
  const found = pair({ lan0: [] })
  expect(reachGrid(found.draft)[0]?.cells.map((cell) => cell.ticked)).toEqual([true, false, false])
  expect(tick(found, 'lan0', 'wan', false)).toEqual(['none'])
  expect(reachGrid(found.draft)[0]?.cells.map((cell) => cell.ticked)).toEqual([false, false, false])
  // Ticked again it means what the router has, and is written as the router has it.
  expect(tick(found, 'lan0', 'wan', true)).toEqual([])
  expect(changes(found.base, found.draft)).toEqual([])
})

test('a list that says wan stays as it says', () => {
  const found = pair({ iot: ['wan'] })
  expect(tick(found, 'iot', 'lan0', true)).toEqual(['wan', 'lan0'])
  expect(tick(found, 'iot', 'lan0', false)).toEqual(['wan'])
  expect(changes(found.base, found.draft)).toEqual([])
})

test('ticks are written the internet first, then LANs in the config’s order, and no tick is none', () => {
  const found = pair({ lan0: ['none'] })
  found.base.lans.push(create(ConfigSchema, { lans: [{ name: 'guest', ipv4: '192.168.3.1/24' }] }).lans[0]!)
  found.draft.lans.push(clone(ConfigSchema, found.base).lans[2]!)
  expect(reachGrid(found.draft)[0]?.cells.map((cell) => cell.ticked)).toEqual([false, false, false, false])
  expect(tick(found, 'lan0', 'guest', true)).toEqual(['guest'])
  expect(tick(found, 'lan0', 'iot', true)).toEqual(['iot', 'guest'])
  expect(tick(found, 'lan0', 'wan', true)).toEqual(['wan', 'iot', 'guest'])
  expect(tick(found, 'lan0', 'iot', false)).toEqual(['wan', 'guest'])
  expect(tick(found, 'lan0', 'wan', false)).toEqual(['guest'])
  // Back to what the router has, as it has it.
  expect(tick(found, 'lan0', 'guest', false)).toEqual(['none'])
  expect(changes(found.base, found.draft)).toEqual([])
})

test('a name the grid does not show is kept', () => {
  // The panel drops nothing it does not show: a LAN's name that no LAN has (the router would
  // refuse it; it is the router's to say).
  const found = pair({ lan0: ['wan', 'gone'] })
  expect(tick(found, 'lan0', 'iot', true)).toEqual(['wan', 'iot', 'gone'])
  expect(tick(found, 'lan0', 'wan', false)).toEqual(['iot', 'gone'])
  expect(tick(found, 'lan0', 'iot', false)).toEqual(['gone'])
})

test('a LAN new in the draft has no router copy to go back to', () => {
  const draft = routerConfig()
  const guest = create(ConfigSchema, { lans: [{ name: 'guest', ipv4: '192.168.3.1/24' }] }).lans[0]!
  draft.lans.push(guest)
  setReach(guest, 'lan0', true, draft, undefined)
  expect(guest.reaches).toEqual(['wan', 'lan0'])
  setReach(guest, 'lan0', false, draft, undefined)
  expect(guest.reaches).toEqual(['wan'])
})

test('ports as they are typed', () => {
  // Review Focus 2.
  expect(parsePorts('80, 443 ,1000-1010')).toEqual(['80', '443', '1000-1010'])
  expect(parsePorts('  22 ')).toEqual(['22'])
  expect(parsePorts('')).toEqual([])
  expect(parsePorts(' , ')).toEqual([])
  expect(portsText(['80', '443', '1000-1010'])).toBe('80, 443, 1000-1010')
  const rule = (ports: string[], proto = 'tcp') => create(RuleSchema, { name: 'r', from: 'wan', to: '192.168.1.10', proto, ports })
  const ports = (list: string[], proto?: string) => ruleProblems([rule(list, proto)], 0).ports
  expect(ports(['80', '443', '1000-1010'])).toBeUndefined()
  expect(ports(['1', '65535'])).toBeUndefined()
  for (const wrong of ['0', '65536', '90-80', 'http', '80-', '-80', '1-2-3', '8 0']) {
    expect(ports([wrong]), wrong).toBe('Ports are numbers from 1 to 65535, or ranges such as 1000-1010.')
  }
  // Ports on a rule that is not TCP or UDP are said to be wrong; they are not thrown away.
  expect(ports(['443'], 'icmp')).toBe('Ports go with TCP and UDP only.')
  expect(ports(['443'], 'any')).toBe('Ports go with TCP and UDP only.')
  expect(ports([], 'icmp')).toBeUndefined()
  expect(ports(['443'], 'udp')).toBeUndefined()

  const forward = (port: number, toPort = 0) => create(PortForwardSchema, { name: 'f', proto: 'tcp', port, to: '192.168.1.10', toPort })
  const problems = (port: number, toPort?: number) => forwardProblems([forward(port, toPort)], 0)
  expect(problems(2222)).toEqual({})
  expect(problems(0).port).toBe('A port from 1 to 65535.')
  expect(problems(65_536).port).toBe('A port from 1 to 65535.')
  // An empty To port is the same port, and is written 0.
  expect(problems(2222, 0).to_port).toBeUndefined()
  expect(problems(2222, 22).to_port).toBeUndefined()
  expect(problems(2222, 65_536).to_port).toBe('A port from 1 to 65535.')
})

test('a name is needed and is its own', () => {
  const forwards = [
    create(PortForwardSchema, { name: 'ssh', proto: 'tcp', port: 22, to: '192.168.1.10' }),
    create(PortForwardSchema, { name: '', proto: 'tcp', port: 23, to: '192.168.1.10' }),
    create(PortForwardSchema, { name: 'ssh', proto: 'udp', port: 24, to: '192.168.1.10' }),
    create(PortForwardSchema, { name: 'web', proto: 'tcp', port: 80, to: '192.168.1.10' }),
  ]
  expect(forwardProblems(forwards, 0).name).toBe('Another forward has this name.')
  expect(forwardProblems(forwards, 1).name).toBe('Give it a name.')
  expect(forwardProblems(forwards, 2).name).toBe('Another forward has this name.')
  // A row is not told that it clashes with itself.
  expect(forwardProblems(forwards, 3).name).toBeUndefined()
  const rules = [
    create(RuleSchema, { name: 'web6', from: 'wan', to: '2001:db8:1:1::10', proto: 'tcp' }),
    create(RuleSchema, { name: 'web6', from: 'wan', to: '2001:db8:1:1::11', proto: 'tcp' }),
    create(RuleSchema, { name: '', from: 'wan', to: '2001:db8:1:1::12', proto: 'tcp' }),
  ]
  expect(ruleProblems(rules, 0).name).toBe('Another rule has this name.')
  expect(ruleProblems(rules, 2).name).toBe('Give it a name.')
})

test('a forward’s target is an IPv4 address', () => {
  const to = (text: string) => forwardProblems([create(PortForwardSchema, { name: 'f', proto: 'tcp', port: 80, to: text })], 0).to
  expect(to('192.168.1.10')).toBeUndefined()
  // Nothing typed yet is not a mistake: the router says a forward needs a target.
  expect(to('')).toBeUndefined()
  for (const wrong of ['192.168.1', '192.168.1.256', 'nas', '2001:db8::1', '192.168.1.0/24']) {
    expect(to(wrong), wrong).toBe('An IPv4 address.')
  }
})

test('a rule’s target is an address, a range or a block, of either family', () => {
  const to = (text: string) => ruleProblems([create(RuleSchema, { name: 'r', from: 'wan', to: text, proto: 'tcp' })], 0).to
  for (const right of ['192.168.1.10', '192.168.1.10-192.168.1.20', '192.168.1.0/28', '2001:db8:1:1::10', '2001:db8:1::/64', '']) {
    expect(to(right), right).toBeUndefined()
  }
  for (const wrong of ['192.168.1', '10-20', 'host', '192.168.1.20-192.168.1.10', '192.168.1.10-2001:db8::1', '192.168.1.0/33']) {
    expect(to(wrong), wrong).toBe('An address, a range such as 192.168.1.10-192.168.1.20, or a block such as 192.168.1.0/28.')
  }
})

test('a forward listens on an address only when there is a public block', () => {
  const config = routerConfig()
  expect(publicBlocks(config)).toBe(false)
  config.publicIpv4 = create(ConfigSchema, { publicIpv4: [{ prefix: '198.51.100.0/29' }] }).publicIpv4
  expect(publicBlocks(config)).toBe(true)
  const address = (text: string) => forwardProblems([create(PortForwardSchema, { name: 'f', proto: 'tcp', port: 80, to: '192.168.1.10', address: text })], 0).address
  expect(address('')).toBeUndefined()
  expect(address('198.51.100.2')).toBeUndefined()
  expect(address('nope')).toBe('An IPv4 address.')
})

test('what a new row starts as, and what its choices are', () => {
  const forward: PortForward = newForward()
  expect([forward.name, forward.proto, forward.port, forward.to, forward.toPort]).toEqual(['', 'tcp', 0, '', 0])
  const rule: Rule = newRule()
  expect([rule.name, rule.from, rule.to, rule.proto, rule.ports]).toEqual(['', 'wan', '', 'tcp', []])
  expect(FORWARD_PROTOCOLS).toEqual([
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
  ])
  expect(RULE_PROTOCOLS.map((option) => [option.value, option.label])).toEqual([
    ['tcp', 'TCP'],
    ['udp', 'UDP'],
    ['icmp', 'ICMP'],
    ['any', 'Any'],
  ])
  expect(fromOptions(routerConfig())).toEqual([
    { value: 'wan', label: 'Internet' },
    { value: 'lan0', label: 'lan0' },
    { value: 'iot', label: 'iot' },
  ])
})

test('answering ping is put back as the router has it', () => {
  // A router with no firewall settings at all, a toggle switched on and off again: no change.
  const base = routerConfig()
  base.firewall = undefined
  const draft = clone(ConfigSchema, base)
  setWanPing(draft, true, base)
  expect(draft.firewall?.wanPing).toBe(true)
  expect(changes(base, draft)).toEqual([{ subject: 'The router', what: 'answers ping from the internet', before: 'no', after: 'yes' }])
  setWanPing(draft, false, base)
  expect(draft.firewall).toBeUndefined()
  expect(changes(base, draft)).toEqual([])
  // With settings there, the message stays.
  const kept = routerConfig()
  setWanPing(kept, true, routerConfig())
  setWanPing(kept, false, routerConfig())
  expect(kept.firewall?.portForwards).toHaveLength(1)
  expect(changes(routerConfig(), kept)).toEqual([])
})
