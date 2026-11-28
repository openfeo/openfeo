// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Firewall page works out (SPEC §7.5, §8.4): the grid of which network may start
// connections to which, a new forward and a new rule, and what the page can know is wrong with
// one before the router is asked. Everything else is the router's to refuse.

import { create, FirewallSchema, PortForwardSchema, RuleSchema, toJson, type Config, type Lan, type PortForward, type Rule } from '@openfeo/client'

import { isCidr6, isIp6, parse4, parseCidr4 } from './ip'

/** `reaches`' word for the internet. */
export const INTERNET = 'wan'
/** `reaches`' word for nothing at all. */
const NOTHING = 'none'

export interface ReachCell {
  /** `wan`, or a LAN's name. */
  to: string
  /** As a sentence names it: `the internet`, or the LAN's name. */
  label: string
  ticked: boolean
  /** The row's own LAN: no tick to give. */
  own: boolean
}

export interface ReachRow {
  lan: string
  cells: ReachCell[]
}

/** What a list of `reaches` lets its LAN reach: an empty list is the internet alone, `none` is nothing. */
function reached(reaches: readonly string[]): string[] {
  return reaches.length === 0 ? [INTERNET] : reaches.filter((name) => name !== NOTHING)
}

/** A row per LAN, a cell for the internet and for each LAN; a LAN's own cell is `own` and has no tick. */
export function reachGrid(config: Config): ReachRow[] {
  return config.lans.map((lan) => {
    const may = reached(lan.reaches)
    return {
      lan: lan.name,
      cells: [
        { to: INTERNET, label: 'the internet', ticked: may.includes(INTERNET), own: false },
        ...config.lans.map((other) => ({ to: other.name, label: other.name, ticked: other.name !== lan.name && may.includes(other.name), own: other.name === lan.name })),
      ],
    }
  })
}

/**
 * Tick or untick `to` for `lan`. No tick left is `none`; what the router has (`base`) is put
 * back as the router has it when the ticks come to mean the same, so that an empty list stays
 * empty; otherwise the internet first, then LANs in the config's order. A name the grid does
 * not show is kept, after the ones it does.
 */
export function setReach(lan: Lan, to: string, on: boolean, config: Config, base: Lan | undefined): void {
  const may = new Set(reached(lan.reaches))
  if (on) {
    may.add(to)
  } else {
    may.delete(to)
  }
  const shown = [INTERNET, ...config.lans.map((other) => other.name)]
  const ordered = [...shown.filter((name) => may.has(name)), ...[...may].filter((name) => !shown.includes(name))]
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((name) => b.includes(name))
  if (base !== undefined && same(reached(base.reaches), ordered)) {
    lan.reaches = [...base.reaches]
  } else {
    lan.reaches = ordered.length === 0 ? [NOTHING] : ordered
  }
}

export const FORWARD_PROTOCOLS: { value: string; label: string }[] = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
]

export const RULE_PROTOCOLS: { value: string; label: string }[] = [
  ...FORWARD_PROTOCOLS,
  { value: 'icmp', label: 'ICMP' },
  { value: 'any', label: 'Any' },
]

/** Where a rule may start from: the internet, or a LAN. */
export function fromOptions(config: Config): { value: string; label: string }[] {
  return [{ value: INTERNET, label: 'Internet' }, ...config.lans.map((lan) => ({ value: lan.name, label: lan.name }))]
}

export function newForward(): PortForward {
  return create(PortForwardSchema, { proto: 'tcp' })
}

export function newRule(): Rule {
  return create(RuleSchema, { from: INTERNET, proto: 'tcp' })
}

/** Whether the config has a public IPv4 block: only then may a forward listen on an address of its own. */
export function publicBlocks(config: Config): boolean {
  return config.publicIpv4.length > 0
}

/**
 * Whether the router answers ping from the internet. A config that had no firewall settings
 * and has none again is left without them, as the router has it.
 */
export function setWanPing(config: Config, on: boolean, base: Config | null): void {
  config.firewall ??= create(FirewallSchema, {})
  config.firewall.wanPing = on
  settle(config, base)
}

/**
 * Take the firewall settings out of `config` when nothing is set in them and the router has
 * none either: there with nothing in them and not there at all are two files, and a row added
 * and removed again, or a toggle switched and switched back, should leave the first as it was.
 */
export function settle(config: Config, base: Config | null): void {
  if (config.firewall !== undefined && base?.firewall === undefined && Object.keys(toJson(FirewallSchema, config.firewall) as object).length === 0) {
    config.firewall = undefined
  }
}

/** A rule's ports as one field: "80, 443, 1000-1010". */
export function portsText(ports: readonly string[]): string {
  return ports.join(', ')
}

/** The ports typed into that field: separated by commas, what is around them left out. */
export function parsePorts(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

const PORT = 'A port from 1 to 65535.'
const IPV4 = 'An IPv4 address.'

function isPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65_535
}

/** One port, or `low-high`. */
function portOrRange(text: string): boolean {
  const parts = text.split('-')
  if (parts.length > 2 || !parts.every((part) => /^\d+$/.test(part))) {
    return false
  }
  const [low, high] = parts.map(Number)
  return low !== undefined && isPort(low) && (high === undefined || (isPort(high) && low <= high))
}

function nameProblem(names: readonly string[], n: number, what: string): string | undefined {
  const name = names[n] ?? ''
  if (name === '') {
    return 'Give it a name.'
  }
  return names.some((other, at) => at !== n && other === name) ? `Another ${what} has this name.` : undefined
}

/** A record of what is wrong, without the fields that are right. */
function only(found: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(Object.entries(found).filter((entry): entry is [string, string] => entry[1] !== undefined))
}

/** What the page can know is wrong with forward `n`, by field: name, port, to, to_port, address. */
export function forwardProblems(forwards: readonly PortForward[], n: number): Record<string, string> {
  const forward = forwards[n]
  if (forward === undefined) {
    return {}
  }
  return only({
    name: nameProblem(
      forwards.map((each) => each.name),
      n,
      'forward',
    ),
    port: isPort(forward.port) ? undefined : PORT,
    to: forward.to === '' || parse4(forward.to) !== null ? undefined : IPV4,
    // 0 is the same port as the one it listens on.
    to_port: forward.toPort === 0 || isPort(forward.toPort) ? undefined : PORT,
    address: forward.address === '' || parse4(forward.address) !== null ? undefined : IPV4,
  })
}

/** An address, an `a-b` range within one family, or a block, IPv4 or IPv6. */
function isTarget(text: string): boolean {
  if (parse4(text) !== null || isIp6(text) || parseCidr4(text) !== null || isCidr6(text)) {
    return true
  }
  const ends = text.split('-')
  if (ends.length !== 2) {
    return false
  }
  const [first, last] = ends.map((end) => end.trim())
  if (first === undefined || last === undefined) {
    return false
  }
  const [low, high] = [parse4(first), parse4(last)]
  return low !== null && high !== null ? low <= high : isIp6(first) && isIp6(last)
}

/** What the page can know is wrong with rule `n`, by field: name, to, ports. */
export function ruleProblems(rules: readonly Rule[], n: number): Record<string, string> {
  const rule = rules[n]
  if (rule === undefined) {
    return {}
  }
  const ported = rule.proto === 'tcp' || rule.proto === 'udp'
  return only({
    name: nameProblem(
      rules.map((each) => each.name),
      n,
      'rule',
    ),
    to: rule.to === '' || isTarget(rule.to) ? undefined : 'An address, a range such as 192.168.1.10-192.168.1.20, or a block such as 192.168.1.0/28.',
    ports:
      rule.ports.length === 0
        ? undefined
        : !ported
          ? 'Ports go with TCP and UDP only.'
          : rule.ports.every(portOrRange)
            ? undefined
            : 'Ports are numbers from 1 to 65535, or ranges such as 1000-1010.',
  })
}
