// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the LAN & DHCP page knows beyond arranging fields (SPEC §8.4): the sizes a subnet may
// have and the range each gives, the ports a LAN may take, how its DHCP server and its IPv6
// are switched without losing what was set, what stands in the way of removing it, and what
// is wrong with a field as typed.

import { clone, create, LanDhcpSchema, LanSchema, type Config, type Lan, type LanDhcp, type PortState } from '@openfeo/client'

import { addressList, between, cidr4, cidr6, inSubnet, mac, pool } from './check'
import { contains, format4, formatNetwork, hostCount, hostRange, network, parse4, parseCidr4, type Cidr4 } from './ip'
import { under } from './path'

/** The lease time the router gives when the config names none. */
const DEFAULT_LEASE_SECS = 43_200

function addresses(prefix: number): string {
  const count = hostCount(prefix)
  return count === 0 ? 'no addresses for devices' : `${count} address${count === 1 ? '' : 'es'}`
}

/** The sizes a LAN's subnet may be given: a /16 to a /30, and the one it has, each with what it holds. */
export function sizeOptions(current: number): { value: string; label: string }[] {
  const sizes = new Set([current])
  for (let prefix = 16; prefix <= 30; prefix++) {
    sizes.add(prefix)
  }
  return [...sizes].sort((a, b) => a - b).map((prefix) => ({ value: String(prefix), label: `/${prefix} · ${addresses(prefix)}` }))
}

/** The addresses devices can have on a LAN whose own is `lan`: `192.168.50.1 to 192.168.50.254.` */
export function rangeWords(lan: string): string {
  const subnet = parseCidr4(lan)
  if (subnet === null) {
    return ''
  }
  if (hostCount(subnet.prefix) === 0) {
    return 'No addresses for devices.'
  }
  const [first, last] = hostRange(subnet)
  return `${format4(first)} to ${format4(last)}.`
}

const LEASES: { value: string; label: string }[] = [
  { value: '3600', label: '1 hour' },
  { value: '43200', label: '12 hours' },
  { value: '86400', label: '1 day' },
  { value: '604800', label: '1 week' },
]

/** The lease times offered: four, and Other for any number of seconds. */
export function leaseOptions(): { value: string; label: string }[] {
  return [...LEASES, { value: 'other', label: 'Other…' }]
}

/** Which of {@link leaseOptions} a lease time is. Left to the router (0) it is twelve hours. */
export function leaseValue(secs: number): string {
  const value = String(secs === 0 ? DEFAULT_LEASE_SECS : secs)
  return LEASES.some((lease) => lease.value === value) ? value : 'other'
}

/** Set the lease time. One that means what the router's config (`base`) means is written as the router has it. */
export function setLease(dhcp: LanDhcp, secs: number, base: LanDhcp | undefined): void {
  const means = (value: number) => (value === 0 ? DEFAULT_LEASE_SECS : value)
  dhcp.leaseSecs = base !== undefined && means(base.leaseSecs) === means(secs) ? base.leaseSecs : secs
}

/**
 * The ports a LAN may tick: its own members, and the ports nothing else has. A port that is
 * a WAN's, or another LAN's untagged member, is not offered. Its tagged members (a VLAN on a
 * port, `p3.20`) are shown and fixed: LAN VLANs are set in the config file.
 */
export function portChoices(ports: PortState[], config: Config, lan: Lan): { name: string; hint: string; ticked: boolean; fixed: boolean }[] {
  const others = config.lans.filter((other) => other !== lan && other.name !== lan.name)
  const choices: { name: string; hint: string; ticked: boolean; fixed: boolean }[] = []
  for (const port of ports) {
    if (lan.ports.includes(port.name)) {
      choices.push({ name: port.name, hint: '', ticked: true, fixed: false })
    } else if (!config.wans.some((wan) => wan.port === port.name) && !others.some((other) => other.ports.includes(port.name))) {
      const tagged = others.filter((other) => other.ports.some((member) => member.startsWith(`${port.name}.`))).map((other) => other.name)
      choices.push({ name: port.name, hint: tagged.length === 0 ? 'free' : `carries ${tagged.join(', ')} tagged`, ticked: false, fixed: false })
    }
  }
  for (const member of lan.ports) {
    if (member.includes('.')) {
      choices.push({ name: member, hint: 'tagged: set in the config file', ticked: true, fixed: true })
    } else if (!ports.some((port) => port.name === member)) {
      choices.push({ name: member, hint: 'not a port of this router', ticked: true, fixed: false })
    }
  }
  return choices
}

/** A first DHCP server's pool: the 100th to the 200th address of a subnet that has them, or one still to be typed. */
function proposed(lan: Lan): LanDhcp {
  const subnet = parseCidr4(lan.ipv4)
  const range = subnet !== null && hostCount(subnet.prefix) >= 200 ? [format4(network(subnet) + 100), format4(network(subnet) + 200)] : []
  return create(LanDhcpSchema, { range })
}

/**
 * Switch a LAN's DHCP server on or off. Off keeps its pool and reservations, which come back
 * when it is switched on again; with nothing kept, on is what the router's config (`base`)
 * has for it, or for a first server a pool proposed from the subnet.
 */
export function setDhcp(lan: Lan, on: boolean, kept: Map<string, LanDhcp>, base?: Lan): void {
  if ((lan.dhcp !== undefined) === on) {
    return
  }
  if (!on) {
    if (lan.dhcp !== undefined) {
      kept.set(lan.name, lan.dhcp)
    }
    lan.dhcp = undefined
    return
  }
  lan.dhcp = kept.get(lan.name) ?? (base?.dhcp !== undefined ? clone(LanDhcpSchema, base.dhcp) : proposed(lan))
}

/**
 * Switch a LAN's IPv6 on or off. Off is `ipv6 = "none"`, and takes with it what the router
 * accepts only on a LAN that carries IPv6 (whether it advertises, its number in a
 * delegation); on brings back what the router's config (`base`) has, when that is on.
 */
export function setLanIpv6(lan: Lan, on: boolean, base: Lan | undefined): void {
  const had = base !== undefined && base.ipv6 !== 'none' ? base : undefined
  lan.ipv6 = on ? (had?.ipv6 ?? '') : 'none'
  lan.ra = on ? had?.ra : undefined
  lan.ipv6Index = on ? (had?.ipv6Index ?? 0) : 0
}

/** The first and last address a rule's target covers (an address, an `a-b` range or a block), when it is IPv4. */
function bounds(target: string): [number, number] | null {
  const ends = /^([^-/]+)-([^-/]+)$/.exec(target)
  if (ends !== null) {
    const first = parse4(ends[1] ?? '')
    const last = parse4(ends[2] ?? '')
    return first === null || last === null ? null : [first, last]
  }
  const block = parseCidr4(target)
  if (block !== null) {
    return [network(block), network(block) + 2 ** (32 - block.prefix) - 1]
  }
  const address = parse4(target)
  return address === null ? null : [address, address]
}

/**
 * What still points at a LAN, and so stands in the way of removing it, each in words. Each is
 * removed where it is edited, on the Firewall page: removing them with the LAN would delete
 * firewall config on the strength of a press elsewhere.
 */
export function blockers(config: Config, lan: Lan): string[] {
  const subnet = parseCidr4(lan.ipv4)
  const inside = (first: number, last: number) => subnet !== null && contains(subnet, first) && contains(subnet, last)
  const found: string[] = []
  for (const forward of config.firewall?.portForwards ?? []) {
    const to = parse4(forward.to)
    if (to !== null && inside(to, to)) {
      found.push(`port forward ${forward.name} points into it`)
    }
  }
  for (const rule of config.firewall?.rules ?? []) {
    const covered = bounds(rule.to)
    if (covered !== null && inside(covered[0], covered[1])) {
      found.push(`rule ${rule.name} points into it`)
    }
    if (rule.from === lan.name) {
      found.push(`rule ${rule.name} starts from it`)
    }
  }
  for (const other of config.lans) {
    if (other.name !== lan.name && other.reaches.includes(lan.name)) {
      found.push(`${other.name} may reach it`)
    }
  }
  return found
}

/** A LAN as it starts: a name, and nothing else yet. */
export function newLan(name: string): Lan {
  return create(LanSchema, { name })
}

/**
 * The paths under `lans[i]` the page has a field for. A violation at or beneath one is shown
 * there; so is one at or beneath a reservation's row (see {@link claimed}).
 */
export const LAN_FIELDS: string[] = ['ipv4', 'dhcp.range', 'dhcp.lease_secs', 'dhcp.dns', 'dhcp.ntp', 'ipv6', 'ipv6_index']

/** Whether a violation at `within` (its path under the LAN) has a field of the page to be shown at. */
export function claimed(within: string): boolean {
  return LAN_FIELDS.some((field) => under(within, field)) || /^dhcp\.static\[\d+\]/.test(within)
}

/**
 * What is wrong with each of a LAN's fields as typed, by its path under the LAN. The pool's
 * start answers for `dhcp.range` (where the router says what it finds wrong with a pool) and
 * its end for `dhcp.range[1]`.
 */
export function lanProblems(lan: Lan): Record<string, string> {
  const found: [string, string | null][] = [
    ['ipv4', cidr4(lan.ipv4)],
    ['ipv6', lan.ipv6 === 'none' ? null : cidr6(lan.ipv6)],
    ['ipv6_index', lan.ipv6Index === 0 ? null : between(String(lan.ipv6Index), 1, 65_535)],
  ]
  const dhcp = lan.dhcp
  if (dhcp !== undefined) {
    const ends = pool(dhcp.range[0] ?? '', dhcp.range[1] ?? '', lan.ipv4)
    found.push(
      ['dhcp.range', ends.start],
      ['dhcp.range[1]', ends.end],
      ['dhcp.lease_secs', dhcp.leaseSecs !== 0 && dhcp.leaseSecs < 60 ? 'At least 60 seconds.' : null],
      ['dhcp.dns', addressList(dhcp.dns.join(', '))],
      ['dhcp.ntp', addressList(dhcp.ntp.join(', '))],
    )
    for (const [at, lease] of dhcp.static.entries()) {
      found.push([`dhcp.static[${at}].mac`, lease.clientId === '' ? mac(lease.mac) : null], [`dhcp.static[${at}].ip`, inSubnet(lease.ip, lan.ipv4)])
    }
  }
  return Object.fromEntries(found.filter((entry): entry is [string, string] => entry[1] !== null))
}

/**
 * Whether an address the renumbering could not place is still what its field holds. One on
 * this page that has since been changed by hand is no longer the renumbering's to report;
 * one that is on no page here is reported until the draft is another.
 */
export function stillUnfit(config: Config, unfit: { path: string; value: string }): boolean {
  const list = /^lans\[(\d+)\]\.dhcp\.(range|dns|ntp)\[(\d+)\]$/.exec(unfit.path)
  if (list !== null) {
    const dhcp = config.lans[Number(list[1])]?.dhcp
    const held = list[2] === 'range' ? dhcp?.range : list[2] === 'dns' ? dhcp?.dns : dhcp?.ntp
    return held?.[Number(list[3])] === unfit.value
  }
  const lease = /^lans\[(\d+)\]\.dhcp\.static\[(\d+)\]\.ip$/.exec(unfit.path)
  if (lease !== null) {
    return config.lans[Number(lease[1])]?.dhcp?.static[Number(lease[2])]?.ip === unfit.value
  }
  return true
}

/**
 * What a field whose address the renumbering could not place says: which subnet it has no
 * place in, that of the LAN whose move left it behind.
 */
export function unfitWords(base: Config, draft: Config, value: string): string {
  const address = parse4(value)
  for (const lan of draft.lans) {
    const before = base.lans.find((other) => other.name === lan.name)
    const from: Cidr4 | null = before === undefined || before.ipv4 === lan.ipv4 ? null : parseCidr4(before.ipv4)
    const to = parseCidr4(lan.ipv4)
    if (address !== null && from !== null && to !== null && contains(from, address)) {
      return `Has no place in ${formatNetwork(to)}.`
    }
  }
  return 'Has no place in the new subnet.'
}
