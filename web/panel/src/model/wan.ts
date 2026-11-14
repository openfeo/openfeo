// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the WAN page knows beyond arranging fields (SPEC §8.4): which type a WAN is and how
// one is changed for another without losing what was typed, the ports it may sit on, how a
// new one starts, and what is wrong with a field as typed.

import { clone, create, Ipv6WanSchema, WanSchema, type Config, type Ipv6Wan, type PortState, type Wan } from '@openfeo/client'

import { address4, address6, addressList, between, cidr4, cidr6 } from './check'

export type WanType = 'dhcp' | 'pppoe' | 'static'

/** The WAN's type. One with none yet (which no running config has) reads as DHCP. */
export function typeOf(wan: Wan): WanType {
  return wan.kind.case ?? 'dhcp'
}

/**
 * Make the WAN another type. What was typed for the type it leaves is kept, under the WAN's
 * name and that type, and comes back if the type is chosen again; with nothing kept, a type
 * that is the router's own for this WAN (`base`) comes back as the router has it, so that
 * going there and back is no change.
 */
export function setType(wan: Wan, type: WanType, kept: Map<string, Wan['kind']>, base?: Wan): void {
  if (wan.kind.case === type) {
    return
  }
  if (wan.kind.case !== undefined) {
    kept.set(`${wan.name}:${wan.kind.case}`, wan.kind)
  }
  const before = kept.get(`${wan.name}:${type}`)
  if (before !== undefined) {
    wan.kind = before
  } else if (base?.kind.case === type) {
    wan.kind = clone(WanSchema, base).kind
  } else {
    wan.kind = create(WanSchema, { kind: { case: type, value: {} } }).kind
  }
}

/** Whether the WAN carries IPv6: it has the table, and the table does not say `disabled`. */
export function ipv6On(wan: Wan): boolean {
  return wan.ipv6 !== undefined && wan.ipv6.mode !== 'disabled'
}

/**
 * Switch a WAN's IPv6 on or off. Off keeps what was typed for it, which comes back when it
 * is switched on again; off where the router's own config (`base`) has it off is that
 * config's spelling of off, and on where it has it on is what it has.
 */
export function setIpv6(wan: Wan, on: boolean, kept: Map<string, Ipv6Wan>, base?: Wan): void {
  if (ipv6On(wan) === on) {
    return
  }
  if (!on) {
    if (wan.ipv6 !== undefined) {
      kept.set(wan.name, wan.ipv6)
    }
    wan.ipv6 = base !== undefined && !ipv6On(base) && base.ipv6 !== undefined ? clone(Ipv6WanSchema, base.ipv6) : undefined
    return
  }
  const before = kept.get(wan.name)
  if (before !== undefined && before.mode !== 'disabled') {
    wan.ipv6 = before
  } else if (base !== undefined && ipv6On(base) && base.ipv6 !== undefined) {
    wan.ipv6 = clone(Ipv6WanSchema, base.ipv6)
  } else {
    wan.ipv6 = create(Ipv6WanSchema, {})
  }
}

/** What else in the config sits on a port: the other WANs, then the LANs it is a member of, tagged or not. */
function usersOf(port: string, config: Config, but?: Wan): string[] {
  return [
    ...config.wans.filter((wan) => wan !== but && wan.name !== but?.name && wan.port === port).map((wan) => wan.name),
    ...config.lans.filter((lan) => lan.ports.some((member) => member === port || member.startsWith(`${port}.`))).map((lan) => lan.name),
  ]
}

/**
 * The ports a WAN may sit on, each with its link and its speed, and where it is in use
 * already: the router refuses a port used twice, and says so at this field.
 */
export function portOptions(ports: PortState[], config: Config, wan: Wan): { value: string; label: string }[] {
  const options = ports.map((port) => {
    const parts = [port.name]
    if (port.carrier) {
      if (port.speedMbps !== undefined && port.speedMbps > 0) {
        parts.push(`${port.speedMbps} Mbit/s`)
      }
      parts.push('link up')
    } else {
      parts.push('no link')
    }
    const users = usersOf(port.name, config, wan)
    if (users.length > 0) {
      parts.push(`in ${users.join(', ')}`)
    }
    return { value: port.name, label: parts.join(' · ') }
  })
  if (wan.port === '') {
    options.unshift({ value: '', label: 'Choose a port' })
  } else if (!ports.some((port) => port.name === wan.port)) {
    options.push({ value: wan.port, label: `${wan.port} · not a port of this router` })
  }
  return options
}

/** A WAN as it starts: DHCP, on the first port nothing uses, ten above the highest priority there is. */
export function newWan(config: Config, ports: PortState[], name: string): Wan {
  const free = ports.find((port) => usersOf(port.name, config).length === 0)
  return create(WanSchema, {
    name,
    port: free?.name ?? '',
    priority: Math.max(0, ...config.wans.map((wan) => wan.priority)) + 10,
    kind: { case: 'dhcp', value: {} },
  })
}

/**
 * What is wrong with a name for a new WAN or LAN, or `null`: the router's rule (it becomes
 * part of an interface's name: 11 characters at most for a WAN, 12 for a LAN), and not a
 * name one already has.
 */
export function nameProblem(name: string, taken: string[], longest: number): string | null {
  if (name.length < 1 || name.length > longest || !/^[a-z0-9][a-z0-9_-]*$/.test(name)) {
    return `1 to ${longest} characters: a to z, 0 to 9, - and _, starting with a letter or a digit.`
  }
  return taken.includes(name) ? `${name} is already in use.` : null
}

/** The paths under `wans[i]` the page has a field for. A violation at or beneath one is shown there. */
export const WAN_FIELDS: string[] = [
  'port',
  'vlan',
  'priority',
  'static.address',
  'static.gateway',
  'static.dns',
  'dhcp.hostname',
  'dhcp.vendor_class',
  'pppoe.username',
  'pppoe.password',
  'pppoe.service',
  'pppoe.ac',
  'ipv6.prefix',
  'ipv6.pd_hint',
  'ipv6.gateway',
]

/** What is wrong with each of a WAN's fields as typed, by its path under the WAN. Only what a page can know. */
export function wanProblems(wan: Wan): Record<string, string> {
  const found: [string, string | null][] = [['vlan', wan.vlan === 0 ? null : between(String(wan.vlan), 1, 4094)]]
  if (wan.kind.case === 'static') {
    found.push(
      ['static.address', cidr4(wan.kind.value.address)],
      ['static.gateway', address4(wan.kind.value.gateway)],
      ['static.dns', addressList(wan.kind.value.dns.join(', '))],
    )
  }
  if (wan.ipv6 !== undefined) {
    found.push(
      ['ipv6.prefix', cidr6(wan.ipv6.prefix)],
      ['ipv6.pd_hint', wan.ipv6.pdHint === 0 ? null : between(String(wan.ipv6.pdHint), 48, 64)],
      ['ipv6.gateway', address6(wan.ipv6.gateway)],
    )
  }
  return Object.fromEntries(found.filter((entry): entry is [string, string] => entry[1] !== null))
}
