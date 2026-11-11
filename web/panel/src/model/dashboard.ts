// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the dashboard shows, as pure functions of what the router said (SPEC §8.4): the page
// holds no arithmetic and no wording of its own. Things are named as the config and the
// kernel have them; a status is a word; an enum value this code has not met reads "Unknown"
// rather than being guessed at or dropped.

import {
  AddressOrigin,
  PortUseKind,
  WanKind,
  WanPhase,
  type LanState,
  type LinkRate,
  type PortState,
  type State,
  type WanState,
} from '@openfeo/client'

import { DASH, portSpeed, rate, since } from './format'

const UNKNOWN = 'Unknown'

/** The WAN carrying the IPv4 default route, or failing that the first. */
export function defaultWan(state: State): WanState | undefined {
  return state.wans.find((wan) => wan.default4) ?? state.wans[0]
}

function plural(count: number, one: string): string {
  return `${count} ${one}${count === 1 ? '' : 's'}`
}

function clients(state: State): number {
  return state.lans.reduce((sum, lan) => sum + lan.leases, 0)
}

/** The line under the page's title: the default WAN and since when, and who is on the LANs. */
export function headline(state: State): string {
  const wan = defaultWan(state)
  let first = 'No WAN configured'
  if (wan !== undefined) {
    switch (wan.phase) {
      case WanPhase.UP: {
        // The time it came up is the router's wall clock, which is only true once synced.
        const dated = state.system?.timeSynced === true && wan.phaseSinceUnixMs !== undefined
        first = dated ? `${wan.name} up since ${since(wan.phaseSinceUnixMs ?? 0n)}` : `${wan.name} up`
        break
      }
      case WanPhase.CONNECTING:
        first = `${wan.name} connecting`
        break
      case WanPhase.DOWN:
        first = wan.reason === '' ? `${wan.name} down` : `${wan.name} down: ${wan.reason}`
        break
      default:
        first = `${wan.name} unknown`
    }
  }
  return `${first} · ${plural(clients(state), 'client')} on ${plural(state.lans.length, 'LAN')}`
}

export interface Tile {
  label: string
  value: string
  unit?: string
  foot?: string
  spark?: number[]
  series?: 1 | 2
}

/** What is live beside the state: the default WAN's rate, its last minute, the tracked connections. */
export interface Live {
  rate?: LinkRate | undefined
  history: { rx: number[]; tx: number[] }
  conntrack?: { count: number; max: number } | undefined
}

/** The four tiles: download, upload, clients, connections. */
export function tiles(state: State, live: Live): Tile[] {
  const flow = (label: string, bitsPerSec: number | undefined, spark: number[], series: 1 | 2): Tile => {
    if (bitsPerSec === undefined) {
      return { label, value: DASH, spark, series }
    }
    const { value, unit } = rate(bitsPerSec)
    return { label, value, unit, spark, series }
  }
  const leased: Tile = { label: 'Clients', value: String(clients(state)) }
  if (state.lans.length > 0) {
    leased.foot = state.lans.map((lan) => `${lan.leases} on ${lan.name}`).join(' · ')
  }
  const tracked: Tile =
    live.conntrack === undefined
      ? { label: 'Connections', value: DASH }
      : { label: 'Connections', value: String(live.conntrack.count), foot: `of ${live.conntrack.max} tracked` }
  return [
    flow('Download', live.rate?.rxBitsPerSec, live.history.rx, 1),
    flow('Upload', live.rate?.txBitsPerSec, live.history.tx, 2),
    leased,
    tracked,
  ]
}

interface Rate {
  value: string
  unit: string
}

export interface Card {
  name: string
  role: string
  status: { word: string; tone?: 'ok' | 'info' | 'danger' }
  facts: { key: string; value: string }[]
  rates: { rx: Rate; tx: Rate } | null
  active: boolean
}

/** The design system's limit on a card: more than this belongs on a page of its own. */
const MOST_FACTS = 5

function ratesOf(rates: Map<string, LinkRate> | null, link: string): Card['rates'] {
  const found = rates?.get(link)
  return found === undefined ? null : { rx: rate(found.rxBitsPerSec), tx: rate(found.txBitsPerSec) }
}

function facts(pairs: [key: string, value: string][]): Card['facts'] {
  return pairs
    .filter(([, value]) => value !== '')
    .slice(0, MOST_FACTS)
    .map(([key, value]) => ({ key, value }))
}

const WAN_KINDS: Partial<Record<WanKind, string>> = {
  [WanKind.STATIC]: 'Static',
  [WanKind.DHCP]: 'DHCP',
  [WanKind.PPPOE]: 'PPPoE',
}

const WAN_STATUS: Partial<Record<WanPhase, Card['status']>> = {
  [WanPhase.UP]: { word: 'Up', tone: 'ok' },
  [WanPhase.CONNECTING]: { word: 'Connecting', tone: 'info' },
  [WanPhase.DOWN]: { word: 'Down', tone: 'danger' },
}

function wanCard(wan: WanState, rates: Map<string, LinkRate> | null, active: boolean): Card {
  const under = wan.vlan === 0 ? wan.port : `${wan.port}.${wan.vlan}`
  return {
    name: wan.name,
    role: `WAN · ${WAN_KINDS[wan.kind] ?? UNKNOWN}${wan.vlan === 0 ? '' : ` · VLAN ${wan.vlan}`}`,
    status: WAN_STATUS[wan.phase] ?? { word: UNKNOWN },
    facts: facts([
      // Why it is not up, in the console's own words.
      ['Reason', wan.phase === WanPhase.UP ? '' : wan.reason],
      ['IPv4', wan.ipv4],
      ['Gateway', wan.kind === WanKind.PPPOE ? wan.ipv4Peer : wan.gateway4],
      wan.ipv6 === '' ? ['Prefix', wan.ipv6Prefixes[0] ?? ''] : ['IPv6', wan.ipv6],
      ['Interface', wan.interface === under ? wan.interface : `${wan.interface} on ${under}`],
      ['MTU', wan.mtu === 0 ? '' : String(wan.mtu)],
    ]),
    rates: ratesOf(rates, wan.interface),
    active,
  }
}

function lanCard(lan: LanState, ports: PortState[], rates: Map<string, LinkRate> | null): Card {
  // A member is a port, or a VLAN of one (`p3.20`): it has a link when the port does.
  const linked = lan.members.some((member) => ports.find((port) => port.name === member.split('.')[0])?.carrier === true)
  return {
    name: lan.name,
    role: lan.vlan === undefined ? 'LAN' : `LAN · VLAN ${lan.vlan}`,
    status: linked ? { word: 'Up', tone: 'ok' } : { word: 'No link' },
    facts: facts([
      ['IPv4', lan.ipv4],
      ['IPv6', lan.ipv6[0] ?? ''],
      ['Interface', lan.interface],
      ['Ports', lan.members.join(' ')],
      ['DHCP', lan.dhcp ? `${lan.leases} / ${lan.poolSize} leases` : 'off'],
    ]),
    rates: ratesOf(rates, lan.interface),
    active: false,
  }
}

/** A card for each WAN, in the config's order, and then for each LAN. */
export function cards(state: State, rates: Map<string, LinkRate> | null): Card[] {
  const active = defaultWan(state)
  return [
    ...state.wans.map((wan) => wanCard(wan, rates, wan === active)),
    ...state.lans.map((lan) => lanCard(lan, state.ports, rates)),
  ]
}

const USE_KINDS: Partial<Record<PortUseKind, string>> = {
  [PortUseKind.WAN]: 'WAN',
  [PortUseKind.LAN]: 'LAN',
}

/** The physical ports in their own order, each with what its tooltip says in full. */
export function ports(state: State): { name: string; speed: string; wan: boolean; up: boolean; title: string }[] {
  return state.ports.map((port) => {
    const uses = port.uses.map((use) => `${USE_KINDS[use.kind] ?? UNKNOWN} ${use.name}${use.vlan === 0 ? '' : `, VLAN ${use.vlan}`}`)
    const said = [port.name, port.mac, ...(uses.length === 0 ? ['not in use'] : uses), ...(port.carrier ? [] : ['no link'])]
    return {
      name: port.name,
      speed: portSpeed(port),
      wan: port.uses.some((use) => use.kind === PortUseKind.WAN),
      up: port.carrier,
      title: said.filter((part) => part !== '').join(' · '),
    }
  })
}

const ORIGINS: Partial<Record<AddressOrigin, string>> = {
  [AddressOrigin.CONFIG]: 'Config',
  [AddressOrigin.PPP]: 'PPP',
  [AddressOrigin.DHCP]: 'DHCP',
  [AddressOrigin.ROUTER_ADVERTISEMENT]: 'Router advertisement',
  [AddressOrigin.DELEGATED_PREFIX]: 'Delegated prefix',
  [AddressOrigin.ULA]: 'ULA',
}

export interface AddressRow {
  interface: string
  /** The first row of its interface: the one that names it. */
  first: boolean
  address: string
  from: string
  deprecated: boolean
}

/**
 * Every address the kernel holds but the link-local ones, each interface's kept together in
 * the order the router first named it, with where each came from.
 */
export function addresses(state: State): AddressRow[] {
  const byInterface = new Map<string, AddressRow[]>()
  for (const held of state.addresses) {
    if (held.origin === AddressOrigin.LINK_LOCAL) {
      continue
    }
    const rows = byInterface.get(held.interface) ?? []
    rows.push({
      interface: held.interface,
      first: rows.length === 0,
      address: held.peer === '' ? held.address : `${held.address} peer ${held.peer}`,
      from: ORIGINS[held.origin] ?? UNKNOWN,
      deprecated: held.deprecated,
    })
    byInterface.set(held.interface, rows)
  }
  return [...byInterface.values()].flat()
}
