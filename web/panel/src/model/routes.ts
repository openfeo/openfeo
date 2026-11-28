// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Routes page shows of the router's dump (SPEC §8.4). The dump is every route the
// kernel holds; a person reads the ones that say where traffic goes, so the page leaves out
// the kernel's own entries for its addresses and the link-local and multicast ones every
// interface has, puts the main table first, and says whose each route is.

import { RouteKind, type Route, type State } from '@openfeo/client'

import { contains, network, parseCidr4, parseCidr6, within6, type Cidr6 } from './ip'

/** A row of the page's table (a table's row is its cells by name). */
export interface RouteRow extends Record<string, string> {
  key: string
  /** The block, or `default`. */
  destination: string
  /** The gateway, `on the link`, or `refused`. */
  via: string
  how: 'gateway' | 'link' | 'refused'
  /** The kernel interface; empty for a route that has none. */
  interface: string
  /** The WAN or LAN it belongs to, in words; a dash when it is nobody's. */
  belongsTo: string
}

/** The kinds that turn traffic away. */
const REFUSING: RouteKind[] = [RouteKind.UNREACHABLE, RouteKind.BLACKHOLE, RouteKind.PROHIBIT]
/** The router's main table, and the kernel's own. */
const MAIN = 'main'
const LOCAL = 'local'
const NOBODY = '—'

const block6 = (text: string): Cidr6 => parseCidr6(text) ?? { address: 0n, prefix: 128 }
const LINK_LOCAL6 = block6('fe80::/10')
const MULTICAST6 = block6('ff00::/8')
const MULTICAST4 = parseCidr4('224.0.0.0/4')

/** A destination every interface has and nobody reads: link-local, or multicast. */
function everywhere(route: Route): boolean {
  if (route.v6) {
    const block = parseCidr6(route.destination)
    return block !== null && (within6(block, LINK_LOCAL6) || within6(block, MULTICAST6))
  }
  const block = parseCidr4(route.destination)
  return block !== null && MULTICAST4 !== null && contains(MULTICAST4, network(block))
}

function belongsTo(route: Route, state: State): string {
  const own = route.table === MAIN ? undefined : state.wans.find((wan) => wan.name === route.table)
  if (own !== undefined) {
    return `${own.name}, its own table`
  }
  if (route.interface !== '') {
    const carrier = state.wans.find((wan) => wan.interface === route.interface) ?? state.lans.find((lan) => lan.interface === route.interface)
    if (carrier !== undefined) {
      return carrier.name
    }
  }
  if (route.v6 && REFUSING.includes(route.kind)) {
    const block = parseCidr6(route.destination)
    const wan =
      block === null
        ? undefined
        : state.wans.find((each) =>
            each.ipv6Prefixes.some((prefix) => {
              const whole = parseCidr6(prefix)
              return whole !== null && within6(block, whole)
            }),
          )
    if (wan !== undefined) {
      return `${wan.name}, the part of its prefix no LAN uses`
    }
  }
  return NOBODY
}

/** The routes of one family that a person reads: what the page shows, in its order. */
export function routeRows(routes: Route[], state: State, v6: boolean): RouteRow[] {
  /** Main first, then each WAN's own table in the WANs' order, then any other. */
  const rank = (table: string): number => {
    if (table === MAIN) {
      return 0
    }
    const wan = state.wans.findIndex((each) => each.name === table)
    return wan === -1 ? state.wans.length + 1 : wan + 1
  }
  return routes
    .filter((route) => route.v6 === v6 && route.table !== LOCAL && route.kind !== RouteKind.LOCAL && !everywhere(route))
    .map((route, sent) => ({ route, sent }))
    .sort((a, b) => rank(a.route.table) - rank(b.route.table) || Number(b.route.destination === '') - Number(a.route.destination === '') || a.sent - b.sent)
    .map(({ route }) => {
      const refused = REFUSING.includes(route.kind)
      const how = refused ? 'refused' : route.gateway === '' ? 'link' : 'gateway'
      return {
        key: [route.table, route.destination, route.gateway, route.interface, route.metric, route.kind].join('|'),
        destination: route.destination === '' ? 'default' : route.destination,
        via: how === 'gateway' ? route.gateway : how === 'link' ? 'on the link' : 'refused',
        how,
        interface: refused ? '' : route.interface,
        belongsTo: belongsTo(route, state),
      }
    })
}
