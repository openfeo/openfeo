// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What follows a LAN whose address or subnet changes (SPEC §8.4). The router refuses a
// config whose pool, reservation, port forward or rule points outside its LAN, and most of
// those are edited on pages this LAN's page is not. So every IPv4 address in the config that
// lay in the old subnet is carried to the new one, and the dialog lists each.
//
// The rule: what was the router's own address is the router's new one. An address a device
// can still have in the new subnet stays where it is. One left outside takes the place the
// same distance from the new subnet's start. One with no such place is left as it was and
// reported, for the person to put right.
//
// Two LANs can be in one subnet for a moment: half way through swapping two, or while one is
// given the subnet another is about to leave. An address there does not say which LAN it
// belongs to, so two things do. A LAN's own pool and reservations follow that LAN and no
// other. Everything else follows the LAN it pointed into as the router has it, wherever
// earlier moves of this draft have carried it since; what the router's config does not
// place in any LAN (typed in this draft) follows whichever LAN leaves first, as it always did.
//
// Which fields hold such addresses is said once, in STRING_FIELDS, for every string field
// the config has: the walk below carries what it says to carry and a test holds the list to
// the schema, so a field added later is classified or the test fails.

import { ConfigSchema, ScalarType, type Config, type DescMessage } from '@openfeo/client'

import { contains, format4, isHost, network, parse4, parseCidr4, type Cidr4 } from './ip'

/** An address the renumbering could not place: where it is, as the router writes a path, and what it holds. */
export interface Unfit {
  path: string
  value: string
}

/**
 * Every string field of the config, by its path without indices: `carried` holds IPv4
 * addresses that follow a renumbered LAN, `own` holds a LAN's own (its pool, its
 * reservations), which follow that LAN alone, `target` a firewall rule's target (an address,
 * an `a-b` range or a block), and `left` is never touched. A LAN's own `ipv4` is left: the
 * edit that renumbers it sets it. The servers a LAN hands out are `carried` and not `own`:
 * one that sits on another LAN follows that LAN.
 */
export const STRING_FIELDS: Record<string, 'carried' | 'own' | 'target' | 'left'> = {
  'system.hostname': 'left',
  'system.domain': 'left',
  'system.timezone': 'left',
  'system.ntp_servers': 'carried',
  'ports.id': 'left',
  'ports.name': 'left',
  'wans.name': 'left',
  'wans.port': 'left',
  // The ISP's side of a static WAN, whatever it looks like.
  'wans.static.address': 'left',
  'wans.static.gateway': 'left',
  'wans.static.dns': 'carried',
  'wans.dhcp.hostname': 'left',
  'wans.dhcp.vendor_class': 'left',
  'wans.pppoe.username': 'left',
  'wans.pppoe.password': 'left',
  'wans.pppoe.service': 'left',
  'wans.pppoe.ac': 'left',
  'wans.ipv6.mode': 'left',
  'wans.ipv6.prefix': 'left',
  'wans.ipv6.gateway': 'left',
  'lans.name': 'left',
  'lans.ports': 'left',
  'lans.ipv4': 'left',
  'lans.reaches': 'left',
  'lans.ipv6': 'left',
  'lans.dhcp.range': 'own',
  'lans.dhcp.static.mac': 'left',
  'lans.dhcp.static.ip': 'own',
  'lans.dhcp.static.hostname': 'left',
  'lans.dhcp.static.client_id': 'left',
  'lans.dhcp.dns': 'carried',
  'lans.dhcp.ntp': 'carried',
  'firewall.port_forwards.name': 'left',
  'firewall.port_forwards.proto': 'left',
  'firewall.port_forwards.to': 'carried',
  // The public address a forward listens on lies outside every LAN.
  'firewall.port_forwards.address': 'left',
  'firewall.rules.name': 'left',
  'firewall.rules.from': 'left',
  'firewall.rules.to': 'target',
  'firewall.rules.proto': 'left',
  'firewall.rules.ports': 'left',
  'dns.upstreams': 'carried',
  'dns.blocklists': 'left',
  'dns.rebind_allow': 'left',
  'dns.records.name': 'left',
  'dns.records.address': 'carried',
  'public_ipv4.prefix': 'left',
  'admin.password_hash': 'left',
}

type Visit = (key: string, path: string, value: string, set: (next: string) => void) => void

/**
 * Every string a message holds, each with its field's path without indices (`key`), its
 * place as the router writes one (`path`: `lans[0].dhcp.range[1]`), and the way to replace it.
 */
function strings(schema: DescMessage, message: Record<string, unknown>, key: string, path: string, visit: Visit): void {
  for (const field of schema.fields) {
    const fieldKey = key === '' ? field.name : `${key}.${field.name}`
    const fieldPath = path === '' ? field.name : `${path}.${field.name}`
    // A member of a oneof lives in its group, and only while it is the one chosen.
    let holder = message
    let slot = field.localName
    if (field.oneof !== undefined) {
      const group = message[field.oneof.localName] as { case?: string } | undefined
      if (group?.case !== field.localName) {
        continue
      }
      holder = group as Record<string, unknown>
      slot = 'value'
    }
    const value = holder[slot]
    if (field.fieldKind === 'scalar' && field.scalar === ScalarType.STRING) {
      if (typeof value === 'string') {
        visit(fieldKey, fieldPath, value, (next) => {
          holder[slot] = next
        })
      }
    } else if (field.fieldKind === 'message') {
      if (value !== undefined) {
        strings(field.message, value as Record<string, unknown>, fieldKey, fieldPath, visit)
      }
    } else if (field.fieldKind === 'list' && Array.isArray(value)) {
      const list = value as unknown[]
      for (const [at, item] of list.entries()) {
        if (field.listKind === 'message') {
          strings(field.message, item as Record<string, unknown>, fieldKey, `${fieldPath}[${at}]`, visit)
        } else if (field.listKind === 'scalar' && field.scalar === ScalarType.STRING && typeof item === 'string') {
          visit(fieldKey, `${fieldPath}[${at}]`, item, (next) => {
            list[at] = next
          })
        }
      }
    }
  }
}

/** Where an address of the old subnet belongs in the new one, or `null` when it has no place. */
function place(address: number, from: Cidr4, to: Cidr4): number | null {
  if (address === from.address) {
    return to.address
  }
  if (isHost(to, address)) {
    return address
  }
  const moved = network(to) + (address - network(from))
  return isHost(to, moved) ? moved : null
}

/**
 * What the renumbering makes of one address that lay in `from`'s subnet, when the LAN goes
 * to `to`: where it is carried to (itself, when it stays), or `null` when it is not such an
 * address or has no place. For a field to say that it was moved with the subnet.
 */
export function carried(address: string, from: string, to: string): string | null {
  const before = parseCidr4(from)
  const after = parseCidr4(to)
  const value = parse4(address)
  if (before === null || after === null || value === null || !contains(before, value)) {
    return null
  }
  const placed = place(value, before, after)
  return placed === null ? null : format4(placed)
}

/**
 * A rule's target after the move: itself when it need not change, `null` when it has no
 * place, `undefined` when it is not IPv4 or does not lie in the old subnet. A range moves
 * whole or not at all. The old subnet itself becomes the new one; a smaller block moves by
 * the same distance as an address would when it is still a block inside the new subnet.
 */
function retarget(text: string, from: Cidr4, to: Cidr4): string | null | undefined {
  const distance = network(to) - network(from)
  const ends = /^([^-/]+)-([^-/]+)$/.exec(text)
  if (ends !== null) {
    const first = parse4(ends[1] ?? '')
    const last = parse4(ends[2] ?? '')
    if (first === null || last === null || !contains(from, first) || !contains(from, last)) {
      return undefined
    }
    if (contains(to, first) && contains(to, last)) {
      return text
    }
    return contains(to, first + distance) && contains(to, last + distance) ? `${format4(first + distance)}-${format4(last + distance)}` : null
  }
  const block = parseCidr4(text)
  if (block !== null) {
    const first = network(block)
    const last = first + 2 ** (32 - block.prefix) - 1
    if (!contains(from, first) || !contains(from, last)) {
      return undefined
    }
    if (first === network(from) && block.prefix === from.prefix) {
      return `${format4(network(to))}/${to.prefix}`
    }
    if (contains(to, first) && contains(to, last)) {
      return text
    }
    const moved = first + distance
    const aligned = contains(to, moved) && network({ address: moved, prefix: block.prefix }) === moved
    return aligned && contains(to, last + distance) ? `${format4(moved)}/${block.prefix}` : null
  }
  const address = parse4(text)
  if (address === null || !contains(from, address)) {
    return undefined
  }
  const placed = place(address, from, to)
  return placed === null ? null : format4(placed)
}

/** Whether two subnets have an address in common. */
function overlap(one: Cidr4, other: Cidr4): boolean {
  return contains(one, network(other)) || contains(other, network(one))
}

/** The address a field's text starts with: the address itself, a range's first, a block's. */
function first(text: string): number | null {
  return parse4(text.split(/[-/]/)[0] ?? '')
}

/**
 * Whose a field is when the subnet a LAN is leaving holds another LAN too: for each field of
 * `base` (the config the draft was read from), by its path, whether what it holds there
 * points into a LAN other than `owner`. Such a field belongs to that LAN and stays. `null`
 * when no other LAN shares the subnet, or there is nothing to tell by: then every address in
 * the subnet follows.
 *
 * A field is known by its path, so a row added or removed above it in this draft is taken
 * for its neighbour: in a subnet two LANs share, and nowhere else.
 */
function anothers(config: Config, before: Cidr4, owner: string | undefined, base: Config | undefined): ((path: string) => boolean) | null {
  if (owner === undefined || base === undefined) {
    return null
  }
  const shared = config.lans.some((lan) => {
    const subnet = lan.name === owner ? null : parseCidr4(lan.ipv4)
    return subnet !== null && overlap(subnet, before)
  })
  if (!shared) {
    return null
  }
  const others = base.lans.flatMap((lan) => {
    const subnet = lan.name === owner ? null : parseCidr4(lan.ipv4)
    return subnet === null ? [] : [subnet]
  })
  const home = parseCidr4(base.lans.find((lan) => lan.name === owner)?.ipv4 ?? '')
  const theirs = new Set<string>()
  strings(ConfigSchema, base as unknown as Record<string, unknown>, '', '', (key, path, value) => {
    const kind = STRING_FIELDS[key]
    const address = kind === 'carried' || kind === 'target' ? first(value) : null
    if (address !== null && !(home !== null && contains(home, address)) && others.some((subnet) => contains(subnet, address))) {
      theirs.add(path)
    }
  })
  return (path) => theirs.has(path)
}

/**
 * Carry every IPv4 address that lay in `from`'s subnet along to `to`'s (both as a LAN's
 * `ipv4`: the router's address and the subnet's size), in place. What had no place in the new
 * subnet is left as it was and handed back. When either is not a valid address, or the two
 * are the same, nothing is touched.
 *
 * With `owner`, the name of the LAN that is moving, a pool and a reservation follow only when
 * they are that LAN's own. With `base` as well, the config the draft was read from, a field
 * that points into another LAN there stays when that LAN shares the subnet being left.
 * Without them every address in the subnet follows.
 */
export function renumber(config: Config, from: string, to: string, owner?: string, base?: Config): Unfit[] {
  const before = parseCidr4(from)
  const after = parseCidr4(to)
  if (before === null || after === null || (before.address === after.address && before.prefix === after.prefix)) {
    return []
  }
  const own = owner === undefined ? null : `lans[${config.lans.findIndex((lan) => lan.name === owner)}].`
  const theirs = anothers(config, before, owner, base)
  const unfit: Unfit[] = []
  strings(ConfigSchema, config as unknown as Record<string, unknown>, '', '', (key, path, value, set) => {
    const kind = STRING_FIELDS[key]
    let next: string | null | undefined
    if (kind === 'own' ? own !== null && !path.startsWith(own) : theirs?.(path) === true) {
      return
    }
    if (kind === 'carried' || kind === 'own') {
      const address = parse4(value)
      if (address !== null && contains(before, address)) {
        const placed = place(address, before, after)
        next = placed === null ? null : format4(placed)
      }
    } else if (kind === 'target') {
      next = retarget(value, before, after)
    }
    if (next === null) {
      unfit.push({ path, value })
    } else if (next !== undefined && next !== value) {
      set(next)
    }
  })
  return unfit
}
