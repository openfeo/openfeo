// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The lease table as the panel shows it (SPEC §8.4): its order, what a filter finds, how an
// age is said, and what Reserve does to the draft. Pure functions of what the router sent;
// the pages hold no arithmetic and no wording of their own.

import { create, StaticLeaseSchema, type Config, type Lan, type Lease } from '@openfeo/client'

import { clock, DASH } from './format'

/** An IPv4 address as a number, so that `.9` comes before `.10`; one that does not parse sorts last. */
function numeric(address: string): number {
  const parts = address.split('.').map(Number)
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return Number.MAX_SAFE_INTEGER
  }
  return parts.reduce((sum, part) => sum * 256 + part, 0)
}

/**
 * Newest first: by when each joined, and for leases that joined in the same second by LAN and
 * then by address, so that the order does not shuffle from one push to the next.
 */
export function newestFirst(leases: readonly Lease[]): Lease[] {
  return [...leases].sort((a, b) => {
    if (a.joinedUnix !== b.joinedUnix) {
      return a.joinedUnix < b.joinedUnix ? 1 : -1
    }
    return a.lan.localeCompare(b.lan) || numeric(a.address) - numeric(b.address) || a.address.localeCompare(b.address)
  })
}

/**
 * Whether `filter` is in the lease's address, its name or its MAC, without regard to case.
 * The filter is the text itself, never a pattern, and an empty one finds every lease.
 */
export function matches(lease: Lease, filter: string): boolean {
  const wanted = filter.trim().toLowerCase()
  return wanted === '' || [lease.address, lease.hostname, lease.mac].some((field) => field.toLowerCase().includes(wanted))
}

/** How many leases each of `lans` has, in the order given. */
export function perLan(leases: readonly Lease[], lans: readonly string[]): { lan: string; count: number }[] {
  return lans.map((lan) => ({ lan, count: leases.filter((lease) => lease.lan === lan).length }))
}

/**
 * How long ago, given the seconds since: "just now" under a minute, then its largest unit.
 * A time ahead of the clock (a lease file written under a right clock and read under the
 * build's) is "just now" too, never a negative age.
 */
export function ago(secs: number): string {
  if (!(secs >= 60)) {
    return 'just now'
  }
  if (secs < 3_600) {
    return `${Math.floor(secs / 60)} min ago`
  }
  if (secs < 86_400) {
    return `${Math.floor(secs / 3_600)} h ago`
  }
  return `${Math.floor(secs / 86_400)} d ago`
}

/**
 * Whether a lease that joined `secs` ago is the device just plugged in: within a minute of the
 * router's clock, on either side of it. A second or two ahead is still new (the stamp and the
 * clock are each said to the second); a lease far ahead of the clock was read from a file under
 * a clock that is wrong, and is no newer than the rest.
 */
export function justJoined(secs: number | undefined): boolean {
  return secs !== undefined && Math.abs(secs) < 60
}

/** How long until, given the seconds left, by its two largest units; "expired" with none left. */
export function until(secs: number): string {
  if (!(secs > 0)) {
    return 'expired'
  }
  if (secs < 60) {
    return 'in under a minute'
  }
  const minutes = Math.floor(secs / 60)
  if (minutes < 60) {
    return `in ${minutes} min`
  }
  const hours = Math.floor(minutes / 60)
  if (hours < 24) {
    return `in ${hours} h ${String(minutes % 60).padStart(2, '0')} min`
  }
  const days = Math.floor(hours / 24)
  return hours % 24 === 0 ? `in ${days} d` : `in ${days} d ${hours % 24} h`
}

/** What tells a lease's row from every other: its LAN, its MAC and its address. */
export function leaseKey(lease: Lease): string {
  return `${lease.lan} ${lease.mac.toLowerCase()} ${lease.address}`
}

/**
 * What Reserve would be for a lease. `applied`: the router's config and the draft both reserve
 * this address for this MAC on this LAN. `draft`: only the draft does. `unavailable`: the
 * draft cannot take the reservation (there is no draft, its LAN is gone from it or has no DHCP
 * server there, or the MAC or the address is already reserved otherwise). `no`: it is offered.
 */
export type Reserved = 'no' | 'draft' | 'applied' | 'unavailable'

const sameMac = (a: string, b: string) => a !== '' && a.toLowerCase() === b.toLowerCase()

function lanOf(config: Config | null, name: string): Lan | undefined {
  return config?.lans.find((lan) => lan.name === name)
}

/** Whether `lan` reserves the lease's address for the lease's MAC. */
function holds(lan: Lan | undefined, lease: Lease): boolean {
  return lan?.dhcp?.static.some((each) => sameMac(each.mac, lease.mac) && each.ip === lease.address) ?? false
}

export function reserved(lease: Lease, base: Config | null, draft: Config | null): Reserved {
  const lan = lanOf(draft, lease.lan)
  if (lan?.dhcp === undefined) {
    return 'unavailable'
  }
  if (holds(lan, lease)) {
    return holds(lanOf(base, lease.lan), lease) ? 'applied' : 'draft'
  }
  // The MAC with another address, or the address with another device (one known by its
  // client identifier among them): the router would refuse a second claim on either.
  const taken = lan.dhcp.static.some((each) => sameMac(each.mac, lease.mac) || each.ip === lease.address)
  return taken ? 'unavailable' : 'no'
}

/**
 * Reserve: the lease's MAC always gets its address, under the name it gave when it gave one.
 * It joins the draft's other changes, in that LAN's reservations. Nothing is added unless
 * {@link reserved} says the reservation is on offer, so a second press adds nothing.
 *
 * The router keeps a reservation's name to one device a LAN. A name another reservation
 * there already has is left out (two devices of one make give the same name, and one that
 * replaces another gives its predecessor's): the address is what was asked for, and a name
 * can be given on LAN & DHCP.
 */
export function reserve(draft: Config, base: Config | null, lease: Lease): void {
  if (reserved(lease, base, draft) !== 'no') {
    return
  }
  const held = lanOf(draft, lease.lan)?.dhcp?.static
  const taken = held?.some((each) => each.hostname !== '' && each.hostname.toLowerCase() === lease.hostname.toLowerCase()) ?? false
  held?.push(create(StaticLeaseSchema, { mac: lease.mac, ip: lease.address, hostname: taken ? '' : lease.hostname }))
}

/** A lease as a table shows it: every cell as text, with what the page hangs on the row. */
export interface LeaseRow extends Record<string, string> {
  /** What tells the row from every other ({@link leaseKey}). */
  key: string
  /** How long ago it joined, and the exact time for the cell's title. */
  joined: string
  joinedAt: string
  address: string
  /** The name the device gave or its reservation has, or "none given". */
  name: string
  /** 'yes' when it has a name: "none given" is the page's word, said more quietly. */
  named: string
  mac: string
  lan: string
  /** How long until it expires, and the exact time for the cell's title. */
  expires: string
  expiresAt: string
  /** 'yes' for a row to be marked as new. */
  fresh: string
}

/**
 * The rows of a lease table, in the order given. Ages are counted against `routerClock`, the
 * router's own wall clock in seconds as it is by now, never against the browser's; the exact
 * times are for a cell's title, on the browser's clock and in its zone, counted back or on
 * from `now` by the router's measure. Until the router has said what time it is there is no
 * age to say. `fresh` says which rows are marked as new, given how long ago each joined.
 */
export function leaseRows(
  leases: readonly Lease[],
  routerClock: number | undefined,
  now: Date,
  fresh: (lease: Lease, joinedSecsAgo: number | undefined) => boolean,
): LeaseRow[] {
  const exact = (secsFromNow: number) => clock(BigInt(Math.round(now.getTime() + secsFromNow * 1000)), now)
  return leases.map((lease) => {
    const joinedSecsAgo = routerClock === undefined ? undefined : routerClock - Number(lease.joinedUnix)
    const left = routerClock === undefined ? undefined : Number(lease.expiresUnix) - routerClock
    return {
      key: leaseKey(lease),
      joined: joinedSecsAgo === undefined ? DASH : ago(joinedSecsAgo),
      joinedAt: joinedSecsAgo === undefined ? '' : exact(-Math.max(0, joinedSecsAgo)),
      address: lease.address,
      name: lease.hostname === '' ? 'none given' : lease.hostname,
      named: lease.hostname === '' ? '' : 'yes',
      mac: lease.mac,
      lan: lease.lan,
      expires: left === undefined ? DASH : until(left),
      expiresAt: left === undefined ? '' : exact(left),
      fresh: fresh(lease, joinedSecsAgo) ? 'yes' : '',
    }
  })
}
