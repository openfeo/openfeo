// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What is wrong with a field as it was typed, in the words the page shows under it, or
// `null`. These are the router's own rules where a page can know them (a CIDR, a MAC, a
// range); the router validates the whole draft before anything is applied, and what it
// refuses is shown at the same field. An empty field is "not set" and is fine here: whether
// it is needed is the router's to say.

import { format4, formatNetwork, isCidr6, isHost, isIp6, contains, parse4, parseCidr4, parseMac } from './ip'

export function address4(text: string): string | null {
  return text === '' || parse4(text) !== null ? null : 'Not an IPv4 address.'
}

export function address6(text: string): string | null {
  return text === '' || isIp6(text) ? null : 'Not an IPv6 address.'
}

/** Addresses of either family, separated by commas. */
export function addressList(text: string): string | null {
  if (text === '') {
    return null
  }
  const parts = text.split(',').map((part) => part.trim())
  if (parts.includes('')) {
    return 'One or more addresses, separated by commas.'
  }
  const not = parts.find((part) => parse4(part) === null && !isIp6(part))
  return not === undefined ? null : `${not} is not an address.`
}

export function cidr4(text: string): string | null {
  return text === '' || parseCidr4(text) !== null ? null : 'An address and a size, such as 192.168.1.1/24.'
}

export function cidr6(text: string): string | null {
  return text === '' || isCidr6(text) ? null : 'A prefix and its length, such as 2001:db8:1::/48.'
}

export function mac(text: string): string | null {
  return text === '' || parseMac(text) !== null ? null : 'A MAC address is six pairs of hex digits, such as 02:00:00:aa:01:10.'
}

/** A whole number from `low` to `high`, written in digits alone. */
export function between(text: string, low: number, high: number): string | null {
  if (text === '') {
    return null
  }
  const value = /^\d+$/.test(text) ? Number(text) : Number.NaN
  return value >= low && value <= high ? null : `${low} to ${high}.`
}

/** An address a device can have in the LAN whose own address is `lan` (`192.168.1.1/24`). */
export function inSubnet(text: string, lan: string): string | null {
  if (text === '') {
    return null
  }
  const address = parse4(text)
  if (address === null) {
    return 'Not an IPv4 address.'
  }
  const subnet = parseCidr4(lan)
  if (subnet === null) {
    return null
  }
  if (!contains(subnet, address)) {
    return `Not in ${formatNetwork(subnet)}.`
  }
  return isHost(subnet, address) ? null : `Not an address a device can have in ${formatNetwork(subnet)}.`
}

/**
 * A DHCP pool's two ends, as the router checks them: each an address a device can have in
 * the LAN, the start not after the end, and the router's own address outside.
 */
export function pool(start: string, end: string, lan: string): { start: string | null; end: string | null } {
  const found = { start: inSubnet(start, lan), end: inSubnet(end, lan) }
  const first = parse4(start)
  const last = parse4(end)
  if (found.start !== null || found.end !== null || first === null || last === null) {
    return found
  }
  if (first > last) {
    return { start: 'The pool starts after it ends.', end: null }
  }
  const router = parseCidr4(lan)?.address
  if (router !== undefined && first <= router && router <= last) {
    return { start: `The router's own address, ${format4(router)}, is inside the pool.`, end: null }
  }
  return found
}
