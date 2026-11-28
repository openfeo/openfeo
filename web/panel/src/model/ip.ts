// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Addresses as the settings pages need them: read strictly, as the router reads them, so
// that what a field accepts here is not refused there for its spelling. An IPv4 address is
// an unsigned 32-bit number; IPv6 is only told from what is not IPv6.

const QUAD = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/
const MOST = 0xffffffff

/** A dotted quad as a number, or `null`: four decimal parts of 0 to 255, no leading zero, no space. */
export function parse4(text: string): number | null {
  const parts = QUAD.exec(text)
  if (parts === null) {
    return null
  }
  let address = 0
  for (const part of parts.slice(1)) {
    const byte = Number(part)
    if (byte > 255) {
      return null
    }
    address = address * 256 + byte
  }
  return address
}

export function format4(address: number): string {
  return [address >>> 24, (address >>> 16) & 255, (address >>> 8) & 255, address & 255].join('.')
}

/** An address with the size of its subnet. The address is as typed, not masked: a LAN's is the router's own. */
export interface Cidr4 {
  address: number
  prefix: number
}

/** `192.168.1.1/24`, or `null`. The prefix is 0 to 32. */
export function parseCidr4(text: string): Cidr4 | null {
  const parts = /^([^/]+)\/(0|[1-9]\d?)$/.exec(text)
  const address = parts === null ? null : parse4(parts[1] ?? '')
  const prefix = Number(parts?.[2])
  return address === null || prefix > 32 ? null : { address, prefix }
}

function mask(prefix: number): number {
  return prefix === 0 ? 0 : (MOST << (32 - prefix)) >>> 0
}

/** How many addresses a subnet of this size holds, its first and last among them. */
function size(prefix: number): number {
  return 2 ** (32 - prefix)
}

/** The subnet's first address. */
export function network(cidr: Cidr4): number {
  return (cidr.address & mask(cidr.prefix)) >>> 0
}

/** Whether `address` lies in the subnet. A number that is no address lies in none. */
export function contains(cidr: Cidr4, address: number): boolean {
  return Number.isInteger(address) && address >= 0 && address <= MOST && (address & mask(cidr.prefix)) >>> 0 === network(cidr)
}

/** How many devices a subnet of this size has room for: 254 for a /24, none above a /30. */
export function hostCount(prefix: number): number {
  return prefix > 30 ? 0 : size(prefix) - 2
}

/** The first and last address a device can have. It means something only where {@link hostCount} is not 0. */
export function hostRange(cidr: Cidr4): [number, number] {
  const first = network(cidr)
  return [first + 1, first + size(cidr.prefix) - 2]
}

/** Whether a device can have `address` in the subnet: inside it, and neither its first address nor its last. */
export function isHost(cidr: Cidr4, address: number): boolean {
  const [first, last] = hostRange(cidr)
  return contains(cidr, address) && address >= first && address <= last
}

/** The subnet as it is written: `192.168.1.0/24`. */
export function formatNetwork(cidr: Cidr4): string {
  return `${format4(network(cidr))}/${cidr.prefix}`
}

/** A hardware address as the router writes it (`aa:bb:cc:dd:ee:ff`), or `null`. Upper case and `-` are taken. */
export function parseMac(text: string): string | null {
  return /^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$/i.test(text) ? text.toLowerCase().replaceAll('-', ':') : null
}

/** Whether `text` is an IPv6 address: eight groups, or fewer round one `::`, the last two as a dotted quad if it likes. */
export function isIp6(text: string): boolean {
  const halves = text.split('::')
  if (halves.length > 2) {
    return false
  }
  const groups = halves.flatMap((half) => (half === '' ? [] : half.split(':')))
  let count = 0
  for (const [at, group] of groups.entries()) {
    if (at === groups.length - 1 && group.includes('.')) {
      if (parse4(group) === null) {
        return false
      }
      count += 2
    } else if (/^[0-9a-fA-F]{1,4}$/.test(group)) {
      count += 1
    } else {
      return false
    }
  }
  return halves.length === 2 ? count <= 7 : count === 8
}

/** Whether `text` is an IPv6 address with a prefix length of 0 to 128. */
export function isCidr6(text: string): boolean {
  const parts = /^([^/]+)\/(0|[1-9]\d{0,2})$/.exec(text)
  return parts !== null && Number(parts[2]) <= 128 && isIp6(parts[1] ?? '')
}

/** An IPv6 block: its address as one number, and how many of its bits are the network's. */
export interface Cidr6 {
  address: bigint
  prefix: number
}

/** The 128 bits of an IPv6 address that `isIp6` takes, as one number. */
function parse6(text: string): bigint | null {
  if (!isIp6(text)) {
    return null
  }
  const words = (half: string): number[] =>
    half === ''
      ? []
      : half.split(':').flatMap((group) => {
          const quad = group.includes('.') ? parse4(group) : null
          return quad === null ? [Number.parseInt(group, 16)] : [quad >>> 16, quad & 0xffff]
        })
  const [head = '', tail] = text.split('::')
  const before = words(head)
  const after = tail === undefined ? [] : words(tail)
  const all = [...before, ...Array.from({ length: 8 - before.length - after.length }, () => 0), ...after]
  return all.reduce((sum, word) => (sum << 16n) | BigInt(word), 0n)
}

/** An IPv6 block as it is written, `2001:db8:1::/48`; `null` when it is not one. */
export function parseCidr6(text: string): Cidr6 | null {
  if (!isCidr6(text)) {
    return null
  }
  const [address = '', prefix = ''] = text.split('/')
  const bits = parse6(address)
  return bits === null ? null : { address: bits, prefix: Number(prefix) }
}

/** Whether `inner` lies within `outer`: no wider, and the same in every bit `outer` fixes. */
export function within6(inner: Cidr6, outer: Cidr6): boolean {
  const free = BigInt(128 - outer.prefix)
  return inner.prefix >= outer.prefix && inner.address >> free === outer.address >> free
}
