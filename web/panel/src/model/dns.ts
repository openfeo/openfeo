// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the DNS page works out (SPEC §7.7, §8.4): what a local name becomes under the router's
// domain, what the page can know is wrong with one, the switch for the WAN's resolvers (on
// when the config does not say), and the resolvers the router says it is asking.

import { create, DnsSchema, RecordSchema, toJson, type Config, type Dns, type DnsState, type Record as DnsRecord } from '@openfeo/client'

import { isIp6, parse4 } from './ip'

/** The domain the router takes when the config names none. */
export const DEFAULT_DOMAIN = 'home.arpa'

/** `[system] domain`, lower-case, or the default: what a name with no dot is put under. */
export function domainOf(config: Config): string {
  const domain = config.system?.domain ?? ''
  return domain === '' ? DEFAULT_DOMAIN : domain.toLowerCase()
}

/** What a local name becomes: `www` is `www.home.arpa`; a name with a dot stands, and gives null. */
export function becomes(name: string, domain: string): string | null {
  const label = name.trim().toLowerCase()
  return label === '' || label.includes('.') ? null : `${label}.${domain}`
}

export function newRecord(): DnsRecord {
  return create(RecordSchema, {})
}

/** 4 or 6 for an address the page can read, null for anything else. */
function family(address: string): 4 | 6 | null {
  return parse4(address) !== null ? 4 : isIp6(address) ? 6 : null
}

/** What the page can know is wrong with record `n`, by field: name, address. A name may have one address of each family. */
export function recordProblems(records: readonly DnsRecord[], n: number): { name?: string; address?: string } {
  const record = records[n]
  if (record === undefined) {
    return {}
  }
  const found: { name?: string; address?: string } = {}
  if (record.name === '') {
    found.name = 'Give it a name.'
  }
  const of = family(record.address)
  if (record.address !== '' && of === null) {
    found.address = 'An IPv4 or IPv6 address.'
  } else if (of !== null && records.some((other, at) => at !== n && other.name.toLowerCase() === record.name.toLowerCase() && family(other.address) === of)) {
    found.address = `This name already has an IPv${of} address.`
  }
  return found
}

/** Whether the WAN's resolvers are used too: on when the config does not say. */
export function usesWan(dns: Dns | undefined): boolean {
  return dns?.useWanDns ?? true
}

/**
 * Switch the WAN's resolvers on or off. What the router has is put back as the router has it:
 * a config that does not say, switched off and on again, goes back to not saying.
 */
export function setUsesWan(config: Config, on: boolean, base: Config | null): void {
  config.dns ??= create(DnsSchema, {})
  const was = base?.dns?.useWanDns
  if (on === (was ?? true)) {
    // What the router has means the same: written as it has it, said or unsaid.
    if (was === undefined) {
      delete config.dns.useWanDns
    } else {
      config.dns.useWanDns = was
    }
  } else {
    config.dns.useWanDns = on
  }
  settleDns(config, base)
}

/**
 * Take the DNS settings out of `config` when nothing is set in them and the router has none
 * either: there with nothing in them and not there at all are two files, and a name added and
 * removed again should leave the first as it was.
 */
export function settleDns(config: Config, base: Config | null): void {
  if (config.dns !== undefined && base?.dns === undefined && Object.keys(toJson(DnsSchema, config.dns) as object).length === 0) {
    config.dns = undefined
  }
}

/** The resolvers in use, grouped by where they came from, in the order they are asked: `yours`, or `from <wan>`. */
export function inUse(dns: DnsState | undefined): { addresses: string[]; from: string }[] {
  const groups: { addresses: string[]; from: string }[] = []
  for (const resolver of dns?.resolvers ?? []) {
    const from = resolver.wan === '' ? 'yours' : `from ${resolver.wan}`
    const last = groups.at(-1)
    if (last !== undefined && last.from === from) {
      last.addresses.push(resolver.address)
    } else {
      groups.push({ addresses: [resolver.address], from })
    }
  }
  return groups
}
