// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What applying a draft would alter (SPEC §8.4): every difference between the config as the
// router has it and the draft, in the order the pages show it. A setting of a WAN or a LAN
// is named as its page names it; a pool is one change and a LAN's reservations are one; an
// address elsewhere that a renumbering carried is named by what it belongs to; and anything
// else that differs, on a page this panel does not have yet or in a spelling no page writes,
// is listed by its path. Nothing that differs goes unlisted, and a password is never shown:
// only that it changed.

import { ConfigSchema, LanSchema, toJson, WanSchema, type Config, type Lan, type LanDhcp, type StaticLease, type Wan } from '@openfeo/client'

import { durationWords } from './format'

/** One line of the dialog: whose setting, what it is called, what it was and what it becomes. */
export interface Change {
  subject: string
  what: string
  before: string
  after: string
}

/** A change to a WAN or a LAN, with the fields of its message that the change accounts for. */
interface Setting {
  what: string
  before: string
  after: string
  covers: string[]
}

/** The lease time the router gives when the config names none. */
const DEFAULT_LEASE_SECS = 43_200

// ---- Any two messages, leaf by leaf ----

interface Leaf {
  /** Where, as the router writes a path: `port_forwards[0].to_port`. */
  path: string
  /** Empty when it was not there. */
  before: string
  /** Empty when it is no longer there. */
  after: string
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isMessages(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.some(isObject)
}

/** A value with nothing beneath it, as it is written. A list of plain values is one. */
function written(value: unknown): string {
  return Array.isArray(value) ? value.map((item) => String(item)).join(', ') : String(value)
}

/** What a value that is left out reads as, by the kind of the one it is compared with: JSON leaves a default out. */
function leftOut(like: unknown): string {
  return typeof like === 'boolean' ? 'false' : typeof like === 'number' ? '0' : ''
}

/** Every leaf under something that is on one side only. */
function under(value: unknown, path: string, found: [path: string, value: string][]): void {
  if (isObject(value)) {
    for (const [key, inner] of Object.entries(value)) {
      under(inner, path === '' ? key : `${path}.${key}`, found)
    }
  } else if (isMessages(value)) {
    value.forEach((inner, at) => under(inner, `${path}[${at}]`, found))
  } else {
    found.push([path, written(value)])
  }
}

/** The leaves that differ between two messages in their JSON form (which leaves defaults out). */
function differ(a: unknown, b: unknown, path: string, found: Leaf[]): void {
  if (a === undefined && b === undefined) {
    return
  }
  const structured = (value: unknown) => isObject(value) || isMessages(value)
  if (a === undefined || b === undefined) {
    const there = a ?? b
    if (structured(there)) {
      // A whole message or list is on one side only: each of its leaves came or went.
      const leaves: [string, string][] = []
      under(there, path, leaves)
      if (leaves.length === 0) {
        // Present with nothing set in it, against not present at all.
        leaves.push([path, 'empty'])
      }
      for (const [at, value] of leaves) {
        found.push(a === undefined ? { path: at, before: '', after: value } : { path: at, before: value, after: '' })
      }
      return
    }
    const before = a === undefined ? leftOut(b) : written(a)
    const after = b === undefined ? leftOut(a) : written(b)
    if (before !== after) {
      found.push({ path, before, after })
    }
    return
  }
  if (isObject(a) && isObject(b)) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      differ(a[key], b[key], path === '' ? key : `${path}.${key}`, found)
    }
  } else if (isMessages(a) && isMessages(b)) {
    for (let at = 0; at < Math.max(a.length, b.length); at++) {
      differ(a[at], b[at], `${path}[${at}]`, found)
    }
  } else if (written(a) !== written(b)) {
    found.push({ path, before: written(a), after: written(b) })
  }
}

/** A path without its indices: the field it is, whichever element it is in. */
function fieldOf(path: string): string {
  return path.replace(/\[\d+\]/g, '')
}

function byPath(leaf: Leaf, prefix: string): Change {
  return { subject: `${prefix}${leaf.path}`, what: '', before: leaf.before, after: leaf.after === '' ? 'none' : leaf.after }
}

// ---- A WAN ----

const TYPES = { dhcp: 'DHCP', pppoe: 'PPPoE', static: 'Static' } as const

function typeName(wan: Wan): string {
  return wan.kind.case === undefined ? 'none' : TYPES[wan.kind.case]
}

function describeWan(wan: Wan): string {
  return `${typeName(wan)} on ${wan.port === '' ? 'no port' : wan.port}${wan.vlan === 0 ? '' : `.${wan.vlan}`}`
}

/** The settings of a WAN's own type, in the page's order: what each is called, its value, and its field. */
function typeSettings(wan: Wan): { what: string; value: string; field: string; secret?: boolean }[] {
  const kind = wan.kind
  switch (kind.case) {
    case 'pppoe':
      return [
        { what: 'username', value: kind.value.username, field: 'pppoe.username' },
        { what: 'password', value: kind.value.password, field: 'pppoe.password', secret: true },
        { what: 'service name', value: kind.value.service, field: 'pppoe.service' },
        { what: 'access concentrator', value: kind.value.ac, field: 'pppoe.ac' },
      ]
    case 'static':
      return [
        { what: 'address', value: kind.value.address, field: 'static.address' },
        { what: 'gateway', value: kind.value.gateway, field: 'static.gateway' },
        { what: 'DNS servers', value: kind.value.dns.join(', '), field: 'static.dns' },
      ]
    case 'dhcp':
      return [
        { what: 'hostname sent', value: kind.value.hostname, field: 'dhcp.hostname' },
        { what: 'vendor class sent', value: kind.value.vendorClass, field: 'dhcp.vendor_class' },
      ]
    default:
      return []
  }
}

function carries6(wan: Wan): boolean {
  return wan.ipv6 !== undefined && wan.ipv6.mode !== 'disabled'
}

function v6Settings(wan: Wan): { what: string; value: string; field: string }[] {
  const ipv6 = wan.ipv6
  return [
    { what: 'routed prefix', value: ipv6?.prefix ?? '', field: 'ipv6.prefix' },
    { what: 'prefix length to ask for', value: ipv6 === undefined || ipv6.pdHint === 0 ? '' : String(ipv6.pdHint), field: 'ipv6.pd_hint' },
    { what: 'IPv6 gateway', value: ipv6?.gateway ?? '', field: 'ipv6.gateway' },
  ]
}

/** A setting that differs, an empty value reading `none`. */
function differing(found: Setting[], what: string, before: string, after: string, field: string): void {
  if (before !== after) {
    found.push({ what, before: before === '' ? 'none' : before, after: after === '' ? 'none' : after, covers: [field] })
  }
}

function wanSettings(base: Wan, draft: Wan): Setting[] {
  const found: Setting[] = []
  const typed = base.kind.case === draft.kind.case
  if (!typed) {
    // The type, then what was typed for the new one. What the old one had goes with it.
    found.push({ what: 'type', before: typeName(base), after: typeName(draft), covers: ['static', 'dhcp', 'pppoe'] })
  }
  const was = new Map(typeSettings(base).map((setting) => [setting.what, setting.value]))
  for (const setting of typeSettings(draft)) {
    if (setting.secret === true) {
      // The router hands no password out, so one that is here was typed. It is never shown.
      if (setting.value !== '') {
        found.push({ what: setting.what, before: '', after: 'changed', covers: [setting.field] })
      }
    } else {
      differing(found, setting.what, typed ? (was.get(setting.what) ?? '') : '', setting.value, setting.field)
    }
  }
  differing(found, 'port', base.port, draft.port, 'port')
  differing(found, 'VLAN tag', base.vlan === 0 ? '' : String(base.vlan), draft.vlan === 0 ? '' : String(draft.vlan), 'vlan')
  differing(found, 'priority', String(base.priority), String(draft.priority), 'priority')
  const on = carries6(draft)
  if (carries6(base) !== on) {
    found.push({ what: 'IPv6', before: on ? 'off' : 'on', after: on ? 'on' : 'off', covers: ['ipv6'] })
  }
  if (on) {
    const before = new Map(v6Settings(base).map((setting) => [setting.what, carries6(base) ? setting.value : '']))
    for (const setting of v6Settings(draft)) {
      differing(found, setting.what, before.get(setting.what) ?? '', setting.value, setting.field)
    }
  }
  return found
}

// ---- A LAN ----

function describeLan(lan: Lan): string {
  return `${lan.ipv4 === '' ? 'no address' : lan.ipv4} on ${lan.ports.length === 0 ? 'no ports' : lan.ports.join(', ')}`
}

function poolWords(dhcp: LanDhcp): string {
  return dhcp.range.join(' – ')
}

function leaseWords(dhcp: LanDhcp): string {
  return durationWords(dhcp.leaseSecs === 0 ? DEFAULT_LEASE_SECS : dhcp.leaseSecs)
}

function count(n: number, what: string): string {
  return `${n} ${what}${n === 1 ? '' : 's'}`
}

/** A reservation is the same one when its MAC is, or its client identifier where it has no MAC. */
function leaseKey(lease: StaticLease): string {
  return lease.mac !== '' ? lease.mac : `id:${lease.clientId}`
}

/**
 * What happened to a LAN's reservations, together: how many were added, removed, changed, or
 * (`moved`: the LAN's own address changed) differ only in an address that followed the LAN.
 * Empty when nothing did.
 */
function reservationWords(base: StaticLease[], draft: StaticLease[], moved: boolean): string {
  const was = new Map(base.map((lease) => [leaseKey(lease), lease]))
  const kept = new Set<string>()
  let added = 0
  let changed = 0
  let carried = 0
  for (const lease of draft) {
    const key = leaseKey(lease)
    const before = was.get(key)
    if (before === undefined || kept.has(key)) {
      added += 1
      continue
    }
    kept.add(key)
    const same = before.mac === lease.mac && before.clientId === lease.clientId && before.hostname === lease.hostname
    if (same && before.ip === lease.ip) {
      continue
    }
    if (same && moved) {
      carried += 1
    } else {
      changed += 1
    }
  }
  const removed = base.length - kept.size
  return [
    added > 0 ? `${added} added` : '',
    removed > 0 ? `${removed} removed` : '',
    changed > 0 ? `${changed} changed` : '',
    carried > 0 ? `${carried} moved into the new subnet` : '',
  ]
    .filter((part) => part !== '')
    .join(', ')
}

/** What goes with a DHCP server that is switched off. */
function offWords(dhcp: LanDhcp): string {
  const pool = dhcp.range.length > 0
  const held = dhcp.static.length
  if (pool && held > 0) {
    return `off; its pool and ${count(held, 'reservation')} go`
  }
  if (pool) {
    return 'off; its pool goes'
  }
  return held > 0 ? `off; its ${count(held, 'reservation')} ${held === 1 ? 'goes' : 'go'}` : 'off'
}

function reaches(lan: Lan): string {
  return lan.reaches.length === 0 ? 'wan' : lan.reaches.join(', ')
}

function lanSettings(base: Lan, draft: Lan): Setting[] {
  const found: Setting[] = []
  differing(found, 'address', base.ipv4, draft.ipv4, 'ipv4')
  differing(found, 'ports', base.ports.join(', '), draft.ports.join(', '), 'ports')
  differing(found, 'may reach', reaches(base), reaches(draft), 'reaches')

  const [was, now] = [base.dhcp, draft.dhcp]
  if (was !== undefined && now === undefined) {
    found.push({ what: 'DHCP server', before: 'on', after: offWords(was), covers: ['dhcp'] })
  } else if (now !== undefined) {
    if (was === undefined) {
      found.push({ what: 'DHCP server', before: 'off', after: 'on', covers: ['dhcp'] })
    }
    // Against a server that was off, what is listed is what was set for the new one.
    differing(found, 'pool', was === undefined ? '' : poolWords(was), poolWords(now), 'dhcp.range')
    differing(found, 'lease time', leaseWords(was ?? now), leaseWords(now), 'dhcp.lease_secs')
    const handed = (list: string[]) => (list.length === 0 ? 'the router' : list.join(', '))
    differing(found, 'DNS servers handed out', handed(was?.dns ?? []), handed(now.dns), 'dhcp.dns')
    differing(found, 'NTP servers handed out', handed(was?.ntp ?? []), handed(now.ntp), 'dhcp.ntp')
    const reserved = reservationWords(was?.static ?? [], now.static, base.ipv4 !== draft.ipv4)
    if (reserved !== '') {
      found.push({ what: 'reservations', before: '', after: reserved, covers: ['dhcp.static'] })
    }
  }

  const on = draft.ipv6 !== 'none'
  if ((base.ipv6 !== 'none') !== on) {
    found.push({ what: 'IPv6', before: on ? 'off' : 'on', after: on ? 'on' : 'off', covers: ['ipv6'] })
  }
  if (on) {
    differing(found, 'routed /64', base.ipv6 === 'none' ? '' : base.ipv6, draft.ipv6, 'ipv6')
  }
  const advertises = (lan: Lan) => (lan.ra === false ? 'off' : 'on')
  differing(found, 'router advertisements', advertises(base), advertises(draft), 'ra')
  differing(found, 'subnet number', base.ipv6Index === 0 ? '' : String(base.ipv6Index), draft.ipv6Index === 0 ? '' : String(draft.ipv6Index), 'ipv6_index')
  return found
}

// ---- The whole config ----

/**
 * The changes to those of a list (the WANs, the LANs) that are in both configs under one
 * name, in the draft's order; one line for each that is only in the draft; then one for each
 * that is only in the base.
 */
function named<T extends { name: string }>(
  base: T[],
  draft: T[],
  kind: { word: string; list: string; describe: (item: T) => string; settings: (base: T, draft: T) => Setting[]; json: (item: T) => unknown; secret?: string },
  found: Change[],
): void {
  for (const [at, item] of draft.entries()) {
    const before = base.find((other) => other.name === item.name)
    if (before === undefined) {
      found.push({ subject: item.name, what: kind.word, before: '', after: `added: ${kind.describe(item)}` })
      continue
    }
    const settings = kind.settings(before, item)
    found.push(...settings.map(({ what, before: was, after }) => ({ subject: item.name, what, before: was, after })))
    // Whatever else differs between the two, in a field no setting above accounts for (a
    // spelling no page writes, a field a later schema adds), is listed by its path.
    const leaves: Leaf[] = []
    differ(kind.json(before), kind.json(item), '', leaves)
    for (const leaf of leaves) {
      const field = fieldOf(leaf.path)
      const covered = settings.some((setting) => setting.covers.some((cover) => field === cover || field.startsWith(`${cover}.`)))
      if (!covered && field !== kind.secret) {
        found.push(byPath(leaf, `${kind.list}[${at}].`))
      }
    }
  }
  for (const item of base) {
    if (!draft.some((other) => other.name === item.name)) {
      found.push({ subject: item.name, what: kind.word, before: kind.describe(item), after: 'removed' })
    }
  }
}

/** An address elsewhere in the config that a renumbering carries, by what it belongs to. */
const ELSEWHERE: { field: string; what: string; subject: (config: Config, at: number) => string | undefined }[] = [
  { field: 'firewall.port_forwards.to', what: 'target', subject: (config, at) => named1('port forward', config.firewall?.portForwards[at]?.name) },
  { field: 'firewall.rules.to', what: 'target', subject: (config, at) => named1('rule', config.firewall?.rules[at]?.name) },
  { field: 'dns.records.address', what: 'address', subject: (config, at) => named1('DNS record', config.dns?.records[at]?.name) },
]

function named1(kind: string, name: string | undefined): string | undefined {
  return name === undefined || name === '' ? undefined : `${kind} ${name}`
}

/** Everything applying `draft` over `base` would alter, in the order the pages show it. */
export function changes(base: Config, draft: Config): Change[] {
  const found: Change[] = []
  const json = { useProtoFieldName: true }
  named(
    base.wans,
    draft.wans,
    { word: 'WAN', list: 'wans', describe: describeWan, settings: wanSettings, json: (wan) => toJson(WanSchema, wan, json), secret: 'pppoe.password' },
    found,
  )
  named(base.lans, draft.lans, { word: 'LAN', list: 'lans', describe: describeLan, settings: lanSettings, json: (lan) => toJson(LanSchema, lan, json) }, found)

  // The rest of the config, leaf by leaf. The WANs and the LANs are done; the admin's hash is
  // neither sent nor taken, so it is never a change.
  const rest = (config: Config): Record<string, unknown> => {
    const whole = toJson(ConfigSchema, config, json) as Record<string, unknown>
    return Object.fromEntries(Object.entries(whole).filter(([key]) => key !== 'wans' && key !== 'lans'))
  }
  const leaves: Leaf[] = []
  differ(rest(base), rest(draft), '', leaves)
  for (const leaf of leaves) {
    const field = fieldOf(leaf.path)
    if (field === 'admin.password_hash' || field === 'admin') {
      continue
    }
    const elsewhere = ELSEWHERE.find((entry) => entry.field === field)
    const at = Number(/\[(\d+)\]/.exec(leaf.path)?.[1])
    const subject = elsewhere !== undefined && leaf.before !== '' && leaf.after !== '' ? elsewhere.subject(draft, at) : undefined
    found.push(elsewhere !== undefined && subject !== undefined ? { subject, what: elsewhere.what, before: leaf.before, after: leaf.after } : byPath(leaf, ''))
  }
  return found
}
