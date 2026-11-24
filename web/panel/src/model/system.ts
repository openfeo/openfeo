// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the System page works out (SPEC §8.4, §9): the router's name and whether a draft
// changes it (its certificate is issued again when it does), what the page can know is wrong
// with a name or a time server, and what About says of the router.

import { SystemSchema, toJson, type Config, type State, type System } from '@openfeo/client'

import { domainOf } from './dns'
import { duration } from './format'
import { parse4 } from './ip'

/** The hostname the router takes when the config names none. */
export const DEFAULT_HOSTNAME = 'openfeo'

/** `<hostname>.<domain>`, lower-case, with the router's defaults for what is not set. */
export function routerName(config: Config): string {
  const hostname = config.system?.hostname ?? ''
  return `${hostname === '' ? DEFAULT_HOSTNAME : hostname.toLowerCase()}.${domainOf(config)}`
}

/** The router's name now and once `draft` is applied, when the two differ. */
export function renamedTo(base: Config | null, draft: Config): { from: string; to: string } | null {
  if (base === null) {
    return null
  }
  const [from, to] = [routerName(base), routerName(draft)]
  return from === to ? null : { from, to }
}

/** A DNS label as the router takes one: letters, digits and hyphens, 63 at most, no hyphen at either end. */
function isLabel(text: string): boolean {
  return /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(text)
}

/** Labels separated by dots, 253 bytes in all: a domain, or a host's name. */
function isName(text: string): boolean {
  return text.length <= 253 && text.split('.').every(isLabel)
}

/** What the page can know is wrong, by field: hostname, domain, ntp_servers. Nothing typed is the router's default. */
export function systemProblems(system: System | undefined): Record<string, string> {
  const found: Record<string, string> = {}
  if (system === undefined) {
    return found
  }
  if (system.hostname !== '' && !isLabel(system.hostname)) {
    found.hostname = 'Letters, digits and hyphens, 63 at most.'
  }
  if (system.domain !== '' && !isName(system.domain)) {
    found.domain = 'Names separated by dots, such as home.arpa.'
  }
  const not = system.ntpServers.find((server) => parse4(server) === null && !isName(server))
  if (not !== undefined) {
    found.ntp_servers = `${not} is not a name or an address.`
  }
  return found
}

/**
 * Take the system settings out of `config` when nothing is set in them and the router has
 * none either: there with nothing in them and not there at all are two files.
 */
export function settleSystem(config: Config, base: Config | null): void {
  if (config.system !== undefined && base?.system === undefined && Object.keys(toJson(SystemSchema, config.system) as object).length === 0) {
    config.system = undefined
  }
}

/**
 * About's rows: the version, how long the router has run (counted on here since it last
 * said, or as it last said), and its certificate's fingerprint.
 */
export function about(state: State, sinceBootMs: number | undefined): { label: string; value: string; mono: boolean }[] {
  const system = state.system
  const upSecs = sinceBootMs === undefined ? Number(system?.uptimeSecs ?? 0n) : sinceBootMs / 1000
  return [
    { label: 'Version', value: system?.version ?? '', mono: true },
    { label: 'Running for', value: duration(upSecs), mono: false },
    { label: 'Certificate', value: `SHA-256 ${system?.tlsFingerprint ?? ''}`, mono: true },
  ]
}
