// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { ConfigEffectKind, create, StateSchema, type ConfigEffect } from '@openfeo/client'
import { expect, test } from 'vitest'

import { effectSentence } from '../src/model/effects'

function effect(subject: string, kind: ConfigEffectKind): ConfigEffect {
  const made = create(StateSchema, { system: { pendingConfig: { effects: [{ subject, kind }] } } }).system?.pendingConfig?.effects[0]
  if (made === undefined) {
    throw new Error('no effect was made')
  }
  return made
}

test('each thing the router says a change interrupts has its sentence', () => {
  const said = (subject: string, kind: ConfigEffectKind) => effectSentence(effect(subject, kind))
  expect(said('wan1', ConfigEffectKind.WAN_ADDED)).toBe('wan1 is added.')
  expect(said('wan1', ConfigEffectKind.WAN_REMOVED)).toBe('wan1 is removed.')
  expect(said('wan0', ConfigEffectKind.WAN_RECONNECTS)).toBe('wan0 drops and comes back.')
  expect(said('guest', ConfigEffectKind.LAN_ADDED)).toBe('guest is added.')
  expect(said('guest', ConfigEffectKind.LAN_REMOVED)).toBe('guest is removed.')
  expect(said('lan0', ConfigEffectKind.LAN_ADDRESS_MOVES)).toBe('lan0 moves: its devices need new addresses.')
  expect(said('lan0', ConfigEffectKind.LAN_DHCP_STARTS)).toBe("lan0's DHCP server starts.")
  expect(said('lan0', ConfigEffectKind.LAN_DHCP_STOPS)).toBe("lan0's DHCP server stops.")
  expect(said('lan0', ConfigEffectKind.LAN_DHCP_RESTARTS)).toBe("lan0's DHCP server restarts; leases are kept.")
  expect(said('openfeo.home.arpa', ConfigEffectKind.ROUTER_RENAMED)).toBe(
    'The router becomes openfeo.home.arpa: its certificate is issued again and the browser will ask.',
  )
})

test('an effect this page does not know is shown as it came', () => {
  // A newer router behind a page that was cached: something is interrupted, and it is said.
  expect(effectSentence(effect('wan0', 99 as ConfigEffectKind))).toBe('wan0 (effect 99).')
  expect(effectSentence(effect('wan0', ConfigEffectKind.UNSPECIFIED))).toBe('wan0 (effect 0).')
})
