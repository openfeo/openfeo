// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the router says a change of config interrupts (SPEC §8.3), in words. The router, not
// the panel, works out what restarts: the same slices its tasks compare. An effect this code
// does not know (a newer router behind a page that was cached) is shown as it came.

import { ConfigEffectKind, type ConfigEffect } from '@openfeo/client'

export function effectSentence(effect: ConfigEffect): string {
  const who = effect.subject
  switch (effect.kind) {
    case ConfigEffectKind.WAN_ADDED:
    case ConfigEffectKind.LAN_ADDED:
      return `${who} is added.`
    case ConfigEffectKind.WAN_REMOVED:
    case ConfigEffectKind.LAN_REMOVED:
      return `${who} is removed.`
    case ConfigEffectKind.WAN_RECONNECTS:
      return `${who} drops and comes back.`
    case ConfigEffectKind.LAN_ADDRESS_MOVES:
      return `${who} moves: its devices need new addresses.`
    case ConfigEffectKind.LAN_DHCP_STARTS:
      return `${who}'s DHCP server starts.`
    case ConfigEffectKind.LAN_DHCP_STOPS:
      return `${who}'s DHCP server stops.`
    case ConfigEffectKind.LAN_DHCP_RESTARTS:
      return `${who}'s DHCP server restarts; leases are kept.`
    case ConfigEffectKind.ROUTER_RENAMED:
      return `The router becomes ${who}: its certificate is issued again and the browser will ask.`
    default:
      return `${who} (effect ${String(effect.kind)}).`
  }
}
