// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the Ports page shows (SPEC §8.4): each physical port with its link, what uses it, its
// MAC, where it sits on the bus, and the bytes it has carried since the router started. All
// of it is the state's but the two counters, which are the port's own link's in the sample
// the router pushes each second.

import { PortUseKind, type Counters, type State } from '@openfeo/client'

import { bytes, DASH } from './format'

export interface PortRow {
  /** The kernel name, `p0`. */
  name: string
  /** The link has a carrier. */
  up: boolean
  /** `2500 Mbit/s`; empty when the link is down or the driver does not say. */
  speed: string
  /** The WANs and LANs it is given to: where each is set, its name, and its tag (0 for none). */
  uses: { to: string; name: string; tag: number }[]
  mac: string
  /** The bus path it is known by (SPEC §7.1). */
  hardware: string
  /** Bytes in words, or a dash until a sample has come that names the port. */
  received: string
  sent: string
}

/** A row for each port, in port order. */
export function portRows(state: State, counters: Counters | null): PortRow[] {
  return state.ports.map((port) => {
    const counted = counters?.links.find((link) => link.name === port.name)
    const mbps = port.speedMbps ?? 0
    return {
      name: port.name,
      up: port.carrier,
      speed: port.carrier && mbps > 0 ? `${String(mbps)} Mbit/s` : '',
      uses: port.uses.map((use) => ({ to: `${use.kind === PortUseKind.WAN ? '/wan' : '/lan'}/${use.name}`, name: use.name, tag: use.vlan })),
      mac: port.mac,
      hardware: port.id,
      received: counted === undefined ? DASH : bytes(counted.rxBytes),
      sent: counted === undefined ? DASH : bytes(counted.txBytes),
    }
  })
}
