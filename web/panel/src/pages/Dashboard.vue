<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoCard, OfoDataTable, OfoInterfaceCard, OfoPageHeader, OfoPortStrip, OfoSkeleton, OfoStatTile } from '@openfeo/ui'
import { computed, inject } from 'vue'

import { LIVE } from '../live'
import { addresses, cards, defaultWan, headline, ports, tiles } from '../model/dashboard'
import { sentence, when } from '../model/events'

// The dashboard (SPEC §8.4): read-only and live. What it says and how it says it is
// model/; this arranges it. What it shows is what the shell hears from the router.
const live = inject(LIVE)!
const { state, now, sinceBootMs } = live

const stats = computed(() => {
  if (state.value === null) {
    return null
  }
  const wan = defaultWan(state.value)
  return tiles(state.value, {
    rate: wan === undefined ? undefined : live.rates.value?.get(wan.interface),
    history: live.history.value,
    conntrack: live.conntrack.value ?? undefined,
  })
})
const interfaces = computed(() => (state.value === null ? null : cards(state.value, live.rates.value)))
const strip = computed(() => (state.value === null ? null : ports(state.value)))
const held = computed(() =>
  state.value === null
    ? null
    : addresses(state.value).map((row) => ({
        interface: row.first ? row.interface : '',
        address: row.address,
        from: row.deprecated ? `${row.from} · deprecated` : row.from,
      })),
)
const ADDRESS_COLUMNS = [
  { key: 'interface', label: 'Interface', mono: true },
  { key: 'address', label: 'Address', mono: true },
  { key: 'from', label: 'From' },
]
const happened = computed(() =>
  live.events.value.map((event) => ({
    at: when(event, state.value?.system?.timeSynced === true, now.value, sinceBootMs.value),
    parts: sentence(event),
  })),
)
</script>

<template>
  <div class="dash">
    <OfoPageHeader title="Dashboard" :sub="state ? headline(state) : undefined" />

    <div class="ofo-grid ofo-grid--4">
      <template v-if="stats">
        <OfoStatTile v-for="tile in stats" :key="tile.label" v-bind="tile" />
      </template>
      <template v-else>
        <div v-for="n in 4" :key="n" class="ofo-stat dash__waiting">
          <OfoSkeleton :width="40" />
          <OfoSkeleton size="lg" :width="60" />
        </div>
      </template>
    </div>

    <div class="ofo-grid ofo-grid--3">
      <template v-if="interfaces">
        <OfoInterfaceCard v-for="card in interfaces" :key="card.role + card.name" v-bind="card" />
      </template>
      <template v-else>
        <div v-for="n in 3" :key="n" class="ofo-iface dash__waiting">
          <OfoSkeleton :width="40" />
          <OfoSkeleton :width="80" />
          <OfoSkeleton :width="60" />
          <OfoSkeleton :width="80" />
        </div>
      </template>
    </div>

    <OfoCard title="Ports">
      <template v-if="strip">
        <OfoPortStrip :ports="strip" />
        <p class="ofo-muted dash__legend">An oxide frame is a WAN port. A teal light is a link; grey is no cable.</p>
      </template>
      <div v-else class="dash__waiting">
        <OfoSkeleton size="lg" :width="40" />
      </div>
    </OfoCard>

    <div class="ofo-grid ofo-grid--2">
      <OfoCard title="Addresses">
        <OfoDataTable v-if="held" class="dash__addresses" :columns="ADDRESS_COLUMNS" :rows="held" />
        <div v-else class="dash__waiting">
          <OfoSkeleton :width="80" />
          <OfoSkeleton :width="60" />
          <OfoSkeleton :width="80" />
        </div>
      </OfoCard>

      <OfoCard title="Recent events">
        <div v-if="state === null" class="dash__waiting">
          <OfoSkeleton :width="80" />
          <OfoSkeleton :width="60" />
          <OfoSkeleton :width="80" />
        </div>
        <p v-else-if="happened.length === 0" class="ofo-muted dash__events said__line">Nothing has happened since the router started.</p>
        <div v-else class="ofo-table-wrap dash__events">
          <table class="ofo-table">
            <tbody>
              <tr v-for="(event, at) in happened" :key="at">
                <td class="ofo-mono ofo-muted dash__when">{{ event.at }}</td>
                <td>
                  <template v-for="(part, n) in event.parts" :key="n">
                    <code v-if="part.mono" class="ofo-mono">{{ part.text }}</code>
                    <template v-else>{{ part.text }}</template>
                  </template>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </OfoCard>
    </div>
  </div>
</template>
