<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoCard, OfoChart, OfoDataTable, OfoInterfaceCard, OfoPageHeader, OfoPortStrip, OfoSegmented, OfoSkeleton, OfoStatTile } from '@openfeo/ui'
import { computed, inject, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { LIVE } from '../live'
import { drawn, marks, OPENING, peak, rangeOf, RANGES, ticks, type Range } from '../model/chart'
import { addresses, cards, defaultWan, headline, ports, tiles } from '../model/dashboard'
import { sentence, when } from '../model/events'
import { justJoined, leaseRows, newestFirst } from '../model/leases'
import { PAGES } from '../routes'

// The dashboard (SPEC §8.4): read-only and live. What it says and how it says it is
// model/; this arranges it. What it shows is what the shell hears from the router.
const live = inject(LIVE)!
const { state, now, sinceBootMs } = live

/**
 * The right edge of every chart, on the router's boot clock: its uptime by now, or the newest
 * sample where that is later (the uptime is said in whole seconds).
 */
const edgeMs = computed(() => Math.max(sinceBootMs.value ?? 0, ...[...live.samples.value.values()].map((kept) => kept.at(-1)?.atMs ?? 0)))

const stats = computed(() => {
  if (state.value === null) {
    return null
  }
  const wan = defaultWan(state.value)
  const kept = wan === undefined ? undefined : live.samples.value.get(wan.interface)
  return tiles(state.value, {
    rate: wan === undefined ? undefined : live.rates.value?.get(wan.interface),
    history: live.history.value,
    peak: kept === undefined ? undefined : peak(kept, edgeMs.value),
    conntrack: live.conntrack.value ?? undefined,
  })
})

// One range for the page: every WAN's chart is read against the same stretch of time.
const range = ref<Range>(OPENING)
const RANGE_CHOICES = RANGES.map(({ value, label }) => ({ value, label }))
function choose(chosen: string): void {
  range.value = rangeOf(chosen as Range).value
}
const charts = computed(() =>
  state.value === null
    ? null
    : state.value.wans.map((wan) => ({
        title: wan.name,
        label: `Download and upload on ${wan.name} over ${rangeOf(range.value).words}`,
        // A WAN the router has kept nothing of (a PPPoE WAN with no session in the hour: its
        // interface is named all the while, and is there only during one) has an empty plot.
        ...drawn(live.samples.value.get(wan.interface) ?? [], range.value, edgeMs.value, live.rates.value?.get(wan.interface)),
        marks: marks(live.events.value, wan.name, range.value, edgeMs.value, sinceBootMs.value, now.value),
        ticks: ticks(range.value, edgeMs.value, sinceBootMs.value, now.value),
        note: live.historyFailed.value ? 'The last hour could not be read from the router. The line starts from when this page was opened.' : undefined,
      })),
)

/** How many of the newest leases the dashboard lists; the Leases page has them all. */
const NEWEST = 5
const LEASE_COLUMNS = [
  { key: 'joined', label: 'Joined' },
  { key: 'address', label: 'Address', mono: true },
  { key: 'name', label: 'Name' },
  { key: 'mac', label: 'MAC', mono: true },
  { key: 'lan', label: 'LAN' },
]
const leased = computed(() => live.leases.value?.leases.length ?? 0)
const newest = computed(() =>
  live.leases.value === null
    ? null
    : // A device that joined under a minute ago is marked: it is the one just plugged in.
      leaseRows(newestFirst(live.leases.value.leases).slice(0, NEWEST), live.routerClock.value, now.value, (_, ago) => justJoined(ago)),
)
const marked = (row: Record<string, string>) => (row.fresh === 'yes' ? 'ofo-table__row--new' : undefined)
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
/** How many events the dashboard lists; the shell keeps as many as the router does, for the charts' marks. */
const RECENT = 8
const happened = computed(() =>
  live.events.value.slice(0, RECENT).map((event) => ({
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

    <template v-if="charts">
      <OfoChart v-for="chart in charts" :key="chart.title" v-bind="chart">
        <template #range>
          <OfoSegmented label="Range" :options="RANGE_CHOICES" :model-value="range" @update:model-value="choose" />
        </template>
      </OfoChart>
    </template>
    <div v-else class="ofo-chart dash__waiting">
      <OfoSkeleton :width="40" />
      <OfoSkeleton size="lg" :width="80" />
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

    <OfoCard title="Newest leases">
      <template #actions>
        <RouterLink v-if="leased > 0" class="dash__more" :to="PAGES.leases">{{ leased === 1 ? '1 lease' : `All ${leased} leases` }}</RouterLink>
      </template>
      <OfoDataTable v-if="newest && newest.length > 0" class="dash__leases" :columns="LEASE_COLUMNS" :rows="newest" row-key="key" :row-class="marked">
        <template #cell-joined="{ row, value }">
          <span :title="row.joinedAt">{{ value }}</span>
        </template>
        <template #cell-name="{ row, value }">
          <span :class="{ 'ofo-muted': row.named === '' }">{{ value }}</span>
        </template>
        <template #cell-mac="{ value }">
          <span class="ofo-muted">{{ value }}</span>
        </template>
      </OfoDataTable>
      <p v-else-if="newest" class="ofo-muted said__line">No device has taken an address yet.</p>
      <div v-else class="dash__waiting">
        <OfoSkeleton :width="80" />
        <OfoSkeleton :width="60" />
        <OfoSkeleton :width="80" />
      </div>
    </OfoCard>

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
