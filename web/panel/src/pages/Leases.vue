<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { Lease } from '@openfeo/client'
import { OfoBanner, OfoButton, OfoDataTable, OfoEmpty, OfoInput, OfoPageHeader, OfoSegmented, OfoSkeleton, OfoStatusPill } from '@openfeo/ui'
import { computed, inject, ref, watch } from 'vue'

import { CONFIG } from '../config'
import { LIVE } from '../live'
import { leaseKey, leaseRows, matches, newestFirst, perLan, reserve, reserved } from '../model/leases'

// The Leases page (SPEC §8.4): every device that took an address from the router, newest
// first, so that the one just plugged in is at the top with its address. It is a view of what
// the shell hears, with one thing to do: Reserve puts a reservation in the draft, where the
// save bar counts it; a reservation is edited and removed on LAN & DHCP, where they live.
const store = inject(CONFIG)!
const live = inject(LIVE)!
const { now } = live

const table = computed(() => live.leases.value)
const editable = computed(() => store.readOnly.value === null && store.draft.value !== null)
const domain = computed(() => live.state.value?.system?.domain ?? '')

// ---- What narrows the table ----

const filter = ref('')
/** Every LAN, or the one chosen. */
const ALL = ''
const chosen = ref(ALL)
/** The LANs that hand out addresses, as the router has them. */
const lans = computed(() => (live.state.value?.lans ?? []).filter((lan) => lan.dhcp).map((lan) => lan.name))
// A LAN that is no longer one of them is no longer a choice.
watch(lans, (names) => {
  if (chosen.value !== ALL && !names.includes(chosen.value)) {
    chosen.value = ALL
  }
})
const choices = computed(() => [
  { value: ALL, label: 'All LANs' },
  ...perLan(table.value?.leases ?? [], lans.value).map(({ lan, count }) => ({ value: lan, label: lan, count })),
])

// ---- Which rows have just arrived ----

/** The leases of the table before this one, by their keys; `null` until the page has seen a table. */
let known: Set<string> | null = null
/** When each lease that arrived while the page was open did, by the browser's clock. */
const arrived = ref(new Map<string, number>())
/** How long a row stays marked. */
const NEW_MS = 60_000
watch(
  table,
  (current) => {
    if (current === null) {
      return
    }
    const keys = new Set(current.leases.map(leaseKey))
    // What was there when the page was opened did not arrive while it was open.
    const next = new Map([...arrived.value].filter(([key]) => keys.has(key)))
    if (known !== null) {
      for (const key of keys) {
        if (!known.has(key)) {
          next.set(key, Date.now())
        }
      }
    }
    known = keys
    arrived.value = next
  },
  { immediate: true },
)
const fresh = (lease: Lease) => {
  const at = arrived.value.get(leaseKey(lease))
  return at !== undefined && now.value.getTime() - at < NEW_MS
}

// ---- The rows ----

const shown = computed(() =>
  newestFirst(table.value?.leases ?? []).filter((lease) => (chosen.value === ALL || lease.lan === chosen.value) && matches(lease, filter.value)),
)
const rows = computed(() => {
  const made = leaseRows(shown.value, live.routerClock.value, now.value, fresh)
  return made.map((row, at) => {
    const lease = shown.value[at]
    return { ...row, reserved: lease === undefined ? 'unavailable' : reserved(lease, store.base.value, store.draft.value) }
  })
})
const COLUMNS = [
  { key: 'joined', label: 'Joined' },
  { key: 'address', label: 'Address', mono: true },
  { key: 'name', label: 'Name' },
  { key: 'mac', label: 'MAC', mono: true },
  { key: 'lan', label: 'LAN' },
  { key: 'expires', label: 'Expires' },
  { key: 'action', label: '', num: true },
]
const marked = (row: Record<string, string>) => (row.fresh === 'yes' ? 'ofo-table__row--new' : undefined)

/** Reserve: this MAC always gets this address, under the name it gave. It joins the draft's other changes. */
function keep(key: string): void {
  const lease = shown.value.find((each) => leaseKey(each) === key)
  if (lease !== undefined) {
    store.edit((draft) => reserve(draft, store.base.value, lease))
  }
}
</script>

<template>
  <div class="page">
    <OfoPageHeader title="Leases" sub="Devices that took an address from the router, newest first." />
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>

    <div v-if="table === null" class="leases__waiting">
      <OfoSkeleton :width="40" />
      <OfoSkeleton :width="80" />
      <OfoSkeleton :width="60" />
      <OfoSkeleton :width="80" />
    </div>
    <OfoEmpty
      v-else-if="table.leases.length === 0"
      title="No leases yet"
      text="A device appears here when it takes an address from the router, such as a phone joining the Wi-Fi."
    />
    <template v-else>
      <div class="leases__tools">
        <OfoInput v-model="filter" class="leases__filter" placeholder="Filter by name, address or MAC" aria-label="Filter the leases" />
        <OfoSegmented v-if="lans.length > 1" label="LAN" :options="choices" :model-value="chosen" @update:model-value="chosen = $event" />
      </div>
      <OfoDataTable class="leases__table" :columns="COLUMNS" :rows="rows" row-key="key" :row-class="marked">
        <template #cell-joined="{ row, value }">
          <span :title="row.joinedAt">{{ value }}</span>
        </template>
        <template #cell-name="{ row, value }">
          <span :class="{ 'ofo-muted': row.named === '' }">{{ value }}</span>
        </template>
        <template #cell-mac="{ value }">
          <span class="ofo-muted">{{ value }}</span>
        </template>
        <template #cell-expires="{ row, value }">
          <span :title="row.expiresAt">{{ value }}</span>
        </template>
        <template #cell-action="{ row }">
          <OfoButton v-if="row.reserved === 'no' && editable" size="sm" variant="ghost" @click="keep(row.key ?? '')">Reserve</OfoButton>
          <OfoStatusPill v-else-if="row.reserved === 'draft'" tone="info">Reserved, not applied yet</OfoStatusPill>
          <OfoStatusPill v-else-if="row.reserved === 'applied'" tone="info">Reserved</OfoStatusPill>
        </template>
        <template #empty>
          <span class="ofo-muted">
            <template v-if="filter.trim() !== ''">
              No leases match <code class="ofo-mono">{{ filter.trim() }}</code>
              <template v-if="chosen !== ALL"> on {{ chosen }}</template>
            </template>
            <template v-else>No leases on {{ chosen }}</template>
          </span>
        </template>
      </OfoDataTable>
      <p v-if="table.truncated" class="leases__cut ofo-muted">
        The router holds more leases than it sends at once. These are the {{ table.leases.length }} that joined most recently.
      </p>
      <p class="leases__help ofo-muted">
        A new row appears by itself when a device joins. A device with a name is also found as
        <code class="ofo-mono">name.{{ domain }}</code
        >. Reserve keeps this address for the device: it joins your other changes, to apply when you are ready. IPv6 devices choose their own
        addresses, so they are not listed.
      </p>
    </template>
  </div>
</template>
