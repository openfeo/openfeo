<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { Route } from '@openfeo/client'
import { OfoBanner, OfoButton, OfoDataTable, OfoPageHeader, OfoSegmented, OfoSkeleton } from '@openfeo/ui'
import { computed, inject, ref, watch } from 'vue'

import { LIVE } from '../live'
import { routeRows } from '../model/routes'
import { ROUTER } from '../session'

// The Routes page (SPEC §8.4): where the router sends traffic for each destination, as the
// kernel has it now. A view: the routes follow from the WAN and LAN settings. The router
// answers every route it holds; the page shows the ones a person reads (model/routes.ts) and
// says whose each is. It reads when it opens and again whenever the router's state changes,
// since a route changes with a WAN that comes or goes, and with nothing else.
const live = inject(LIVE)!
const router = inject(ROUTER)!

const FAMILIES = [
  { value: '4', label: 'IPv4' },
  { value: '6', label: 'IPv6' },
]
const family = ref('4')

/** The routes as the router last answered them; `null` until it first has. */
const routes = ref<Route[] | null>(null)
/** The last read failed. What was read before stays on screen. */
const failed = ref(false)
/** Which read is the newest: an answer to an older one is about a router that has changed since. */
let asked = 0

async function read(): Promise<void> {
  const mine = ++asked
  try {
    const answer = await router.dumpRoutes()
    if (mine === asked) {
      routes.value = answer
      failed.value = false
    }
  } catch {
    if (mine === asked) {
      failed.value = true
    }
  }
}

// Whose a route is comes from the state, so there is nothing to show before the state has
// come; and each new state is a reason to read again.
watch(
  () => live.state.value?.generation,
  (generation) => {
    if (generation !== undefined) {
      void read()
    }
  },
  { immediate: true },
)

const COLUMNS = [
  { key: 'destination', label: 'Destination', mono: true },
  { key: 'via', label: 'Via' },
  { key: 'interface', label: 'Interface', mono: true },
  { key: 'belongsTo', label: 'Belongs to' },
]
const rows = computed(() => {
  const state = live.state.value
  return routes.value === null || state === null ? null : routeRows(routes.value, state, family.value === '6')
})
</script>

<template>
  <div class="page">
    <OfoPageHeader title="Routes" sub="Where the router sends traffic for each destination, as it is now." />
    <OfoBanner v-if="failed" class="routes__failed" tone="warn">
      The routes could not be read from the router.
      <OfoButton size="sm" variant="ghost" @click="read">Try again</OfoButton>
    </OfoBanner>
    <div v-if="rows === null" class="routes__waiting">
      <template v-if="!failed">
        <OfoSkeleton :width="40" />
        <OfoSkeleton :width="80" />
        <OfoSkeleton :width="60" />
      </template>
    </div>
    <template v-else>
      <div class="routes__tools">
        <OfoSegmented label="Family" :options="FAMILIES" :model-value="family" @update:model-value="family = $event" />
      </div>
      <p v-if="rows.length === 0" class="routes__none ofo-muted">No {{ family === '6' ? 'IPv6' : 'IPv4' }} routes.</p>
      <OfoDataTable v-else class="routes__table" :columns="COLUMNS" :rows="rows" row-key="key">
        <template #cell-via="{ row, value }">
          <span v-if="row.how === 'gateway'" class="ofo-mono">{{ value }}</span>
          <span v-else class="ofo-muted">{{ value }}</span>
        </template>
      </OfoDataTable>
      <p class="routes__note ofo-muted">A view: the routes follow from the WAN and LAN settings, and there is nothing to edit here.</p>
    </template>
  </div>
</template>
