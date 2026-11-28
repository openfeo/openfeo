<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoCard, OfoDataTable, OfoPageHeader, OfoPortStrip, OfoSkeleton, OfoStatusPill } from '@openfeo/ui'
import { computed, inject } from 'vue'
import { RouterLink } from 'vue-router'

import { LIVE } from '../live'
import { ports } from '../model/dashboard'
import { portRows } from '../model/ports'

// The Ports page (SPEC §8.4): the sockets on the box in the order they are on it. A view of
// what the shell already hears: the state says each port's link and what uses it, and the
// counters, pushed each second, say what it has carried since the router started. A port is
// given to a WAN or a LAN on that WAN's or LAN's own page, so each use is a link to it.
const live = inject(LIVE)!

const strip = computed(() => (live.state.value === null ? null : ports(live.state.value)))
const found = computed(() => (live.state.value === null ? null : portRows(live.state.value, live.counters.value)))

const COLUMNS = [
  { key: 'name', label: 'Port', mono: true },
  { key: 'link', label: 'Link' },
  { key: 'uses', label: 'Used by' },
  { key: 'mac', label: 'MAC', mono: true },
  { key: 'hardware', label: 'Hardware', mono: true },
  { key: 'received', label: 'Received', mono: true, num: true },
  { key: 'sent', label: 'Sent', mono: true, num: true },
]
/** The table's rows: its cells by name. What a cell draws of a port is looked up by the port's name. */
const rows = computed(() => (found.value ?? []).map((port) => ({ name: port.name, link: '', uses: '', mac: port.mac, hardware: port.hardware, received: port.received, sent: port.sent })))
const byName = computed(() => new Map((found.value ?? []).map((port) => [port.name, port])))
</script>

<template>
  <div class="page">
    <OfoPageHeader title="Ports" sub="The sockets on the box, in the order they are on it." />
    <div v-if="found === null || strip === null" class="ports__waiting">
      <OfoSkeleton :width="40" />
      <OfoSkeleton :width="80" />
      <OfoSkeleton :width="60" />
    </div>
    <template v-else>
      <OfoCard class="ports__strip">
        <OfoPortStrip :ports="strip" />
      </OfoCard>
      <OfoDataTable class="ports__table" :columns="COLUMNS" :rows="rows" row-key="name">
        <template #cell-link="{ row }">
          <template v-if="byName.get(row.name ?? '')?.up">
            <OfoStatusPill tone="ok">Up</OfoStatusPill>
            {{ byName.get(row.name ?? '')?.speed }}
          </template>
          <OfoStatusPill v-else>No cable</OfoStatusPill>
        </template>
        <template #cell-uses="{ row }">
          <span v-if="(byName.get(row.name ?? '')?.uses ?? []).length === 0" class="ofo-muted">Not in use</span>
          <template v-for="(use, n) in byName.get(row.name ?? '')?.uses ?? []" v-else :key="use.to + String(use.tag)">
            <template v-if="n > 0"> · </template>
            <RouterLink :to="use.to">{{ use.name }}</RouterLink
            ><template v-if="use.tag !== 0">, tag {{ use.tag }}</template>
          </template>
        </template>
        <template #cell-mac="{ value }">
          <span class="ofo-muted">{{ value }}</span>
        </template>
        <template #cell-hardware="{ value }">
          <span class="ofo-muted">{{ value }}</span>
        </template>
      </OfoDataTable>
      <p class="ports__note ofo-muted">A view: a port is given to a WAN or a LAN on that WAN’s or LAN’s own page. Received and Sent count from when the router started.</p>
    </template>
  </div>
</template>
