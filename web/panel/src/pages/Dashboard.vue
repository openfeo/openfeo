<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import {
  chooseTheme,
  OfoBanner,
  OfoButton,
  OfoCard,
  OfoDataTable,
  OfoInterfaceCard,
  OfoNav,
  OfoPageHeader,
  OfoPortStrip,
  OfoShell,
  OfoSkeleton,
  OfoStatTile,
  OfoThemeSwitch,
  storedTheme,
  systemTheme,
  type NavEntry,
  type Theme,
} from '@openfeo/ui'
import { computed, inject, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { routerKey } from 'vue-router'

import { useLive } from '../live'
import { addresses, cards, defaultWan, headline, ports, tiles } from '../model/dashboard'
import { sentence, when } from '../model/events'
import { clock, duration } from '../model/format'
import { ROUTER, SESSION, storageOr } from '../session'

// The dashboard (SPEC §8.4): read-only and live. What it says and how it says it is
// model/; this arranges it. A page appears in the sidebar in the part that builds it, so for
// now the sidebar holds the dashboard alone.
const router = inject(ROUTER)!
const session = inject(SESSION)!
const routes = inject(routerKey, null)
const live = useLive(router)
const { state, lostAt } = live

// The clock the page reads: what "today" is for an event's time, and how far the uptime has
// moved on since the router last said it.
const now = ref(new Date())
let ticking: ReturnType<typeof setInterval> | undefined
let stateAt = Date.now()
watch(state, () => {
  stateAt = Date.now()
})

onMounted(() => {
  live.start()
  ticking = setInterval(() => {
    now.value = new Date()
  }, 1_000)
})
onBeforeUnmount(() => {
  live.stop()
  clearInterval(ticking)
})

const host = computed(() => {
  const status = session.status.value
  return status === null ? '' : [status.hostname, status.domain].filter((part) => part !== '').join('.')
})
/** How long the router has been up by now: what it last said, and the time since it said it. */
const sinceBootMs = computed(() => {
  const system = state.value?.system
  return system === undefined ? undefined : Number(system.uptimeSecs) * 1000 + Math.max(0, now.value.getTime() - stateAt)
})
const meta = computed(() => {
  const system = state.value?.system
  if (system === undefined || sinceBootMs.value === undefined) {
    return ''
  }
  return `${system.version} · up ${duration(sinceBootMs.value / 1000)}`
})

const nav: NavEntry[] = [{ kind: 'item', label: 'Dashboard', icon: 'layout-dashboard', to: '/', current: true }]

// The theme is the one thing kept in local storage; where that is blocked, a choice lasts the page.
const themeStorage = storageOr(() => window.localStorage)
const theme = ref<Theme>(storedTheme(themeStorage) ?? systemTheme(window.matchMedia?.('(prefers-color-scheme: light)').matches ?? false))
function setTheme(chosen: Theme): void {
  chooseTheme(document.documentElement, themeStorage, chosen)
  theme.value = chosen
}

const problem = computed(() => state.value?.system?.configProblem)
const lostAtClock = computed(() => (lostAt.value === null ? '' : clock(BigInt(lostAt.value.getTime()), now.value)))

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
  <OfoShell :host="host" :meta="meta">
    <template #nav>
      <OfoNav :entries="nav" @navigate="(to) => routes?.push(to)" />
    </template>
    <template #actions>
      <OfoThemeSwitch :theme="theme" @change="setTheme" />
      <OfoButton size="sm" variant="ghost" icon="log-out" @click="router.logout()">Log out</OfoButton>
    </template>

    <div class="dash">
      <OfoBanner v-if="lostAt" tone="danger">The connection to the router was lost at {{ lostAtClock }}. Retrying.</OfoBanner>
      <OfoBanner v-if="problem" tone="warn" title="config.toml was refused">
        <p class="dash__said">{{ problem.reason }}</p>
        <ul v-if="problem.violations.length > 0" class="dash__violations">
          <li v-for="violation in problem.violations" :key="violation.path + violation.code">
            <code class="ofo-mono">{{ violation.path }}</code>: {{ violation.message }}
          </li>
        </ul>
        <p class="dash__said">The router is running on first-boot defaults.</p>
      </OfoBanner>

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
          <p v-else-if="happened.length === 0" class="ofo-muted dash__events dash__said">Nothing has happened since the router started.</p>
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
  </OfoShell>
</template>
