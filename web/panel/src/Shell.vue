<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import {
  chooseTheme,
  OfoBanner,
  OfoButton,
  OfoNav,
  OfoShell,
  OfoThemeSwitch,
  storedTheme,
  systemTheme,
  type NavEntry,
  type Theme,
} from '@openfeo/ui'
import { computed, inject, onBeforeUnmount, onMounted, provide, ref } from 'vue'
import { RouterView, useRoute, useRouter } from 'vue-router'

import { LIVE, useLive } from './live'
import { clock, duration } from './model/format'
import { PAGES } from './routes'
import { ROUTER, SESSION, storageOr } from './session'

// What every page behind the login sits in (SPEC §8.4): the sidebar, the top bar, and what
// is said above every page. It listens to the router once, for all of them. A page appears
// in the sidebar in the part that builds it.
const router = inject(ROUTER)!
const session = inject(SESSION)!
const route = useRoute()
const routes = useRouter()
const live = useLive(router)
provide(LIVE, live)
const { state, lostAt, now, sinceBootMs } = live

onMounted(() => live.start())
onBeforeUnmount(() => live.stop())

const host = computed(() => {
  const status = session.status.value
  return status === null ? '' : [status.hostname, status.domain].filter((part) => part !== '').join('.')
})
const meta = computed(() => {
  const system = state.value?.system
  if (system === undefined || sinceBootMs.value === undefined) {
    return ''
  }
  return `${system.version} · up ${duration(sinceBootMs.value / 1000)}`
})

/** Whether the address is `page`'s or one beneath it (`/lan/lan0` is LAN & DHCP's). */
function at(page: string): boolean {
  return route.path === page || route.path.startsWith(`${page}/`)
}
const nav = computed<NavEntry[]>(() => [
  { kind: 'item', label: 'Dashboard', icon: 'layout-dashboard', to: PAGES.dashboard, current: route.path === PAGES.dashboard },
  { kind: 'group', label: 'Network' },
  { kind: 'item', label: 'WAN', icon: 'globe', to: PAGES.wan, current: at(PAGES.wan) },
  { kind: 'item', label: 'LAN & DHCP', icon: 'network', to: PAGES.lan, current: at(PAGES.lan) },
])

// The theme is the one thing kept in local storage; where that is blocked, a choice lasts the page.
const themeStorage = storageOr(() => window.localStorage)
const theme = ref<Theme>(storedTheme(themeStorage) ?? systemTheme(window.matchMedia?.('(prefers-color-scheme: light)').matches ?? false))
function setTheme(chosen: Theme): void {
  chooseTheme(document.documentElement, themeStorage, chosen)
  theme.value = chosen
}

const problem = computed(() => state.value?.system?.configProblem)
const lostAtClock = computed(() => (lostAt.value === null ? '' : clock(BigInt(lostAt.value.getTime()), now.value)))
</script>

<template>
  <OfoShell :host="host" :meta="meta">
    <template #nav>
      <OfoNav :entries="nav" @navigate="(to) => routes.push(to)" />
    </template>
    <template #actions>
      <OfoThemeSwitch :theme="theme" @change="setTheme" />
      <OfoButton size="sm" variant="ghost" icon="log-out" @click="router.logout()">Log out</OfoButton>
    </template>

    <div v-if="lostAt || problem" class="said">
      <OfoBanner v-if="lostAt" tone="danger">The connection to the router was lost at {{ lostAtClock }}. Retrying.</OfoBanner>
      <OfoBanner v-if="problem" tone="warn" title="config.toml was refused">
        <p class="said__line">{{ problem.reason }}</p>
        <ul v-if="problem.violations.length > 0" class="said__list">
          <li v-for="violation in problem.violations" :key="violation.path + violation.code">
            <code class="ofo-mono">{{ violation.path }}</code>: {{ violation.message }}
          </li>
        </ul>
        <p class="said__line">The router is running on first-boot defaults.</p>
      </OfoBanner>
    </div>

    <RouterView />
  </OfoShell>
</template>
