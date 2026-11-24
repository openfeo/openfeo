<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import {
  chooseTheme,
  OfoBanner,
  OfoButton,
  OfoNav,
  OfoSaveBar,
  OfoShell,
  OfoThemeSwitch,
  storedTheme,
  systemTheme,
  type NavEntry,
  type Theme,
} from '@openfeo/ui'
import { computed, inject, nextTick, onBeforeUnmount, onMounted, provide, ref } from 'vue'
import { RouterView, useRoute, useRouter } from 'vue-router'

import { CONFIG, useConfig, type Review } from './config'
import { LIVE, useLive } from './live'
import { clock, duration } from './model/format'
import { renamedTo } from './model/system'
import ApplyDialog from './parts/ApplyDialog.vue'
import NoticeBanner from './parts/NoticeBanner.vue'
import PendingBanner from './parts/PendingBanner.vue'
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
const { state, lostAt, restarting, now, sinceBootMs } = live

const host = computed(() => {
  const status = session.status.value
  return status === null ? '' : [status.hostname, status.domain].filter((part) => part !== '').join('.')
})

// One draft of the config for every settings page, beside the session: it is read when the
// shell comes up and dropped when it goes.
const config = useConfig(router, live, () => host.value)
provide(CONFIG, config)

onMounted(() => {
  live.start()
  config.start()
})
onBeforeUnmount(() => {
  config.stop()
  live.stop()
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
  { kind: 'item', label: 'Leases', icon: 'monitor-smartphone', to: PAGES.leases, current: at(PAGES.leases) },
  { kind: 'item', label: 'Firewall', icon: 'shield', to: PAGES.firewall, current: at(PAGES.firewall) },
  { kind: 'item', label: 'DNS', icon: 'text', to: PAGES.dns, current: at(PAGES.dns) },
  { kind: 'group', label: 'Router' },
  { kind: 'item', label: 'System', icon: 'settings', to: PAGES.system, current: at(PAGES.system) },
])

// The theme is the one thing kept in local storage; where that is blocked, a choice lasts the page.
const themeStorage = storageOr(() => window.localStorage)
const theme = ref<Theme>(storedTheme(themeStorage) ?? systemTheme(window.matchMedia?.('(prefers-color-scheme: light)').matches ?? false))
function setTheme(chosen: Theme): void {
  chooseTheme(document.documentElement, themeStorage, chosen)
  theme.value = chosen
}

// What the settings pages have changed is applied from here, whichever of them is shown:
// the bar beneath the page counts it, and one dialog says what an apply does before it is sent.
// (Leases is one of them: Reserve on a row is a change like any other.)
const settings = computed(() => [PAGES.wan, PAGES.lan, PAGES.leases, PAGES.firewall, PAGES.dns, PAGES.system].some(at))
/**
 * Why another apply is not offered just now: one is waiting to be confirmed, or one was sent
 * and the router has not yet said whether it took it (another would be asked of a router
 * that may be moving, and its refusal would take the place of the notice that says so).
 */
const held = computed(() => {
  if (config.pending.value !== undefined) {
    return 'Confirm or revert the change that is waiting first.'
  }
  return config.awaiting.value ? 'Waiting to hear from the router what became of the change that was sent.' : undefined
})
/** What the router made of the draft, while the dialog that shows it is open. */
const reviewed = ref<Review | null>(null)

/** Take the person to something on the page: the control of a field, or what is there. */
function bring(to: Element | null): void {
  const control = to?.querySelector<HTMLElement>('input, select') ?? (to as HTMLElement | null)
  control?.scrollIntoView?.({ block: 'center' })
  control?.focus()
}

async function review(): Promise<void> {
  // What the page itself finds wrong in a field is not in the draft, so the router would not
  // see it: it is put right first.
  await nextTick()
  const typed = document.querySelector('.page [data-typed]')
  if (typed !== null) {
    bring(typed)
    return
  }
  const found = await config.review()
  if (found === null) {
    // The page shows what the router refused: the first of it is where to start.
    await nextTick()
    bring(document.querySelector('.page .ofo-field--error, .page .refused'))
    return
  }
  reviewed.value = found
}

async function apply(immediate: boolean): Promise<void> {
  if (reviewed.value !== null) {
    await config.apply(reviewed.value, immediate)
    // Whatever became of it: the notice says.
    reviewed.value = null
  }
}

const problem = computed(() => state.value?.system?.configProblem)
const lostAtClock = computed(() => (lostAt.value === null ? '' : clock(BigInt(lostAt.value.getTime()), now.value)))
/** How long a restart is given before the page says the router has not come back. */
const RESTART_MS = 120_000
/** What is said while the router restarts because this page asked it to. */
const restartingWords = computed(() => {
  const asked = restarting.value
  if (asked === null) {
    return null
  }
  return now.value.getTime() - asked.getTime() < RESTART_MS
    ? 'The router is restarting. You log in again when it is back.'
    : `The router was asked to restart at ${clock(BigInt(asked.getTime()), now.value)} and has not answered since.`
})
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

    <div v-if="restartingWords || lostAt || problem || config.pending.value || config.notice.value" class="said">
      <!-- A restart that was asked for is not a connection lost: it is said as what it is. -->
      <OfoBanner v-if="restartingWords" tone="info">{{ restartingWords }}</OfoBanner>
      <OfoBanner v-else-if="lostAt" tone="danger">The connection to the router was lost at {{ lostAtClock }}. Retrying.</OfoBanner>
      <OfoBanner v-if="problem" tone="warn" title="config.toml was refused">
        <p class="said__line">{{ problem.reason }}</p>
        <ul v-if="problem.violations.length > 0" class="said__list">
          <li v-for="violation in problem.violations" :key="violation.path + violation.code">
            <code class="ofo-mono">{{ violation.path }}</code>: {{ violation.message }}
          </li>
        </ul>
        <p class="said__line">The router is running on first-boot defaults.</p>
      </OfoBanner>
      <!-- A change that is waiting, on every page of every session; then what became of one. -->
      <PendingBanner
        v-if="config.pending.value"
        class="pending"
        :pending="config.pending.value"
        :since-boot-ms="sinceBootMs"
        :now="now"
        :busy="config.busy.value"
        @confirm="config.confirm()"
        @revert="config.revert()"
      />
      <NoticeBanner v-if="config.notice.value" :notice="config.notice.value" @dismiss="config.notice.value = null" />
    </div>

    <RouterView />

    <OfoSaveBar
      v-if="settings && config.readOnly.value === null"
      :count="config.changes.value.length"
      :busy="config.busy.value"
      :held="held"
      @discard="config.discard()"
      @apply="review"
    />
    <ApplyDialog
      v-if="reviewed"
      :review="reviewed"
      :host="session.status.value?.hostname ?? ''"
      :name="host"
      :renamed="renamedTo(config.base.value, reviewed.config) ?? undefined"
      :confirm-secs="config.confirmSecs.value"
      :busy="config.busy.value"
      @apply="apply"
      @cancel="reviewed = null"
    />
  </OfoShell>
</template>
