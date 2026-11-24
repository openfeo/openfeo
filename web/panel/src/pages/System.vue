<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { create, SystemSchema, type System } from '@openfeo/client'
import { OfoBanner, OfoFormSection, OfoPageHeader, OfoSkeleton, OfoStatusPill } from '@openfeo/ui'
import { computed, inject, provide, watch } from 'vue'

import { CONFIG } from '../config'
import { FIELDS, listText, pageFields, parseList } from '../fields'
import { LIVE } from '../live'
import { about, routerName, settleSystem, systemProblems } from '../model/system'
import RefusedList from '../parts/RefusedList.vue'
import SettingField from '../parts/SettingField.vue'

// The System page (SPEC §8.4): the router's name and its time servers, which are settings
// like any other and go through the draft; the password and a restart, which do not (each is
// a call of its own, made at once); and what the router is running.
const store = inject(CONFIG)!
const live = inject(LIVE)!
const fields = pageFields()
provide(FIELDS, fields)
// A draft that is another one (discarded, applied, read again with something new in it) starts clean.
watch(
  () => store.draft.value,
  (now, before) => {
    if (now !== before) {
      fields.left.clear()
      fields.typed.clear()
    }
  },
)

const draft = computed(() => store.draft.value)
const system = computed(() => draft.value?.system)
const was = computed(() => store.base.value?.system)
const local = computed(() => systemProblems(system.value))

/** Change the system settings; a router that had none and has none again is left without. */
function change(edit: (system: System) => void): void {
  store.edit((config) => {
    config.system ??= create(SystemSchema, {})
    edit(config.system)
    settleSystem(config, store.base.value)
  })
}
/** What a field was in the router's config; nothing to compare with until that is read. */
function wasOf(value: (system: System | undefined) => string): string | undefined {
  return store.base.value === null ? undefined : value(was.value)
}

// ---- Name ----

/** Where the panel is now: the name changes when the change is applied, not as it is typed. */
const name = computed(() => (store.base.value === null ? '' : routerName(store.base.value)))
const nameText = computed(
  () => `${name.value === '' ? '' : `The panel is at ${name.value}. `}Changing either gives the router a new certificate, so your browser will ask about it once more.`,
)

// ---- Time ----

const servers = computed(() => system.value?.ntpServers ?? [])
function setServers(text: string): void {
  fields.typed.set('system.ntp_servers', text)
  change((shown) => (shown.ntpServers = parseList(text)))
}
/** Whether the router's clock was set from the internet; null until it has said. */
const synced = computed(() => live.state.value?.system?.timeSynced ?? null)

// ---- About ----

const rows = computed(() => (live.state.value === null ? null : about(live.state.value, live.sinceBootMs.value)))

// ---- What the router refused where no field is ----

/** Whether a field of this page is for `path`, and so says what the router said of it. */
function claimed(path: string): boolean {
  return /^system\.(hostname|domain)$/.test(path) || /^system\.ntp_servers(\[|$)/.test(path)
}
/**
 * What the router refused that no field here shows: a setting of another page. Said above the
 * page, so that pressing Apply changes never looks like nothing happened.
 */
const unplaced = computed(() => store.violations.value.filter((violation) => !claimed(violation.path)))
</script>

<template>
  <div class="page">
    <OfoPageHeader title="System" sub="The router’s name, clock, password and software." />
    <OfoBanner v-if="store.readOnly.value" class="readonly" tone="info">{{ store.readOnly.value }}</OfoBanner>
    <RefusedList :violations="unplaced" />
    <template v-if="draft === null">
      <OfoSkeleton :lines="6" />
    </template>
    <template v-else>
      <OfoFormSection title="Name" :text="nameText">
        <SettingField
          label="Hostname"
          path="system.hostname"
          :value="system?.hostname ?? ''"
          :was="wasOf((each) => each?.hostname ?? '')"
          :problem="local.hostname"
          placeholder="openfeo"
          mono
          @update="(text) => change((shown) => (shown.hostname = text))"
        />
        <SettingField
          label="Domain"
          path="system.domain"
          :value="system?.domain ?? ''"
          :was="wasOf((each) => each?.domain ?? '')"
          :problem="local.domain"
          help="Every local name is under it."
          placeholder="home.arpa"
          mono
          @update="(text) => change((shown) => (shown.domain = text))"
        />
      </OfoFormSection>

      <OfoFormSection title="Time" text="The panel shows times in your browser’s time zone.">
        <p v-if="synced !== null" class="clock ofo-span-2 page__none">
          <template v-if="synced"><OfoStatusPill tone="ok">Synced</OfoStatusPill> The router’s clock was set from the internet.</template>
          <template v-else>
            <OfoStatusPill tone="warn">Not set yet</OfoStatusPill> The router has not had the time from the internet yet. Times from before it has are counted from when the router
            started.
          </template>
        </p>
        <SettingField
          label="Time servers"
          path="system.ntp_servers"
          :value="listText(fields, 'system.ntp_servers', servers)"
          :was="wasOf((each) => (each?.ntpServers ?? []).join(', '))"
          :means="servers.join(', ')"
          :problem="local.ntp_servers"
          help="Names or addresses, separated by commas."
          mono
          span
          @update="setServers"
        />
      </OfoFormSection>

      <OfoFormSection title="Password" text="Changing it takes effect at once and logs out every other session." />

      <OfoFormSection title="Restart" text="Everything goes offline for about a minute. You log in again when it is back." />

      <OfoFormSection title="About" text="" plain>
        <dl v-if="rows !== null" class="about">
          <template v-for="row in rows" :key="row.label">
            <dt class="ofo-muted">{{ row.label }}</dt>
            <dd :class="{ 'ofo-mono': row.mono }">{{ row.value }}</dd>
          </template>
          <dt class="ofo-muted">Licences</dt>
          <dd><a href="/licences.txt">Open-source notices</a></dd>
        </dl>
      </OfoFormSection>
    </template>
  </div>
</template>
