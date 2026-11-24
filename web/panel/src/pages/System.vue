<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { create, ErrorCode, RouterError, SystemSchema, type System } from '@openfeo/client'
import { OfoBanner, OfoButton, OfoDialog, OfoField, OfoFormSection, OfoInput, OfoPageHeader, OfoSkeleton, OfoStatusPill } from '@openfeo/ui'
import { computed, inject, onBeforeUnmount, provide, ref, watch } from 'vue'

import { CONFIG } from '../config'
import { FIELDS, listText, pageFields, parseList } from '../fields'
import { LIVE } from '../live'
import { about, routerName, settleSystem, systemProblems } from '../model/system'
import RefusedList from '../parts/RefusedList.vue'
import SettingField from '../parts/SettingField.vue'
import { lengthProblem, ROUTER } from '../session'

// The System page (SPEC §8.4): the router's name and its time servers, which are settings
// like any other and go through the draft; the password and a restart, which do not (each is
// a call of its own, made at once); and what the router is running.
const store = inject(CONFIG)!
const live = inject(LIVE)!
const router = inject(ROUTER)!
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

// ---- Password ----

// The three texts are this page's own: in no draft, no store and no storage. They are
// emptied when the change is made and when the page is left.
const current = ref('')
const next = ref('')
const again = ref('')
/** Which of the two new fields have been left: what the page knows of one is said then. */
const leftNext = ref(false)
const leftAgain = ref(false)
const changing = ref(false)
const changed = ref(false)
/** What the router said of the current password: that it is wrong, or that there were too many tries. */
const refused = ref<'wrong' | 'soon' | null>(null)
/** The browser's clock when another try may be made, after a wait the router asked for. */
const waitUntil = ref<number | null>(null)
/** Anything else the router said of the change. */
const failed = ref<string | null>(null)
const PENDING = 'A change of config is waiting to be confirmed. Confirm or revert it first.'
onBeforeUnmount(forget)

function forget(): void {
  current.value = ''
  next.value = ''
  again.value = ''
  leftNext.value = false
  leftAgain.value = false
}
/** The seconds still to wait, counted down by the page's clock. */
const wait = computed(() => (waitUntil.value === null ? 0 : Math.max(0, Math.ceil((waitUntil.value - live.now.value.getTime()) / 1000))))
const pending = computed(() => store.pending.value !== undefined)
const nextProblem = computed(() => (leftNext.value ? (lengthProblem(next.value) ?? undefined) : undefined))
const againProblem = computed(() => (leftAgain.value && again.value !== next.value ? 'The two passwords differ.' : undefined))
const currentProblem = computed(() => {
  if (refused.value === null || (refused.value === 'soon' && wait.value === 0)) {
    return undefined
  }
  const words = refused.value === 'wrong' ? 'That is not the current password.' : 'Too many tries.'
  return wait.value > 0 ? `${words} Wait ${wait.value} s.` : words
})
function typedCurrent(text: string): void {
  current.value = text
  // What was said was said of the password that was there.
  if (refused.value === 'wrong') {
    refused.value = null
  }
  changed.value = false
}
function typedNew(text: string, which: 'next' | 'again'): void {
  ;(which === 'next' ? next : again).value = text
  changed.value = false
}

async function changePassword(): Promise<void> {
  if (changing.value || wait.value > 0 || pending.value) {
    return
  }
  leftNext.value = true
  leftAgain.value = true
  if (lengthProblem(next.value) !== null || again.value !== next.value) {
    return
  }
  changing.value = true
  failed.value = null
  refused.value = null
  changed.value = false
  try {
    await router.changePassword(current.value, next.value)
    forget()
    waitUntil.value = null
    changed.value = true
  } catch (error) {
    const said = error instanceof RouterError ? error : null
    if (said?.retryAfterSecs !== undefined) {
      waitUntil.value = live.now.value.getTime() + said.retryAfterSecs * 1000
    }
    if (said?.code === ErrorCode.INVALID_ARGUMENT) {
      refused.value = 'wrong'
    } else if (said?.code === ErrorCode.RESOURCE_EXHAUSTED) {
      refused.value = 'soon'
    } else if (said?.code === ErrorCode.FAILED_PRECONDITION) {
      failed.value = PENDING
    } else {
      failed.value = error instanceof Error ? error.message : 'The password could not be changed.'
    }
  } finally {
    changing.value = false
  }
}

// ---- Restart ----

const asking = ref(false)
const restartBusy = ref(false)
const restartFailed = ref<string | null>(null)
/** What a restart loses, beside a minute: said before it is asked. */
const loses = computed(() => {
  const lines = ['Every device loses the internet for about a minute.']
  if (pending.value) {
    lines.push('The change that is waiting to be confirmed goes back to how it was.')
  }
  const drafted = store.changes.value.length
  if (drafted > 0) {
    lines.push(drafted === 1 ? '1 change that is not applied yet is lost.' : `${drafted} changes that are not applied yet are lost.`)
  }
  return lines
})
function ask(): void {
  restartFailed.value = null
  asking.value = true
}
async function restart(): Promise<void> {
  if (restartBusy.value) {
    return
  }
  restartBusy.value = true
  restartFailed.value = null
  try {
    await router.reboot()
    asking.value = false
    // The router answers before it goes: from here the shell says it is restarting.
    live.restart()
  } catch (error) {
    restartFailed.value = error instanceof Error ? error.message : 'The router could not be asked to restart.'
  } finally {
    restartBusy.value = false
  }
}

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

      <OfoFormSection title="Password" text="Changing it takes effect at once and logs out every other session.">
        <OfoBanner v-if="changed" class="changed ofo-span-2" tone="ok">The password was changed. Every other session was logged out.</OfoBanner>
        <OfoField class="ofo-span-2" label="Current password" :error="currentProblem">
          <OfoInput type="password" autocomplete="current-password" :model-value="current" :invalid="!!currentProblem" @update:model-value="typedCurrent" />
        </OfoField>
        <OfoField label="New password" help="At least 12 characters." :error="nextProblem">
          <OfoInput
            type="password"
            autocomplete="new-password"
            :model-value="next"
            :invalid="!!nextProblem"
            @update:model-value="(text) => typedNew(text, 'next')"
            @blur="leftNext = true"
          />
        </OfoField>
        <OfoField label="New password again" :error="againProblem">
          <OfoInput
            type="password"
            autocomplete="new-password"
            :model-value="again"
            :invalid="!!againProblem"
            @update:model-value="(text) => typedNew(text, 'again')"
            @blur="leftAgain = true"
          />
        </OfoField>
        <p v-if="pending" class="held ofo-field__help ofo-span-2 page__none">{{ PENDING }}</p>
        <div class="ofo-span-2">
          <OfoButton :disabled="changing || wait > 0 || pending" @click="changePassword">Change password</OfoButton>
        </div>
        <p v-if="failed" class="failed ofo-field--error ofo-span-2 page__none"><span class="ofo-field__help" role="alert">{{ failed }}</span></p>
      </OfoFormSection>

      <OfoFormSection title="Restart" text="Everything goes offline for about a minute. You log in again when it is back.">
        <div class="ofo-span-2">
          <OfoButton variant="danger" :disabled="live.restarting.value !== null" @click="ask">Restart the router</OfoButton>
        </div>
      </OfoFormSection>

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

    <OfoDialog v-if="asking" class="restart" :title="`Restart ${name}?`" @cancel="restartBusy || (asking = false)">
      <p v-for="line in loses" :key="line" class="ofo-dialog__text">{{ line }}</p>
      <p v-if="restartFailed" class="ofo-field--error page__none"><span class="ofo-field__help" role="alert">{{ restartFailed }}</span></p>
      <template #foot>
        <OfoButton variant="ghost" autofocus :disabled="restartBusy" @click="asking = false">Cancel</OfoButton>
        <OfoButton variant="danger" :disabled="restartBusy" @click="restart">Restart</OfoButton>
      </template>
    </OfoDialog>
  </div>
</template>
