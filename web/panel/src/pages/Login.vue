<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { ErrorCode, RouterError } from '@openfeo/client'
import { OfoButton, OfoCard, OfoField, OfoInput, OfoWordmark } from '@openfeo/ui'
import { computed, inject, onBeforeUnmount, ref } from 'vue'

import { ROUTER, SESSION } from '../session'

const router = inject(ROUTER)!
const session = inject(SESSION)!

const password = ref('')
const busy = ref(false)
/** What the last attempt came to: a wrong password, one made too soon, or a router that did not answer. */
const refused = ref<'wrong' | 'soon' | 'unreachable' | 'other' | null>(null)
const other = ref('')
/** Seconds until the router will look at another attempt (SPEC §9). */
const wait = ref(0)
let ticking: ReturnType<typeof setInterval> | undefined

const host = computed(() => {
  const status = session.status.value
  return status === null ? '' : [status.hostname, status.domain].filter((part) => part !== '').join('.')
})

/** Why the person is here: something said once, or how the last session ended. */
const why = computed(() => {
  if (session.notice.value !== null) {
    return session.notice.value
  }
  switch (session.ended.value) {
    case 'lapsed':
      return 'Your session ended. Log in again.'
    case 'revoked':
      return 'This session was ended from elsewhere. Log in again.'
    default:
      return null
  }
})

const error = computed(() => {
  const next = wait.value > 0 ? `Next attempt in ${wait.value} s.` : null
  switch (refused.value) {
    case 'wrong':
      return next === null ? 'Wrong password.' : `Wrong password. ${next}`
    case 'soon':
      return next ?? undefined
    case 'unreachable':
      return 'The router is not answering. Try again.'
    case 'other':
      return other.value
    default:
      return undefined
  }
})

function countDown(secs: number): void {
  clearInterval(ticking)
  wait.value = secs
  if (secs > 0) {
    ticking = setInterval(() => {
      wait.value -= 1
      if (wait.value <= 0) {
        wait.value = 0
        clearInterval(ticking)
      }
    }, 1_000)
  }
}

async function submit(): Promise<void> {
  if (busy.value || wait.value > 0) {
    return
  }
  busy.value = true
  try {
    // Exactly as typed.
    await router.login(password.value)
    refused.value = null
    await session.entered()
  } catch (thrown) {
    const code = thrown instanceof RouterError ? thrown.code : undefined
    const secs = thrown instanceof RouterError ? (thrown.retryAfterSecs ?? 0) : 0
    if (code === ErrorCode.UNAUTHENTICATED) {
      refused.value = 'wrong'
      countDown(secs)
    } else if (code === ErrorCode.RESOURCE_EXHAUSTED) {
      refused.value = 'soon'
      countDown(Math.max(secs, 1))
    } else if (code === ErrorCode.UNAVAILABLE) {
      refused.value = 'unreachable'
    } else {
      refused.value = 'other'
      other.value = `The router refused: ${thrown instanceof Error ? thrown.message : 'no reason given'}.`
    }
  } finally {
    busy.value = false
  }
}

onBeforeUnmount(() => clearInterval(ticking))
</script>

<template>
  <main class="gate">
    <div class="gate__col">
      <div class="gate__brand"><OfoWordmark :height="28" /></div>
      <p class="gate__host ofo-mono">{{ host }}</p>
      <h1 class="gate__title gate__title--small">Log in</h1>
      <p v-if="why" class="gate__why">{{ why }}</p>
      <OfoCard>
        <form class="gate__form" novalidate @submit.prevent="submit">
          <OfoField label="Password" :error="error">
            <OfoInput v-model="password" type="password" autocomplete="current-password" />
          </OfoField>
          <OfoButton variant="primary" type="submit" :disabled="busy || wait > 0">{{ busy ? 'Logging in…' : 'Log in' }}</OfoButton>
        </form>
      </OfoCard>
      <p class="gate__foot"><a href="/licences.txt">Licences</a></p>
    </div>
  </main>
</template>
