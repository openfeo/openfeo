<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { ErrorCode, RouterError } from '@openfeo/client'
import { OfoButton, OfoCard, OfoField, OfoInput, OfoWordmark } from '@openfeo/ui'
import { computed, inject, ref } from 'vue'

import { lengthProblem, passwordProblem, ROUTER, SESSION } from '../session'

// A router with no password yet (SPEC §9): anyone on the LAN can set it, once, and is then
// logged in. The fingerprint is here because this is the moment to check whose router it is.
const router = inject(ROUTER)!
const session = inject(SESSION)!

const password = ref('')
const repeat = ref('')
/** The person has tried to send it: from then on what is wrong is said as they type. */
const tried = ref(false)
const busy = ref(false)
const failure = ref<string | null>(null)

const lengthError = computed(() => (tried.value ? (lengthProblem(password.value) ?? undefined) : undefined))
const repeatError = computed(() =>
  tried.value && lengthProblem(password.value) === null && password.value !== repeat.value ? 'The two passwords differ.' : undefined,
)

/** The fingerprint as two lines of sixteen pairs, as the console prints it on one. */
const fingerprint = computed(() => {
  const pairs = (session.status.value?.tlsFingerprint ?? '').split(':')
  return [pairs.slice(0, 16).join(':'), pairs.slice(16).join(':')]
})

async function submit(): Promise<void> {
  if (busy.value) {
    return
  }
  tried.value = true
  failure.value = null
  if (passwordProblem(password.value, repeat.value) !== null) {
    return
  }
  busy.value = true
  try {
    // Exactly as typed: a space at either end is part of the password.
    await router.setInitialPassword(password.value)
    await session.entered()
  } catch (error) {
    if (error instanceof RouterError && error.code === ErrorCode.FAILED_PRECONDITION) {
      // Someone else set one first. The router now has a password; this is no longer the screen.
      session.notice.value = 'A password was set a moment ago. Log in with it.'
      await session.refresh()
    } else if (error instanceof RouterError && error.code === ErrorCode.UNAVAILABLE) {
      failure.value = 'The router is not answering. Try again.'
    } else {
      failure.value = `The router refused the password: ${error instanceof Error ? error.message : 'no reason given'}.`
    }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <main class="gate">
    <div class="gate__col">
      <div class="gate__brand"><OfoWordmark :height="28" /></div>
      <h1 class="gate__title">Set the admin password</h1>
      <p class="gate__lede">This router has no password yet. Set one now: until you do, anyone on the LAN can.</p>
      <OfoCard>
        <form class="gate__form" novalidate @submit.prevent="submit">
          <OfoField label="New password" help="12 characters or more." :error="lengthError">
            <OfoInput v-model="password" type="password" autocomplete="new-password" />
          </OfoField>
          <OfoField label="Repeat password" :error="repeatError">
            <OfoInput v-model="repeat" type="password" autocomplete="new-password" />
          </OfoField>
          <p v-if="failure" class="gate__failure" role="alert">{{ failure }}</p>
          <OfoButton variant="primary" type="submit" :disabled="busy">{{ busy ? 'Setting…' : 'Set password' }}</OfoButton>
        </form>
      </OfoCard>
      <div class="fp">
        <div class="fp__label">Certificate fingerprint (SHA-256)</div>
        <div class="fp__value">
          <span>{{ fingerprint[0] }}</span>
          <span>{{ fingerprint[1] }}</span>
        </div>
        <p class="fp__help">The router's console prints the same fingerprint. If the two differ, this is not your router.</p>
      </div>
      <p class="gate__foot"><a href="/licences.txt">Licences</a></p>
    </div>
  </main>
</template>
