<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoBanner, OfoButton, OfoChangeList, OfoChoice, OfoDialog } from '@openfeo/ui'
import { computed, ref } from 'vue'

import type { Review } from '../config'
import { effectSentence } from '../model/effects'
import { durationWords } from '../model/format'

// The one dialog before an apply (SPEC §8.4): every change, what the router says it
// interrupts, where to come back to when it moves whoever is asking, and how long there is
// to confirm. The way to apply with no going back is chosen here, each time: the box is
// clear whenever the dialog opens.
const props = defineProps<{
  review: Review
  /** The router's hostname, for the question. */
  host: string
  /** Its full name, to come back to. */
  name: string
  /** The window the router gives, in seconds. */
  confirmSecs: number
  /** The apply is under way. */
  busy: boolean
}>()
const emit = defineEmits<{ apply: [immediate: boolean]; cancel: [] }>()
const immediate = ref(false)

const count = computed(() => props.review.changes.length)
const moves = computed(() => {
  const caller = props.review.caller
  if (caller === undefined || !(caller.connectionDrops || caller.lanChanges)) {
    return undefined
  }
  return {
    title: caller.connectionDrops ? 'This moves the address you are using to reach the router' : 'This changes the subnet your device is on',
    address: caller.routerAfter,
  }
})
</script>

<template>
  <OfoDialog class="apply" :title="`Apply ${count} ${count === 1 ? 'change' : 'changes'} to ${host}?`" @cancel="busy || emit('cancel')">
    <OfoChangeList :changes="review.changes" />

    <p class="ofo-field__label apply__head">What this interrupts</p>
    <ul v-if="review.effects.length > 0" class="ofo-dialog__text apply__effects">
      <li v-for="(effect, at) in review.effects" :key="at">{{ effectSentence(effect) }}</li>
    </ul>
    <p v-else class="ofo-dialog__text">Nothing is interrupted.</p>

    <OfoBanner v-if="moves" tone="warn" :title="moves.title">
      Renew your DHCP lease, or change your static address, then come back to
      <code class="ofo-mono">https://{{ name }}</code
      ><template v-if="moves.address">
        or <code class="ofo-mono">https://{{ moves.address }}</code></template
      >.
    </OfoBanner>

    <p v-if="immediate" class="ofo-dialog__text apply__window">Nothing will undo this change by itself.</p>
    <p v-else class="ofo-dialog__text apply__window">
      You have <strong>{{ durationWords(confirmSecs) }}</strong> to confirm once it is applied. If you don't, the router goes back to how it was.
    </p>
    <OfoChoice
      v-model="immediate"
      class="ofo-dialog__confirm"
      label="Apply immediately, no confirmation countdown"
      hint="The change stays, whether or not you can reach the router afterwards."
      :disabled="busy"
    />

    <template #foot>
      <OfoButton variant="ghost" autofocus :disabled="busy" @click="emit('cancel')">Cancel</OfoButton>
      <OfoButton :variant="immediate ? 'danger' : 'primary'" :disabled="busy" @click="emit('apply', immediate)">
        {{ immediate ? 'Apply immediately' : 'Apply changes' }}
      </OfoButton>
    </template>
  </OfoDialog>
</template>
