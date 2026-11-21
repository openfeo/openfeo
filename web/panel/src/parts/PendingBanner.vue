<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { PendingConfig } from '@openfeo/client'
import { OfoAdvanced, OfoBanner, OfoButton } from '@openfeo/ui'
import { computed } from 'vue'

import { effectSentence } from '../model/effects'
import { countdown, hourMinute } from '../model/format'

// A change of config that is waiting to be confirmed (SPEC §5.5, §8.4), said on every page
// of every session: when it was applied, how long is left, Confirm and Revert now, and the
// router's own account of what it did. The time left is counted on the router's clock (its
// uptime, which the change is stamped with), never on the browser's: only "applied at" is
// told by the clock the person is looking at.
const props = defineProps<{
  pending: PendingConfig
  /** How long the router has been up by now, in milliseconds; not known until it has said. */
  sinceBootMs: number | undefined
  now: Date
  /** A confirm or a revert is under way. */
  busy: boolean
}>()
const emit = defineEmits<{ confirm: []; revert: [] }>()

/** How long is left, and when it was applied; neither without the router's uptime. */
const timing = computed(() =>
  props.sinceBootMs === undefined
    ? undefined
    : {
        left: countdown(Number(props.pending.revertsUptimeMs) - props.sinceBootMs),
        applied: hourMinute(new Date(props.now.getTime() - Math.max(0, props.sinceBootMs - Number(props.pending.appliedUptimeMs)))),
      },
)
</script>

<template>
  <!-- A group, not a status: what it says changes every second, and is not to be read out every second. -->
  <OfoBanner tone="warn" title="A change is waiting for you to confirm" role="group" aria-label="A change of config waiting to be confirmed">
    <span v-if="timing" class="pending__said">
      Applied at {{ timing.applied }}. The router goes back to how it was in <strong class="ofo-mono" role="timer">{{ timing.left }}</strong> unless you confirm.
    </span>
    <span v-else class="pending__said">The router goes back to how it was unless you confirm.</span>
    <OfoAdvanced summary="What changed">
      <ul v-if="pending.effects.length > 0" class="ofo-span-2 said__list">
        <li v-for="(effect, at) in pending.effects" :key="at">{{ effectSentence(effect) }}</li>
      </ul>
      <p v-else class="ofo-span-2 said__line">Nothing was interrupted.</p>
    </OfoAdvanced>
    <template #action>
      <div class="ofo-row">
        <OfoButton size="sm" variant="ghost" :disabled="busy" @click="emit('revert')">Revert now</OfoButton>
        <OfoButton size="sm" variant="primary" :disabled="busy" @click="emit('confirm')">Confirm</OfoButton>
      </div>
    </template>
  </OfoBanner>
</template>
