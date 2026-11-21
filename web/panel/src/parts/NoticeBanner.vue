<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoBanner, OfoButton } from '@openfeo/ui'
import { computed } from 'vue'

import type { Notice } from '../config'
import { hourMinute } from '../model/format'

// What became of a change of config, said above every page until it is dismissed or
// something newer is said: the router went back, the config was changed elsewhere, the
// router refused something, or it has moved to another address.
const props = defineProps<{ notice: Notice }>()
const emit = defineEmits<{ dismiss: [] }>()

interface Shown {
  tone: 'info' | 'danger'
  title: string | undefined
  /** What it says; the notice that the router moved says it with links, in the template. */
  said: string
}

function describe(notice: Notice): Shown {
  if (notice.kind === 'reverted') {
    const change = notice.appliedAt === null ? 'The change' : `The change applied at ${hourMinute(notice.appliedAt)}`
    const what = notice.why === 'timeout' ? `${change} was not confirmed in time.` : notice.why === 'asked' ? `${change} was reverted.` : 'The change is not in force.'
    return { tone: 'info', title: 'The router went back to how it was', said: notice.draftKept ? `${what} Your changes are still here as a draft.` : what }
  }
  if (notice.kind === 'changed-elsewhere') {
    return { tone: 'info', title: undefined, said: "The router's config was changed from another session. Your changes are kept: look through them before you apply." }
  }
  if (notice.kind === 'refused') {
    return { tone: 'danger', title: undefined, said: notice.message }
  }
  return { tone: 'info', title: 'The router is moving', said: '' }
}

const shown = computed(() => describe(props.notice))
</script>

<template>
  <OfoBanner class="notice" :tone="shown.tone" :title="shown.title">
    <span v-if="notice.kind === 'moved'" class="notice__said">
      Renew your DHCP lease, or change your static address, then open
      <a :href="`https://${notice.name}`">https://{{ notice.name }}</a
      ><template v-if="notice.address">
        or <a :href="`https://${notice.address}`">https://{{ notice.address }}</a></template
      >.
    </span>
    <span v-else class="notice__said">{{ shown.said }}</span>
    <template #action>
      <OfoButton size="sm" variant="ghost" @click="emit('dismiss')">Dismiss</OfoButton>
    </template>
  </OfoBanner>
</template>
