<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoSkeleton } from '@openfeo/ui'
import { computed, inject } from 'vue'
import { RouterView, useRoute } from 'vue-router'

import { correction } from './routes'
import { SESSION } from './session'

const { screen, unreachable } = inject(SESSION)!
const route = useRoute()

// A page is shown only once its address is the screen's. On a first visit the address is
// known before the screen is, and when the screen changes the address follows a moment later:
// in between, the page at the old address must not be set up for a router it does not fit
// (the dashboard, with no session to subscribe on).
const agrees = computed(() => screen.value !== null && correction(screen.value, route.path) === null)
</script>

<template>
  <main v-if="unreachable" class="gate">
    <p class="gate__col gate__lede" role="status">The router is not answering. Retrying.</p>
  </main>
  <main v-else-if="!agrees" class="gate" aria-busy="true">
    <div class="gate__col"><OfoSkeleton size="lg" :width="40" /></div>
  </main>
  <RouterView v-else />
</template>
