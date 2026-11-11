<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoSkeleton } from '@openfeo/ui'
import { inject } from 'vue'
import { RouterView } from 'vue-router'

import { SESSION } from './session'

const { screen, unreachable } = inject(SESSION)!
</script>

<template>
  <main v-if="unreachable" class="gate">
    <p class="gate__col gate__lede" role="status">The router is not answering. Retrying.</p>
  </main>
  <main v-else-if="screen === null" class="gate" aria-busy="true">
    <div class="gate__col"><OfoSkeleton size="lg" :width="40" /></div>
  </main>
  <RouterView v-else />
</template>
