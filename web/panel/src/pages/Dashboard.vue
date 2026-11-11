<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoButton } from '@openfeo/ui'
import { inject } from 'vue'

import { ROUTER } from '../session'

const router = inject(ROUTER)!
</script>

<template>
  <main class="gate">
    <div class="gate__col">
      <h1 class="gate__title gate__title--small">Dashboard</h1>
      <OfoButton icon="log-out" @click="router.logout()">Log out</OfoButton>
    </div>
  </main>
</template>
