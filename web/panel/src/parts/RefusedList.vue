<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoBanner } from '@openfeo/ui'

// What the router refused that has no field to be shown at: each by its path, as the router
// writes one, and in the router's own words. Nothing it refuses is ever silent.
defineProps<{ violations: { path: string; message: string }[] }>()
</script>

<template>
  <OfoBanner v-if="violations.length > 0" class="refused" tone="danger" title="The router does not accept this">
    <ul class="said__list">
      <li v-for="violation in violations" :key="violation.path + violation.message">
        <code class="ofo-mono">{{ violation.path }}</code>: {{ violation.message }}
      </li>
    </ul>
  </OfoBanner>
</template>
