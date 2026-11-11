<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { computed } from 'vue'

import { sparkPath } from '../spark'

const props = defineProps<{
  label: string
  value: string
  unit?: string
  foot?: string
  spark?: number[]
  series?: 1 | 2
}>()

const path = computed(() => sparkPath(props.spark ?? []))
</script>

<template>
  <div class="ofo-stat">
    <div class="ofo-stat__label">{{ label }}</div>
    <div class="ofo-stat__value">{{ value }}<span v-if="unit" class="ofo-stat__unit">{{ unit }}</span></div>
    <svg v-if="spark" class="ofo-stat__spark" :class="`ofo-spark--s${series ?? 1}`" viewBox="0 0 180 28" preserveAspectRatio="none" aria-hidden="true">
      <path :d="path" />
    </svg>
    <div v-else-if="foot" class="ofo-stat__foot">{{ foot }}</div>
  </div>
</template>
