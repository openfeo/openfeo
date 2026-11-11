<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { IconName } from '../icons'
import OfoIcon from './OfoIcon.vue'

defineProps<{ tone: 'info' | 'ok' | 'warn' | 'danger'; title?: string }>()

const ICON: Record<'info' | 'ok' | 'warn' | 'danger', IconName> = {
  info: 'info',
  ok: 'circle-check',
  warn: 'triangle-alert',
  danger: 'circle-alert',
}
</script>

<template>
  <div class="ofo-banner" :class="`ofo-banner--${tone}`" :role="tone === 'danger' ? 'alert' : 'status'">
    <OfoIcon class="ofo-banner__icon" :name="ICON[tone]" />
    <div class="ofo-banner__body">
      <div v-if="title" class="ofo-banner__title">{{ title }}</div>
      <slot />
    </div>
    <slot name="action" />
  </div>
</template>
