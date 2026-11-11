<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { IconName } from '../icons'
import OfoIcon from './OfoIcon.vue'
import OfoWordmark from './OfoWordmark.vue'

export type NavEntry =
  | { kind: 'item'; label: string; icon: IconName; to: string; current: boolean }
  | { kind: 'group'; label: string }

defineProps<{ entries: NavEntry[] }>()
// An item is a real link, so it can be opened in a new tab; a plain click is taken over and
// handed to whoever owns the routes.
const emit = defineEmits<{ navigate: [to: string] }>()
</script>

<template>
  <nav class="ofo-nav" aria-label="Pages">
    <div class="ofo-nav__brand">
      <span class="ofo-nav__word"><OfoWordmark /></span>
      <span class="ofo-nav__mark"><OfoWordmark variant="mark" /></span>
    </div>
    <template v-for="entry in entries" :key="entry.kind + entry.label">
      <div v-if="entry.kind === 'group'" class="ofo-nav__group">{{ entry.label }}</div>
      <a v-else class="ofo-nav__item" :href="entry.to" :aria-current="entry.current ? 'page' : undefined" @click.prevent="emit('navigate', entry.to)">
        <OfoIcon :name="entry.icon" />
        <span class="ofo-nav__label">{{ entry.label }}</span>
      </a>
    </template>
  </nav>
</template>
