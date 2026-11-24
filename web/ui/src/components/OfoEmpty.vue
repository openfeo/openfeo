<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// What a list or a table shows before it has anything in it (EmptyState.md): the lattice
// mark, what is missing, one line with a concrete example, and the action that fixes it in
// the slot. Not for an error (a Banner), nor for a filter that found nothing (said in the
// table).
defineProps<{ title: string; text?: string }>()

/** The mark's 3×3 face: iron at the corners and the centre, oxygen between. */
const FACE = [10, 32, 54].flatMap((cx, column) => [10, 32, 54].map((cy, row) => ({ cx, cy, iron: (column + row) % 2 === 0 })))
</script>

<template>
  <div class="ofo-empty">
    <svg class="ofo-empty__art" viewBox="0 0 64 64" aria-hidden="true">
      <circle v-for="dot in FACE" :key="`${dot.cx}-${dot.cy}`" :class="dot.iron ? 'fe' : 'o'" :cx="dot.cx" :cy="dot.cy" :r="dot.iron ? 8 : 4.5" />
    </svg>
    <p class="ofo-empty__title">{{ title }}</p>
    <p v-if="text" class="ofo-empty__text">{{ text }}</p>
    <slot />
  </div>
</template>
