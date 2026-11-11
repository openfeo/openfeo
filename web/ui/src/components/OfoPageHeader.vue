<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ title: string; sub?: string }>()
</script>

<template>
  <header class="ofo-pagehead">
    <div>
      <h1 class="ofo-pagehead__title">{{ title }}</h1>
      <p v-if="sub" class="ofo-pagehead__sub">{{ sub }}</p>
    </div>
    <div v-if="$slots.actions" class="ofo-pagehead__actions">
      <slot name="actions" />
    </div>
  </header>
</template>
