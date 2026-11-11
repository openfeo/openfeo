<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ title?: string }>()
</script>

<template>
  <section class="ofo-card">
    <div v-if="title || $slots.actions" class="ofo-card__head">
      <h2 class="ofo-card__title">{{ title }}</h2>
      <slot name="actions" />
    </div>
    <slot />
  </section>
</template>
