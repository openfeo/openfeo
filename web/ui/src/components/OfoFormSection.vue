<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// One row of a settings page: what the settings are and what they control on the left, the
// fields on the right. `plain` holds something that is not a grid of fields (a table).
withDefaults(defineProps<{ title: string; text: string; plain?: boolean }>(), { plain: false })
</script>

<template>
  <div class="ofo-formsec">
    <div>
      <h2 class="ofo-formsec__title">{{ title }}</h2>
      <p class="ofo-formsec__text">{{ text }}</p>
    </div>
    <div :class="{ 'ofo-formsec__fields': !plain }">
      <slot />
    </div>
  </div>
</template>
