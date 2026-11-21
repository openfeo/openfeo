<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// Choices that belong together, under the question they answer.
defineProps<{ legend: string }>()
</script>

<template>
  <fieldset class="ofo-choices">
    <legend class="ofo-field__label">{{ legend }}</legend>
    <div class="ofo-row">
      <slot />
    </div>
  </fieldset>
</template>
