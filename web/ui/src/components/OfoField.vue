<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ label: string; help?: string; error?: string }>()
</script>

<template>
  <label class="ofo-field" :class="{ 'ofo-field--error': !!error }">
    <span class="ofo-field__label">{{ label }}</span>
    <slot />
    <span v-if="error" class="ofo-field__help" role="alert">{{ error }}</span>
    <span v-else-if="help" class="ofo-field__help">{{ help }}</span>
  </label>
</template>
