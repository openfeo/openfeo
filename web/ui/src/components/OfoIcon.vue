<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { ICONS, type IconName } from '../icons'

// The shapes are constants taken from Lucide's files when the page is built, never data: this
// is the one component that sets markup directly (the lint rule is lifted for this file alone).
defineProps<{ name: IconName }>()
</script>

<template>
  <svg class="ofo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" v-html="ICONS[name]" />
</template>
