<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ size?: 'lg'; width?: 40 | 60 | 80 }>()
</script>

<template>
  <span class="ofo-skel" :class="[size === 'lg' && 'ofo-skel--lg', width && `ofo-skel--w${width}`]" aria-hidden="true" />
</template>
