<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { Tone } from '../tone'

// The word is the slot: a status is never colour alone.
defineProps<{ tone?: Tone }>()
</script>

<template>
  <span class="ofo-pill" :class="tone && `ofo-pill--${tone}`"><slot /></span>
</template>
