<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { ref, watch } from 'vue'

// The settings most people never touch, one click away. It opens by itself when it is told
// to (a field inside holds something, or has a problem) and is otherwise the person's to open
// and close: closing it by hand is kept until there is something new to say.
const props = withDefaults(defineProps<{ open?: boolean }>(), { open: false })
const shown = ref(props.open)
watch(
  () => props.open,
  (open) => {
    if (open) {
      shown.value = true
    }
  },
)
</script>

<template>
  <details class="ofo-adv" :open="shown" @toggle="shown = ($event.currentTarget as HTMLDetailsElement).open">
    <summary>Advanced</summary>
    <div class="ofo-adv__grid">
      <slot />
    </div>
  </details>
</template>
