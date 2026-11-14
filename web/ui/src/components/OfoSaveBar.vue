<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import OfoButton from './OfoButton.vue'

// What a settings page has changed and not yet applied. It is there only while there is
// something to apply. `held` is why an apply is not offered just now, shown in its place.
withDefaults(defineProps<{ count: number; busy?: boolean; held?: string }>(), { busy: false })
const emit = defineEmits<{ discard: []; apply: [] }>()
</script>

<template>
  <div v-if="count > 0" class="ofo-savebar">
    <span><strong>{{ count }}</strong> {{ count === 1 ? 'change' : 'changes' }} not applied yet</span>
    <div class="ofo-savebar__actions">
      <span v-if="held" class="ofo-savebar__held">{{ held }}</span>
      <OfoButton variant="ghost" :disabled="busy" @click="emit('discard')">Discard</OfoButton>
      <OfoButton v-if="!held" variant="primary" :disabled="busy" @click="emit('apply')">Apply changes</OfoButton>
    </div>
  </div>
</template>
