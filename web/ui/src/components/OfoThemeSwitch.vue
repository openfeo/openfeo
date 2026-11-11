<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { computed } from 'vue'

import type { Theme } from '../theme'
import OfoIcon from './OfoIcon.vue'

const props = defineProps<{ theme: Theme }>()
const emit = defineEmits<{ change: [theme: Theme] }>()

const other = computed<Theme>(() => (props.theme === 'dark' ? 'light' : 'dark'))
const label = computed(() => `Use ${other.value} theme`)
</script>

<template>
  <button class="ofo-btn ofo-btn--sm ofo-btn--ghost" type="button" :aria-label="label" :title="label" @click="emit('change', other)">
    <OfoIcon :name="theme === 'dark' ? 'sun' : 'moon'" />
  </button>
</template>
