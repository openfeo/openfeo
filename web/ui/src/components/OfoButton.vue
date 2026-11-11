<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { IconName } from '../icons'
import OfoIcon from './OfoIcon.vue'

withDefaults(
  defineProps<{
    variant?: 'primary' | 'ghost' | 'danger'
    size?: 'sm' | 'lg'
    type?: 'button' | 'submit'
    disabled?: boolean
    icon?: IconName
  }>(),
  { type: 'button', disabled: false },
)
</script>

<template>
  <button class="ofo-btn" :class="[variant && `ofo-btn--${variant}`, size && `ofo-btn--${size}`]" :type="type" :disabled="disabled">
    <OfoIcon v-if="icon" :name="icon" />
    <slot />
  </button>
</template>
