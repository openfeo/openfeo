<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// Two to five views of the same data (Segmented.md): a chart's range, one LAN or all of them.
// It filters or rescales what is already on screen; a setting that needs Apply is a Choice,
// and whole pages are Tabs. An option may carry a count beside its label.
defineProps<{
  /** What the choice is of, for assistive tech. */
  label: string
  options: { value: string; label: string; count?: number }[]
  modelValue: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <div class="ofo-seg" role="group" :aria-label="label">
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      :aria-pressed="option.value === modelValue ? 'true' : 'false'"
      @click="emit('update:modelValue', option.value)"
    >
      {{ option.label }}<span v-if="option.count !== undefined" class="ofo-tabs__count">{{ option.count }}</span>
    </button>
  </div>
</template>
