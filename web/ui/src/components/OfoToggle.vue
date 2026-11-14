<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// A feature on or off, taking effect when the page's changes are applied. The label names
// the feature, not the action.
withDefaults(defineProps<{ modelValue: boolean; label: string; disabled?: boolean }>(), { disabled: false })
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
</script>

<template>
  <label class="ofo-toggle">
    <input type="checkbox" :checked="modelValue" :disabled="disabled" @change="emit('update:modelValue', ($event.target as HTMLInputElement).checked)">
    <span class="ofo-toggle__track" />
    {{ label }}
  </label>
</template>
