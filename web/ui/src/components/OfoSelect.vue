<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
withDefaults(defineProps<{ modelValue: string; options: { value: string; label: string; disabled?: boolean }[]; disabled?: boolean }>(), {
  disabled: false,
})
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <select class="ofo-select" :value="modelValue" :disabled="disabled" @change="emit('update:modelValue', ($event.target as HTMLSelectElement).value)">
    <option v-for="option in options" :key="option.value" :value="option.value" :disabled="option.disabled" :selected="option.value === modelValue">
      {{ option.label }}
    </option>
  </select>
</template>
