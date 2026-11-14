<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { nextTick } from 'vue'

const props = withDefaults(defineProps<{ modelValue: string; options: { value: string; label: string; disabled?: boolean }[]; disabled?: boolean }>(), {
  disabled: false,
})
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

async function chosen(event: Event): Promise<void> {
  const select = event.target as HTMLSelectElement
  emit('update:modelValue', select.value)
  // What is shown is the model: a choice the owner did not take is put back.
  await nextTick()
  if (select.value !== props.modelValue) {
    select.value = props.modelValue
  }
}
</script>

<template>
  <select class="ofo-select" :value="modelValue" :disabled="disabled" @change="chosen">
    <option v-for="option in options" :key="option.value" :value="option.value" :disabled="option.disabled" :selected="option.value === modelValue">
      {{ option.label }}
    </option>
  </select>
</template>
