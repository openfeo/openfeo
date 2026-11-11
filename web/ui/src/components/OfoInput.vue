<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
withDefaults(
  defineProps<{ modelValue: string; type?: string; mono?: boolean; autocomplete?: string; disabled?: boolean }>(),
  { type: 'text', mono: false, disabled: false },
)
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <input
    class="ofo-input"
    :class="{ 'ofo-input--mono': mono }"
    :type="type"
    :value="modelValue"
    :autocomplete="autocomplete"
    :disabled="disabled"
    @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  >
</template>
