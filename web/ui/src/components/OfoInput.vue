<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
withDefaults(
  defineProps<{
    modelValue: string
    type?: string
    mono?: boolean
    autocomplete?: string
    disabled?: boolean
    placeholder?: string
    /** What is in it is wrong: the field around it says why. */
    invalid?: boolean
    /** For a table's cell. */
    small?: boolean
  }>(),
  { type: 'text', mono: false, disabled: false, invalid: false, small: false },
)
const emit = defineEmits<{ 'update:modelValue': [value: string]; blur: [] }>()
</script>

<template>
  <input
    class="ofo-input"
    :class="{ 'ofo-input--mono': mono, 'ofo-input--sm': small }"
    :type="type"
    :value="modelValue"
    :autocomplete="autocomplete"
    :placeholder="placeholder"
    :disabled="disabled"
    :aria-invalid="invalid ? 'true' : undefined"
    @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    @blur="emit('blur')"
  >
</template>
