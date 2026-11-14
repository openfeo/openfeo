<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
const props = withDefaults(
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
    /** A whole number: nothing but digits gets in. */
    digits?: boolean
  }>(),
  { type: 'text', mono: false, disabled: false, invalid: false, small: false, digits: false },
)
const emit = defineEmits<{ 'update:modelValue': [value: string]; blur: [] }>()

function typed(event: Event): void {
  const input = event.target as HTMLInputElement
  if (props.digits) {
    // What is not a digit never reaches the field, so what it shows is what it holds.
    const digits = input.value.replace(/\D/g, '')
    if (digits !== input.value) {
      input.value = digits
    }
  }
  emit('update:modelValue', input.value)
}
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
    :inputmode="digits ? 'numeric' : undefined"
    @input="typed"
    @blur="emit('blur')"
  >
</template>
