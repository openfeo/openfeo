<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// A checkbox (its model is whether it is ticked) or a radio button (its model is the value of
// whichever of its group is chosen). `bare` is a tick with no text beside it, where the row
// and the column it stands in already say what it is (a grid): its label is then given to
// assistive technology and not shown.
const props = withDefaults(
  defineProps<{
    modelValue: boolean | string
    type?: 'checkbox' | 'radio'
    value?: string
    name?: string
    label: string
    hint?: string
    disabled?: boolean
    bare?: boolean
  }>(),
  { type: 'checkbox', disabled: false, bare: false },
)
const emit = defineEmits<{ 'update:modelValue': [value: boolean | string] }>()

function changed(event: Event): void {
  const input = event.target as HTMLInputElement
  if (props.type === 'radio') {
    if (input.checked) {
      emit('update:modelValue', props.value ?? '')
    }
  } else {
    emit('update:modelValue', input.checked)
  }
}
</script>

<template>
  <label class="ofo-choice" :class="{ 'ofo-choice--bare': bare }">
    <input
      :type="type"
      :name="name"
      :value="value"
      :checked="type === 'radio' ? modelValue === value : modelValue === true"
      :disabled="disabled"
      :aria-label="bare ? label : undefined"
      @change="changed"
    >
    <span v-if="!bare">{{ label }}<span v-if="hint" class="ofo-choice__hint">{{ hint }}</span></span>
  </label>
</template>
