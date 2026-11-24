<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoInput, OfoSelect } from '@openfeo/ui'

import { useSetting } from './setting'

// One cell of a table edited in place: a field without a label of its own (the column has
// it), and under it the same one line a labelled field has (see `setting.ts`). With `options`
// it is a choice, not a text.
const props = withDefaults(
  defineProps<{
    path: string
    value: string
    was?: string | undefined
    note?: string | undefined
    problem?: string | null | undefined
    error?: string | undefined
    /** A choice, not a text. */
    options?: { value: string; label: string }[] | undefined
    mono?: boolean
    /** A whole number: nothing but digits is let in. */
    digits?: boolean
    placeholder?: string | undefined
    /** Shown and not to be changed. */
    fixed?: boolean
  }>(),
  { mono: false, digits: false, fixed: false },
)
const emit = defineEmits<{ update: [value: string]; left: [] }>()
const { store, wrong, typed, said, changed, left } = useSetting(props, emit)
</script>

<template>
  <td :class="{ 'ofo-field--error': !!wrong }" :data-typed="typed ? '' : undefined">
    <OfoSelect v-if="options" :model-value="value" :options="options" :disabled="fixed || store.readOnly.value !== null" small @update:model-value="changed" />
    <OfoInput
      v-else
      :model-value="value"
      :mono="mono"
      :digits="digits"
      :placeholder="placeholder"
      :invalid="!!wrong"
      :disabled="fixed || store.readOnly.value !== null"
      small
      @update:model-value="changed"
      @blur="left"
    />
    <span v-if="wrong" class="ofo-field__help" role="alert">{{ wrong }}</span>
    <span v-else-if="said" class="ofo-field__help">{{ said }}</span>
  </td>
</template>
