<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoInput } from '@openfeo/ui'

import { useSetting } from './setting'

// One cell of a table edited in place: a field without a label of its own (the column has
// it), and under it the same one line a labelled field has (see `setting.ts`).
const props = withDefaults(
  defineProps<{
    path: string
    value: string
    was?: string | undefined
    note?: string | undefined
    problem?: string | null | undefined
    error?: string | undefined
    mono?: boolean
    placeholder?: string | undefined
    /** Shown and not to be changed. */
    fixed?: boolean
  }>(),
  { mono: false, fixed: false },
)
const emit = defineEmits<{ update: [value: string]; left: [] }>()
const { store, wrong, typed, said, changed, left } = useSetting(props, emit)
</script>

<template>
  <td :class="{ 'ofo-field--error': !!wrong }" :data-typed="typed ? '' : undefined">
    <OfoInput
      :model-value="value"
      :mono="mono"
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
