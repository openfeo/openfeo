<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoField, OfoInput, OfoSelect } from '@openfeo/ui'

import { useSetting } from './setting'

// One field of a settings page (SPEC §8.4): its label, its control, and under it one line
// (see `setting.ts` for what the line says).
const props = withDefaults(
  defineProps<{
    label: string
    path: string
    value: string
    was?: string | undefined
    means?: string | undefined
    help?: string | undefined
    note?: string | undefined
    problem?: string | null | undefined
    error?: string | undefined
    /** A choice, not a text. */
    options?: { value: string; label: string; disabled?: boolean }[] | undefined
    type?: string
    mono?: boolean
    digits?: boolean
    placeholder?: string | undefined
    autocomplete?: string | undefined
    span?: boolean
  }>(),
  { type: 'text', mono: false, digits: false, span: false },
)
const emit = defineEmits<{ update: [value: string]; left: [] }>()
const { store, wrong, typed, said, changed, left } = useSetting(props, emit)
</script>

<template>
  <OfoField :label="label" :help="said" :error="wrong" :class="{ 'ofo-span-2': span }" :data-typed="typed ? '' : undefined">
    <OfoSelect v-if="options" :model-value="value" :options="options" :disabled="store.readOnly.value !== null" @update:model-value="changed" />
    <OfoInput
      v-else
      :model-value="value"
      :type="type"
      :mono="mono"
      :digits="digits"
      :placeholder="placeholder"
      :autocomplete="autocomplete"
      :invalid="!!wrong"
      :disabled="store.readOnly.value !== null"
      @update:model-value="changed"
      @blur="left"
    />
  </OfoField>
</template>
