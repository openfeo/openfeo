<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoField, OfoInput, OfoSelect } from '@openfeo/ui'
import { computed, inject } from 'vue'

import { CONFIG } from '../config'
import { FIELDS, under } from '../fields'

// One field of a settings page (SPEC §8.4): its label, its control, and under it one line.
// The line is the help, then what the field was when it differs from the router's config;
// or, in its place, what is wrong: something the page can tell once the field has been left,
// or what the router said of the field's path when it last looked at the draft.
const props = withDefaults(
  defineProps<{
    label: string
    /** Where the field is in the config, as the router writes a path: `wans[0].vlan`. */
    path: string
    value: string
    /** What the field holds in the router's config; left out when there is nothing to compare with. */
    was?: string | undefined
    /** What `value` means, when what is shown is not how it is kept: compared with `was`. */
    means?: string | undefined
    help?: string | undefined
    /** Said after what it was: `Moved with the subnet.` */
    note?: string | undefined
    /** What is wrong with it as typed, said once the field has been left. */
    problem?: string | null | undefined
    /** What is wrong with it, said at once. */
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
const emit = defineEmits<{ update: [value: string] }>()
const store = inject(CONFIG)!
const fields = inject(FIELDS)!

const wrong = computed(() => {
  if (props.error !== undefined) {
    return props.error
  }
  const typed = fields.left.has(props.path) ? props.problem : null
  return typed ?? store.problemAt(props.path)
})
const said = computed(() => {
  const differs = props.was !== undefined && props.was !== (props.means ?? props.value)
  const was = !differs ? '' : props.was === '' ? 'Was empty.' : `Was ${props.was}.`
  return [props.help, was, differs ? props.note : ''].filter((part) => part !== undefined && part !== '').join(' ')
})

function changed(value: string): void {
  // What the router said of this field was said of what it held then.
  if (store.problemAt(props.path) !== undefined) {
    store.violations.value = store.violations.value.filter((violation) => !under(violation.path, props.path))
  }
  emit('update', value)
}
</script>

<template>
  <OfoField :label="label" :help="said" :error="wrong" :class="{ 'ofo-span-2': span }">
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
      @blur="fields.left.add(path)"
    />
  </OfoField>
</template>
