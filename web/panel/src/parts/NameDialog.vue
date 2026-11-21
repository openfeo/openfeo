<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoButton, OfoDialog, OfoField, OfoInput } from '@openfeo/ui'
import { ref } from 'vue'

import { nameProblem } from '../model/wan'

// The name of a new WAN or LAN. It is asked for once, here, because it cannot be changed
// afterwards: it becomes part of an interface's name, and everything refers to it.
const props = defineProps<{ title: string; taken: string[]; longest: number }>()
const emit = defineEmits<{ name: [name: string]; cancel: [] }>()
const name = ref('')
const problem = ref<string | null>(null)

function add(): void {
  problem.value = nameProblem(name.value, props.taken, props.longest)
  if (problem.value === null) {
    emit('name', name.value)
  }
}
</script>

<template>
  <OfoDialog :title="title" role="dialog" @cancel="emit('cancel')">
    <OfoField label="Name" help="Lower-case letters, digits, - and _. It cannot be changed afterwards." :error="problem ?? undefined">
      <OfoInput v-model="name" mono autocomplete="off" :invalid="problem !== null" @keydown.enter.prevent="add" />
    </OfoField>
    <template #foot>
      <OfoButton variant="ghost" @click="emit('cancel')">Cancel</OfoButton>
      <OfoButton variant="primary" @click="add">Add</OfoButton>
    </template>
  </OfoDialog>
</template>
