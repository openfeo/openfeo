<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script lang="ts">
import type { Tone } from '../tone'

/** One tab: what it is called, and beside the name a count or a status. */
export interface TabEntry {
  id: string
  label: string
  count?: string
  pill?: { text: string; tone: Tone }
}
</script>

<script setup lang="ts">
import { ref } from 'vue'

import OfoStatusPill from './OfoStatusPill.vue'

// The sub-pages of one page: a tablist whose chosen tab is the only one in the tab order.
// Left and Right move between tabs and choose as they go, round the ends; Home and End go
// to the first and the last. `panel` is the id of the element the tabs switch.
const props = defineProps<{ tabs: TabEntry[]; modelValue: string; panel: string }>()
const emit = defineEmits<{ 'update:modelValue': [id: string] }>()
const list = ref<HTMLElement | null>(null)

function go(index: number): void {
  const count = props.tabs.length
  const tab = props.tabs[((index % count) + count) % count]
  if (tab === undefined) {
    return
  }
  emit('update:modelValue', tab.id)
  // The focus goes with the choice, so the next key is heard by the tab it chose.
  const buttons = list.value?.querySelectorAll<HTMLElement>('[role="tab"]')
  buttons?.[props.tabs.indexOf(tab)]?.focus()
}

function key(event: KeyboardEvent, index: number): void {
  const to = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: props.tabs.length - 1 }[event.key]
  if (to !== undefined) {
    event.preventDefault()
    go(to)
  }
}
</script>

<template>
  <div ref="list" class="ofo-tabs" role="tablist">
    <button
      v-for="(tab, index) in tabs"
      :key="tab.id"
      type="button"
      role="tab"
      :aria-selected="tab.id === modelValue ? 'true' : 'false'"
      :aria-controls="panel"
      :tabindex="tab.id === modelValue ? 0 : -1"
      @click="emit('update:modelValue', tab.id)"
      @keydown="key($event, index)"
    >
      {{ tab.label }}
      <span v-if="tab.count" class="ofo-tabs__count">{{ tab.count }}</span>
      <OfoStatusPill v-if="tab.pill" :tone="tab.pill.tone">{{ tab.pill.text }}</OfoStatusPill>
    </button>
  </div>
</template>
