<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import type { Tone } from '../tone'
import OfoStatusPill from './OfoStatusPill.vue'

interface Rate {
  value: string
  unit: string
}

withDefaults(
  defineProps<{
    name: string
    role: string
    status: { word: string; tone?: Tone }
    facts: { key: string; value: string }[]
    rates?: { rx: Rate; tx: Rate } | null
    active?: boolean
  }>(),
  { rates: null, active: false },
)

/** The guideline's limit: more than this belongs on the interface's own page. */
const MOST_FACTS = 5
</script>

<template>
  <div class="ofo-iface" :class="{ 'ofo-iface--active': active }">
    <div class="ofo-iface__head">
      <span class="ofo-iface__name">{{ name }}</span>
      <span class="ofo-iface__role">{{ role }}</span>
      <OfoStatusPill :tone="status.tone">{{ status.word }}</OfoStatusPill>
    </div>
    <dl class="ofo-iface__kv">
      <template v-for="fact in facts.slice(0, MOST_FACTS)" :key="fact.key">
        <dt>{{ fact.key }}</dt>
        <dd>{{ fact.value }}</dd>
      </template>
    </dl>
    <div class="ofo-iface__rates">
      <span class="ofo-iface__rx">↓ <b>{{ rates ? rates.rx.value : '—' }}</b><template v-if="rates">&nbsp;{{ rates.rx.unit }}</template></span>
      <span class="ofo-iface__tx">↑ <b>{{ rates ? rates.tx.value : '—' }}</b><template v-if="rates">&nbsp;{{ rates.tx.unit }}</template></span>
    </div>
  </div>
</template>
