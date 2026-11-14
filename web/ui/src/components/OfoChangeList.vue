<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// What applying would alter, one line each: whose setting, what it was (struck through) and
// what it becomes.
defineProps<{ changes: { subject: string; what: string; before: string; after: string }[] }>()
</script>

<template>
  <ul class="ofo-changes">
    <li v-for="(change, index) in changes" :key="index">
      <span class="ofo-changes__key">{{ change.what ? `${change.subject} ${change.what}` : change.subject }}</span>
      <span class="ofo-changes__value">
        <template v-if="change.before"><s>{{ change.before }}</s></template>
        <template v-if="change.before && change.after"> → </template>
        <template v-if="change.after">{{ change.after }}</template>
      </span>
    </li>
  </ul>
</template>
