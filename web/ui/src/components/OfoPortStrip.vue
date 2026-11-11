<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ ports: { name: string; speed: string; wan: boolean; up: boolean; title: string }[] }>()
</script>

<template>
  <div class="ofo-ports" role="list" aria-label="Physical ports">
    <div
      v-for="port in ports"
      :key="port.name"
      class="ofo-port"
      :class="{ 'ofo-port--wan': port.wan, 'ofo-port--up': port.up }"
      role="listitem"
      :title="port.title"
    >
      <div class="ofo-port__jack" />
      <span class="ofo-port__name">{{ port.name }}</span>
      <span class="ofo-port__speed">{{ port.speed }}</span>
    </div>
  </div>
</template>
