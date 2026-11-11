<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
defineProps<{ host: string; meta: string }>()
</script>

<template>
  <div class="ofo-shell">
    <!-- The nav is the shell's own child: the stylesheet's narrow layout selects it so. -->
    <slot name="nav" />
    <div class="ofo-shell__main">
      <div class="ofo-topbar">
        <span class="ofo-topbar__host">{{ host }}</span>
        <span class="ofo-topbar__meta">{{ meta }}</span>
        <div class="ofo-topbar__end">
          <slot name="actions" />
        </div>
      </div>
      <main class="ofo-shell__content">
        <slot />
      </main>
    </div>
  </div>
</template>
