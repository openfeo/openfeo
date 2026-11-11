<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { OfoWordmark } from '@openfeo/ui'

// A config file that is not even TOML (SPEC §9): no password can be read from it and none may
// be set over it, so the panel has nothing to offer. It says so; the console is the way back.
</script>

<template>
  <main class="gate">
    <div class="gate__col">
      <div class="gate__brand"><OfoWordmark :height="28" /></div>
      <h1 class="gate__title gate__title--small">The config file cannot be read</h1>
      <p class="gate__lede">
        <code class="ofo-mono">/state/config.toml</code> is not valid TOML. The router is running on first-boot defaults and nobody can log
        in until the file is fixed or removed from the console.
      </p>
    </div>
  </main>
</template>
