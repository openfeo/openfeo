<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import markOnLight from '../../logos/openfeo-mark-light.svg'
import markOnDark from '../../logos/openfeo-mark.svg'
import wordmarkOnDark from '../../logos/openfeo-wordmark-on-dark.svg'
import wordmarkOnLight from '../../logos/openfeo-wordmark-on-light.svg'

// The logo files have fixed colours, so both are offered and the stylesheet shows the one for
// the ground (the Brand guideline).
withDefaults(defineProps<{ variant?: 'wordmark' | 'mark'; height?: number }>(), { variant: 'wordmark', height: 24 })
</script>

<template>
  <span>
    <img class="ofo-on-dark" :src="variant === 'mark' ? markOnDark : wordmarkOnDark" alt="OpenFeO" :height="height">
    <img class="ofo-on-light" :src="variant === 'mark' ? markOnLight : wordmarkOnLight" alt="OpenFeO" :height="height">
  </span>
</template>
