<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
// Lines in mono on the sunken surface (CodeBlock.md): an install command, a config snippet,
// the panel's log. The four tones are the whole palette: dim for a time or a comment, and ok,
// warn and err for a level. Text is text: a part is drawn as its characters, never as markup.
defineProps<{
  lines: { key: string; parts: { text: string; tone?: 'dim' | 'ok' | 'warn' | 'err' }[] }[]
  /** What the block holds, for assistive tech. */
  label: string
  /** Lines are added as they happen: announced politely, as a log. */
  live?: boolean
  /** A long line wraps instead of running off to the right. */
  wrap?: boolean
}>()
</script>

<!-- A pre keeps every character between its tags, so the template is one line: what is
     between the lines is the newline written out, and nothing else. -->
<template>
  <pre class="ofo-code" :class="{ 'ofo-code--wrap': wrap }" :role="live ? 'log' : 'group'" :aria-live="live ? 'polite' : undefined" :aria-label="label"><template v-for="line in lines" :key="line.key"><template v-for="(part, n) in line.parts" :key="n"><span v-if="part.tone" :class="`ofo-code__${part.tone}`">{{ part.text }}</span><template v-else>{{ part.text }}</template></template>{{ '\n' }}</template></pre>
</template>
