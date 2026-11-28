<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { LogLevel, logMatches, type LogBatch, type LogLine, type Subscription } from '@openfeo/client'
import { OfoBanner, OfoButton, OfoCode, OfoInput, OfoPageHeader, OfoSegmented, OfoSkeleton } from '@openfeo/ui'
import { computed, inject, onBeforeUnmount, onMounted, ref, shallowRef, useTemplateRef, watch } from 'vue'

import { LIVE } from '../live'
import {
  appended,
  earlierThan,
  fileLine,
  fileName,
  gapped,
  joined,
  KEPT_LINES,
  levelWord,
  lineCount,
  PAGE_LINES,
  preceded,
  resumed,
  timeOfDay,
  TYPING_MS,
  writtenAt,
  type Clocks,
  type Row,
} from '../model/logs'
import { SAVE, saveText } from '../save'
import { ROUTER } from '../session'

// The Logs page (SPEC §8.4): what the router wrote down, as it writes it. The router answers
// the past by a level and a text, over the whole of what it keeps; every line it writes after
// that arrives on a subscription, at every level, and is matched here by the same rule
// (`logMatches`). The page subscribes first and asks second, so that no line falls between
// the two, and a line's number tells one that came by both roads. It holds a bounded number of
// lines, shown or waiting, and says where lines were skipped.
const live = inject(LIVE)!
const router = inject(ROUTER)!
const save = inject(SAVE, saveText)

// ---- What is asked for ----

const LEVELS = [
  { value: String(LogLevel.ERROR), label: 'Errors' },
  { value: String(LogLevel.WARN), label: 'Warnings' },
  { value: String(LogLevel.INFO), label: 'Info' },
  { value: String(LogLevel.DEBUG), label: 'Debug' },
]
/** The level shown, with everything more serious. */
const level = ref<LogLevel>(LogLevel.INFO)
/** What is in the box, as it is typed. */
const typed = ref('')
/** The text the router was last asked for: the box's, once the typing paused. */
const text = ref('')

const matches = (line: LogLine): boolean => logMatches(line, level.value, text.value)

// ---- What is shown ----

const rows = shallowRef<Row[]>([])
/** Older lines match that are not on the page. */
const earlier = ref(false)
/** The router's two clocks, as its newest answer or batch gave them: what a line's time is counted from. */
const clocks = shallowRef<Clocks | null>(null)
/** The router has answered at least once. */
const loaded = ref(false)
/** The last question was not answered. */
const failed = ref(false)
/** New lines are shown as they come; when not, they wait. */
const following = ref(true)
/** What arrived while the view was held still. */
const waiting = shallowRef<Row[]>([])
/** Lines that arrived while a question was on its way, to be joined to its answer. */
let pending: LogLine[] | null = null
/** Which question is the newest: an answer to an older one is to a filter since changed. */
let asked = 0

function newer(now: Clocks): void {
  if (clocks.value === null || now.uptimeMs >= clocks.value.uptimeMs) {
    clocks.value = now
  }
}

/** Show `next`; when lines went off the top to make room, the top says where they are. */
function show(next: Row[]): void {
  if (rows.value.length > 0 && next[0] !== rows.value[0] && lineCount(next) >= KEPT_LINES) {
    earlier.value = true
  }
  rows.value = next
}

/** Ask the router for the newest lines that match what is chosen now. */
async function ask(): Promise<void> {
  const mine = ++asked
  pending = []
  // A new question is a new view: what waited for the old one is not part of it.
  waiting.value = []
  try {
    const answer = await router.logs({ level: level.value, contains: text.value, limit: PAGE_LINES })
    if (mine !== asked) {
      return
    }
    newer({ uptimeMs: answer.uptimeMs, timeUnixMs: answer.timeUnixMs })
    rows.value = joined(answer.lines, pending.filter(matches))
    earlier.value = answer.earlier
    loaded.value = true
    failed.value = false
  } catch {
    if (mine === asked) {
      failed.value = true
    }
  } finally {
    if (mine === asked) {
      pending = null
    }
  }
}

function arrived(batch: LogBatch): void {
  newer({ uptimeMs: batch.uptimeMs, timeUnixMs: batch.timeUnixMs })
  if (pending !== null) {
    pending.push(...batch.lines)
    return
  }
  if (!loaded.value) {
    return
  }
  const wanted = batch.lines.filter(matches)
  if (following.value) {
    show(appended(rows.value, wanted))
  } else {
    waiting.value = appended(waiting.value, wanted)
  }
}

/** The router skipped lines (this reader fell behind, or the socket was away). */
function lost(): void {
  if (pending !== null) {
    // The view is being made anyway: make it afresh, from the router's own account.
    void ask()
  } else if (loaded.value && following.value) {
    rows.value = gapped(rows.value)
  } else if (loaded.value) {
    waiting.value = gapped(waiting.value)
  }
}

const held = computed(() => lineCount(waiting.value))

function follow(): void {
  show(resumed(rows.value, waiting.value))
  waiting.value = []
  following.value = true
}

function chose(value: string): void {
  level.value = Number(value) as LogLevel
  void ask()
}

let typing: ReturnType<typeof setTimeout> | undefined
watch(typed, () => {
  clearTimeout(typing)
  typing = setTimeout(() => {
    const next = typed.value.trim()
    if (next !== text.value) {
      text.value = next
      void ask()
    }
  }, TYPING_MS)
})

/** Fetch the lines before the oldest one shown. The reader is looking back: the view holds still. */
async function earlierLines(): Promise<void> {
  const mine = asked
  following.value = false
  try {
    const answer = await router.logs({
      level: level.value,
      contains: text.value,
      limit: Math.min(PAGE_LINES, KEPT_LINES - lineCount(rows.value)),
      beforeSeq: earlierThan(rows.value),
    })
    if (mine === asked) {
      rows.value = preceded(rows.value, answer.lines)
      earlier.value = answer.earlier
    }
  } catch {
    if (mine === asked) {
      failed.value = true
    }
  }
}

// ---- The whole log, as a file ----

const downloading = ref(false)
const downloadFailed = ref(false)

/** Every line the router keeps, at every level, whatever is chosen on the page: the file a bug report wants. */
async function download(): Promise<void> {
  downloading.value = true
  downloadFailed.value = false
  try {
    const pages: LogLine[][] = []
    let at: Clocks | null = null
    let beforeSeq: bigint | undefined
    for (;;) {
      const answer = await router.logs(beforeSeq === undefined ? { limit: 0 } : { limit: 0, beforeSeq })
      at ??= { uptimeMs: answer.uptimeMs, timeUnixMs: answer.timeUnixMs }
      pages.unshift(answer.lines)
      const oldest = answer.lines[0]
      if (!answer.earlier || oldest === undefined) {
        break
      }
      beforeSeq = oldest.seq
    }
    const read = at
    save(fileName(live.state.value?.system?.hostname ?? '', new Date()), pages.flat().map((line) => `${fileLine(line, read)}\n`).join(''))
  } catch {
    downloadFailed.value = true
  } finally {
    downloading.value = false
  }
}

// ---- The lines as the block draws them ----

const SKIPPED = 'Some lines were skipped here.'
const drawn = computed(() => {
  const at = clocks.value
  return rows.value.map((each) => {
    if (each.kind === 'gap') {
      return { key: each.key, parts: [{ text: SKIPPED, tone: 'dim' as const }] }
    }
    const word = levelWord(each.line.level).padEnd(6)
    const when = { text: `${at === null ? '--:--:--' : timeOfDay(writtenAt(each.line, at))} `, tone: 'dim' as const }
    // A warning and an error are coloured; nothing else is.
    const said = each.line.level === LogLevel.ERROR ? { text: word, tone: 'err' as const } : each.line.level === LogLevel.WARN ? { text: word, tone: 'warn' as const } : { text: word }
    return { key: String(each.line.seq), parts: [when, said, { text: each.line.text }] }
  })
})

// While following, the view stays at its end.
const view = useTemplateRef<{ $el: HTMLElement }>('view')
watch(
  drawn,
  () => {
    const block = view.value?.$el
    if (following.value && block !== undefined) {
      block.scrollTop = block.scrollHeight
    }
  },
  { flush: 'post' },
)

let subscription: Subscription | undefined
onMounted(() => {
  subscription = router.subscribe('logs', arrived, { onLost: lost })
  void ask()
})
onBeforeUnmount(() => {
  subscription?.close()
  clearTimeout(typing)
  // Whatever is still on its way is to a page that is gone.
  asked += 1
})
</script>

<template>
  <div class="page">
    <OfoPageHeader title="Logs" sub="What the router wrote down, as it writes it." />
    <div class="logs__tools">
      <span class="logs__show ofo-muted" aria-hidden="true">Show</span>
      <OfoSegmented label="Show" :options="LEVELS" :model-value="String(level)" @update:model-value="chose" />
      <OfoInput v-model="typed" class="logs__filter" placeholder="Filter by text" aria-label="Filter the log by text" />
      <span class="logs__actions">
        <OfoButton v-if="following" size="sm" @click="following = false">Pause</OfoButton>
        <OfoButton v-else size="sm" @click="follow">{{ held === 0 ? 'Follow' : `Follow (${held} new)` }}</OfoButton>
        <OfoButton size="sm" :disabled="downloading" @click="download">{{ downloading ? 'Downloading…' : 'Download' }}</OfoButton>
      </span>
    </div>
    <OfoBanner v-if="failed" class="logs__failed" tone="warn">
      The log could not be read from the router.
      <OfoButton size="sm" variant="ghost" @click="ask">Try again</OfoButton>
    </OfoBanner>
    <OfoBanner v-if="downloadFailed" class="logs__download-failed" tone="warn">The log could not be downloaded.</OfoBanner>
    <div v-if="!loaded" class="logs__waiting">
      <template v-if="!failed">
        <OfoSkeleton :width="80" />
        <OfoSkeleton :width="60" />
        <OfoSkeleton :width="80" />
      </template>
    </div>
    <template v-else>
      <p v-if="earlier" class="logs__earlier">
        <OfoButton v-if="lineCount(rows) < KEPT_LINES" size="sm" variant="ghost" @click="earlierLines">Earlier lines</OfoButton>
        <span v-else class="ofo-muted">Download has the rest.</span>
      </p>
      <p v-if="rows.length === 0" class="logs__none ofo-muted">No lines match.</p>
      <!-- The block is what scrolls, inside its own frame; so the keyboard can reach it. -->
      <OfoCode v-else ref="view" class="logs__view" tabindex="0" label="The router’s log" :lines="drawn" live wrap />
      <p class="logs__note ofo-muted">
        Following: new lines appear at the bottom. Pause holds the view still while you read. The router keeps about the last 8 MiB in memory, so a
        restart clears it.
      </p>
    </template>
  </div>
</template>
