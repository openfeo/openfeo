<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { across, areaPath, BOTTOM, ceiling, height, HEIGHT, levels, linePath, plotWidth, TOP, type ChartMark, type ChartPoint, type ChartTick } from '../chart'

// Download and upload over time (ThroughputChart.md). It is given numbers and draws them:
// unbroken runs of points, a gap between two runs left as a gap, straight segments, a scale
// whose top is a round value so that it does not move with every sample, the values of the
// moment in the legend, and dashed marks with a short label. The range choice goes in the
// `range` slot, at the head's end.
const props = defineProps<{
  title: string
  /** What the picture is, for a reader who cannot see it. */
  label: string
  /** Unbroken runs of points; a gap lies between two runs. */
  runs: ChartPoint[][]
  from: number
  to: number
  /** The unit of every value, said once in the legend. */
  unit: string
  /** The values of the moment, as text. */
  now: { rx: string; tx: string }
  marks?: ChartMark[]
  ticks?: ChartTick[]
  /** Said under the head when there is something to say of the picture as a whole. */
  note?: string
}>()

// The box is as wide as the picture is drawn, so that nothing in it is stretched: a fixed box
// scaled to the element's width would widen the labels and the upright strokes with it. (On
// a narrow screen the stylesheet keeps the picture 720 wide and lets its frame scroll, so it
// is the picture that is measured, not the frame.)
const picture = ref<SVGSVGElement | null>(null)
const width = ref(720)
let watching: ResizeObserver | undefined
function measure(): void {
  const measured = Math.round(picture.value?.getBoundingClientRect().width ?? 0)
  if (measured > 0) {
    width.value = measured
  }
}
onMounted(() => {
  measure()
  if (typeof ResizeObserver !== 'undefined' && picture.value !== null) {
    watching = new ResizeObserver(measure)
    watching.observe(picture.value)
  }
})
onBeforeUnmount(() => watching?.disconnect())

const top = computed(() => ceiling(Math.max(0, ...props.runs.flatMap((run) => run.flatMap((point) => [point.rx, point.tx])))))
const grid = computed(() => levels(top.value).map((level) => ({ level, y: height(level, top.value) })))
const edge = computed(() => plotWidth(width.value))
const path = (series: 'rx' | 'tx') => linePath(props.runs, series, props.from, props.to, top.value, width.value)
const area = computed(() => areaPath(props.runs, 'rx', props.from, props.to, top.value, width.value))
const placed = <T extends { at: number }>(things: T[] | undefined) =>
  (things ?? []).flatMap((thing) => {
    const x = across(thing.at, props.from, props.to, width.value)
    return x === undefined ? [] : [{ ...thing, x }]
  })
const events = computed(() => placed(props.marks))
const along = computed(() => placed(props.ticks))
</script>

<template>
  <div class="ofo-chart">
    <div class="ofo-chart__head">
      <h2 class="ofo-card__title">{{ title }}</h2>
      <div class="ofo-chart__legend">
        <span class="ofo-chart__key ofo-chart__key--rx">Download <b>{{ now.rx }}</b> {{ unit }}</span>
        <span class="ofo-chart__key ofo-chart__key--tx">Upload <b>{{ now.tx }}</b> {{ unit }}</span>
      </div>
      <slot name="range" />
    </div>
    <p v-if="note" class="ofo-chart__note">{{ note }}</p>
    <div class="ofo-chart__plot">
      <svg ref="picture" :viewBox="`0 0 ${width} ${HEIGHT}`" role="img" :aria-label="label">
        <g class="grid">
          <line v-for="line in grid" :key="line.level" x1="0" :x2="edge" :y1="line.y" :y2="line.y" />
        </g>
        <g class="axis">
          <text v-for="line in grid" :key="line.level" class="ofo-chart__level" :x="edge + 6" :y="line.y" dominant-baseline="middle">{{ line.level }}</text>
          <text v-for="tick in along" :key="tick.at" class="ofo-chart__tick" :x="tick.x" :y="BOTTOM + 18" text-anchor="middle">{{ tick.label }}</text>
        </g>
        <path class="area rx" :d="area" />
        <path class="line rx" :d="path('rx')" />
        <path class="line tx" :d="path('tx')" />
        <g v-for="event in events" :key="event.at" class="event">
          <line :x1="event.x" :x2="event.x" :y1="TOP" :y2="BOTTOM" />
          <text :x="event.x + 4" :y="TOP + 10">{{ event.label }}</text>
        </g>
      </svg>
    </div>
  </div>
</template>
