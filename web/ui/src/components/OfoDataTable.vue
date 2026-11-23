<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
withDefaults(
  defineProps<{
    columns: { key: string; label: string; mono?: boolean; num?: boolean }[]
    rows: Record<string, string>[]
    head?: boolean
    /** The field of a row that tells it from every other, so that a row keeps its place as others come and go. */
    rowKey?: string
    /** A class for a row: how one is marked out. */
    rowClass?: (row: Record<string, string>) => string | undefined
  }>(),
  { head: true },
)
</script>

<template>
  <div class="ofo-table-wrap">
    <table class="ofo-table">
      <thead v-if="head">
        <tr>
          <th v-for="column in columns" :key="column.key" :class="{ 'ofo-num': column.num }">{{ column.label }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(row, at) in rows" :key="rowKey === undefined ? at : (row[rowKey] ?? at)" :class="rowClass?.(row)">
          <td v-for="column in columns" :key="column.key" :class="{ 'ofo-mono': column.mono, 'ofo-num': column.num }">
            <slot :name="`cell-${column.key}`" :row="row" :value="row[column.key] ?? ''">{{ row[column.key] }}</slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
