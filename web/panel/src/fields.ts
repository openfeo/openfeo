// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the fields of one settings page share (SPEC §8.4): which of them have been left (a
// field says what is wrong with it only once the person has left it), and what was typed in
// a field whose value is kept in another shape. A page makes one and provides it; the fields
// (`parts/SettingField.vue`) find it.

import { reactive, type InjectionKey } from 'vue'

import type { ConfigStore } from './config'
import { fromItem } from './model/path'

export { under } from './model/path'

export interface PageFields {
  /** The paths of the fields that have been left. */
  left: Set<string>
  /** What was typed in a field that holds a list, by its path, for as long as it still means that list. */
  typed: Map<string, string>
}

export const FIELDS: InjectionKey<PageFields> = Symbol("a page's fields")

export function pageFields(): PageFields {
  return { left: reactive(new Set<string>()), typed: reactive(new Map<string, string>()) }
}

/**
 * The item at `at` of the list at `list` (`lans`, `lans[0].dhcp.static`) was removed. What
 * the router refused, what had no place, which fields were left and what was typed in them
 * are all kept by a path, and a path names an item by its place: every item after the one
 * that went now has another. So what was said of the item removed and of those after it is
 * dropped, rather than said of their neighbours; the router says again what still holds when
 * it is next asked.
 */
export function forgetFrom(fields: PageFields, store: ConfigStore, list: string, at: number): void {
  const gone = (path: string) => fromItem(path, list, at)
  store.violations.value = store.violations.value.filter((violation) => !gone(violation.path))
  store.unfit.value = store.unfit.value.filter((unfit) => !gone(unfit.path))
  for (const path of [...fields.left]) {
    if (gone(path)) {
      fields.left.delete(path)
    }
  }
  for (const path of [...fields.typed.keys()]) {
    if (gone(path)) {
      fields.typed.delete(path)
    }
  }
}

/** A list as it is typed, separated by commas, into the list it means. */
export function parseList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

/**
 * The text a list's field shows: what was typed there, comma in mid-air and all, while it
 * still means the list that is kept; otherwise the list, written out.
 */
export function listText(fields: PageFields, path: string, list: string[]): string {
  const typed = fields.typed.get(path)
  const written = list.join(', ')
  return typed !== undefined && parseList(typed).join(', ') === written ? typed : written
}

/** A whole number as its field shows it: nothing for 0, where 0 means "not set". */
export function numberText(value: number): string {
  return value === 0 ? '' : String(value)
}

/** What was typed in a number's field (digits alone) as a number that fits the config's 32 bits. */
export function toNumber(text: string): number {
  return text === '' ? 0 : Math.min(Number(text), 0xffffffff)
}
