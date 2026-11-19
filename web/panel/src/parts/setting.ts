// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What a field of a settings page says under itself, whichever shape it has (a labelled
// field, a table's cell): the help, then what it was when it differs from the router's
// config; or, in their place, what is wrong. Something the page can tell is said once the
// field has been left; what the router said of the field's path is said until the field is
// changed, since it was said of what the field held then.

import { computed, inject, type ComputedRef } from 'vue'

import { CONFIG, type ConfigStore } from '../config'
import { FIELDS, under } from '../fields'

export interface SettingProps {
  /** Where the field is in the config, as the router writes a path: `wans[0].vlan`. */
  path: string
  value: string
  /** What the field holds in the router's config; left out when there is nothing to compare with. */
  was?: string | undefined
  /** What `value` means, when what is shown is not how it is kept: compared with `was`. */
  means?: string | undefined
  help?: string | undefined
  /** Said after what it was: `Moved with the subnet.` */
  note?: string | undefined
  /** What is wrong with it as typed, said once the field has been left. */
  problem?: string | null | undefined
  /** What is wrong with it, said at once. */
  error?: string | undefined
}

export interface Setting {
  store: ConfigStore
  /** What is wrong, when anything is. */
  wrong: ComputedRef<string | undefined>
  /** Whether what is wrong is what the page itself found in what was typed. */
  typed: ComputedRef<boolean>
  /** The line beneath when nothing is wrong. */
  said: ComputedRef<string>
  changed(value: string): void
  left(): void
}

export function useSetting(props: SettingProps, emit: { (event: 'update', value: string): void; (event: 'left'): void }): Setting {
  const store = inject(CONFIG)!
  const fields = inject(FIELDS)!
  const local = computed(() => (props.error === undefined && fields.left.has(props.path) ? (props.problem ?? undefined) : undefined))
  const wrong = computed(() => props.error ?? local.value ?? store.problemAt(props.path))
  const said = computed(() => {
    const differs = props.was !== undefined && props.was !== (props.means ?? props.value)
    const was = !differs ? '' : props.was === '' ? 'Was empty.' : `Was ${props.was}.`
    return [props.help, was, differs ? props.note : ''].filter((part) => part !== undefined && part !== '').join(' ')
  })
  return {
    store,
    wrong,
    typed: computed(() => local.value !== undefined),
    said,
    changed: (value) => {
      if (store.problemAt(props.path) !== undefined) {
        store.violations.value = store.violations.value.filter((violation) => !under(violation.path, props.path))
      }
      emit('update', value)
    },
    left: () => {
      fields.left.add(props.path)
      emit('left')
    },
  }
}
