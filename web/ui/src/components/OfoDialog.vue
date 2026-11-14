<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Andrew Newton -->
<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, useId } from 'vue'

// A modal for a decision (alertdialog) or a small form (dialog). It takes the focus when it
// opens (the control marked `autofocus`, or else its first), keeps Tab inside itself, cancels
// on Esc and gives the focus back when it goes. A click on the scrim does nothing: a decision
// is made with a button.
withDefaults(defineProps<{ title: string; role?: 'alertdialog' | 'dialog' }>(), { role: 'alertdialog' })
const emit = defineEmits<{ cancel: [] }>()
const box = ref<HTMLElement | null>(null)
const titleId = useId()
let opener: Element | null = null

const CONTROLS = 'a[href], button, input, select, textarea, summary, [tabindex]'

function controls(): HTMLElement[] {
  return Array.from(box.value?.querySelectorAll<HTMLElement>(CONTROLS) ?? []).filter(
    (control) => !(control as HTMLButtonElement).disabled && control.tabIndex >= 0,
  )
}

function key(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    emit('cancel')
    return
  }
  if (event.key !== 'Tab') {
    return
  }
  const all = controls()
  const first = all[0]
  const last = all.at(-1)
  if (first === undefined || last === undefined) {
    event.preventDefault()
    return
  }
  const active = document.activeElement
  if (!box.value?.contains(active)) {
    event.preventDefault()
    first.focus()
  } else if (event.shiftKey && active === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && active === last) {
    event.preventDefault()
    first.focus()
  }
}

onMounted(() => {
  opener = document.activeElement
  const all = controls()
  ;(all.find((control) => control.hasAttribute('autofocus')) ?? all[0])?.focus()
  document.addEventListener('keydown', key)
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', key)
  if (opener instanceof HTMLElement && opener.isConnected) {
    opener.focus()
  }
})
</script>

<template>
  <div class="ofo-scrim">
    <div ref="box" class="ofo-dialog" :role="role" aria-modal="true" :aria-labelledby="titleId">
      <div class="ofo-dialog__body">
        <h2 :id="titleId" class="ofo-dialog__title">{{ title }}</h2>
        <slot />
      </div>
      <div class="ofo-dialog__foot">
        <slot name="foot" />
      </div>
    </div>
  </div>
</template>
