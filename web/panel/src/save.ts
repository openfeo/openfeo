// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The one place a page hands the browser a file to save. The text is made into a Blob and
// offered through a link with `download`, which the page's content security policy allows
// as it stands: nothing is fetched, and no `data:` URL is made (SPEC §8.4).

import type { InjectionKey } from 'vue'

/** Have the browser save `text` as a file called `name`. */
export function saveText(name: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.hidden = true
  document.body.append(link)
  link.click()
  link.remove()
  // The browser has the file's bytes by the time the click returns; the address is let go
  // once it has had a moment to begin.
  setTimeout(() => {
    URL.revokeObjectURL(url)
  }, 1_000)
}

/** How a page saves a file: {@link saveText}, or what a test hands it in its place. */
export const SAVE: InjectionKey<typeof saveText> = Symbol('save')
