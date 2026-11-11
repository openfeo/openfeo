// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The theme (SPEC §8.4): dark by default, light its equal. Until the person chooses, the
// stylesheet follows their system; a choice is an attribute on the root element and one key
// in local storage, the only thing the panel keeps there.

export type Theme = 'dark' | 'light'

/** The local-storage key the choice is kept under. */
export const THEME_KEY = 'openfeo.theme'

/** The theme the person chose earlier, or `null` when they have not (or it cannot be read). */
export function storedTheme(storage: Pick<Storage, 'getItem'>): Theme | null {
  try {
    const held = storage.getItem(THEME_KEY)
    return held === 'dark' || held === 'light' ? held : null
  } catch {
    return null
  }
}

/** The theme the system asks for: light when it prefers light, dark otherwise. */
export function systemTheme(prefersLight: boolean): Theme {
  return prefersLight ? 'light' : 'dark'
}

/** Put a choice on the root element, or take it off so that the system decides. */
export function applyTheme(root: HTMLElement, theme: Theme | null): void {
  if (theme === null) {
    root.removeAttribute('data-theme')
  } else {
    root.setAttribute('data-theme', theme)
  }
}

/** Apply a choice and remember it. A store that refuses does not stop it applying. */
export function chooseTheme(root: HTMLElement, storage: Pick<Storage, 'setItem'>, theme: Theme): void {
  applyTheme(root, theme)
  try {
    storage.setItem(THEME_KEY, theme)
  } catch {
    // Kept for this page only.
  }
}
