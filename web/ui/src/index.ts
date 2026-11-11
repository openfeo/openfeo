// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The OpenFeO design system in code (SPEC §8.4). Nothing here knows the API: every
// component takes plain props and emits plain events.
//
// The styles are three files a page loads in this order: `@openfeo/ui/tokens.css` (the custom
// properties and the two fonts), `@openfeo/ui/ofo.css` (the design system's own stylesheet)
// and `@openfeo/ui/additions.css` (what building the panel showed it lacked).

export { default as OfoBanner } from './components/OfoBanner.vue'
export { default as OfoButton } from './components/OfoButton.vue'
export { default as OfoCard } from './components/OfoCard.vue'
export { default as OfoDataTable } from './components/OfoDataTable.vue'
export { default as OfoField } from './components/OfoField.vue'
export { default as OfoIcon } from './components/OfoIcon.vue'
export { default as OfoInput } from './components/OfoInput.vue'
export { default as OfoInterfaceCard } from './components/OfoInterfaceCard.vue'
export { default as OfoNav } from './components/OfoNav.vue'
export { default as OfoPageHeader } from './components/OfoPageHeader.vue'
export { default as OfoPortStrip } from './components/OfoPortStrip.vue'
export { default as OfoShell } from './components/OfoShell.vue'
export { default as OfoSkeleton } from './components/OfoSkeleton.vue'
export { default as OfoStatTile } from './components/OfoStatTile.vue'
export { default as OfoStatusPill } from './components/OfoStatusPill.vue'
export { default as OfoThemeSwitch } from './components/OfoThemeSwitch.vue'
export { default as OfoWordmark } from './components/OfoWordmark.vue'
export type { NavEntry } from './components/OfoNav.vue'
export { ICONS } from './icons'
export type { IconName } from './icons'
export { sparkPath } from './spark'
export { applyTheme, chooseTheme, storedTheme, systemTheme, THEME_KEY } from './theme'
export type { Theme } from './theme'
export type { Tone } from './tone'
