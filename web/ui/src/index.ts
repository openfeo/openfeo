// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The OpenFeO design system in code (SPEC §8.4). Nothing here knows the API.
//
// The styles are three files a page loads in this order: `@openfeo/ui/tokens.css` (the custom
// properties and the two fonts), `@openfeo/ui/ofo.css` (the design system's own stylesheet)
// and `@openfeo/ui/additions.css` (what building the panel showed it lacked).

export { applyTheme, chooseTheme, storedTheme, systemTheme, THEME_KEY } from './theme'
export type { Theme } from './theme'
