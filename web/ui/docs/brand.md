OpenFeO is a router OS that is a Linux kernel and one Rust binary running as PID 1. The design system serves two surfaces: the **web panel** served by the router itself (Vue, often offline, used at 2 a.m. when the internet is down) and the **public website and docs**. Both use the same tokens, fonts and `ofo-*` CSS classes.

The idea in one line: **iron oxide on steel**. A cool graphite/steel neutral base, one hot rust accent, machine values in monospace. Precise, small radii, no decoration that doesn't carry information.

## Voice and content

- **Plain, exact, unhurried.** Say what happened, when, and what the router is doing about it: "wan0 missed 3 probes at 14:02:11. Traffic is on wan1 (4G)." Never "Oops!" or "Something went wrong".
- **Name things as the kernel does.** Interfaces are `wan0`, `br-lan`, `eth2` — set in mono, never renamed to "Internet port 1" in data. Friendly role words go beside them ("WAN · primary").
- **Sentence case** everywhere: buttons, titles, menu items. Labels are written in sentence case and uppercased by the `label` style.
- **Buttons are verbs**: "Apply changes", "Add lease", "Download image". The one commit action per view is the primary button.
- **Units always, with a space**: `941.2 Mbit/s`, `8 ms`, `2.5 Gbit/s`. Rates to one decimal; counts as integers.
- **Website copy** makes measurable claims ("~24 MB image", "failover in < 3 s") and no superlatives. No emoji, anywhere.
- The name is **OpenFeO** (capital O, F, O). Lowercase `openfeo` only for the binary, package, repo and domain.

## Colour

Dark is the primary theme; light is a full equal. Set `data-theme="dark"` or `"light"` on `<html>`; default to dark and follow `prefers-color-scheme` if the person hasn't chosen.

- **Grounds:** `ground` for the page, `surface` for cards, sidebar and tables, `surface-raised` for menus, hovered rows and inputs, `surface-sunken` for logs and code.
- **Lines:** `line` for dividers and card edges (decorative only); `line-strong` for any control's border (3:1).
- **Text:** `ink` for primary text, `ink-muted` for labels, units and metadata. Both pass 4.5:1 on all four grounds in both themes.
- **Brand:** `oxide` is the only brand hue in UI — primary buttons, the selected nav item (`oxide` on `oxide-soft`), the active interface's border, toggles when on, RX data. Its label colour is `on-oxide` (dark text in dark theme, white in light). `oxide-deep` (haematite) and `steel` are for large website and illustration fields only, never UI chrome; anything oxide drawn on an `oxide-deep` field uses `oxide-bright` (the light theme's `oxide` is too dark there).
- **Status:** `ok` (teal), `warn` (amber), `danger` (crimson), `info` (blue), each with a `-soft` background. `ok` deliberately sits toward teal and `danger` toward pink so neither is confused with the brand or with each other for colour-blind readers — and every status still carries a word.
- **Data:** `series-1` (oxide) = download/RX, `series-2` (info) = upload/TX, `series-3` (violet) = an extra WAN or interface. Links in prose use `link` (= `info`), never oxide.
- **Focus:** a solid 2px `focus` ring at 2px offset on every focusable element (`.ofo :focus-visible` does this). Never remove it.

## Type

Two open fonts (SIL OFL 1.1), shipped as variable woff2 files inside the binary — about 70 KB together, no network fetch:

- **Instrument Sans** (`sans`, weights 400–700) for all UI and website text.
- **JetBrains Mono** (`mono`) for anything a machine produced: IPs, MACs, interface names, ports, rates, logs, config, and headline numbers. Always with `font-variant-numeric: tabular-nums` (`ofo-mono` sets it) so live numbers don't jitter.

Styles: `display-xl` (website hero, once per page) and `display` (section heads, first-run screen); `title` for panel page titles; `heading` for card headings; `body` for prose; `body-sm` for tables and dense panel text; `label` (uppercase, tracked) for field labels and stat captions; `caption` for timestamps. Mono: `metric` for stat-tile numbers, `data` for values in tables and cards, `code` for code and logs.

## Space, shape and depth

- **4px grid:** `space-1`…`space-9` (4 → 96px). Panel cards pad `space-4`, website blocks `space-5`/`space-7`; page gutter `space-6` on desktop, `space-5` on mobile.
- **Small radii — hardware, not a toy:** `radius-sm` (3px) pills and ports, `radius-md` (6px) buttons and inputs, `radius-lg` (10px) cards. `radius-full` only for status dots and toggle tracks.
- **Controls:** `control-md` (36px) default, `control-sm` (28px) in table rows, `control-lg` (44px) website CTAs and touch-first screens.
- **Depth by borders, not shadows.** Cards are `surface` with a `line` edge. `shadow-pop` only for floating layers (menus, popovers, dialogs, toasts).
- **Motion:** 120ms colour/position transitions on controls; nothing in the panel animates on its own except live data. The one brand animation is MarkMotion (the lattice opening into 3-D) — splash, hero, video only. Respect `prefers-reduced-motion`.

## Layout

- **Panel:** fixed `Nav` sidebar (220px, `surface`) + content on `ground`, max 1280px. The dashboard leads with a row of `StatTile`s, then `InterfaceCard`s, then the `PortStrip`. Collapse the sidebar to the mark below 900px.
- **Website:** `SiteHeader`, `Hero`, `FeatureGrid`, then docs. Docs prose is `body` at max 70ch with `CodeBlock`s for every command.
- Status is always word + colour (+ icon or dot). Never colour alone.

## Iconography

Line icons on a 24px grid, 1.75 stroke, round caps and joins, `currentColor`, shown at 16px in the panel and 28px in website feature cells. The previews use a small hand-drawn set in this style; for the full set use **Lucide** (ISC licence), which matches this spec — inline the SVGs you use rather than shipping the font. No emoji, no filled or duotone icons.

## Imagery

No photos or stock. Illustration comes from the mark: the FeO lattice — flat as a 3×3 dot face, or opened into a 3-D ball-and-stick crystal with Fe in `oxide`, O in `ink` / `on-oxide-deep` and faint bonds — usually on `oxide-deep`. Otherwise real screenshots of the panel. Never depict the Rust language's logo or mascot.

## Logo

The mark is a face of iron oxide's rock-salt crystal: big Fe dots in `oxide` on the corners and centre, small O dots in `ink` between. Use the Logos files as they are (see the Brand component for rules); use `openfeo-favicon.svg` below 20px.

## Using it

Load `tokens.css`, the two fonts, then `components/bundle.css`; put `class="ofo"` on `<body>` (or the panel root). Components are plain CSS classes (`ofo-btn`, `ofo-field`, `ofo-iface`…) — each component's README lists the markup it expects — and `components/bundle.js` adds `OpenFeO.lattice()` for MarkMotion.

In code, use the `@openfeo/ui` package (the `openfeo-web` repo): the same tokens and CSS plus Vue 3 components for every card here (`OfoButton`, `OfoInterfaceCard`, `OfoShell`, `OfoHero`…), theme switching and the lattice animation. Its `tokens.json` mirrors this system's; copy it across and run `npm run tokens` after changing tokens here.

**Panel pages** are PageShell (Nav + topbar) → PageHeader → content in `ofo-grid` columns; settings pages are FormSections with a save bar, and nothing applies until **Apply changes**. **Website pages** are SiteHeader → Hero or Section blocks → SiteFooter; docs use DocsLayout with `ofo-prose`.
