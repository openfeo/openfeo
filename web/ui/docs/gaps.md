# What the design system is waiting to hear

Building the panel on the design system shows where it is silent or wrong. Each line here
is something to change in the design system itself; until it is changed there and copied
across, the working answer lives in `additions.css` or in a component, as noted.

- The brand guide's "Using it" section names an `openfeo-web` repository. The package lives
  in the router's repository, under `web/ui`.
- The brand guide loads `tokens.css`, but the design system holds only `tokens.json`. Here
  `scripts/tokens.mjs` writes the stylesheet; the design system could carry the same file.
- A stat tile's sparkline is coloured in the previews by a `style` attribute on its path.
  The router's content security policy refuses inline styles, so the series needs classes:
  `ofo-spark--s1` and `ofo-spark--s2` in `additions.css`.
- An icon has a size only inside `ofo-btn`, `ofo-nav__item` and `ofo-banner`. `ofo-icon` in
  `additions.css` gives it one anywhere.
- The Nav guideline shows the wordmark and the mark as images with `ofo-nav__word` and
  `ofo-nav__mark` on them. Each needs both theme files, so here the two classes sit on a
  `span` that holds the pair; the stylesheet's rules work on either.
- The guidelines do not say what separates a number from its unit in an interface card's
  rates. Here it is a non-breaking space, so the two never part at a line's end.
- `tokens.json`: the `data` type style's sample holds a hardware address with a maker's
  assigned prefix. The router's repository is public and uses documentation
  addresses in every example, so its copy has `02:00:00:0a:11:3e`; the design system's sample
  should change to match.
- There is no class for an "Advanced" disclosure in a form section. `ofo-adv` and
  `ofo-adv__grid` in `additions.css` are a `details` that spans the section's columns and
  lays its fields out in the same two-column grid.
- The Choice guideline groups choices in a `fieldset` with a `legend`, and the stylesheet has
  no rule that resets a fieldset (its border, padding and minimum width). `ofo-choices` in
  `additions.css` does.
- There is one height of input. A table edited in place needs a smaller one:
  `ofo-input--sm` (30px) in `additions.css`.
- There is no list for the changes a dialog confirms. `ofo-changes` in `additions.css` is the
  approved mockup's: a 96px column for whose setting it is, then what it was (struck through,
  muted) and what it becomes, in mono.
- The save bar has no place for a sentence beside its buttons. `ofo-savebar__held` in
  `additions.css` holds why an apply is not offered (another change is waiting to be
  confirmed).
- The Dialog guideline does not say which control takes the focus when it opens. Here it is
  the one marked `autofocus`, or else the first.
- The StatTile guideline gives a tile a sparkline or a foot. The dashboard's rate tiles need
  both: the last minute's line and, beneath it, the hour's peak. `OfoStatTile` shows the foot
  under the sparkline when it is given both.
- The Segmented guideline has labels only. A choice of LAN wants each LAN's count beside its
  name; `OfoSegmented` draws it with `ofo-tabs__count`, the class a tab's count has.
- There is no way to mark a table's row out. `ofo-table__row--new` in `additions.css` gives a
  row an oxide edge: a lease that has just arrived, for a minute.
- The ThroughputChart guideline has a title, a legend, a range and the picture, and nowhere
  to say something of the picture as a whole. `ofo-chart__note` in `additions.css` is a line
  under the head: that the hour before could not be read.
- The chart's preview draws into a fixed box that is stretched to the element's width, which
  widens its labels and its upright strokes. `OfoChart` makes the box as wide as the picture
  is drawn; nothing in the stylesheet needed changing for it.
- The chart's two kinds of label (the scale's levels, the times along the range) have one
  rule, `.ofo-chart .axis text`. `OfoChart` names them `ofo-chart__level` and
  `ofo-chart__tick` so that a test and a later rule can tell them apart; they carry no rule
  of their own today.
