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
