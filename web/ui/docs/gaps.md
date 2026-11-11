# What the design system is waiting to hear

Building the panel on the design system shows where it is silent or wrong. Each line here
is something to change in the design system itself; until it is changed there and copied
across, the working answer lives in `additions.css` or in a component, as noted.

- The brand guide's "Using it" section names an `openfeo-web` repository. The package lives
  in the router's repository, under `web/ui`.
- The brand guide loads `tokens.css`, but the design system holds only `tokens.json`. Here
  `scripts/tokens.mjs` writes the stylesheet; the design system could carry the same file.
