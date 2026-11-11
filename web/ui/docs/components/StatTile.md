# StatTile

A single headline number for the dashboard: `ofo-stat` with `__label`, `__value` (+ `__unit`), and either a `__spark` SVG or a `__foot` line.

**Provide** the label, the number pre-formatted (one decimal for rates, none for counts), its unit, and optionally 60 samples for the sparkline or one line of context.

- Numbers use the `metric` style (JetBrains Mono, tabular) so they don't jitter as they update.
- Sparklines: download/RX in `series-1` (oxide), upload/TX in `series-2` (info). No axes, no fill.

**Don't** colour the number by state — put a StatusPill or a `__foot` line next to it instead.
