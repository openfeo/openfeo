# ThroughputChart

The live RX/TX line chart for an interface: `ofo-chart` with a `__head` (title, `__legend` of current values, a Segmented range) and an inline `<svg>`.

**Provide** two series of samples (bits per second) and a range; draw in the SVG:
- `g.grid` horizontal lines at 4–5 round values, `g.axis` labels in mono (y on the right, unit in the legend not on every tick).
- `path.area.rx` (12% fill) + `path.line.rx` in `series-1` for download/RX, `path.line.tx` in `series-2` for upload/TX, `s3` (`series-3`) for a second WAN.
- `g.event` dashed `warn` markers with a short label for failovers and reconnects.

**Do** keep the y scale stable (link speed or a round max) so the chart doesn't rescale every tick; show current values in the legend, not tooltips only. Give the SVG a `role="img"` and `aria-label`.
**Don't** smooth the lines (spline) or use stacked areas — people read exact drops here.
