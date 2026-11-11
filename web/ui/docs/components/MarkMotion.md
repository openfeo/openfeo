# MarkMotion

The lattice mark opening into a 3-D FeO crystal, routing packets through it, and closing back to the mark — for splash screens, the website hero, release videos and the panel's boot/first-run screen.

**How it moves** (16.6 s loop):

1. **The mark** (1 s): the flat 3×3 face — 5 oxide Fe dots, 4 ink O dots.
2. **Unfold** (1.0–3.4 s): copies of the face swing out on hinges like paper — one to the left (hinged on the left column), one upwards (hinged on the top row) — then a third swings up out of the left one into the empty top-left corner. The tiles share their hinge rows, so the result is an exact 5×5 rock-salt face. The view leans in slightly while folding so the hinges read as 3-D, and zooms out to fit.
3. **Extrude** (3.6–5.2 s): four more layers slide out behind the face into a 5×5×5 crystal; atoms shrink to ball-and-stick, bonds fade in, the camera turns.
4. **Packets** (5.6–11.9 s): two glowing packets, 3 s each, run along the bonds from an atom on one outer face to one on a different face, detouring to the top and bottom of the crystal on the way. The route lights behind them, the rest dims, start and end atoms flash. New routes every loop.
5. **Fold back** (12.2–15.8 s): the crystal flattens to the 5×5 face, the corner folds back into the left tile, left and top fold back onto the mark, and it holds.

The first and last frames are identical to `openfeo-mark.svg`. Easing is cubic in-out.

**Provide** an `<svg viewBox="-150 -150 300 300">` on `ground` or `oxide-deep` with the flat 3×3 circles in its markup (so the mark shows before the script runs), then call `OpenFeO.lattice(svg).play()` from `components/bundle.js`. It returns `{play, stop, replay, draw(t), loop}`; options `{packets: 0|1|2}`.

Style these classes with tokens:

| class | ground | oxide-deep |
|---|---|---|
| `.fe` | `oxide` | `oxide-bright` |
| `.o` | `ink` | `on-oxide-deep` |
| `.bond` | `ink-muted` | `on-oxide-deep` |
| `.trail` | `oxide-hover` | `on-oxide-deep` |
| `.trail-glow` | `oxide` | `oxide-bright` |
| `.packet` / `.packet-halo` | `ink` / `oxide-hover` | `on-oxide-deep` / `oxide-bright` |

**Do** play it once on load, or loop it only where nothing else moves. Honour `prefers-reduced-motion` (the script shows the flat mark and stops). For video, step frames with `draw(t)` from 0 to `loop`.
**Don't** run it in the panel's everyday chrome (sidebar, header) — the UI rule is that nothing animates on its own except live data.
