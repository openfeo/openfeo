# Skeleton

Placeholder bars while the first data loads: `ofo-skel` (12px), `--lg` (28px, for metric numbers) and width modifiers `--w40`, `--w60`, `--w80`, placed inside the real component's frame.

**Provide** the same layout the loaded state will have, so nothing jumps. Show skeletons only on first load; afterwards keep stale values on screen and update in place.

The pulse stops under `prefers-reduced-motion`.
