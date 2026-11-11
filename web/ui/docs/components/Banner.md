# Banner

A page-level message: `ofo-banner` + tone (`--info`, `--ok`, `--warn`, `--danger`) with an `__icon`, a `__body` (optional `__title`), and at most one Button.

**Provide** what happened, when, and what OpenFeO is doing about it, in that order ("wan0 missed 3 probes at 14:02:11. Traffic is on wan1…"). Name interfaces and values exactly.

**Do** put pending-changes notices here (`--info` with the Apply button). One banner per concern, newest first, at the top of the page.
**Don't** use banners for field validation (use Field errors) or celebrate routine success — `--ok` is for things the person was waiting on.
