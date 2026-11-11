# PageShell

The panel's frame: `ofo-shell` = the Nav sidebar (220px, sticky) + `ofo-shell__main` with a sticky `ofo-topbar` and `ofo-shell__content` (max 1280px, `space-6` padding).

**Provide**
- Topbar: hostname (mono), firmware version and uptime (`__meta`), and at the end the unapplied-changes pill and the theme toggle.
- Content: a PageHeader, then the page body. Lay out cards with `ofo-grid ofo-grid--2|3|4` (collapses to 2 columns below 1100px and to 1 below 640px).

Below 900px the sidebar becomes a 64px icon rail (labels, group headers and pills hide; the wordmark swaps to the mark).

**Don't** put page actions in the topbar — they belong in the PageHeader.
