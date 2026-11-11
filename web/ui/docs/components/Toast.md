# Toast

A brief confirmation or alert that appears bottom-right and leaves on its own: `ofo-toasts` (the fixed stack) of `ofo-toast` + tone, with an `__icon`, `__body` and either a close button or one small action.

**Provide** one sentence in past tense for results ("Changes applied. Firewall reloaded in 38 ms.") or present for events ("wan0 down — now on wan1.").

- `--ok` and `--info` auto-dismiss after 5 s; `--warn` and `--danger` stay until dismissed. Use `role="status"` (polite) except `--danger`, which is `role="alert"`.
- At most three at once; newest at the bottom.

**Don't** put anything in a toast the person must act on later — that's a Banner.
