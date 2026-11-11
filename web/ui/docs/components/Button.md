# Button

The one control that commits or navigates; `ofo-btn` on a `<button>` (or an `<a>` for links).

**Provide** a short verb-first label ("Apply changes", "Add lease"); optionally a 16px stroke icon before it.

| class | use |
|---|---|
| `ofo-btn--primary` | The one commit per view: Apply, Save, Download. `oxide` fill, `on-oxide` label. |
| (none) | Secondary: Discard, Edit, Cancel. `line-strong` border. |
| `ofo-btn--ghost` | Tertiary/toolbar: Reload, Add row. |
| `ofo-btn--danger` | Destructive and irreversible: Delete rule, Factory reset. Always behind a confirm. |
| `ofo-btn--sm` / `--lg` | `control-sm` in table rows; `control-lg` for website CTAs. |

**Do** keep one primary per page or dialog; show progress by disabling and changing the label ("Applying…").
**Don't** use primary for navigation, put two primaries side by side, or use `danger` for anything recoverable.
