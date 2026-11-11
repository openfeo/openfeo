# Dialog

A modal for decisions that can't wait or can't be undone: `ofo-scrim` (fixed, dims the page) holding `ofo-dialog` with `__body` (`__title`, `__text`) and `__foot` (buttons, right-aligned, cancel first).

**Provide** a question as the title, one or two sentences saying exactly what will happen (name the router, the interface, the downtime), and buttons labelled with the outcome ("Reset router", not "OK").

- Destructive and irreversible: the confirm button is `ofo-btn--danger`; for the worst cases (factory reset, firmware rollback) add a type-to-confirm Field.
- Use `role="alertdialog"` for confirms, `role="dialog"` for small forms. Trap focus; Esc and Cancel close it; focus returns to the trigger.

**Don't** stack dialogs, or use one for information a Banner or Toast would carry.
