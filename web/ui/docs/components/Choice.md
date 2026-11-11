# Choice

Checkboxes and radio buttons: a native `<input type="checkbox|radio">` inside `<label class="ofo-choice">`, then the label text in a `<span>` with an optional `ofo-choice__hint`.

**Provide** the label and, when the consequence isn't obvious, a one-line hint. Group related choices in a `<fieldset>` with a `<legend class="ofo-field__label">`.

- Checkbox: independent options (several firewall allowances). Radio: one of 2–5 (failover mode). Six or more options → `ofo-select`.
- Use a Toggle instead for a single feature on/off in a settings form.

**Don't** use them for actions that apply immediately.
