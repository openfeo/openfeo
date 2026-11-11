# Field

A labelled input or select with help or an error underneath: `ofo-field` wrapping `ofo-field__label`, `ofo-input`/`ofo-select`, `ofo-field__help`.

**Provide** a label (uppercase via CSS — write it in sentence case), the control, and one line of help that says the format or consequence.

- Add `ofo-input--mono` for anything a machine reads: IPs, CIDRs, MACs, ports, rates, keys.
- Put `ofo-field--error` on the wrapper and replace the help with what is wrong and the limit ("Exceeds the link rate (1000 Mbit/s)").
- Units go in the help or label, not the value.

**Don't** use placeholder text as the label, or show errors before the person leaves the field.
