# FormSection

How settings pages are laid out: a stack of `ofo-formsec` rows, each with a title and explanation on the left and `__fields` (a 2-column grid of Fields; add `ofo-span-2` for full width) on the right. Changes collect in a sticky `ofo-savebar` at the bottom.

**Provide** per section a 1–3 word title and one sentence saying what the settings control. Group by what changes together, not by protocol.

- The savebar appears only when something has changed, counting the changes, with Discard and **Apply changes**. Nothing applies until Apply.
- Stacks to one column below 900px.

**Don't** auto-save router config — every change is explicit, because a wrong value can cut the person off from the panel.
