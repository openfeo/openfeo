# CodeBlock

Monospace output on `surface-sunken`: `<pre class="ofo-code">` for install commands, config snippets and the panel's live log view.

**Provide** the text; wrap a shell prompt in `__prompt` (oxide `$ `, unselectable), comments and timestamps in `__dim`, and log levels in `__ok` / `__warn` / `__err`. Add an `ofo-btn--sm ofo-btn--ghost ofo-code__copy` for commands people will paste.

Inline code and keys use `ofo-codeinline` / `ofo-kbd`.

**Don't** syntax-highlight with extra colours; the four tones above are the whole palette.
