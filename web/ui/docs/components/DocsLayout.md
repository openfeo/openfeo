# DocsLayout

The documentation page frame on the website: `ofo-docs`, a three-column grid of `__nav` (section links), the article in `ofo-prose`, and an "On this page" `__toc`. Add `__pager` (previous/next) at the end of the article.

**Provide** the nav as `__group` headings with `__link`s (`aria-current="page"` on the current one), the page's Markdown rendered inside `ofo-prose`, and its h2s for the TOC.

`ofo-prose` styles plain HTML from Markdown: h1–h3, lists with oxide markers, `code`/`pre` on `surface-sunken`, tables, and blockquotes as info notes. Columns drop the TOC below 1100px and stack below 760px.

**Don't** put marketing blocks (Hero, FeatureGrid) inside docs pages.
