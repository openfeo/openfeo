# DataTable

Dense rows for leases, firewall rules, routes, ports and the website's hardware list: a `<table class="ofo-table">` inside `ofo-table-wrap` (which scrolls horizontally on narrow screens).

**Provide** column headers as short nouns, cells pre-formatted. Put `ofo-mono` on machine values (IPs, MACs, ports, counters) and `ofo-num` on numeric columns and the actions column so they right-align.

**Do** keep row actions as `ofo-btn--sm ofo-btn--ghost`; use a StatusPill for state. Secondary machine values (MACs) can be `ofo-muted`.
**Don't** zebra-stripe (hover highlights the row), or wrap IPs — let the wrapper scroll.
