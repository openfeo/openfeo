# InterfaceCard

One network interface at a glance — WAN, LAN bridge or VLAN: `ofo-iface` with `__head` (name, role, StatusPill), `__kv` (a `<dl>` of facts) and `__rates`.

**Provide** the kernel name (`wan0`, `br-lan`), a role ("WAN · primary"), state, 3–5 key/value facts, and live RX/TX.

- `ofo-iface--active` (oxide border) marks the interface currently carrying the default route — exactly one at a time.
- Values in `__kv` are mono; keys are short nouns (Mode, IPv4, Link, Loss).
- RX in `oxide` (series-1), TX in `info` (series-2), always with ↓/↑ and units.

**Don't** put more than five facts in the card — link to the interface page for the rest.
