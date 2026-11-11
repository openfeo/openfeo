# PortStrip

The router's front panel as the person sees it on the box: one `ofo-port` per physical NIC inside `ofo-ports`.

**Provide** per port: the kernel name, negotiated speed ("2.5G", "1G", "—" when no carrier, "err" on errors), and modifiers — `ofo-port--wan` (oxide frame) for WAN-role ports, `--up` (teal LED) or `--down` (crimson LED).

**Do** order ports as they appear on the hardware, and give each a `title` with full details (MAC, driver, errors). Pair state with the speed text so the LED colour is never the only signal.
**Don't** use it for virtual interfaces (bridges, VLANs, WireGuard) — those are InterfaceCards.
