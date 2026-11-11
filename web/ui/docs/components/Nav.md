# Nav

The panel's left sidebar: `ofo-nav` holding a `__brand` (the wordmark), `__group` headers and `__item` links.

**Provide** each item an icon (16px stroke), a one- or two-word label in `ofo-nav__label`, `href`, and `aria-current="page"` on the current one (it gets `oxide` on `oxide-soft`). A small StatusPill at the end of an item flags something needing attention (e.g. a degraded WAN).

**Do** keep the order: Dashboard, then Network (WAN, LAN & DHCP, Firewall, SQM / CAKE, Routes), then Router (Logs, System).
Inside PageShell the nav collapses to a 64px icon rail below 900px: labels, group headers and pills hide, and the brand swaps the wordmark (`ofo-nav__word`) for the mark (`ofo-nav__mark`).

**Don't** nest more than one level, or add items for one-off actions (reboot, backup live under System).
