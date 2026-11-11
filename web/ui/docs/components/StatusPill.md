# StatusPill

One or two words of state beside a name, with a dot: `ofo-pill` plus a tone.

| tone | means |
|---|---|
| `--ok` | Up, online, link established, lease active. |
| `--warn` | Degraded, failover active, high latency, update available. |
| `--danger` | Down, error, rule rejected. |
| `--info` | Neutral activity: probing, negotiating, applying. |
| `--brand` | Role labels: Primary WAN, Default route. |
| (none) | Disabled / not configured. |

**Provide** the word — always. Colour is never the only signal; ok (teal) and danger (crimson) also differ by hue axis for colour-blind readers.
**Don't** use pills as buttons or for counts above 99.
