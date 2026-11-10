# M4: the API and the panel

Design for milestone M4 (SPEC §12): the router gets an API, a JavaScript client for it, and a web
panel built on that client. Until now the only way to see what the router is doing is its console
and the only way to change it is to edit `/state/config.toml` and reboot.

M4 is too large for one branch. This document fixes the shape of the whole milestone and its five
parts, and designs **part 1** in full: the API with login and reading, the client, the component
package, and a panel with three screens (set a password, log in, a read-only dashboard). Each later
part gets its own design when it is reached, as M2's parts did; what was already decided about them
is recorded under "Decisions recorded for later parts".

It comes out of a brainstorm with the maintainer on 2026-11-10. What he decided is listed first,
in his terms. Every other choice is the author's and is listed under "Calls made for the
maintainer" at the end, each with what it costs if wrong.

## Decided in the brainstorm

- **The order is API, then a JavaScript client for it, then the panel as a Vue app that uses the
  client.** The reason is his: anyone adopting OpenFeO can build their own UI on the same client.
- **Everything lives in this repository, and a build embeds the panel in the binary.** He asked
  for guidance on the Rust side of that; the layout and the build below are the author's.
- **The design system is his**: a design-system document he keeps outside the repository
  (tokens, a stylesheet of `ofo-*` classes, two fonts, logos, a guideline per component, voice
  rules). Its link is his to give and is not recorded here; part 1 copies its files into
  `web/ui` (see "The components"), and from then on the repository's copy is what is built
  from. Its navigation and menus were a first guess and may be changed to fit what is built.
- **Commit-confirm waits 120 s by default**, not the 60 s of SPEC §2. A change that moves the
  router's address needs the client to take a new lease, pass the certificate warning again and
  log in again, all inside the window.
- **The WAN's VLAN tag is in scope everywhere a WAN is set up**, the wizard included: altnet FTTP
  lines need it. (The author's reading, which he did not correct: this is the tag on the WAN.
  Editing LAN VLANs in the panel stays post-MVP; M4 shows them and carries them through edits.)
- **The first look is three screens**, approved as mocked up with the design system's own
  stylesheet: set the admin password, log in, and a read-only dashboard. The mock-up was a
  throwaway and is not in the repository; "The panel" below describes what was approved, and
  where the two differ this text wins. (The mock-up's sidebar listed every page of M4, and its
  events included a clock sync and a config confirmation, which part 1 does not emit.)
- **The parts and their order** below.
- **The default LAN is `192.168.168.1/24`**, in place of `192.168.1.1/24`, so that a router tried
  behind an existing network does not sit on that network's subnet.
- He approved, without changing them: one admin and no other users; the panel is not reachable
  from the WAN; the client is GPL-2.0-or-later like the rest and is not published to npm; no
  command-line tool in M4.

## Intent

A router is run from a browser by someone who may be doing it at 2 a.m. with the internet down.
The panel has to say plainly what the box is doing (which ports have a link, which addresses it
holds and where each came from, whether the WAN is up and since when) before it offers to change
anything, and a change has to be safe to get wrong.

The spec already fixes the bones (§2, §8, §9, §10): one protobuf schema for config, state, events
and services; Rust types by `prost` and `pbjson`, TypeScript by `protobuf-es`; one HTTPS listener
carrying the panel, a binary WebSocket and gRPC; bearer tokens, never cookies; a self-signed
certificate whose fingerprint the console prints; a Vue panel inside the binary.

What the brainstorm added is the layering. The panel is not the API's only consumer and must not
be its only description: the protocol knowledge (the envelope, the auth frame, matching replies to
requests, subscriptions, reconnecting) lives in a client package with no Vue in it, the look lives
in a component package with no API in it, and the panel is the thin thing that joins them.

## Goals

- An API that reads the router's state and, in later parts, changes its config, over a WebSocket
  for browsers and gRPC for scripts, with the same messages on both.
- A JavaScript client that hides the wire, works in a browser and in Node, and is the only way
  the panel talks to the router.
- A panel on the maintainer's design system that shows what the kernel actually has.
- Part 1 usable on its own: after it lands, a booted router can be given a password and looked
  at from a browser.
- Every part proven in the harness from the LAN side, the panel by Playwright against the VM.

## Non-goals

- More than one user, roles, or an audit trail of who did what.
- Reaching the panel from a WAN (SPEC §9 allows enabling it per WAN; M4 does not build that).
- Publishing `@openfeo/client` or `@openfeo/ui` to npm, or promising their surfaces stay put
  before 1.0. `buf breaking` guards the messages; the packages are versioned with the router.
- A command-line tool. gRPC is there for one later.
- Pages whose backends arrive later: updates and backup/restore (M5), shaping and CAKE (M6).
- Editing in the panel what SPEC §12 puts after the MVP (LAN VLANs). They are shown, not edited.
- ACME, remote syslog, translation of the panel's text.

## Anti-goals

- **A panel that drops what it does not show.** An edit made in the panel must leave every part
  of the config it does not display exactly as it was. (Part 2 onward; recorded here because it
  shapes how config is held in the client from the start.)
- **A cookie, or any credential a browser sends by itself.** A page on another site must not be
  able to act as the admin.
- **Anything fetched from the internet by the panel.** Fonts, icons and scripts are in the
  binary; the panel works with the WAN down.
- **Per-packet or idle work in userspace** to feed a dashboard nobody is looking at.
- **A cargo build that runs npm.** Rust work must not wait on Node.
- **Friendly names in place of real ones.** The panel names things as the config and the kernel
  do (`wan0`, `br-lan0`, `p0`), with role words beside them.

## Constraints

What exists on `main` today and bounds the design:

- `proto/openfeo/v1/config.proto` is the only schema file; `openfeo-config` generates its types
  with `prost` and `pbjson`. There is no `state.proto`, `events.proto` or `api.proto`, no
  `openfeo-api` crate, no `web/`.
- The World (`openfeo-world`) is one immutable snapshot of config plus facts (`links`, `dhcp4`,
  `leases`, `time`, `ipv6`, `routes`, `dhcp6`, `pppoe`, `ula`), published through a `watch`
  channel by `openfeo-runtime`'s `Publisher`. It holds no interface addresses beyond each link's
  link-local, no link speed and no counters.
- There is no event bus. SPEC §6.3 says events travel by `broadcast`; nothing sends any yet.
- The log ring exists (`openfeo-runtime::log::Ring`, `tail(n)`), with no level filter or follow.
- **Config is read once, at boot.** The WAN and LAN tasks are spawned from it and never see
  another. Part 1 does not need more; part 2 does, and it is the largest piece of M4.
- The firewall already admits TCP 53, 80 and 443 to the router from **private** LANs and from
  nowhere else (`LAN_TCP_SERVICES` and `lan_priv_if` in the nft reconciler). A public LAN gets
  neither, as SPEC §7.5 has it, so the panel is not offered there.
- With no config file the router already starts on first-boot defaults: every port in `lan0` at
  `192.168.1.1/24` with DHCP, nothing forwarded. **It does the same with a file it refuses**
  (`config_decision` in `boot.rs`), leaving the file untouched.
- The router's own name already resolves, for LAN clients, to every LAN's address and to the
  router's loopback /128s in the routed prefix, each delegation and the ULA (`router_addrs` in
  the DNS reconciler).
- The health tracker is polled by the heartbeat and notifies nobody; its `is_healthy()` means
  "worth a heartbeat" and counts a degraded subsystem as healthy.
- The only uptime clock (`openfeo_runtime::clock::uptime_ms`) counts from the router process's
  start, not the kernel's.
- The build bakes `OPENFEO_BUILD_EPOCH` into the binary as the clock's floor; the router may not
  know the time when it first serves HTTPS.
- Workspace rules stand: `clippy -D warnings`, no `unwrap`/`expect` outside tests, no shelling
  out, `unsafe` only where ADR-0013 allows, pure crates stay pure, every parser fuzzed, SPDX
  headers, `cargo deny` licences. Test hooks exist only under the `harness` feature.

## The shape of M4

### Layers

```
proto/openfeo/v1/*.proto          one schema
  ├─ Rust:  openfeo-config (messages)  →  openfeo-api (listener, auth, services)
  └─ TS:    web/client  (@openfeo/client)   the wire: envelope, session, subscriptions
            web/ui      (@openfeo/ui)       the look: tokens, ofo-* CSS, fonts, Vue components
            web/panel                       the app: pages that join the two
```

`@openfeo/client` has no Vue and no DOM beyond `fetch` and `WebSocket`. `@openfeo/ui` has no
knowledge of the API: its components take plain props. `web/panel` holds no protocol code and no
CSS of its own beyond page layout. The rule is checked the way the Rust dependency rules are: a
script in lint fails if `web/ui` imports `@openfeo/client`, if `web/client` imports `vue`, or if
the panel imports the generated message code other than through the client.

### Repository layout

`web/` is an npm workspace (npm, not pnpm or yarn: it comes with Node) with one lockfile:

```
web/
  package.json  package-lock.json  .nvmrc (Node 22)
  client/   @openfeo/client   src/gen/ (protobuf-es output, not committed)  src/  test/
  ui/       @openfeo/ui       tokens.json  tokens.css (generated)  ofo.css  fonts/  logos/  src/
  panel/    private           src/  e2e/ (Playwright)  → dist/
```

`buf generate` writes the TypeScript into `web/client/src/gen/` with the `protobuf-es` plugin
taken from the workspace's own `node_modules`, so no plugin is fetched at build time. Like the
Rust types, the generated code is built, not committed.

### Into the binary

Cargo never runs npm. `make panel` installs the workspace (`npm ci --ignore-scripts`), generates
the message code, type-checks and builds the panel into `$(BUILD)/panel`. `make bin` (and so
`make kernel`) depends on it and passes `OPENFEO_PANEL_DIST` to its own cargo call. Unlike
`OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE`, which the Makefile exports to every target, this
one is set for the binary's build only: `make lint` and `make test` do not build the panel and
must not point at one. `openfeo-api`'s `build.rs` turns that directory into a table of embedded
files (path, content type, the bytes compressed ahead of time, a hash for `ETag`), and the
listener serves them from memory.

With `OPENFEO_PANEL_DIST` unset, the build embeds a one-page placeholder that says the panel was
not built and the API is up. So `cargo build`, `cargo test` and `cargo clippy` need no Node; an
image always goes through `make` and always carries the real panel, and a harness scenario fails
if the booted VM serves the placeholder.

### Licences

All of `web/` is project code: GPL-2.0-or-later with the SPDX header, so a UI that bundles the
client must be GPL-compatible. The npm dependencies that end up in the bundle pass the same
accepted list as `cargo deny` applies (SPEC §14), checked by a script in lint over the lockfile.
The two fonts are SIL OFL 1.1, added to that list for font files only, and ship with their
licence texts.

Part 1 is the first binary to carry third-party JavaScript and fonts, so it carries their
notices: the panel's build writes one text file (each bundled npm package's licence and the two
OFL texts), served at `/licences.txt` without a login and linked as "Licences" at the foot of
the set-password and login screens. The Rust side's notices (`cargo about`, SPEC §13) arrive
with the System page in part 3; until then `docs/third-party.md` stands.

### Names on screen

A WAN or LAN is titled by its name in the config (`wan0`, `lan0`, `iot`), because that is what
the person chose and what the log says. The kernel interface is a fact beside it (`ppp-wan0 on
p0.911`, `br-lan0`), in mono. Physical ports are `p0…pN`. Status is always a word with a colour.
Units are always present, with a space. The design system's voice rules apply to every string.

### Navigation

For the whole of M4, in this order; a page appears in the sidebar in the part that builds it and
not before:

- Dashboard
- **Network**: WAN · LAN & DHCP · Firewall · DNS · Routes
- **Router**: Ports · Logs · Diagnostics · System

This is the design system's list with DNS, Ports and Diagnostics added from SPEC §8.4 and
`SQM / CAKE` held back for M6. Reboot, password and the notices live under System.

## Parts and where each is proven

Each part is its own branch, plan and PR, and appends its entry to `docs/progress.md`.

1. **API and a first look** (this design). The schema for state, events and services; the HTTPS
   listener and its certificate; password and sessions; the WebSocket envelope and gRPC; the
   client; the components; the panel's three screens. Proven: the `m4` harness suite from the LAN
   side (below), which includes SPEC §12's "a WS upgrade with a foreign `Origin` is refused";
   the client's own tests against the VM; Playwright: set a password, log in, see `wan0` up, cut
   the ISP, see it down without reloading. It lands as two branches and PRs, as M1's parts did:
   **1a**, everything in Rust, serving a placeholder page where the panel will be
   (`docs/superpowers/plans/2026-11-10-m4-part1a-api.md`); then **1b**, the web workspace, the
   embedding, the notices, the lab relay and Playwright.
2. **Changing config.** The running router takes a new config: each task family follows the
   config in the World and restarts only what changed. `Config` service (get, validate, apply
   with commit-confirm at 120 s, confirm, revert), the pending file, the events. In the panel:
   edits gather across pages, a preview of what will change, apply, the countdown, confirm; the
   WAN and LAN & DHCP pages. Proven: SPEC §12's "LAN subnet changed without confirming →
   reverted", and the confirm path from the new address.
3. **The remaining pages.** Firewall (zone matrix, forwards, rules, and the live ruleset), DNS,
   leases and static leases, Routes, Ports, Logs (level filter, live tail), System (password,
   time, reboot, notices).
4. **Diagnostics.** Ping and traceroute bound to a WAN, the dumps, packet capture streamed as
   pcapng, the support bundle. Proven: SPEC §12's "capture stream opens in Wireshark" (`tshark`
   reads it in the harness).
5. **First boot.** The unconfigured state and the wizard. Proven: SPEC §12's "wizard → routing".

## Part 1

### Schema

Three new files beside `config.proto`, all in package `openfeo.v1`:

- `state.proto`: `State` and its parts, `Counters`.
- `events.proto`: `Event`.
- `api.proto`: the envelope (`ClientMsg`, `ServerMsg`, as SPEC §8.3 gives them), the request and
  response messages, and the services. Later parts add the config, diagnostics and system
  services here.

SPEC §8.3 names the services `Auth`, `Config`, `State` and so on. Those names cannot stand: a
service and a message share one namespace in a package (`State` and `Config` are messages, and
`Auth` is the envelope's first frame), and `proto/buf.yaml` lints with `STANDARD`, which wants
the `Service` suffix and a request and a response message of its own for every call. The lint
is kept. So:

| Service | Call | Request → response |
|---|---|---|
| `AuthService` | `Login` | `LoginRequest { password }` → `LoginResponse { session }` |
| | `SetInitialPassword` | `SetInitialPasswordRequest { password }` → `SetInitialPasswordResponse { session }` |
| | `Logout` | `LogoutRequest {}` → `LogoutResponse {}` |
| | `ChangePassword` | `ChangePasswordRequest { old, new }` → `ChangePasswordResponse {}` |
| `StateService` | `GetState` | `GetStateRequest {}` → `GetStateResponse { state }` |
| | `Subscribe` | `SubscribeRequest { topics, backlog }` → stream of `SubscribeResponse { state \| counters \| event }` |
| (HTTP only) | status | `GetStatusResponse { hostname, domain, needs_password, config_refused, tls_fingerprint }` |

`Session` is `{ token, idle_secs }`. The WebSocket's `Request` and `Response` carry these same
request and response messages (SPEC §8.3: both transports share message types).

`config.proto` gains `Admin { string password_hash = 1; }` as `Config.admin`, the `[admin]`
table SPEC §8.2 already shows. Validation accepts an empty hash or an Argon2id PHC string.

The message types stay in `openfeo-config` (which must not gain `tonic`, `hyper` or `tokio`);
`openfeo-api` generates only the gRPC service code and points it at those types.

`State` is what one screen of the dashboard needs and no more. Its shape (field numbers are the
builder's; names are part of the design):

```proto
message State {
  uint64 generation = 1;            // the World's
  SystemState system = 2;
  repeated PortState ports = 3;     // in port order
  repeated WanState wans = 4;       // in config order
  repeated LanState lans = 5;       // in config order
  repeated AddressState addresses = 6;
}
message SystemState {
  string hostname = 1; string domain = 2; string version = 3;
  uint64 uptime_secs = 4;           // since the kernel booted
  bool time_synced = 5;
  bool healthy = 6; repeated string unhealthy = 7;   // see "Health"
  string tls_fingerprint = 8;
  optional ConfigProblem config_problem = 9;         // set when config.toml was refused: the reason and its violations (path, code, message)
}
message PortState {
  string name = 1; string id = 2; string mac = 3;    // p0, the bus path, the hardware address
  bool carrier = 4;
  optional uint32 speed_mbps = 5;                    // absent when the driver does not say
  repeated PortUse uses = 6;                         // {WAN|LAN, name, vlan}: p3 is in lan0, and in iot as VLAN 20
}
message WanState {
  string name = 1; WanKind kind = 2;                 // STATIC, DHCP, PPPOE
  string port = 3; uint32 vlan = 4; string interface = 5;
  WanPhase phase = 6;                                // DOWN, CONNECTING, UP: see "What up means"
  string reason = 7;                                 // why it is not up, as the console says it
  optional uint64 phase_since_unix_ms = 8;           // when it entered this phase
  string ipv4 = 9; string ipv4_peer = 10; string gateway4 = 11;
  uint32 mtu = 12;
  string ipv6 = 13; repeated string ipv6_prefixes = 14;
  bool default4 = 15; bool default6 = 16;            // carries the default route
}
message LanState {
  string name = 1; string interface = 2; repeated string members = 3;   // "p1", "p3.20"
  string ipv4 = 4; repeated string ipv6 = 5;
  optional uint32 vlan = 6;                          // when every member is the same VLAN
  bool dhcp = 7; uint32 pool_size = 8; uint32 leases = 9;
  repeated string reaches = 10;
}
message AddressState {
  string interface = 1; string address = 2; string peer = 3;
  AddressOrigin origin = 4;   // CONFIG, PPP, DHCP, ROUTER_ADVERTISEMENT, DELEGATED_PREFIX, ULA, LINK_LOCAL
  bool deprecated = 5;
}
```

Addresses are strings in the forms `config.proto` already uses.

### State is a pure function of the World

`fn state(&World, &SystemFacts) -> State` lives in `openfeo-reconcile` beside the other pure
views of the World and is snapshot-tested with `insta` against World fixtures, like them.
`SystemFacts` is what the World does not hold and should not (version, uptime, health, the
fingerprint), read by `openfeo-api` when it builds a snapshot.

For that the World gains three facts:

- **addresses**, from the netlink-facts task: every address the kernel holds, on every
  interface, with prefix length, peer and the deprecated flag. The view tags each with its
  origin by matching it against the facts that explain it (the LAN's config, the DHCP lease,
  the PPP session, the WAN's IPv6 fact, a delegated prefix, the ULA).
- **speed** on `LinkFact`, from the same task: read from sysfs (`/sys/class/net/<port>/speed`,
  which SPEC §10 already names as a telemetry source) when carrier changes, absent when the
  driver reports none (virtio does unless QEMU is told a speed; the harness tells it one port).
- **WAN status**, one entry per WAN: its phase, when it entered it, and the cause last given
  for leaving `UP`. See the next section.

### What up means

SPEC §7.4 defines a WAN as up by its probes, which are M6's. Until then the phase is derived
from facts the World already has, by one pure function per kind:

| Kind | `UP` | `CONNECTING` | `DOWN` |
|---|---|---|---|
| static | carrier on its interface and its address there | never | no carrier |
| DHCP | carrier and a lease held | carrier, no lease | no carrier |
| PPPoE | a session with IPCP up | carrier, no such session | no carrier |

IPv6 does not enter into it: the WAN's IPv6 address and prefixes are shown beside the phase,
not folded into it. M6 tightens `UP` to "and its probes pass"; the names `wan.<name>.up` and
`.down` keep meaning the edges of this phase.

The phase and its start are stamped where the World is published (the same place events are
derived, below): when a publish changes a WAN's derived phase, the publisher records the new
phase and the time on the boot clock in the status fact. The API turns that into wall time when
it builds a snapshot. A restart of the router process starts the phases again from when the new
process first saw them.

The **cause** is the one thing that cannot be derived. The DHCP and PPPoE tasks already work it
out for their console lines (`keepalive lost (3 echoes)`, `authentication failed`, `lease
expired`, `nak`); each now also publishes it into its WAN's status fact when it loses the lease
or the session, in the same words. `reason` is that cause while the WAN is not up, `no carrier`
when the link is down, and empty when it is up. A static WAN has no task and only ever says
`no carrier`.

### Health

`healthy` is true when no subsystem is degraded or wedged and no task is dead; `unhealthy` lists
the subsystems and tasks that are, by name. This is stricter than the tracker's `is_healthy()`,
which answers whether the watchdog should still be petted. The heartbeat already evaluates the
tracker's report on every beat; health for the API, and the `health.ok` and `health.degraded`
events on its edges, are taken from that evaluation, not from a second poller.

### The boot clock

`uptime_secs`, an event's `uptime_ms` and a phase's start are all time since the kernel booted,
and do not reset when the router process restarts. The existing process clock learns its offset
from the kernel's uptime once at start.

### Counters stay out of the World

Interface counters change every second and must not bump the World's generation or run a
reconciler. `openfeo-api` owns a telemetry task that, **only while at least one subscriber
wants counters**, reads each link's 64-bit statistics from netlink and the conntrack count and
limit once a second, and publishes:

```proto
message Counters {
  uint64 monotonic_ms = 1;                       // when they were read
  repeated LinkCounters links = 2;               // name, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors
  uint32 conntrack = 3; uint32 conntrack_max = 4;
}
```

The router keeps no history and computes no rates. The client computes rates from two samples
and their timestamps, which stays right when a slow browser is sent only the latest sample.

### Events

`Event { uint64 time_unix_ms; uint64 uptime_ms; string topic; map<string, string> fields; }`.
Topics are SPEC §10's stable names. Part 1 emits `wan.<name>.up`, `.down`, `.addr`, `.prefix`,
`lan.<name>.lease.granted`, `.released`, `health.ok` and `health.degraded`. The fields carry
the values (`address`, `prefix`, `reason`, `host`, `mac`); the panel writes the sentence. Both
times travel because the wall clock may be the build's epoch until SNTP answers; the panel
shows wall time once `time_synced`, uptime before.

Events for facts are **derived where the World is published**: `Publisher::update` has the old
and the new snapshot in hand, a pure `fn events(&World, &World) -> Vec<Event>` (in
`openfeo-reconcile`, unit-tested) names what changed, and the publisher sends the result on a
`broadcast` channel. A watcher of the `watch` channel would miss a down-and-up that happened
between two looks. Health events come from the heartbeat's evaluation (above). `openfeo-api`
keeps the last 256 events in memory so a dashboard opened later can show the recent ones.

### The listener

One task under the supervisor, in `openfeo-api`, started by the router beside the other
services. It binds TCP 443 and 80 on every address and accepts a connection only if **the
client's address is inside a private LAN** in the current World: the LAN's IPv4 subnet, any of
its IPv6 /64s (routed, delegated, ULA), or a link-local address scoped to its interface. The
firewall's existing rule is the first gate and this is the second; both mean "from a private
LAN". The test is on the client and not on the address it reached, because the router's name
resolves to its loopback /128s as well as its LAN addresses and all of them must work. Port 80
answers every request with a redirect to the same host on HTTPS, after the host check below.

TLS is rustls with `ring` (SPEC §13), offering HTTP/2 and HTTP/1.1. gRPC is told apart by
`content-type: application/grpc`. The WebSocket is an HTTP/1.1 upgrade at `/ws`.

Routes in part 1:

| Route | Auth | What |
|---|---|---|
| `GET /`, asset paths | none | the panel; any other path that is not `/api/…` or `/ws` returns the panel's page, so its own routes survive a reload |
| `GET /licences.txt` | none | the notices |
| `GET /api/status` | none | `GetStatusResponse` |
| `POST /api/password` | none, and only while no password is set | `SetInitialPassword` |
| `POST /api/login` | none | `Login` |
| `GET /api/state` | token | `GetState` |
| `GET /ws` | token, in the first frame | the envelope |
| `/openfeo.v1.AuthService/*`, `/openfeo.v1.StateService/*` | token, in `authorization` metadata (not `Login` or `SetInitialPassword`) | gRPC |

HTTP bodies are protobuf (`application/x-protobuf`). `?format=json` on a GET, or a JSON
`content-type` on a POST, switches that call to the canonical JSON mapping, for `curl`.

Every response carries a strict `Content-Security-Policy` (own origin only, no inline script,
no `eval`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy:
no-referrer`. There are no CORS headers and no HSTS (the certificate is self-signed). Files
with a content hash in their name are cacheable for good; the page itself is not cached.

### The certificate

ECDSA P-256, self-signed, made with `rcgen` at the first start that finds none, kept in
`/state/tls` (key mode 0600). Its names are the hostname and `<hostname>.<domain>`. The console
prints `tls: fingerprint sha256 3F:9A:…` at every start; the same string is in the status call
and in `State`.

macOS refuses outright (no way past the warning) a server certificate that lacks a subject
alternative name or the `serverAuth` extended key usage, or that is valid for more than 825
days. So the certificate has both and is valid for 825 days, and it is reissued **with the same
key** when:

- its names no longer match the hostname and domain;
- the clock is synced and fewer than 60 days remain;
- the clock has just synced and shows the certificate was issued on a guess that a correct
  clock calls expired or not yet valid.

Its not-before is a day before now when the clock is synced, and a day before the build's epoch
when it is not, so a router that does not yet know the time never issues a certificate from a
client's future. An old image booted with no clock therefore issues once on the guess and once
more after its first sync; after that only the 60-day rule applies. A reissue changes the
fingerprint: the console prints the new one and `State` carries it. There is no event for it;
no topic is minted.

### Requests the router refuses

- **A foreign `Host`.** The `Host` (or `:authority`) must be one of the router's two names, or an
  address literal that the kernel holds (the World's new address fact, any interface), with any
  port. Anything else gets `421`. This is what stops a page on another site, pointed at the
  router by a rebinding DNS answer, from reading it: the attack needs a name, and only the
  router's own names pass.
- **A foreign `Origin`** on the WebSocket upgrade: when the header is present it must name the
  same set, over HTTPS. A request with no `Origin` is not from a browser and is let through to
  the token check.
- **No token, a wrong one, or one that has lapsed**: `401` over HTTP, `UNAUTHENTICATED` over
  gRPC, and over the WebSocket an `Error` and a close with code 4401.
- **A WebSocket that does not send `Auth` within 5 s**, sends a text frame, or sends a frame over
  1 MiB: closed.
- **Everything but the panel's files, `GET /api/status` and `POST /api/password` while no
  password is set.**

### Password and sessions

- The hash is Argon2id with OWASP's parameters (19 MiB, 2 passes, 1 lane) as a PHC string in
  `[admin] password_hash`. A password is 12 to 256 characters; nothing else is demanded of it.
- **Setting the first password** works once, from any LAN client, while the hash is empty, and
  logs that client in. A second attempt gets `FAILED_PRECONDITION`. The console says
  `admin: password set from 192.168.168.23`, never the password.
- Setting or changing the password rewrites that one key in `/state/config.toml` in place,
  atomically, leaving the rest of the file (comments, order) as it was, and updates the config
  in the World. With no file yet, the first-boot defaults are written out with the hash.
- **A refused config keeps its password.** When `config.toml` exists and is refused, the router
  runs on first-boot defaults as it does today, but that is not a first boot and the panel must
  not become claimable by whoever is on the LAN after a typo or a downgrade:
  - if the file parses as TOML, its `[admin] password_hash` is honoured: the owner logs in, and
    the dashboard carries a banner with the reason and the violations (`config_problem`). (A
    file that parses and holds no hash never had a password: the first password is offered as
    usual and written into that file.)
    Changing the password edits the key in the refused file, which stays refused for its other
    reasons and keeps the new hash;
  - if the file does not parse, there is no hash to honour: nobody can log in, the first
    password is **not** offered (`needs_password` false, `config_refused` true, the call
    answers `FAILED_PRECONDITION`), and the panel says the config file cannot be read. The way
    out is M5's console menu.
  The loader in `openfeo-config` grows what this needs: the salvaged hash and whether a file
  was present.
- **Login** verifies one password at a time (a second attempt waits its turn), so a flood of
  logins costs one core's worth of Argon2 and no more. A wrong password makes that source wait:
  1 s, doubling to 5 minutes, forgotten after 15 quiet minutes. A source is an IPv4 address or an
  IPv6 /64. The answer says how long (`429`, `Retry-After`, and `retry_after_secs` in the body).
  The table holds 1024 sources and drops the oldest.
- A **token** is 32 random bytes, base64url. The router keeps its SHA-256, in memory only: a
  restart of the router process logs everyone out. At most 16 sessions; a 17th drops the one
  idle longest.
- A session **lapses after 30 minutes idle**. A request counts as activity, and so does a
  connected WebSocket, so a dashboard left open stays logged in.
- `Logout` ends the caller's session. `ChangePassword { old, new }` checks the old one under
  the same backoff and ends every other session.

### The WebSocket

The envelope is SPEC §8.3's. After `Auth`, the client may send:

- `Request` with one of `GetStateRequest`, `LogoutRequest`, `ChangePasswordRequest`; the reply
  is a `Response` carrying the matching response message, or an `Error`, with the same `id`.
  `Error { code, message }` uses gRPC's code names, so both transports report failures alike.
- `Subscribe { topic }` and `Unsubscribe { topic }`, with topics:
  - `state`: a `Telemetry` push with the whole `State` now and after every change, coalesced.
  - `counters`: a `Telemetry` push with `Counters` each second, coalesced.
  - `events`: `Event` pushes, with `backlog = N` to get the last N first. Events are queued,
    256 deep per socket; a socket that falls further behind is told so with an `Error` push
    (`DATA_LOSS`) and keeps receiving from there.

Coalesced means the socket's writer holds at most one pending push per topic: a newer one
replaces an unsent older one. The server pings every 20 s and closes a socket that misses two.
At most 16 sockets and 16 subscriptions per socket.

Over gRPC the same thing is `StateService.Subscribe`, a server stream of `SubscribeResponse`.

### The client (`@openfeo/client`)

TypeScript, ES modules, one runtime dependency (`@bufbuild/protobuf`). It runs in current
browsers and in Node 22, which has `fetch` and `WebSocket` built in. Its surface, in outline:

```ts
const router = new Router({ baseUrl, tokenStore })     // baseUrl defaults to the page's origin
await router.status()                                  // before login
await router.setInitialPassword(pw); await router.login(pw)
await router.logout(); await router.changePassword(oldPw, newPw)
await router.state()                                   // one snapshot
const sub = router.subscribe('state' | 'counters' | 'events', onPush, { backlog })
sub.close()
router.connection                                      // 'idle' | 'connecting' | 'open' | 'reconnecting'
router.onConnection(cb); router.onSessionEnd(cb)       // cb(reason): 'logout' | 'lapsed' | 'revoked'
rates(previous, next)                                  // Counters × 2 → bit/s per link
```

- It opens the socket on the first call that needs it, sends `Auth`, and numbers requests.
- When the socket drops it reconnects with backoff (0.5 s doubling to 10 s, jittered),
  authenticates again and resubscribes; callers keep their subscriptions. A refused token ends
  the session instead and clears the store.
- A failed login surfaces the wait as a typed error with `retryAfterSecs`.
- `tokenStore` is three functions (`get`, `set`, `clear`). The default keeps the token in
  memory; the panel passes one backed by `sessionStorage` (SPEC §8.4).
- It never touches the DOM, timers aside, and holds no global state: two routers, two objects.

Its unit tests run under `vitest` against a scripted socket. Its integration tests run in Node
inside the harness's LAN namespace against the booted VM.

### The components (`@openfeo/ui`)

A copy of the design system in code. The plan's first web task imports it from the maintainer,
file for file: `tokens.json`; the `ofo-*` stylesheet; the two variable fonts (Instrument Sans,
JetBrains Mono) with their OFL texts; the five logo files; and, as documentation under
`web/ui/docs/`, the brand guide (voice, colour, type, layout, iconography) and each component's
guideline. Nothing is redrawn or approximated. Beside them go a script that writes `tokens.css`
from `tokens.json` (dark the default, light its equal, following the system preference until
the person chooses) and Vue 3 components over the classes. Part 1 builds the ones its three
screens use: the shell (sidebar, top bar), page header, button, field and input, card, stat
tile, interface card, port strip, data table, status pill, banner, skeleton, and the theme
switch. Each takes plain props and emits plain events; none imports the client. Icons are
Lucide's SVGs, inlined (ISC).

The design system stays the source: a token or class changes there first and is copied across.
Where building the panel shows the design system wrong, the fix goes back to it.

### The panel

Vue 3, TypeScript, Vite, `vue-router`; state in composables over the client, no store library.

- **Which screen.** On load it asks `status`. No password set: the set-password screen. A config
  file that cannot be read: a screen that says so and offers nothing. No token, or a refused
  one: the login screen. Otherwise the dashboard. The choice of theme is the only thing it keeps
  in `localStorage`. The set-password and login screens end with a small "Licences" link.
- **Set the admin password.** The wordmark, the heading, one sentence saying anyone on the LAN
  can set it until it is set, two fields ("12 characters or more"), one button, and below them
  the certificate's fingerprint with the line that the console prints the same one.
- **Log in.** The hostname in mono, one field, one button. After a wrong password the field
  says so and counts down the wait, with the button disabled until it ends.
- **Dashboard**, read-only, live:
  - a header line: `wan0 up since 7 Nov 09:14 · 14 clients on 2 LANs`;
  - four tiles: download and upload (the rates of the WAN carrying the default route, each with
    a sparkline of the last minute), clients (leases in use, split by LAN beneath), connections
    (tracked, of the limit);
  - one card per WAN and per LAN: the name, the role (`WAN · PPPoE`, `LAN · VLAN 20`), a status
    word, at most five facts, and its rates. The WAN carrying the default route has the accent
    border. A WAN that is down shows why, in the console's words;
  - the port strip: each physical port in order, its speed or a dash, WAN ports framed;
  - **Addresses**: every address the kernel holds, grouped by interface, with where it came
    from. Link-local addresses are left out;
  - **Recent events**: the last eight, newest first, with no link onward until Logs exists.
  - a warning banner above everything when `config.toml` was refused: the reason, the
    violations, and that the router is running on first-boot defaults.
- **When the connection drops** a banner says since when and that it is retrying, and the
  numbers stop rather than freeze at their last value. **When the session ends** the login
  screen says why.
- Loading shows skeletons, not spinners. Below 900 px the sidebar is the icon rail the design
  system describes. Nothing is fetched from anywhere but the router.

### Looking at the real panel

The panel has to be looked at by a person while it is built, and the lab is a set of namespaces
a host browser cannot reach. `make run PANEL=<address>:<port>` has the harness listen on that
host address and relay to the router's port 443 from inside the LAN namespace. For the host
check to pass, a `harness`-feature build accepts one extra host name given on the kernel
command line (`openfeo.panel_host=`); a release build has no such knob, and a unit test says
so. Playwright also saves a screenshot of each screen in both themes on every run.

### Build and CI

- `make panel` (above); `make web-lint` (type-check, ESLint, the layering script, the npm
  licence gate, generated code up to date); `make web-test` (`vitest`). `make lint`, `make test`
  and `make ci` run them; `make check-env` reports Node, npm and a Chromium Playwright can run.
- The SPDX check extends to `.ts`, `.vue`, `.css`, `.proto` and the workspace's config files.
- CI's lint job gains Node 22 and the web targets. Its harness job builds the panel before the
  kernel, installs Chromium for Playwright (cached), and runs the `m4` suite. The cloud setup
  script installs Node; without a browser the Playwright scenarios skip with a reason there,
  and `OPENFEO_NO_SKIP` makes a skip fail in CI as it does for the rest.

### Harness and tests

Unit, in `openfeo-api`: the host and origin checks, the backoff table, sessions (lapse, the cap,
revocation), the envelope's dispatch, coalescing, the asset table. In `openfeo-reconcile`:
`state` and `events` against World fixtures.

A new QEMU suite, `m4`, boots the DHCP WAN fixture and acts from the LAN namespace (and once
from the ISP side). Each line is a scenario:

- The panel is served over HTTPS on the LAN address and by name; port 80 redirects; the page is
  not the placeholder.
- The certificate presented has the fingerprint the console printed, a subject alternative
  name, `serverAuth`, and no more than 825 days.
- A router with no password answers only `status` and the first-password call; a LAN client
  sets one and is logged in; a second attempt is refused; `config.toml` holds the hash, is mode
  0600, and its other lines are unchanged.
- A wrong password is refused and the wait doubles; the right one logs in after the wait.
- A request with a foreign `Host` gets 421; a WebSocket upgrade with a foreign `Origin` is
  refused; one with no `Origin` and a good token is accepted.
- A WebSocket that sends nothing for 5 s is closed; so is one that opens with a bad token.
- `State` over gRPC, over the WebSocket and as JSON agree, and show `wan0` up with the lease
  Kea gave, the LAN with its address and the lease the LAN client holds.
- Taking the WAN port's carrier away (as the M1 link-flap scenario does) pushes `wan.wan0.down`
  and a `State` with the WAN `DOWN`, reason `no carrier`; restoring it passes through
  `CONNECTING` and pushes `up`. A late subscriber's backlog holds both. (An ISP that merely goes
  silent is noticed only when the lease runs out; that path is unit-tested, not booted.)
- On the IPv6 fixture of M2 part 2, the panel answers by the router's name over IPv6, whichever
  of the name's addresses the client picks, and by a LAN address literal.
- A config file that fails validation: the router is on first-boot defaults, the owner's
  password still logs in, the first-password call is refused, and `State` carries the problem.
  One that is not TOML: nobody can log in and the first password is not offered.
- Counters rise while the LAN client fetches from the ISP side, and nothing reads them when no
  one is subscribed (the telemetry task's own counter of reads, in a harness build).
- Changing the password ends the other session and keeps the caller's.
- From the ISP namespace, ports 443 and 80 on the WAN address do not answer.
- After the router process is killed and restarted, the old token is refused and the panel is
  served again.

The client's integration tests (Node, in the LAN namespace): log in, read state, subscribe,
survive a dropped connection and keep receiving, and report the session's end when the token is
revoked. Playwright (Chromium, in the LAN namespace, by the router's name): first visit → set a
password → dashboard shows `wan0` Up with its address; reload → still logged in; log out → log
in; cut the ISP → the card says Down and an event row appears, with no reload.

### Fuzzing

Two targets with a checked-in corpus: the envelope (arbitrary bytes as a `ClientMsg` through
the dispatcher against a stub) and the host and origin parser.

## Decisions recorded for later parts

- **Part 2.** The default wait is 120 s; that changes SPEC §2, so its ADR comes first, with §5.5
  and §12 amended. Reverting is republishing the previous config through the same path as
  applying (SPEC §5.5); the work is making every task family follow the config, in the manner
  the RA and DHCPv6 server tasks already follow their desired state. The panel holds the whole
  typed config as its draft and each page edits only its own fields, which is how config the
  panel does not show survives an edit. Secrets (`[admin] password_hash`, a PPPoE password) are
  write-only over the API. Confirming after a change that moved the router's address is a
  problem to solve there: the token is tied to the old address.
- **Part 5.** The maintainer asked whether the first boot should make every port a LAN or only
  the first to get a link. The direction recommended to him, to be settled in that part's
  design: the panel stays reachable on every port, since being locked out is the worst outcome
  on unknown hardware; ports are kept apart from one another until configured; and before
  offering DHCP on a port the router sends a DHCP request and a PPPoE discovery out of it. A
  port where something answers gets no DHCP server and is offered by the wizard as the likely
  WAN, with the type filled in. A tagged line will not answer, so the wizard keeps "plug the ISP
  cable in now" and a field for the tag. The default LAN is `192.168.168.1/24`, the same before
  and after the wizard so that finishing with the default does not move the browser; when the
  upstream network overlaps it the wizard proposes the next free /24 and says why. These change
  SPEC §5.6.
- **Throughout.** LAN VLAN members, public IPv4 blocks, `reaches` and the IPv6 fields are shown
  wherever they bear on a page, and edited only where SPEC §8.4 lists the page.

## SPEC amendments (the plan's first task)

- §8.1: the TypeScript is generated into `web/client/src/gen/`.
- §8.2 and §9: a refused config keeps its password; the first password is offered when no hash
  is set and the file, if there is one, parses.
- §6.2: the three new facts; what `UP`, `CONNECTING` and `DOWN` mean until M6.
- §8.3: the services carry the `Service` suffix and each call has its own request and response
  message; `GET /api/status`, `POST /api/password` and `/licences.txt`; JSON bodies; a WebSocket
  upgrade with no `Origin`; `StateService.Subscribe` over gRPC; the topics and their coalescing.
- §8.4: the three packages and the rule between them; the navigation; names on screen; a page
  appears in the part that builds it.
- §9: the password's length; the backoff schedule and what a source is; sessions in memory, 16
  at most, 30 minutes idle; one verification at a time; the certificate's 825 days, its extended
  key usage and its reissue; the second gate on the listener (the client is on a private LAN);
  which `Host` values pass.
- §10: events derived where the World is published; counters read only while subscribed; an
  event's two times, both on the boot clock; what `healthy` means to the API.
- §11: the client's tests; Playwright inside the LAN namespace.
- §12: M4's row in five parts, each with its acceptance, as M2's row is.
- §13: `web/`'s layout; `openfeo-api`; the npm notices. §14: the npm licence gate; OFL fonts.
- `CLAUDE.md`: the new make targets, the tools the harness now needs, the layering rule.

## ADRs

- ADR-0024: the web workspace is built by `make` and embedded by cargo through an environment
  variable; Node is a build dependency of the image and not of the Rust workspace; npm packages
  install without their scripts and pass the licence gate; OFL fonts ship in the binary.
- Kernel, browser and protocol quirks found on the way get their own, as before. The 825-day
  certificate is the first candidate.

## What is left to the builder

- The HTTP stack inside the constraints (hyper, tonic and rustls are named by SPEC §2 and §13;
  whether `axum` routes, which WebSocket crate), and whether the asset table is `rust-embed` or
  a few lines of `build.rs`. All must pass `cargo deny`.
- How `openfeo-api` generates service code against `openfeo-config`'s types.
- Field numbers, the exact request and response message names, the error text.
- Where conntrack's count and the kernel's uptime are read from, and which crate reads them
  under the kernel-calling rule.
- How the heartbeat's evaluation reaches the API (a `watch` channel is the obvious way).
- The shape of the WAN status fact in the World, and where exactly each task sets the cause.
- How the Rust harness starts Node and Playwright inside the LAN namespace, and how a
  Playwright test asks the lab to cut the ISP while its page stays open.
- Whether Chromium needs `--no-sandbox` inside the rootless lab. **Prove Playwright in the
  namespace first**, before anything depends on it; likewise the static musl build with `ring`.
- The relay behind `make run PANEL=`. If the sandbox makes it impractical, say so and keep the
  screenshots.
- ESLint's rule set; the panel's file layout; how the sparkline is drawn.

## Calls made for the maintainer

1. **Sessions live in memory.** A restart of the router process logs everyone out. Cost: a
   login after every crash or update; the alternative is token hashes on disk.
2. **30 minutes idle, and an open dashboard counts as activity; no absolute lifetime.** Cost: a
   tab left open on an unattended machine stays logged in for as long as it is open.
3. **12 characters minimum, no composition rules.** Cost: a floor some will find high; lowering
   it later is a one-line change, raising it is not.
4. **Backoff per source of 1 s doubling to 5 minutes; one Argon2 verification at a time.** Cost:
   a person who mistypes five times waits half a minute; a second person logging in at the same
   instant waits a fraction of a second.
5. **Setting the first password logs that client in.** Cost: none found; it saves a step.
6. **Hostname and fingerprint are readable before login; the version is not.** Cost: anyone on
   the LAN learns the router's name.
7. **A WebSocket upgrade with no `Origin` is accepted.** Browsers always send one; scripts do
   not. Cost: the origin check protects only against browsers, which is the attack it is for.
8. **The listener checks the client is on a private LAN**, as well as relying on the firewall.
   Cost: a second place to change when the panel is one day enabled on a WAN.
9. **An 825-day certificate, reissued with the same key.** Cost: the fingerprint changes every
   two years or so and the browser warns again; the alternative is a long-lived certificate
   that macOS refuses.
10. **Events carry a topic and fields; the panel writes the sentence.** Cost: another UI has to
    write its own sentences; in exchange it is not handed English.
11. **Events are derived from World changes where the World is published.** Cost: an event for
    something that is not a fact needs its own send.
12. **Counters are read once a second, only while someone subscribes, and the router keeps no
    history.** Cost: a dashboard opens with empty sparklines.
13. **Addresses become a World fact, and the snapshot is a pure function of the World.** Cost:
    the World grows by a map that no reconciler reads yet.
14. **Changing the password edits one key of the config file in place.** Cost: a
    format-preserving TOML dependency; part 2 decides what a full apply writes.
15. **The sidebar shows only pages that exist.** Cost: the navigation grows part by part
    instead of showing the plan.
16. **Link-local addresses are left out of the Addresses table.** Cost: someone debugging IPv6
    looks elsewhere until Diagnostics lands.
17. **A lab relay and a harness-only extra host name, so the real panel can be opened from a
    browser outside the lab.** Cost: one more harness-only knob to keep out of release builds.
18. **`npm ci --ignore-scripts` and a licence gate over the lockfile.** Cost: a package that
    needs its install script has to be dealt with by hand.
19. **The client supports Node 22 as well as browsers.** Cost: nothing browser-only may be used
    in it; in exchange its tests and other people's scripts can use it.
20. **npm workspaces, with the generated TypeScript built and not committed.** Cost: the client
    cannot be used from a checkout without running the build once.

Calls 21 to 27 were made after a fresh reader checked this document against the repository:

21. **A refused config keeps its password, and no first password is offered over a config file
    that cannot be read.** Cost: an owner whose config file is corrupt beyond parsing cannot use the
    panel until M5's console menu; the alternative lets anyone on the LAN claim the router
    after a typo.
22. **Until M6's probes, a WAN is up when it has carrier and its lease, session or address**, and
    IPv6 does not count. Cost: a line that is connected but passes no traffic still reads Up.
23. **The DHCP and PPPoE tasks publish why they lost the WAN**, so the panel can say it. Cost:
    part 1 touches two task families it otherwise would not.
24. **Services are `AuthService` and `StateService`, each call with its own request and response
    message**, keeping `buf lint` at `STANDARD`. Cost: longer names than SPEC §8.3 wrote; they
    are frozen by `buf breaking` once merged.
25. **Any address the kernel holds passes the `Host` check as a literal; only the router's two
    names pass as names.** Cost: none found; rebinding needs a name.
26. **The npm and font notices ship in part 1 behind a "Licences" link on the two gate screens**,
    which the approved mock-up did not show; the Rust notices wait for part 3. Cost: one link
    more on those screens.
27. **No event for a reissued certificate.** Cost: the change of fingerprint is on the console
    and in `State` but not in the event list.
