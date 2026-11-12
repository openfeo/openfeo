# M4 part 2: changing config

Design for the second part of milestone M4 (SPEC §12). Part 1 gave the router an API, a client
and a panel that reads. This part lets the running router take a new config, safely, and gives
the panel its first two pages that change anything: WAN, and LAN & DHCP.

The milestone's shape, its layers and its rules are in
`docs/superpowers/specs/2026-11-10-m4-api-and-panel-design.md` and are not repeated here; what
that document recorded for this part ("Decisions recorded for later parts") is carried out here.

It comes out of a brainstorm with the maintainer on 2026-11-11, with the apply flow and both
pages mocked up in his design system's own styles and approved as shown (the mockups were
throwaway and are not in the repository). What he decided is listed first, in his terms. Every
other choice is the author's and is listed under "Calls made for the maintainer" at the end,
each with what it costs if wrong.

## Decided in the brainstorm

- **A change that moves the address you are connected through warns you first**: you have two
  minutes to confirm before the router goes back by itself, and you will need to renew your DHCP
  lease or change your static address. After that it is on the person to get back in time.
- **There is a way to apply with no going back**, for someone who is sure: a tick box worded
  "Apply immediately, no confirmation countdown". With it the change simply happens.
- **The WAN page configures every type the router supports over Ethernet** (DHCP, PPPoE, static,
  each with or without a VLAN tag) with every setting the config has for them: "not quite as in
  depth as MikroTik WinBox, but plenty of configurability".
- **The LAN page sets the subnet, the router's address, and DHCP**: the pool's start and end,
  reservations by MAC address, and the rest of what the config has.
- **Only settings the config already has.** Knobs it lacks (a cloned MAC, an MTU override, PPPoE
  keepalive timing, the DHCP client identifier, switching a WAN off without removing it, further
  DHCP server options) are left for later, if they turn out to be needed.
- **A LAN's renumbering carries along everything that pointed into it.** The router refuses a
  config whose port forward or rule points outside its LAN, and the page that edits those is
  part 3. So every address in the config that sat in the old subnet moves to the same place in
  the new one, and the dialog lists each. He chose this over refusing the change until part 3,
  knowing it bends the milestone's rule that an edit leaves what a page does not show exactly as
  it was.
- **LANs can be added and removed in the panel.** SPEC §1.2 kept "multiple LAN zones in the
  panel" out of the MVP; he lifts that. LAN VLANs stay in the file only.
- Carried over from 2026-11-10: the wait is **120 s**, not SPEC §2's 60 s; the WAN's VLAN tag is
  in scope wherever a WAN is set up.

Approved from the mockup: settings pages laid out as the design system's form sections with a
bar that counts unapplied changes; one Apply for everything changed on any page; a dialog that
lists the changes; a banner on every page while a change waits to be confirmed, with Confirm and
Revert now; the less common fields under "Advanced".

## Intent

Until now a config change is an edit to `/state/config.toml` and a reboot. That is fine for a
developer and useless for the person the panel is for. This part makes a change something that
can be made from a browser, takes effect at once, interrupts only what it has to, and can be got
wrong without a trip to the console.

The spec already fixes how (§5.5): a change is written beside the config as pending, applied, and
promoted only when confirmed; reverting is publishing the previous config again through the same
path. So the real work is not the timer. It is that **the router has never taken a second
config**: every WAN and LAN task is started from the one read at boot. Once the running router
follows the config in the World, applying, reverting and confirming are all the same act.

## Goals

- The running router takes a new config and converges on it, restarting only what the change
  touches. A reservation added on one LAN does not drop a PPPoE session.
- Commit-confirm as SPEC §5.5 has it, at 120 s, with an immediate apply for those who ask.
- A `ConfigService` on the WebSocket and gRPC, and its calls in `@openfeo/client`.
- The WAN page and the LAN & DHCP page, editing every field the config has for a WAN and a LAN.
- A person who moves the router's address under their own feet is told before, can get back, and
  finds the countdown waiting.
- Proven in the harness from the LAN side, including SPEC §12's "LAN subnet changed without
  confirming → reverted" and the confirm made from the new address.

## Non-goals

- New config fields. The pages edit what `proto/openfeo/v1/config.proto` has today.
- The other pages (part 3), diagnostics (part 4), the wizard and the new default LAN (part 5).
- Backup and restore of the config (`Config.Backup`, `Config.Restore`: M5).
- Editing LAN VLAN members, public IPv4 blocks, `reaches`, port forwards, rules or DNS records
  in the panel. They are shown where they bear on a page and carried through every edit; the
  one thing that touches them is a renumbering, which says so.
- A history of configs, or undo beyond the one revert.
- Renaming a WAN or a LAN. A name is chosen when it is added.

## Anti-goals

- **A change that half-applies.** A config is refused whole by validation or accepted whole.
- **A way to be locked out by accident.** The default path always has the countdown; the path
  without it is chosen each time, never remembered, and says what it means.
- **A restart of something the change did not touch.** If only a LAN changed, the WAN's lease,
  its session and its "up since" are what they were.
- **A panel that drops what it does not show** (from the milestone's design): the panel sends
  back the whole config it was given, with only its own fields changed. The one exception is
  the maintainer's: addresses that a LAN's renumbering carries along, each listed before it is
  applied.
- **A change the person was not shown.** Everything an apply will alter is in the dialog,
  whichever page it belongs to.
- **A secret that travels back.** The admin's password hash and a PPPoE password are never in an
  answer, a log line, an error or a `Debug` output.
- **A revert with its own code path.** Reverting is applying the previous config (SPEC §5.5).

## Constraints

What exists on `main` today and bounds the design:

- The World (`openfeo-world`) carries `config: Arc<Config>` beside the facts, and is published
  through `openfeo-runtime`'s `Publisher`. Nothing replaces `config` after boot.
- The appliers (links, routing, nft) and the tasks for DNS, router advertisements, the DHCPv6
  server and time already compute what they want from each World they see. They follow a changed
  config as they follow a changed fact, or are close to it.
- **Five families are started once, from the boot config**, one task per WAN or LAN
  (`spawn_all` in `crates/openfeo/src/`): the DHCPv4 client, PPPoE, the router-advertisement
  client, the DHCPv6 client, and the DHCPv4 server. Each copies its settings out of the config
  when it is spawned and never looks again.
- The supervisor (`openfeo-runtime::supervise`) starts tasks and restarts them when they fail. It
  cannot stop one, and a task that ends counts toward health.
- A task publishes facts into the World (`dhcp4`, `pppoe`, `ipv6`, `dhcp6`, `leases`). Nothing
  takes a fact out when its task is gone, because until now none ever was.
- `openfeo-config` parses, validates (`validate::validate`, with a path, a code and a message per
  violation) and renders the config. Changing the password edits one key of the file in place
  (`admin::write_password_hash`); nothing else writes `config.toml`.
- The API's listener binds every address, the firewall and a second gate keep it to private LANs,
  the certificate carries the router's two names and no address, and a session is a token tied
  to nothing. So a client that reaches the router by name keeps its session, and meets no new
  certificate warning, when the router's address moves.
- `api.proto` has `AuthService` and `StateService`. `events.proto` already reserves `config.*`
  topics.
- `@openfeo/ui` has seventeen components. The design system's stylesheet also styles form
  sections, a save bar, a dialog, choices, a toggle, a select and tabs, with a guideline for
  each (`web/ui/docs/components/`), but no Vue component exists for them yet.
- The panel's page for a gate (`web/panel/src/session.ts`) and its live data
  (`web/panel/src/live.ts`) assume one page behind the login: the dashboard.
- Workspace rules stand, as in the milestone's design: no `unwrap` outside tests, pure crates
  stay pure, every parser fuzzed, test hooks only under the `harness` feature, the page's content
  security policy, the layering rule between the web packages.

## The shape of part 2

Two halves, each its own plan and pull request, as part 1 was:

- **2a, the router.** The config becomes something that changes; every task family follows it;
  the `ConfigService`; commit-confirm; the events. Proven by the harness driving the API from the
  LAN namespace. After it lands a script can reconfigure a running router over gRPC.
- **2b, the web.** The client's config calls, the draft, the two pages, the apply dialog, the
  countdown. Proven by the client's own tests and by Playwright against the VM.

## Part 2a: the router

### One keeper of the config

A single task, the **config keeper**, is the only thing that replaces `config` in the World, the
only writer of `config.toml` and `config.pending.toml` besides the password change, and the owner
of the confirm timer. The API's `ConfigService` talks to it and to nothing else. It holds three
things: the config that is confirmed (what `config.toml` says), the config that is running (the
same, or a pending one), and, while a change is pending, when it reverts.

Publishing a config is one `Publisher::update` that swaps `world.config`. Everything downstream
reacts to that World as to any other.

### Following the config

Each of the five families started at boot gets a manager in place of `spawn_all`. A manager
watches the World, works out which instances the config asks for and with what settings, and
starts, stops or restarts its tasks to match. The comparison is a pure function over the config
(in `openfeo-reconcile`, like every other "what is wanted"): for each family, **the slice of the
config an instance depends on**. An instance is restarted when its slice differs and left alone
when it does not.

| Family | One per | Restarts when this changes |
|---|---|---|
| DHCPv4 client | DHCP WAN | the WAN's port or VLAN tag, hostname sent, vendor class sent |
| PPPoE | PPPoE WAN | port or tag, username, password, service name, concentrator name |
| RA client | WAN with IPv6 | port or tag, the kind underneath (PPPoE or not), typed gateway |
| DHCPv6 client | WAN asking for a prefix | port or tag, the kind underneath, the length asked for |
| DHCPv4 server | LAN with DHCP | the LAN's address and subnet, pool, lease time, reservations, DNS and NTP handed out |

A WAN whose type changes is one instance stopped and another started. A WAN's priority is not in
any slice: routing reads it from the World. A LAN's member ports are not in the DHCP server's
slice: the bridge is the links applier's.

Stopping is new and has three duties:

- **It is asked for, not forced.** A task being stopped gets the chance to say goodbye: a PPPoE
  session is terminated as the spec has it (two Terminate-Requests, then PADT), a DHCP lease is
  released. A task that has not finished within a few seconds is dropped.
- **It takes its facts with it.** When an instance stops, what it published about its WAN or LAN
  leaves the World, so that no applier goes on acting on a lease nobody holds.
- **It is not a failure.** A task stopped on purpose does not count toward health and is not
  restarted by the supervisor.

The tasks that already follow the World (DNS, RA server, DHCPv6 server, time, the appliers) are
each checked against a changed config and fixed where they took something once at start. The
API itself follows too: a changed hostname or domain reissues the certificate (it already
reissues for names) and changes which `Host` values pass.

### What a change does

One pure function says what a change from one config to another does:
`effects(old, new) -> Vec<Effect>` in `openfeo-reconcile`. It is built on the same slices the
managers use, so it cannot disagree with them. Each effect names the thing and what happens to
it: `wan0` reconnects, `lan0`'s address moves, `lan0`'s DHCP server restarts, `guest` is removed.

It has two readers. The keeper logs it when it applies. The API returns it from a validation, so
that the panel's dialog shows the router's own account of what will be interrupted and does not
guess.

### Commit-confirm

As SPEC §5.5, with the window at 120 s (ADR-0026).

- **Apply** validates the config. If it is refused, nothing has changed and the answer carries
  the violations. If it is accepted, the keeper writes it as `config.pending.toml`, publishes
  it, and starts the timer. The call answers once the config is published, not once the kernel
  has caught up.
- **Confirm** promotes the pending file to `config.toml` and stops the timer.
- **Revert**, or the timer running out, publishes the confirmed config again and deletes the
  pending file.
- **Apply immediately** (`commit_confirm = false`) writes `config.toml` and publishes, with no
  pending file and no timer.
- **At boot, and whenever the router process starts,** a pending file is deleted and never
  applied, and an event says an unconfirmed change was discarded.
- **While a change is pending** a second apply is refused, and so is a password change, until it
  is confirmed or reverted. Any session may confirm or revert: there is one admin.
- Files are written whole and atomically (a temporary file, synced, renamed).

The request may name its own window, from 10 s to 600 s; the panel never does. The default is
the router's to say: `Config.Get` carries it, and the panel's dialog writes its sentence from that
number. A harness build can be told a shorter default on the kernel command line
(`openfeo.confirm_secs=`, beside `openfeo.panel_host=`), so that a browser scenario does not wait
two minutes; a release build has no such knob.

**While the router runs on first-boot defaults because it refused the file on disk, an apply is
refused.** The confirmed config is then not what `config.toml` says, and a confirm would replace
the owner's own file with defaults and one edit. `Get` and `Validate` still answer.

**An apply names the config it was edited from.** `Config.Get` returns the running config with a
tag that changes whenever the config does; an apply carries that tag, and one made against a
config that has since changed is refused. Two tabs cannot overwrite each other unseen.

### Leases across a change

A change of subnet strands clients in two ways, and the router can soften one of them.

A client that renews during the window gets an address in the new subnet. If the change is then
reverted, that client holds a lease the router no longer honours, and it would sit there until
its renewal time: hours. So **while a change is pending, the DHCPv4 server of a LAN the change
touches grants no lease longer than the window.** Whichever way it ends, such a client asks again
within a minute or two. After a confirm, its next renewal gets the configured time.

**A revert gives back the leases the confirmed config had granted.** A client that held a lease
before the change, and never noticed the change, renews it after a revert and keeps its address.
How the lease database is kept across the window is the builder's.

A client that does not renew during a confirmed change keeps its old address until its lease
runs down. That is true of every router, and it is what the panel's warning is for.

IPv6: a prefix that a change takes off a LAN is deprecated to its hosts the way a withdrawn
delegation already is.

### The ConfigService

On the WebSocket envelope and over gRPC, with the same messages (SPEC §8.3):

- `Get`: the running config, its tag, and what is pending if anything.
- `Validate`: a config in; violations out, or the effects of applying it and whether it moves
  the caller (below).
- `Apply`: a config, the tag it was edited from, `commit_confirm`, an optional window.
- `Confirm`, `Revert`.

**Whether a change moves the caller.** The router knows which of its addresses this connection
arrived at and which LAN the client is on. A validation says two things about the caller, and
either one raises the panel's warning:

- **this connection will drop**: the change takes away the address it arrived at;
- **the caller's LAN changes under it**: that LAN's IPv4 address or subnet changes, or the LAN
  is removed, so the leases its devices hold, the caller's included, no longer fit.

A caller who came in over IPv6 by the router's name meets the second without the first: the tab
stays connected while its own IPv4 lease is stranded. With either, the answer names the LAN and
where the router will be found on it afterwards. The panel cannot work any of this out by itself
when it was opened by name.

**Secrets are write-only.** `Get` returns `admin.password_hash` and every PPPoE password empty.
An apply never changes the hash: the router keeps its own. An empty PPPoE password on a WAN that
is PPPoE in the running config, under the same name, means "keep it"; anywhere else it is the
violation it always was.

### State and events

- The state gains what is pending: that a change is, its effects, when it was applied, and
  when it reverts on the router's uptime clock (the panel already tracks that clock). Every
  session's every page can show the same countdown and the same account of the change from it.
  It carries no count of changes: only the tab that made them has the draft to count.
- Events, on the reserved topics: `config.applied` (pending or immediate, the number of
  effects), `config.confirmed`, `config.reverted` (asked for, or the time ran out),
  `config.discarded` (found pending at start).
- The log says the same, with the effects one per line. No line carries a secret.

## Part 2b: the web

### The client

`@openfeo/client` gains `config()`, `validate()`, `apply()`, `confirm()` and `revert()`, and the
state it already delivers carries what is pending. Nothing else about the wire changes.

### The draft

The panel holds **one draft for the whole config**: the typed config as `Get` returned it, with
its tag. Every page edits its own fields of that one object, which is how everything the panel
does not show survives. What has changed is the difference between the draft and what it was
read from; the bar at the foot of every settings page counts it and offers Discard and Apply
changes.

- The draft lives in the tab's memory. It survives moving between pages and does not survive a
  reload; leaving the page with changes unapplied asks first.
- When the router's config changes under a draft (another tab applied something), the panel
  reads the new config and says so. A draft with nothing in it follows silently. One with changes
  keeps them and must be reviewed again before it is applied.
- When a change is reverted, by the timer or by hand, the changes are still there as a draft.
- Fields are checked as the person leaves them, by the same rules the router uses where the
  panel can know them (a CIDR, a MAC, a range), and the whole draft is validated by the router
  before the dialog opens. A violation is shown at its field, found by the path the router gives.

### The WAN page

A tab per WAN, with its state beside its name; Add WAN; Remove at the foot.

- **Connection.** The type, as three radio choices (DHCP, PPPoE, Static), each showing its own
  fields. PPPoE: username, password (empty, saying "unchanged"; typing sets a new one). Static:
  address, gateway, DNS servers. DHCP: nothing to fill in. Advanced: for PPPoE the service name
  and the concentrator name; for DHCP the hostname sent and the vendor class sent.
- **Port.** The port (each with its link and speed; one in use elsewhere says where), the VLAN
  tag (empty for none), the priority.
- **IPv6.** On or off; a routed prefix. Advanced: the length to ask for, a typed gateway.

### The LAN & DHCP page

A tab per LAN, with its client count; Add LAN; Remove at the foot.

- **Network.** The router's address, the subnet's size (with the range it gives), the member
  ports as ticks over the ports that are free or already this LAN's. Tagged members are listed
  and not editable.
- **DHCP.** On or off; pool start and end; lease time; DNS servers and NTP servers handed out
  (empty for the router itself).
- **Reservations.** A table edited in place: name, MAC address, address; add and remove. A
  reservation that matches by client identifier is shown and kept.
- **IPv6.** On or off; advertisements on or off. Advanced: its own routed /64, its number within
  a delegated prefix.
- What the LAN may reach is shown as a line and edited on the Firewall page (part 3).

**Everything in the old subnet follows the LAN.** When the router's address or the subnet's
size changes, every IPv4 address in the config that lay in the old subnet is moved to the same
place in the new one: the pool's bounds and the reservations on this page, and, on pages this
part does not have, port forward targets, rule targets, DNS records, and DNS or NTP servers
handed out that sit on the LAN. Each field on the page says what it was; everything moved is in
the dialog's list, the ones from elsewhere by what they are ("port forward tcp 8080 to …"). One
that does not fit the new subnet is marked for the person to fix. This is one pure function
over the draft, and a test holds it to every address field the schema has, so that a field added
later is not forgotten.

**Removing a LAN that something still points at is refused**, naming what is in the way (a
forward, a rule, another LAN that may reach it), until the pages that edit those exist.

A violation whose path has no field on these pages is listed above the form with its path and
the router's message. Nothing the router refuses is ever silent.

A field that differs from the router's config says what it was.

On a router running on defaults because it refused its file, both pages show the running config
and cannot change it, and say why, beside the problem the dashboard already shows.

### Applying

Apply changes validates the draft and opens a dialog:

- the changes, as before and after;
- what they interrupt, from the router's effects;
- when the change moves the caller (either of the router's two facts): a warning that it moves
  the address being used to reach the router or the subnet this device is on, to renew the DHCP
  lease or change the static address, and where to come back to (the router's name, and its new
  address);
- "You have 2 minutes to confirm once it is applied. If you don't, the router goes back to how
  it was.", the time being the router's default;
- the tick box **"Apply immediately, no confirmation countdown"**, clear every time. Ticked, the
  sentence above gives way to one saying nothing will undo the change by itself, and the button
  becomes the design system's destructive one, labelled "Apply immediately".

While a change is pending, **every page in every session** carries a banner: that a change is
waiting, when it was applied, the time left counting down, Confirm and Revert now, and the
router's effects for anyone who asks what changed. (The mockup's banner counted the changes;
another session has nothing to count them from.) Apply is not offered until it is settled. When
the time runs out the banner gives way to one that says the router went back to how it was and
that the changes are still there as a draft.

A tab opened by name comes back by itself once the client has an address again: the client
library is already reconnecting, the session still stands, and the banner is there. A tab opened
by address cannot; the dialog has told the person where to go, and after logging in there they
find the same banner.

### Components and navigation

`@openfeo/ui` gains the components the pages need, each over classes the design system already
has and by its guideline: form section, save bar, dialog, choice, toggle, select, tabs. The
"Advanced" disclosure has no class in the design system; it goes into `web/ui/additions.css`
with a line in `gaps.md`, like the two before it.

The sidebar gains a group, Network, with WAN and LAN & DHCP. The gate screens are unchanged.

## Proven

In the harness, from the LAN namespace, by the Rust API client unless it says otherwise:

- **SPEC §12's own.** The LAN's subnet is changed with a short window and not confirmed: the
  router answers at the new address, then, the window over, at the old one; the pending file is
  gone; `config.reverted` says the time ran out; `config.toml` never changed. The lab's config
  has a port forward into that LAN, so the config sent has its target moved too, and the forward
  works at the new address while the change stands.
- **Confirm from the new address.** The same change; the LAN host takes an address in the new
  subnet; the same token confirms, by the router's name; `config.toml` has the new subnet and a
  reboot comes up on it.
- **Immediate.** No pending file at any moment; the file is the new config at once.
- **A restart during the window** (the VM reboots): the pending file is gone, the old config
  runs, `config.discarded` is in the backlog.
- **Only what changed.** With a DHCP WAN up, a reservation is added on the LAN: the WAN's "up
  since" and lease are untouched and no `wan.*` event is emitted. The same over PPPoE: the
  session id is the same after as before.
- **A WAN changes type while running**: DHCP to PPPoE on the lab's ISP, and back; then a VLAN
  tag added and removed. Each time the WAN comes up and the facts of the type it left are gone
  from the state.
- **A LAN is added and removed while running**: a client on the new LAN gets a lease; after the
  removal its bridge and its firewall zone are gone.
- **Leases.** A client that renews during a window holds a lease no longer than the window. A
  client with a lease from before a change keeps its address after a revert.
- **Refusals.** An invalid config changes nothing and returns its violations; an apply against a
  stale tag is refused; a second apply and a password change are refused while one is pending;
  an apply is refused on a router that booted over a file it refused, and the file is untouched.
- **The caller.** A validation of a subnet change, asked from the LAN it changes, says so and
  names the new address; asked over IPv6 by name it says the LAN changes and not that the
  connection drops; asked from another LAN it says neither.
- **Secrets.** `Get` returns none; an apply with the PPPoE password left empty keeps the session
  working; neither the log nor any answer carries one.

`@openfeo/client`'s own tests run the config calls against the VM. Playwright, in the LAN
namespace: edit the pool and add a reservation, see the count in the bar, open the dialog, apply,
see the countdown, confirm, find the reservation in the router's config; apply and revert by
hand; change the subnet and see the warning with the new address and the port forward listed
among the changes; add a LAN and remove it; with the router's default window shortened for the
run, let one run out with the page open, and find the draft still there. A screenshot of each
new screen in both themes joins part 1's.

The pure parts are unit-tested where they live: the slices and `effects` in `openfeo-reconcile`
(a property test that an unchanged slice never yields an effect, and that `effects(a, a)` is
empty), the keeper's states against a clock it is handed, the draft and the "follows the subnet"
rule in the panel.

No parser is added: a config arrives as the same protobuf the envelope already carries. The
envelope's fuzz target takes the new requests into its corpus.

## SPEC amendments (the plan's first task)

- §1.2: LANs are added, removed and edited in the panel; LAN VLANs stay in the file only.
- §2: the commit-confirmed apply defaults to 120 s. ADR-0026 first.
- §5.5: the window; the immediate apply; what is refused while a change is pending; that any
  start of the router process discards a pending file; leases during the window and after a
  revert.
- §6.3: the families that follow the config, and what stopping a task means.
- §8.3: `ConfigService`'s calls as built; the tag; write-only secrets; `Backup` and `Restore`
  stay with M5.
- §8.4: the two pages; the draft; the apply dialog and the countdown.
- §10: the `config.*` events; what the state says is pending.
- §12: M4's part 2 as 2a and 2b, each with its acceptance.
- `CLAUDE.md`: what the harness gains.

## ADRs

- **ADR-0026: commit-confirm waits 120 s by default.** SPEC §2 says 60 s. A change that moves
  the router's address needs the client to take a new lease and get back to the panel inside the
  window; 60 s is not enough for a person doing it by hand.
- Kernel and protocol quirks found on the way get their own, as before.

## What is left to the builder

- How a task is asked to stop and how long it is given; how a manager is written once for five
  families or five times; how a stopped task's facts are taken out.
- Where each slice lives and its exact fields; the wording of each effect.
- How the tag is computed (a counter, a digest of the rendered config).
- Message names, field numbers, error codes and their text; whether a validation and the
  dialog's preview are one call or two.
- How the lease database is kept through a window so that a revert finds the old leases.
- How the keeper is reached from the API, and where it sits in the supervisor.
- How the panel maps a violation's path to a field, counts changes, and lays out a narrow
  screen; whether the settings pages share one form model.
- How the harness's LAN host takes an address in a new subnet (its DHCP client, or a static
  change), and how a Playwright test asks for it. The browser's resolver rule is fixed when it
  starts, so the return **by name** is proven at the API and the return **by address**, with its
  certificate warning and second login, in the browser.

## Calls made for the maintainer

1. **Two pull requests, 2a and 2b.** Cost: 2a lands a service with no page that uses it, as 1a
   did.
2. **The whole config becomes live, not only what these two pages edit.** Part 3's pages then
   need no router work of this kind. Cost: 2a is larger than the two pages alone would need.
3. **An apply answers when the config is accepted and published.** What the kernel then refuses
   shows as health and events, as it does at boot, and is not the call's error. Cost: a change
   that validates and still fails is seen a moment later, not in the dialog; with "apply
   immediately" nothing undoes it.
4. **No apply and no password change while a change is pending.** Cost: up to two minutes in
   which the person must settle one change before making another.
5. **Leases are capped at the window while a change is pending.** Cost: clients on that LAN
   renew a few times more than they would; in exchange a revert strands nobody for hours.
6. **The router, not the panel, says what a change interrupts and whether it moves the
   caller.** Cost: a validation call does more than validate.
7. **A full apply writes the config as the router renders it.** Comments and layout in a file
   written by hand are lost the first time the panel applies over it. The first time that
   happens the file as it was is kept beside it. Cost: someone who keeps notes in the file loses
   them from the live copy; keeping them would mean editing the file's text in place for every
   kind of change.
8. **The draft is not stored.** A reload loses unapplied changes, after asking. Cost: a draft
   lost to a closed tab; storing it would put a typed PPPoE password in the browser's storage.
9. **A name is fixed when a WAN or LAN is added.** Cost: renaming means removing and adding.
10. **Removing the WAN or the LAN you are connected through is allowed**, with the warning.
    Cost: one more way to cut yourself off, behind the countdown.
11. **What a LAN may reach is shown here and edited on the Firewall page** (part 3), and tagged
    members are shown and not edited, as the milestone's design had it. Cost: a new LAN gets the
    default (it may reach the WAN) until part 3.
12. **Reservations are edited on the LAN page**, since they are config; the milestone's design
    had put them with the live lease table in part 3, which keeps the table.
13. **The pool and the reservations move with the subnet too**, by the same rule as the
    maintainer's for forwards, rules and records, and so do DNS and NTP servers handed out that
    sit on the LAN. Cost: a pool the person meant to leave where it was is moved, and says so.
14. **The window can be set per request, 10 s to 600 s, and the panel always uses the
    router's default**, which a harness build may shorten. Cost: nobody can ask the panel for a
    longer one; one more knob that exists only in harness builds.
15. **Any session may confirm or revert.** Cost: none while there is one admin.
16. **The "Advanced" groups** hold what most people never set: service and concentrator names,
    hostname and vendor class sent, the prefix length asked for, a typed IPv6 gateway, a LAN's
    routed /64 and its number in a delegation. Cost: a setting one click further away.
17. **No apply over a refused file.** A router that fell back to defaults because it refused
    `config.toml` shows its pages read-only. Cost: such a router cannot be put right from the
    panel in this part; the file is mended by hand, as today. The alternative replaces the
    owner's file on a confirm.
18. **"Moves the caller" is two facts**, the connection dropping and the caller's LAN changing
    its IPv4 subnet, and either raises the warning. Cost: someone connected over IPv6 is warned
    about a change their own tab survives.
19. **The banner does not count the changes**; it offers the router's account of them instead.
    Cost: the approved mockup's "3 changes are waiting" becomes "A change is waiting".
20. **Removing a LAN that something still points at is refused**, with what is in the way
    named. Cost: such a LAN cannot be removed from the panel until part 3; dropping the
    forwards and rules with it would be the panel deleting firewall config nobody was shown a
    page for.

## After part 2a

What building the router half settled or changed. Part 2b plans from this section as well as
from the design above.

**As built, where the design left it open or said otherwise**

- The request's field is `immediate`, not `commit_confirm = false`: a protobuf `bool` left out
  is `false`, so a request that says nothing gets the countdown.
- The keeper lives in `openfeo-api`, a core with no clock or file of its own and a driver
  beside it. What is pending is a fact in the World, which the state and the DHCP server's
  lease cap both read.
- A refused apply is `INVALID_ARGUMENT` whose text names up to five violations; a validation
  returns them all, each with its path.
- The tag is a digest of the config without its secrets and without the admin table, so
  setting a password moves no tag. It is opaque: the client sends back what it was given.
- `GetConfig` also carries the router's default window (`confirm_secs`), for the dialog's
  wording. The state's JSON name is `pending_config`, as every state field keeps its proto name.
- The file as it was is kept beside the config (`config.toml.orig`) the first time the router
  writes over a file with a comment in it, and not otherwise: the router's own rendering after
  a password change differs from a fresh one and is nobody's hand-written file.
- A router with no config file at all takes an apply; only a refused file refuses.
- A window out of range is refused for an immediate apply too. A password change while a
  change is pending is refused before the old password is looked at, so it costs no attempt.
- A changed domain restarts the LAN's DHCP server as well as renaming the router: the server
  hands the domain out.
- What stopping means, family by family: the DHCPv4 client releases a lease it holds (not one
  it is still confirming after a reboot) and forgets the stored lease, so that its successor
  begins with a DISCOVER and does not ask a server for a lease it was just given back; PPPoE
  sends Terminate-Request and PADT, cut short at three seconds against a concentrator that
  says nothing; the router-advertisement and DHCPv6 clients say nothing and their facts go.
- A DHCPv4 server that is restarted keeps its LAN's leases in the World (no lease is
  reported released and granted again), writes its file as it stops, and holds the records it
  cannot use on its own clock, so that neither a restart nor a revert loses leases to a wall
  clock that SNTP has just stepped.
- Each of apply, confirm and revert runs to its end once begun, whoever is still waiting for
  it, and a confirm writes `config.toml` whole from what the keeper holds, so it can be asked
  again. An API task restarted by the supervisor while a change is pending goes back to the
  confirmed config at once (`config: reverted (the API restarted before it was confirmed)`):
  its timer and every session that could have confirmed went with the old task.
- DNS and time bind their sockets again in place when the LANs change, which is no failure of
  theirs, and serve the LANs that exist whether or not a cable is in. The DHCPv4 server keeps
  the lease records it cannot use under the config of the moment, which is what lets a revert
  give every client back the address it had.
- The lease cap is its own setting beside the lease time: leases restored from the file keep
  the time they were given.
- On the console a change is said before what it sets off: `config: applied; confirm within
  <n> s` or `config: applied immediately`, one `config: effect <subject> <what>` per effect,
  then the tasks' own lines (`wan <wan> dhcp stopped`, `pppoe <wan> stopped`, `wan <wan> ipv6
  stopped`, `dhcp6 <wan> stopped`, `lan <lan> dhcp stopped`); later `config: confirmed`,
  `config: reverted (asked)`, `config: reverted (not confirmed in <n> s)`, or at the next start
  `config: an unconfirmed change was discarded`.

**For part 2b**

- **An apply that takes away the address it arrived at may never be answered.** The call
  answers once the config is published (call 3 above), and the router's old address can be
  gone before the answer is out; the lab met it within three runs. A refusal is always
  answered, since nothing moved. The client must not wait on the answer of an apply
  whose validation said `connection_drops`: no answer means taken. It finds the router at
  `router_after`, and reads the pending change, the countdown and the new tag there. The same
  holds for a revert asked at an address the pending change gave the router: the address goes
  with the change. Answering before publishing is possible on the WebSocket (the reply
  written, then the publish, with the keeper held across both) and would make the answer
  likely, not certain; gRPC cannot tell when its reply has left. It changes call 3 above and
  is left to the maintainer.
- The browser run cannot name a window in the apply, because the panel always uses the
  router's default (call 14): a harness build takes `openfeo.confirm_secs=<10..600>` on the
  kernel command line.
- A caller on a LAN the change leaves alone is still told its LAN and the router's address on
  it; the two booleans say whether anything moves.

**Known limits, found by the scenarios**

- **A change that takes a WAN's own link away can cut the old task's goodbye short.** The
  appliers and the task managers both follow the World, and nothing makes an applier wait for
  the stop of the task that is using a link. Fixed for a WAN that changes type on the same
  port: the port keeps its MTU until a PPPoE session has been ended in order (the kernel
  drops every PPPoE session on a port whose MTU changes), and keeps the leased address until
  a DHCPv4 lease has been given back (its routes go at once, so a release to a server that is
  not on the link may be lost). Still open: a WAN that is removed, or moved to another port
  or tag. Its port is set down, or its sub-interface deleted, at once: a PPPoE session gets
  neither its Terminate-Request nor, reliably, its PADT, and the concentrator learns from its
  own echoes; a DHCPv4 lease is not given back and runs out by itself. Where an ISP allows
  one session per account, a WAN removed and put back (or the revert of a removal) may wait
  for the concentrator to give the old session up. Ordering the appliers after the stops is a
  change to the shape above: the keeper would announce a change, the managers stop what it
  touches, and only then is the config published.
- For as long as a stop takes, the World holds the new config beside the stopping task's
  facts. On a tag change the old lease's address and routes sit on the new interface for some
  milliseconds.
- A WAN changed from PPPoE to static keeps the port's MTU at 1508 until a reboot: a static
  WAN's MTU is left as the kernel has it, which used to mean 1500.
