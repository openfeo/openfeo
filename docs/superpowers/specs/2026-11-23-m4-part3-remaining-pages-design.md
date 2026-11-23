# M4 part 3: the remaining pages

Design for the third part of milestone M4 (SPEC §12). Part 1 gave the router an API, a client and
a panel that reads; part 2 let the running router take a new config and gave the panel the WAN
and LAN & DHCP pages. This part builds the pages that are left: Leases, Firewall, DNS, Routes,
Ports, Logs and System, and makes the dashboard answer the two questions its owner opens it for.

The milestone's shape, its layers and its rules are in
`docs/superpowers/specs/2026-11-10-m4-api-and-panel-design.md`, and how a page changes config is
in `docs/superpowers/specs/2026-11-11-m4-part2-changing-config-design.md` ("After part 2b", "For
part 3"). Neither is repeated here.

It comes out of a brainstorm with the maintainer on 2026-11-22 and 2026-11-23, with all eight
pages mocked up in his design system's own styles and approved as shown (the mockup was throwaway
and is not in the repository). What he decided is listed first, in his terms. Every other choice
is the author's and is listed under "Calls made for the maintainer" at the end, each with what it
costs if wrong.

## Decided in the brainstorm

- **What he opens a router's panel for**, in his words: "Often im checking what recent DHCP
  leases were granted (to find devices IPs to configure them), and im also often just logging in
  to check general status (is pppoe down, is the line maxxed out etc)". The part is cut and
  ordered around those two.
- **The router keeps a short history of its counters**, so that the dashboard opens with the last
  hour already drawn. He chose this over a chart that starts empty when the page is opened,
  knowing what it costs: the router reads its counters every second whether or not anyone is
  looking, and one sentence of SPEC §10 changes.
- **The pages, and what each holds**:
  - Dashboard: the hour's chart for each WAN with its peak, and the newest five leases. No
    "percent of the line": the router does not know the line's speed until M6's shaping.
  - Leases: every device that took an address, newest first.
  - Firewall: which network may reach which, port forwards, rules, and whether the router
    answers ping from the internet.
  - DNS: the WAN's resolvers or typed ones, local names, and the rebinding exceptions under
    Advanced.
  - Routes and Ports: views, with nothing to edit.
  - Logs: live, filtered by level and by text, with pause and download.
  - System: hostname, domain, time servers, whether the clock is set, changing the password,
    restarting, and the version, uptime, certificate fingerprint and licence notices.
- **Left out, each for its reason**: block lists (the router has none; the config field must be
  empty), the time zone (nothing reads it and the image has no zone data), renaming ports, the
  raw ruleset (with part 4's dumps), updates and backup (M5).
- **The cut**: three slices by what he uses, each with its own router work and web work, in this
  order: status and leases; the settings pages; the views. He chose it over a router half
  followed by a web half, as parts 1 and 2 were (see Approaches).
- **A device that comes back has not joined again.** One plugged in at 09:00, unplugged, and
  plugged in again at 15:00 while its lease still runs keeps "Joined 09:00" and does not move to
  the top. He chose it over counting every fresh ask as a joining, which would put every phone
  that wakes or roams at the top and bury the devices that are new, and over keeping a second
  time, "last connected", beside the first.
- **Restart stops in order.** In his words: "stop the session cleanly and write leases". Before
  it restarts, the router ends its PPPoE sessions as the protocol asks and writes the lease
  files. He chose it over a bare sync and reboot, which is what a power cut does.

Approved from the mockup, as shown:

- **Leases is a page of its own** in the sidebar, under Network between LAN & DHCP and Firewall.
  One table for every LAN, newest first, with a filter box and a choice of LAN. Its columns are
  Joined, Address, Name, MAC, LAN and Expires. **Reserve** on a row puts a reservation among the
  changes waiting to be applied.
- **Joined** is when the device first took the address, not when it last renewed.
- **The chart** has a range of `5 min | 1 h`, marks where the WAN reconnected, and the hour's
  peak stands under the Download and Upload tiles.
- **Firewall**: a grid of ticks, a row per LAN and a column for the internet and each other LAN;
  forwards and rules edited in place as tables; a LAN that forwards or rules point into can be
  removed once they are removed, in the same set of changes.
- **DNS** shows which resolvers are in use now and where each came from.
- **System** changes the password at once, outside the apply flow, and Restart asks first. The
  time servers are one field, separated by commas. The panel shows times in the browser's zone.
- **Logs**: each level shows itself and everything more serious; the page says that a restart
  clears the log.

## Intent

The panel can set up a WAN and a LAN and nothing else, and its dashboard shows this second and
no other. The person it is for wants to plug a device in and find its address, and to glance at
the router and know whether the line is up and whether it has been full. Both are one screen
away once the router remembers a little: when each device joined, and what the counters were for
the last hour.

The rest of the part is the pages a router's panel is expected to have. Most of what they need is
already in the config or the state; where it is not, the router gains a call, and each call is
built in the same slice as the page that uses it, so that the page is the call's first test.

## Goals

- The dashboard opens with the last hour of each WAN drawn, the hour's peak, and where the WAN
  went down and came back.
- A device that joins is on the dashboard and at the top of the Leases page within a second or
  two, with its address, name and MAC, and can be given that address for good in one press.
- Firewall, DNS and System edit every field the config has for them (but the two left out
  above), through part 2's draft, dialog and countdown.
- The password is changed and the router restarted from the panel.
- Routes, Ports and Logs show what the router is doing, live where it changes.
- Every new call is on the WebSocket and on gRPC, and in `@openfeo/client`.
- Each slice is proven in the harness from the LAN side: the calls by the Rust client, the
  client's own tests under Node, and the pages in Playwright's Chromium against the VM.

## Non-goals

- New config fields. The pages edit what `proto/openfeo/v1/config.proto` has today.
- A history of anything but the interface counters, or of more than an hour, or one that
  survives a restart.
- "Percent of the line", shaping, CAKE statistics (M6).
- IPv6 devices on the Leases page: they choose their own addresses (SLAAC) and the router keeps
  no table of them. The neighbour dump is part 4's.
- Releasing or ending a lease from the panel.
- Block lists, the time zone, renaming ports, updates, backup and restore, factory reset.
- The raw ruleset, the rule and neighbour dumps, ping, traceroute, capture, the support bundle
  (part 4). Only the routes are read here, because Routes is a page.
- Editing LAN VLAN members and public IPv4 blocks. They stay in the file.
- Sorting a table by a column the person picks. Leases are newest first and filtered.

## Anti-goals

- **A dashboard that lies about the last hour.** A stretch with no samples is drawn as a gap,
  not as zero and not joined across. A counter that restarts with a new interface gives no rate
  for that second, as now.
- **A "Joined" that moves when nothing happened.** A renewal does not change it, and neither
  does a restart of the router: one asked for from the panel writes the leases first, and a
  power cut can cost only those granted in its last five seconds.
- **A lease table that drops a device.** What the page shows is what the DHCP server holds; a
  table too large for one message is cut at its oldest end and says that it was cut.
- **A secret on a new road.** No password, token or hash reaches a log line, an error, a `Debug`
  output or a log sent to the panel. The password fields are in no draft, no store and no
  storage; they are emptied when the change is made and when the page is left.
- **A restart by accident, or by a stranger.** Restart asks first, says what it interrupts, and
  the call needs a session like every other.
- **A log feed that feeds itself.** Sending log lines to a subscriber writes no log line.
- **A panel that drops what it does not show** (the milestone's rule): the new settings pages
  send back the whole config with only their own fields changed.
- **A page that edits what is another page's.** "May reach" is changed on Firewall and shown on
  LAN & DHCP; a reservation is edited on LAN & DHCP and may be added from Leases.

## Constraints

What exists on `main` today and bounds the design:

- **Leases.** Each LAN's DHCPv4 server publishes its leases into the World (`world.leases`, a
  `LeaseFact` with address, MAC, name and wall-clock expiry). The server's record
  (`LeaseRecord`, `openfeo-proto-dhcp4`) has `granted_at`, which is set to now at every renewal;
  the lease file (`Dhcp4ServerLease`) keeps `granted_unix` and `expires_unix`. The core already
  tells a first grant from a renewal (`ServerEvent::Renewed`). `State` carries a count of leases
  per LAN and no more. The events `lan.<name>.lease.granted` and `.released` are derived from
  two Worlds by MAC, address and name, so a renewal makes no event.
- **Counters.** `openfeo-api`'s telemetry task reads each link's counters and the conntrack count
  once a second, and only while a subscriber wants them (`telemetry.rs`; SPEC §10 says so in as
  many words). The client computes rates from two samples (`web/client/src/rates.ts`), and the
  dashboard's sparkline starts empty when the page is opened.
- **Events.** The API keeps the last 256 events for a subscriber's backlog. An event carries the
  wall time and the time since the kernel booted.
- **The log.** `openfeo_runtime::log::Ring` holds formatted lines (`<pri>prefix: message
  key=value`), DEBUG and above, 8 MiB of text, oldest dropped first. A line has no time and no
  number, and nothing can wait for the next one. The API does not see the ring.
- **Restart.** The control pipe from the router child to PID 1 already has `Msg::Reboot`, and
  PID 1 syncs and reboots on it, and does no more. Nothing in the router child sends it, and the
  child has no way to stop in order. What exists is one task's stop (SPEC §6.3): a family's
  manager asks a task to stop and gives it 3 s to say goodbye. A PPPoE session stopped so sends
  its two Terminate-Requests and its PADT. A DHCPv4 server writes its lease file, which it
  otherwise writes at most once in five seconds. A DHCPv4 client releases its lease and forgets
  it. Sessions of the API live in memory, so none survives a restart.
- **Routes.** The netlink monitor's cache holds every route of every table and both families.
  The World carries only the default routes. A WAN's own table is `100 +` its place in the
  config (`reconcile::routing::wan_table`).
- **Resolvers.** Which upstreams the forwarder asks, in order, is already a pure function of the
  World (`reconcile::dns`): the typed ones, then the active WAN's unless switched off.
- **The API.** `AuthService` (with `ChangePassword`, which ends every other session and is
  refused while a change of config is pending), `StateService` and `ConfigService`. Topics
  `state`, `counters` and `events`; `state` and `counters` are coalesced, `events` queued 256
  deep. A frame is at most 1 MiB. Plain HTTPS calls carry the token as `Authorization: Bearer`,
  so a link cannot carry it. SPEC §8.3 already names the services this part begins: `System`
  (Reboot, Logs) and `Diagnostics` (DumpRoutes), and the topics `leases` and `log tail`.
- **The state.** `SystemState` has the version, uptime, `time_synced` and the certificate's
  fingerprint; `PortState` has the bus path, MAC, carrier, speed and uses; `LanState` has
  `reaches`. The Ports page and System's About need nothing new.
- **The config.** `Firewall` (forwards, rules, `wan_ping`), `Lan.reaches`, `Dns` (upstreams,
  `use_wan_dns`, records, `rebind_allow`; `blocklists` must be empty), `System` (hostname,
  domain, `timezone`, `ntp_servers`). A reservation may lie inside the pool.
- **The panel.** A page is a child route of the shell and injects `LIVE` and `CONFIG`; a
  settings page is made of `SettingField` and `SettingCell` with the router's own path per
  field. `model/lan.ts` (`blockers`) refuses to remove a LAN that a forward, a rule or another
  LAN's "may reach" points into, because no page could remove those. `@openfeo/client` already
  has `changePassword`; no page calls it.
- **The components.** `@openfeo/ui` has twenty-seven. The design system documents a throughput
  chart, a segmented choice, a code block and an empty state (`web/ui/docs/components/`), and
  `ofo.css` styles them, but no Vue component exists for them yet.
- **Notices.** `/licences.txt` carries the npm packages' and the fonts' notices, written by the
  panel's build. The Rust crates' and the C libraries' are not in the binary;
  `docs/third-party.md` stands in. SPEC §13 names `cargo about` for them.
- **The page's content security policy** is `default-src 'self'` with no inline script, no
  `style` attribute and no `data:` URL.
- Workspace rules stand, as in the milestone's design.

## Approaches

Three ways to cut the part were put to the maintainer.

1. **By what he uses: three slices, each with its router work and its web work** (chosen).
   Status and leases; then the settings pages; then the views. The two things he opens the panel
   for land first, and the riskiest router changes (counters read all the time, the lease file
   gaining a field) land beside the page that proves them. It costs three rounds of plan, review
   and pull request, and each pull request holds Rust and TypeScript together, which no M4 pull
   request has done.
2. **A router half, then a web half**, as parts 1 and 2 were. Familiar, and each half is read
   under one set of rules. But nothing is seen until the second half, the second half would be
   the largest web pull request yet, and seven calls would be fixed before any page had used
   them.
3. **Looking, then changing: two slices.** Every read-only page with its router work, then
   Firewall, DNS and System. One round fewer than the first way, but its first slice carries
   nearly all the Rust and five pages at once.

He chose the first. One design (this one) covers the part; each slice has its own plan, branch
and pull request, and appends its entry to `docs/progress.md`.

## The shape of part 3

| Slice | Router | Web |
|---|---|---|
| **3a, status and leases** | The joined time, kept across renewals and in the lease file. Leases on the wire: a call and a topic. Counters read all the time, the last hour kept, a call for it. | The client's leases and history. `OfoChart`, `OfoSegmented`, `OfoEmpty`. The dashboard's chart, peaks and newest leases. The Leases page with Reserve. |
| **3b, settings** | The resolvers in use, in `State`. `SystemService.Reboot`, which ends the PPPoE sessions and writes the lease files before it restarts. The Rust and C notices in `/licences.txt`. | Firewall, DNS and System. A LAN can be removed once nothing points into it. |
| **3c, views** | `DiagnosticsService.DumpRoutes`. The log ring gains a time and a number per line; `SystemService.Logs` and the `logs` topic. | The client's routes and logs. `OfoCode`. Routes, Ports and Logs. |

Each slice leaves the panel whole: a page is in the sidebar when its slice lands and not before
(SPEC §8.4).

## Part 3a: status and leases

### Joined

A lease's **joined time** is when its device was first given the address it holds, in the
holding it has now. A renewal keeps it, and so does a device that asks again for the address it
still holds while its lease runs: one plugged in again, restarted, or back on the Wi-Fi. A lease
that ran out or was released and is taken again is a new joining, and so is a device that is
moved to another address.

- This is the line the server's core already draws between `Renewed` and `Granted`. Nothing new
  is told apart, and no kind of request is treated differently from today.
- The DHCPv4 server keeps it beside the lease and writes it to the lease file
  (`Dhcp4ServerLease` gains `joined_unix`), so a restart of the router keeps it. A file from
  before this part has none; its `granted_unix` stands in, which is the last renewal.
- A power cut can lose the leases granted in its last five seconds, as it can today: the file is
  written at most that often. Such a device is adopted when it next asks, and its joined time is
  then. A restart asked for from the panel loses none (part 3b).
- `LeaseFact` gains `joined_unix`, wall-clock like its expiry.
- The events are unchanged: a renewal is still no event.
- A device that joins before the clock is set (the first seconds of a boot with no clock chip)
  must not be stamped for ever with the build's date: its joined time is right once the clock
  is. Expiry already has this problem and solves it by keeping its own clock and stamping at
  publication.

### Leases on the wire

```proto
// One device holding an address from a LAN's DHCPv4 server (SPEC §7.6).
message Lease {
  string lan = 1;
  string address = 2;
  string mac = 3;
  // The reservation's name, else the one the device gave; empty for none.
  string hostname = 4;
  // When the device first took this address (wall clock, seconds).
  uint64 joined_unix = 5;
  uint64 expires_unix = 6;
}

message Leases {
  // The router's wall clock when this was built: ages are counted against it, not the reader's.
  uint64 time_unix = 1;
  // By LAN in config order, then by address.
  repeated Lease leases = 2;
  // More leases exist than are here; those that joined longest ago were left out.
  bool truncated = 3;
}
```

- `StateService` gains `GetLeases`, and there is a topic **`leases`**: the whole table when
  subscribed and after every change, coalesced as `state` is. gRPC's `Subscribe` takes it too.
- The table is a pure function of the World, built where `State` is.
- It holds at most 4096 leases, so that it fits a frame with room to spare. Beyond that the
  newest by joined time are sent and `truncated` is set.
- `State` keeps its count per LAN and gains nothing: a dashboard that wants the newest five
  subscribes to `leases`.

### Counters, all the time

- The telemetry task reads the counters once a second from when the API starts, with or without
  a subscriber, and keeps **the last hour** of every link's received and sent bytes with the
  time each was read. That is 3600 samples, about 60 KiB a link, in memory only.
- The router still computes no rates: it keeps what it read, and a client makes rates of it as
  it does of the live samples.
- `StateService` gains `GetHistory`. The request names the links; the answer carries, for each
  that the router has samples of, the times and the two byte counts, oldest first.

```proto
message GetHistoryRequest {
  // Kernel names, as `WanState.interface` gives them. At least one.
  repeated string links = 1;
}

message LinkHistory {
  string name = 1;
  // When each sample was read, on the clock of `Counters.monotonic_ms`; oldest first.
  repeated uint64 monotonic_ms = 2;
  // One per sample.
  repeated uint64 rx_bytes = 3;
  repeated uint64 tx_bytes = 4;
}

message GetHistoryResponse {
  repeated LinkHistory links = 1;
}
```

- A link that did not exist for a while (a PPPoE interface between sessions) has no samples for
  that while. A reader sees the gap in the times.
- The `counters` topic is as it was. A page asks for the history once, and again when its socket
  opens anew, and carries on from the live samples.
- What changes for the router: one link dump over netlink and two sysctl reads a second, for
  ever, where there were none while nobody watched.

### The client

- `subscribe('leases', …)` and `getLeases()`, `getHistory(links)`.
- Beside `rates`: a function from a link's history to its rates over time, by the same rule as
  the live one (a counter that went backwards gives no rate for that second; samples more than a
  few seconds apart are a gap), and one that averages those rates over buckets of a given length.
  Both are plain functions with no Vue in them, tested under Node.

### The components

`@openfeo/ui` gains three, each from the design system's guideline of the same name and each
taking plain props:

- **`OfoChart`** (ThroughputChart): two series over time, a legend with the current values, a
  slot for the range choice, grid and axis, dashed markers with a label, gaps drawn as gaps. It
  is given numbers and draws them; it knows nothing of counters.
- **`OfoSegmented`** (Segmented): one choice of a few, with an optional count beside a label.
- **`OfoEmpty`** (EmptyState): what a table says when it has no rows.

### The dashboard

Added to what part 1 built; the tiles, the interface cards, Ports, Addresses and Recent events
stay. From the top, as the mockup had it: the tiles; the charts; the interface cards; Newest
leases; then Ports, Addresses and Recent events as they are.

- **A chart for each WAN**, in config order, titled by the WAN's name, of its interface's
  download and upload. The range is `5 min | 1 h`, one choice for the page, 1 h at first. The
  five-minute view draws each second; the hour draws ten-second averages.
- **Markers** where that WAN went down and came back inside the range, from the `wan.<name>.down`
  and `.up` events, labelled with the time it came back ("reconnected 14:12").
- **The hour's peak** under the Download and Upload tiles: the highest ten-second average of the
  last hour, of the same links the tile's rate is of. It is the top of what the hour's chart
  draws, so the two cannot disagree.
- The tiles' sparklines are filled from the history at once and no longer begin empty.
- **Newest leases**: the five that joined last, across every LAN, with Joined, Address, Name,
  MAC and LAN, and a link "All _n_ leases" to the Leases page. With no lease yet it says so.
- A history that cannot be read leaves the chart saying so and the live line drawing from now;
  the rest of the dashboard does not wait for it.

### The Leases page

- One table of every LAN's leases, newest first: Joined, Address, Name, MAC, LAN, Expires, and
  what can be done.
  - **Joined** and **Expires** are said as ages ("2 min ago", "in 11 h 58 min"), counted against
    the router's own clock (`Leases.time_unix`, carried on by the browser between pushes), with
    the exact time in the browser's zone as the cell's title.
  - **Name** says "none given" when the device gave none. Address and MAC are in mono.
- **A filter box** narrows the rows as it is typed in, by address, name or MAC, without regard
  to case. **A choice of LAN** with each LAN's count shows when there is more than one LAN.
- A row that arrives while the page is open is marked as new for a minute.
- **Reserve** adds a reservation to the draft: that MAC, that address, and the lease's name if
  it has one, in that LAN's reservations. It goes through `store.edit` like any other edit, so
  the save bar counts it and the dialog lists it; Leases is therefore one of the shell's
  `settings` pages. The row then says "Reserved, not applied yet", and "Reserved" once the
  config has it. A reservation is edited and removed on LAN & DHCP, where they live.
- A lease whose LAN the draft has removed, or whose MAC or address the draft already reserves,
  offers no Reserve.
- Under the table, as the mockup has it: that a row appears by itself, that a named device is
  also found as `name.<domain>`, what Reserve does, and that IPv6 devices are not listed.
- A table that was cut says how many it shows.

## Part 3b: settings

### The resolvers in use

`State` gains what the forwarder is asking, in the order it asks:

```proto
message DnsState {
  repeated DnsResolver resolvers = 1;
}

message DnsResolver {
  string address = 1;
  // The WAN it was learned from; empty when it is one the owner typed.
  string wan = 2;
}
```

It is `reconcile::dns`'s own answer, so the page shows what the forwarder uses and not a second
opinion.

### Restart

- A new `SystemService` with `Reboot`. It needs a session. It answers, and about a second later
  the router begins to restart.
- **It stops in order first.** Every PPPoE session is ended as SPEC §7.2 has it (two
  Terminate-Requests, then our PADT), so the access concentrator knows the session is over and
  does not hold the account until its own echoes fail. Every LAN's DHCPv4 server writes its
  lease file, so a lease granted a moment before is not lost. Both are the stops those tasks
  already have. What is new is that all of them are asked at once and that nothing is started
  in their place.
- **It does not wait for long.** The tasks are asked together and given the 3 s that any stopped
  task is given (SPEC §6.3). Then the router child sends `Msg::Reboot` up the control pipe
  whether or not they finished, and PID 1 syncs and reboots, as it already does for that
  message. A port with no carrier, or a concentrator that does not answer, costs those seconds
  and nothing else.
- **Nothing else is stopped.** The DHCPv4 client is left as a power cut leaves it: stopped on
  purpose it would release its lease and forget it, and a router that restarts should come back
  to the address it had. No other task has a goodbye to say.
- It is logged at INFO with the address it was asked from.
- A change of config that is waiting to be confirmed is not confirmed by a restart: the router
  comes back on the confirmed config, as it does after a power cut.
- Only a restart asked for through the API stops in order. The watchdog's reboot, a power cut
  and a router child that died are as they were.

### Notices

`/licences.txt` gains the notices of every Rust crate in the binary and of the C libraries
linked into it (`docs/third-party.md`'s list), so that one file covers the whole binary. The
Rust side is written by `cargo about` at build time, as SPEC §13 has it, against the licences
`deny.toml` accepts. System's About links to it; the two gate screens already do.

### The Firewall page

A settings page in four sections.

- **Between networks.** A grid: a row per LAN, a column for the internet and for each other LAN.
  A tick lets devices on the row's LAN start connections to the column. It edits
  `lans[].reaches`: the internet is `wan`; a row with no tick is `none`; a LAN whose list is
  empty in the config is shown, and stays, as reaching the internet alone.
- **Port forwards.** A table edited in place: Name, Protocol, Port, To address, To port (empty
  for the same port), with Add forward and Remove. When the config has a public IPv4 block the
  table has one more column, the address a forward listens on.
- **Rules.** A table edited in place: Name, From (the internet or a LAN), To (an address, a
  range or a block), Protocol (TCP, UDP, ICMP or any), Ports (for TCP and UDP only; several,
  separated by commas, each one port or a range), with Add rule and Remove.
- **The router itself.** One toggle: answer ping from the internet (`firewall.wan_ping`).

What the page finds wrong as it is typed is what it can know without the router: a name that is
empty or used twice, a port outside 1 to 65535, an address that does not parse, ports on a rule
that is not TCP or UDP. Everything else is the router's to refuse, shown at the field by its
path.

**Removing a LAN.** `blockers` now reads the draft, and each thing it names is a link to where
it can be removed: a forward or a rule on Firewall, another LAN's tick in the grid. Once the
draft has none, the LAN can be removed, and the dialog lists the removals with it. The LAN & DHCP
page goes on showing "May reach" and saying where it is changed.

### The DNS page

- **Resolvers.** "Your own resolvers" (`dns.upstreams`): addresses, asked first, in order; empty
  to use the WAN's alone. A toggle, "Also use the resolvers the WAN gives" (`dns.use_wan_dns`,
  which is on when the config does not say). Beneath: "In use now", the resolvers from
  `State.dns` with the WAN each came from.
- **Local names** (`dns.records`): a table edited in place of Name and Address, with Add name
  and Remove. A name with no dot is under the router's domain, and the page says what it
  becomes. One name may have an IPv4 and an IPv6 address.
- **Protection.** A sentence on what the router does, and under Advanced, "Names let through"
  (`dns.rebind_allow`).

`dns.blocklists` is carried through untouched.

### The System page

- **Name.** Hostname and domain, in the draft like any setting. The section says that changing
  either gives the router a new certificate, and the dialog says where the router will then be
  found, as it does when an address moves.
- **Time.** A pill: "Synced" when the router's clock was set from the internet, "Not set yet"
  with what that means for the times on screen. The time servers (`system.ntp_servers`) are one
  field of names or addresses separated by commas. A line says that the panel shows times in
  the browser's zone. `system.timezone` is carried through untouched.
- **Password.** Current, new, and new again, with a Change password button. It is not part of
  the draft and the save bar does not count it: the change is made at once by
  `AuthService.ChangePassword`. What can be known in the page is said at the field (twelve
  characters at least, the two new ones alike); what the router refuses is said at the field it
  is about (a wrong current password, with the wait it earns). While a change of config waits to
  be confirmed the router refuses a change of password, so the section says so and its button is
  held. On success the fields are emptied and a notice says that every other session was logged
  out.
- **Restart.** A button and a dialog: every device loses the internet for about a minute; a
  change waiting to be confirmed goes back to how it was; and, when the draft has changes, that
  they are lost. After Restart the page says the router is restarting until it answers again,
  and is then at the login screen.
- **About.** Version, how long it has run, the certificate's SHA-256 fingerprint in mono, and
  "Open-source notices" linking to `/licences.txt`.

## Part 3c: views

### Routes on the wire

A new `DiagnosticsService` begins with the one dump a page needs, under the name SPEC §8.3 gives
it:

```proto
enum RouteKind {
  ROUTE_KIND_UNSPECIFIED = 0;
  ROUTE_KIND_UNICAST = 1;
  ROUTE_KIND_UNREACHABLE = 2;
  ROUTE_KIND_BLACKHOLE = 3;
  ROUTE_KIND_PROHIBIT = 4;
  // The kernel's own entries for its addresses, broadcasts and multicast.
  ROUTE_KIND_LOCAL = 5;
}

message Route {
  bool v6 = 1;
  // `main`, `local`, the name of the WAN whose table it is, or the number.
  string table = 2;
  // A block, `192.0.2.0/24`; empty for the default route.
  string destination = 3;
  // Empty when the destination is on the link.
  string gateway = 4;
  // Empty when the route has none.
  string interface = 5;
  // Who put it there: `kernel`, `openfeo`, `ra`, or the number.
  string protocol = 6;
  uint32 metric = 7;
  RouteKind kind = 8;
}

message DumpRoutesRequest {}

message DumpRoutesResponse {
  repeated Route routes = 1;
}
```

It answers every route the kernel holds, both families, every table, as the netlink monitor has
them. Part 4 adds the other dumps beside it.

### The log on the wire

- The ring keeps, with each line, a number that only grows, the time since boot, and its level.
  Something can wait for the next line. Its bound is still 8 MiB of text.
- `SystemService` gains `Logs`:

```proto
enum LogLevel {
  LOG_LEVEL_UNSPECIFIED = 0;
  LOG_LEVEL_ERROR = 1;
  LOG_LEVEL_WARN = 2;
  LOG_LEVEL_INFO = 3;
  LOG_LEVEL_DEBUG = 4;
}

message LogLine {
  uint64 seq = 1;
  // Since the kernel booted.
  uint64 uptime_ms = 2;
  LogLevel level = 3;
  // `prefix: message key=value`, without the priority.
  string text = 4;
}

message LogsRequest {
  // This level and everything more serious; unspecified means every line.
  LogLevel level = 1;
  // Only lines whose text holds this, without regard to ASCII case; empty for all.
  string contains = 2;
  // Only lines before this one; 0 for the newest.
  uint64 before_seq = 3;
  // At most this many, the newest that match; the router caps it.
  uint32 limit = 4;
}

message LogsResponse {
  // Oldest first.
  repeated LogLine lines = 1;
  // Older lines that match exist.
  bool earlier = 2;
  // The router's two clocks now, so that a reader can say when a line was written.
  uint64 uptime_ms = 3;
  uint64 time_unix_ms = 4;
}
```

- A topic **`logs`**: every line written after the subscription, in batches, with the two
  clocks. It is queued, not coalesced, and bounded as `events` is: a socket that falls behind is
  told so (`DATA_LOSS`) and keeps receiving.
- The level and the text are matched by the router over the whole ring for a call, so that
  "errors" finds the error from an hour ago and not only those among the last lines sent.
- A line's time on screen is worked out from the two clocks in the answer, so a line written
  before the clock was set is shown at its true time.

### The client

`dumpRoutes()`, `logs(…)` and `subscribe('logs', …)`, and the rule for whether a line matches a
level and a text, as a plain function that the router's rule is held to by shared test cases.

### The components

**`OfoCode`** (CodeBlock): lines in mono with dim, ok, warn and error parts.

### The Routes page

- A choice of `IPv4 | IPv6` and a table: Destination ("default" for the default route), Via
  ("on the link" when there is no gateway, "refused" for a route that turns traffic away),
  Interface, Belongs to.
- **Belongs to** is worked out in the page from the state: the WAN or LAN whose interface the
  route leaves by; for a route in a WAN's own table, that WAN; for a refused block inside a
  WAN's prefix, that WAN with what it is ("the part of its prefix no LAN uses").
- It shows the main table and the WANs' own, and leaves out the kernel's local table and the
  link-local and multicast entries every interface has.
- It is read when the page opens and again whenever the state changes while it is open.
- A view: a line says that routes follow from the WAN and LAN settings.

### The Ports page

- The port strip, and a table in port order: Port, Link ("Up 2500 Mbit/s", "No cable"), Used by
  (each WAN or LAN a link to its page, with its tag; "Not in use"), MAC, Hardware (the bus
  path), Received, Sent.
- Received and Sent are the port's byte counters since the router started, live from `counters`.
- Everything else is from `state`. A view: a line says where a port is given to a WAN or a LAN.

### The Logs page

- **Show**: `Errors | Warnings | Info | Debug`, each meaning that level and everything more
  serious; Info at first. **A filter box** for text.
- Changing either asks the router again (the text after a pause in typing) for the newest lines
  that match; "Earlier lines" at the top fetches the ones before. Lines that arrive live are
  matched in the page by the same rule.
- **Follow** by default: new lines appear at the bottom and the view stays there. **Pause**
  holds the view still; lines that arrive meanwhile are kept and counted on the button.
- Each line: the time (dim), the level as a word, the text. Warnings and errors are coloured;
  nothing else is.
- The page holds a bounded number of lines and drops the oldest while following. When the router
  says lines were skipped, the page says so in place.
- **Download** fetches the whole ring, every level, whatever the filter, and saves it as a text
  file named after the router and the time, each line with its time and level.
- Under the lines: that the router keeps about the last 8 MiB in memory, so a restart clears it.

## Proven

Each slice's plan turns these into tests. A change of the router is proven from the LAN side in
the `m4` harness suite; a page, in Playwright against the VM; and the rest by unit tests beside
the code. Each browser run leaves a screenshot of every new page in both themes in
`$(BUILD)/panel-shots`.

**3a**

- The server's core: a renewal keeps the joined time, and so does a device that asks afresh for
  the address it still holds; a lease taken again after it ran out, or on another address, has
  a new one. The lease file round-trips it, and a file without it reads
  with the granted time. A lease granted before the clock was set has the right joined time
  after.
- Telemetry: samples are read with no subscriber; the history holds an hour and no more; a link
  that was away has a gap.
- Harness: a LAN host takes a lease and `GetLeases` and the `leases` topic show it; after its
  renewal the expiry has moved and the joined time has not. With nobody subscribed for a while,
  `GetHistory` holds a sample for each second of it, and bytes sent through the WAN show in it.
- The client under Node: the leases subscription and the history, against the VM.
- Playwright: the dashboard is opened some time after the router came up and the chart is
  already drawn back to then; a device that joins appears in Newest leases without reloading; on
  Leases, Reserve brings up the save bar, the change is applied and confirmed, and the row says
  Reserved. The ISP is cut and returned, and the chart has its marker.

**3b**

- `State.dns` follows the WAN's lease, the typed resolvers and the switch (unit, and one harness
  scenario).
- The stop for a restart asks the PPPoE sessions and the DHCPv4 servers and no other task,
  starts nothing in their place, and gives up waiting at its limit (unit).
- Harness: `Reboot` without a session is refused. With one, the router goes down and comes back
  with a smaller uptime, the same config, and its leases with their joined times, among them
  one taken less than five seconds before the call. On a PPPoE WAN the access concentrator is
  told that the session is over before the router goes down; with the concentrator stopped, so
  that nothing answers, the router still restarts on time. A restart asked while a change is
  pending comes back on the confirmed config.
- `/licences.txt` in a built binary names a Rust crate, libnftables and an npm package.
- The pages' models: every check a page makes as typed, and `changes.ts` names for every new
  setting. Part 2b's test that alters every leaf of the schema still finds a change each time.
- Playwright: a forward is added, applied and confirmed, and the router's config has it; a LAN
  with a forward into it cannot be removed, and can once the forward is removed in the same
  draft; a local name is added and a lab host resolves it; the password is changed, the old one
  no longer logs in and the new one does; Restart asks, the page waits, and the login screen
  comes back.

**3c**

- The ring: numbers only grow, a waiter is woken by the next line, the level and text rule.
- Harness: `DumpRoutes` has the default route by the WAN and each LAN's subnet. `Logs` answers
  by level and by text and pages backwards without a gap or a repeat. A subscriber to `logs` is
  sent the line the router writes when the ISP is cut. After a wrong login and a right one, no
  line anywhere in the ring holds the lab's password or a token.
- The client under Node: routes, the log call and the feed.
- Playwright: Routes shows the default route as the WAN's; Ports shows a port up with its
  counters moving; on Logs the ISP is cut and its line appears without reloading, Errors hides
  it, the text filter finds it, and Download saves a file that has it.

No new parser arrives with this part: the lease file gains a field in a format that already has
its fuzz target, and the new messages are protobuf. If a slice does write one (the log rule is a
matcher, not a parser), it brings its target.

## SPEC amendments (each slice's first task)

- **§10** (3a): "Interface counters and the conntrack count are read once a second and only
  while a subscriber wants them; the router keeps no history and computes no rates" becomes:
  they are read once a second; the last hour of the interface counters is kept in memory; the
  router computes no rates.
- **§7.6** (3a): a lease's joined time, kept across renewals and in the lease file.
- **§6.3** (3b): a restart asked for through the API first stops the PPPoE sessions and the
  DHCPv4 servers, within the 3 s a stop is given, and leaves the DHCPv4 client running.
- **§8.3**: `StateService` gains `GetLeases` and `GetHistory`, and the topic `leases` (3a);
  `State` says which resolvers are in use, and `SystemService` begins with `Reboot` (3b);
  `DiagnosticsService` begins with `DumpRoutes`, `SystemService` gains `Logs`, and the topic
  `logs` (3c).
- **§8.4**: Leases is a page of its own, between LAN & DHCP and Firewall in the navigation (3a);
  how the Firewall, DNS and System pages are laid out, and that the password and a restart are
  outside the apply flow (3b); Routes, Ports and Logs (3c).
- **§12**: part 3 of the M4 row is three slices, each with what proves it.

## ADRs

None is expected. Nothing here departs from SPEC §2: the sentence that changes is §10's. If the
harness finds a kernel quirk (a reboot under QEMU, a route the monitor reports oddly), it gets
its ADR then.

## What is left to the builder

- How the joined time is held so that a restart keeps it and a clock set later corrects it: in
  the core's record or beside it in the driver.
- The shape of the history in memory, and whether the wire sends counts or differences.
- How the API task reaches the control pipe that the heartbeat task owns.
- The delay between `Reboot`'s answer and the stop; how the PPPoE and DHCPv4 server managers are
  told to stop their tasks and start none; what container mode does; and how the harness reads
  the goodbye on the concentrator's side.
- How `cargo about` is pinned, installed in CI and in `scripts/cloud-setup.sh`, and reported by
  `make check-env`; what a bare `cargo build` without it embeds.
- The ring's waiter, the cap on `Logs`'s `limit`, the size and pace of a batch on the `logs`
  topic, and how many lines the page holds.
- How Download saves a file under the page's content security policy (a Blob and a link with
  `download` needs no change to it; the browser run proves it).
- The chart's drawing: its scale (the design system asks that it stay still), its ticks, how a
  gap is drawn, and how long a gap between samples must be to count as one.
- Which of the lab's hosts joins during the browser run, and the lab verbs the new runs need.
- The names of files, routes, models and tests, after the patterns of part 2b.

## Calls made for the maintainer

Each is the author's, with what it costs if wrong.

1. **What ends a joining.** That a device coming back while its lease runs has not joined again
   is his decision (above). The rest is the author's: a lease that ran out or was released and
   is taken again counts as joining anew, and so does a move to another address. Cost: a
   device that sleeps past its lease looks newly joined when it wakes, which is noise among the
   newest; the other way, a device unplugged for a month would return with a joined time a
   month old and not be found at the top.
2. **An old lease file's last renewal stands in for its joined time.** Cost: on the first boot
   of this version, every device looks as if it joined at its last renewal, until it truly
   joins again. It mends itself and happens once.
3. **Leases travel as their own topic, whole, and not inside `State`.** Cost: one more
   subscription for the panel; inside `State` they would have made every push of the state
   carry every lease.
4. **At most 4096 leases in one answer.** Cost: a LAN with more shows its newest 4096 and says
   so. A router for a home does not reach it.
5. **The history is counters, for every link, for one hour at one second.** Cost: about 60 KiB
   a link held for ever, and a chart that cannot go back further. Rates or coarser samples
   would be smaller and could not serve the five-minute view or a client's own arithmetic.
6. **The hour is drawn in ten-second averages, and the peak is the highest of them.** Cost: a
   burst shorter than ten seconds shows lower than it was. A one-second peak would call a line
   full that was full for a second.
7. **The chart's markers come from the last 256 events.** Cost: on a LAN where more than 256
   things happen in an hour, an early reconnect loses its marker; the gap in the line is still
   there.
8. **Reserve reserves by MAC**, with the lease's name, and is undone on LAN & DHCP. Cost: a
   device that changes its MAC (a phone's private address per network does not; one set to
   rotate does) loses its reservation, as with any reservation by MAC.
9. **No new plain HTTP call.** The new calls are on the socket and on gRPC only. Cost: reading
   leases or routes with `curl` needs a gRPC tool.
10. **The address a forward listens on is a column only when the config has a public block.**
    Cost: none seen; without a block the field must be empty.
11. **A LAN stays refused until the draft has nothing pointing into it**, and is not removed
    together with its forwards and rules. Cost: a few more presses to remove a LAN; the other
    way deletes firewall config on the strength of one press elsewhere.
12. **A rename's way back is the address move's**, and no browser run proves it: the lab's
    browser finds the router by one name through a fixed rule. Cost: a fault in the return by a
    new name would be found by hand. Unit tests cover the dialog; a change that is not confirmed
    still goes back by itself.
13. **After a restart the tab is at the login screen**, where the mockup said "this page comes
    back by itself": sessions are in memory and do not outlive a restart. Cost: one login.
14. **`Reboot` answers first and begins to restart a second later**, and makes no event. Cost:
    a caller cannot tell a restart that was asked for from one that happened, except in the
    log.
15. **The goodbyes get 3 s, and the restart goes ahead without them.** Cost: a concentrator
    slow to answer is left as a power cut leaves it. Waiting longer would hold up a restart the
    owner asked for, and 3 s is what every other stop is given.
16. **A restart leaves the DHCPv4 client alone**: its lease is not released, so the router comes
    back to the address it had. Cost: the ISP's server goes on holding a lease for a router
    that is down for a minute, which is what a lease is for.
17. **The log is not written to `/state/log` at a restart**, though a restart now stops in
    order. SPEC §10 has it at a clean shutdown, nothing implements it, and nothing would yet
    read it; it belongs with part 4's support bundle. Cost: what led up to a restart asked from
    the panel is lost with it.
18. **Notices by `cargo about` at build time**, a tool that CI, the cloud sandbox and a
    developer's machine must then have. Cost: one more thing to install; SPEC §13 names it.
19. **Routes come by `DiagnosticsService.DumpRoutes`, whole, and the page chooses what to
    show** and works out "Belongs to". Cost: the page holds a rule about what is noise; a
    script reading the call sees every route.
20. **The log's level and text are matched by the router for what is past and by the page for
    what arrives.** Cost: one rule in two languages, held together by shared cases.
21. **Download is the whole ring at every level.** Cost: up to 8 MiB fetched for a file whose
    reader wanted ten lines; it is the file a bug report wants.
22. **Info is the level Logs opens at, and 1 h the range the chart opens at.** Cost: a press
    each for someone who wanted otherwise.
