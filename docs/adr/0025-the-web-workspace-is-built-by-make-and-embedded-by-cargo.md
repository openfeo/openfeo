# 0025 — The web workspace is built by make and embedded by cargo

Status: Accepted (11 November 2026)

## Context

The panel is a Vue application and its client is TypeScript (SPEC §2, §8.4), so the binary
that carries them depends on things Rust does not build: Node, npm packages, a bundler, two
font files. SPEC §2 says the panel is embedded in the binary; it does not say how the two
toolchains meet.

The obvious way, a `build.rs` that runs `npm`, makes every `cargo build`, `cargo test` and
`cargo clippy` wait on Node and fail without it. Most work on the router touches no web code,
and the cloud sandbox and a contributor's first build should not need a JavaScript toolchain
to compile a DHCP client.

npm packages also run code at install time when they are allowed to, and what they bundle
into the page ships in a GPLv2 binary (SPEC §14).

## Decision

**Cargo never runs npm.** `make panel` installs the workspace, generates the message code,
builds the client and the panel into `$(BUILD)/panel` and writes the notices beside them.
`make bin` depends on it and passes `OPENFEO_PANEL_DIST` to its own cargo call, and to no
other. `openfeo-api`'s `build.rs` turns that directory into a table of embedded files.

**Without the variable the build embeds a placeholder page** that says the panel was not
built and the API is up. So the Rust workspace builds, tests and lints with no Node on the
machine. An image always goes through `make` and always carries the real panel; a harness
scenario fails if a booted VM serves the placeholder.

**Node is a build dependency of the image and not of the Rust workspace.** `make lint` and
`make test` do need it, for the web side's own checks.

**npm packages install without their scripts** (`npm ci --ignore-scripts`), from one
lockfile. A package that needs its install script is dealt with by hand.

**What is bundled passes the licence gate.** A lint script reads the lockfile and holds every
package that reaches the page to the list `cargo deny` applies. The panel's build writes each
one's licence text, and the fonts', into `/licences.txt`.

**The generated TypeScript is built, not committed,** as the Rust types are.

**The two fonts ship in the binary.** They are SIL OFL 1.1, accepted for font files only, and
their licence texts ship with them. Nothing is fetched from the internet by the panel.

## Consequences

- A Rust-only change is built and tested without Node. A change under `web/` is not seen by
  `cargo test`: `make web-lint` and `make web-test` are where it is checked, and `make lint`
  and `make test` run them.
- `make bin`, `make kernel` and the harness need Node 22. CI's jobs and the cloud sandbox
  install it.
- A binary built by a bare `cargo build` serves the placeholder. That is deliberate and it is
  said on the page; it is also the one way to ship an image with no panel, which is why the
  harness checks.
- The client cannot be used from a fresh checkout until the build has run once, since its
  message code is generated.
- A new kind of file in the panel's output fails the build until its content type is named:
  the table is built from a fixed list.
