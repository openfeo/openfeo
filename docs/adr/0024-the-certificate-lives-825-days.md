# 0024 — The panel's certificate lives 825 days and is reissued with its key

Status: Accepted (10 November 2026)

## Context

The router serves its API and panel over HTTPS with a certificate it makes for itself
(SPEC §9). Nobody else signs it, so every browser warns once and the person compares the
fingerprint with the one on the console. A self-signed certificate is usually given a long
life so that the warning is met once.

macOS does not allow that. Since macOS 10.15 and iOS 13 a TLS server certificate is refused
outright, with no way past the warning in Safari or in Chrome on that platform, unless it has
a subject alternative name, carries the `serverAuth` extended key usage and is valid for 825
days or fewer. A router whose panel cannot be opened from a Mac is not usable.

The router may also not know the time when it first issues: it has no battery-backed clock
on every target, and until SNTP answers its clock is the build's epoch (SPEC §7.10). A
certificate dated from a guess can be, to a client with the right time, already expired or
not yet valid.

## Decision

The certificate is ECDSA P-256, names the hostname and `<hostname>.<domain>` as subject
alternative names, carries `serverAuth`, and is valid for 825 days.

Its not-before is a day before now when the clock is synced, and a day before the build's
epoch when it is not. Whether it was issued on such a guess is recorded beside it.

It is reissued, **with the same key**, when:

- its names no longer match the hostname and domain;
- the clock is synced and fewer than 60 days remain;
- the clock is synced, the certificate was issued on a guess, and a correct clock calls it
  expired or not yet valid.

Without a synced clock no judgement about expiry is made. The certificate's validity and
names are kept in a small file beside it, so deciding needs no X.509 parser in the binary.

## Consequences

- The fingerprint changes at each reissue, about every two years, and the browser warns
  again. The console prints the new fingerprint and the API's state carries it.
- An old image booted with no clock issues once on the guess and once more after its first
  sync; a person who compared the fingerprint in between compares it twice.
- Keeping the key means a client that pinned the public key, and not the certificate, is
  undisturbed by a reissue.
- ACME (post-MVP, SPEC §9) replaces all of this for a router with a public name.
