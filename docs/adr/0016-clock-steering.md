# 0016 — Clock steering: the first sync steps, then half a second decides between slew and step

Status: Accepted (31 October 2026)

## Context

SPEC §7.10 says the SNTP client "steps once at boot, then slews", and that nothing may set the
clock earlier than the build timestamp. Two things about the kernel and the boxes shape how that
is honoured:

- Linux slews through `adjtimex(ADJ_OFFSET_SINGLESHOT)`, which accepts at most half a second per
  call and corrects at 500 parts per million. A three-second error would take a hundred minutes
  to slew out, during which every TLS handshake, every log line and every lease expiry is
  wrong. Such errors happen on a router: a box that ran a day on the build-time clock before its
  WAN came up, a server that was wrong and is right again, a long outage.
- A box with an RTC arrives within milliseconds of the truth. Stepping it at every boot would
  move the clock for nothing and make every boot log a step.

The steering decision is also where a second time source (a GPS receiver with a PPS line, which
some of the target boards carry) would plug in: it must not know where an offset came from.

## Decision

- `openfeo_proto_sntp::discipline::decide(offset_ns, synced_before)` is the one place the
  decision is made. At the first sync an offset of at least 128 ms steps and anything smaller
  slews; once synced, an offset below half a second (the kernel's own single-shot bound) slews
  and anything from half a second steps. An offset of zero holds.
- Every step is announced on the console (`time step +7200.012s from 203.0.113.1 stratum 2`);
  slews are logged at debug.
- The build timestamp is the floor: PID 1 raises a clock that starts before it, and the client
  refuses any server whose transmit time is before it (`time refused ... before the build
  floor`), so no server can take the box back into the past.
- The decision takes a signed offset and nothing else, so samples from another source can feed
  it later without reshaping the SNTP client.

## Consequences

- A clock that jumps is visible in the log, and the spec's "then slews" holds for the ordinary
  case of millisecond drift between polls.
- Step sizes under 128 ms at boot are slewed, so a box with an RTC does not log a step at every
  start.
- The thresholds are constants in one module; a later GPS source or a tuning pass changes them
  in one place.
