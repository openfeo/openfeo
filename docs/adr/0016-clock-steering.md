# 0016 — Clock steering: the first sync steps, then half a second decides between slew and step

Status: Accepted (31 October 2026); amended the same day to say whose bound the half second is
and how far off an RTC box really starts.

## Context

SPEC §7.10 says the SNTP client "steps once at boot, then slews", and that nothing may set the
clock earlier than the build timestamp. Two things about the kernel and the boxes shape how that
is honoured:

- Linux slews through `adjtimex(ADJ_OFFSET_SINGLESHOT)`, which corrects at 500 parts per
  million. The kernel's single-shot path takes any offset; it is glibc's `adjtime(3)` wrapper
  that bounds it, at about ±2145 s, and the PLL path (`ADJ_OFFSET`) that stops at `MAXPHASE`,
  half a second. The half second in the decision below is our own clamp: half a second already
  takes 1000 s to slew out, and a three-second error would take a hundred minutes, during which
  every TLS handshake, every log line and every lease expiry is wrong. Such errors happen on a
  router: a box that ran a day on the build-time clock before its WAN came up, a server that was
  wrong and is right again, a long outage.
- A box with an RTC does not arrive within milliseconds of the truth. The RTC keeps whole
  seconds, and the kernel (`hctosys`) sets the clock to the middle of the second it reads, so
  the clock starts anywhere up to half a second off. Most first syncs on an RTC box therefore
  step, and the step is the honest record of it.

The steering decision is also where a second time source (a GPS receiver with a PPS line, which
some of the target boards carry) would plug in: it must not know where an offset came from.

## Decision

- `openfeo_proto_sntp::discipline::decide(offset_ns, synced_before)` is the one place the
  decision is made. At the first sync an offset of at least 128 ms (RFC 5905's step threshold,
  kept because it is the standard) steps and anything smaller slews; once synced, an offset
  below half a second (our clamp, see Context) slews and anything from half a second steps. An
  offset of zero holds.
- The driver tells the kernel what it decided about the clock as a whole: every sync clears
  `STA_UNSYNC` (`adjtimex(ADJ_STATUS)`, with the kernel's error estimates reset so it does not
  raise the flag again by itself), and a lost sync sets it.
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
- Step sizes under 128 ms at boot are slewed; a box with an RTC usually starts further off than
  that and logs one step at boot.
- While `STA_UNSYNC` is clear the kernel writes the system time back to the RTC every eleven
  minutes (`CONFIG_RTC_SYSTOHC`), so the next boot starts from an RTC that was right to the
  second; a lost sync stops the write-back.
- The thresholds are constants in one module; a later GPS source or a tuning pass changes them
  in one place.
