// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the panel watches (SPEC §8.4, §10): the router's state as it changes, its lease table,
// its counters each second, and its events as they happen. The shell listens once and every
// page behind the login reads from it. The router keeps the last hour of each link's byte
// counters; the panel asks for the WANs' when it opens and carries on from the live samples,
// so a chart is drawn back to before the page was. The router says its uptime only when its
// state changes, and its wall clock only with a lease table, so the clocks that count on from
// there are kept here too.

import {
  rates as ratesOf,
  samplesOf,
  type Connection,
  type Counters,
  type Event,
  type Leases,
  type LinkHistory,
  type LinkRate,
  type LinkSample,
  type State,
  type Subscription,
} from '@openfeo/client'
import { computed, ref, shallowRef, type ComputedRef, type InjectionKey, type Ref } from 'vue'

import { lastMinute } from './model/chart'
import { defaultWan } from './model/dashboard'
import type { PanelRouter } from './session'

/** How many events are kept, and asked for when the shell opens: as many as the router keeps. */
const KEPT_EVENTS = 256
/** How far back the samples are kept: what the router itself keeps. */
const HOUR_MS = 3_600_000
/** The most links the router answers for in one call. */
const MOST_LINKS = 8

export interface LiveData {
  /** What the router last said of itself; `null` until it first has. */
  state: Ref<State | null>
  /** The rate of each link by its name; `null` when there are none to show. */
  rates: Ref<Map<string, LinkRate> | null>
  /** The default WAN's last minute of rates, oldest first. */
  history: ComputedRef<{ rx: number[]; tx: number[] }>
  /** The last hour of each WAN interface's counters, oldest first, by the link's name. */
  samples: Ref<Map<string, LinkSample[]>>
  /** The hour before could not be read from the router: a chart says so, and draws from now. */
  historyFailed: Ref<boolean>
  /** The lease table as the router last pushed it; `null` until it first has. */
  leases: Ref<Leases | null>
  /**
   * The router's wall clock by now, in seconds: what the last lease table said, carried on by
   * the time since it arrived. Ages are counted against this, never against the browser's
   * clock; `undefined` until a table has come.
   */
  routerClock: ComputedRef<number | undefined>
  conntrack: Ref<{ count: number; max: number } | null>
  /** The most recent events, newest first: as many as the router keeps. */
  events: Ref<Event[]>
  connection: Ref<Connection>
  /** When the connection was lost, while it is. */
  lostAt: Ref<Date | null>
  /** The browser's clock, moving on each second while listening: what "today" is, and what a countdown ticks by. */
  now: Ref<Date>
  /**
   * How long the router has been up by now, in milliseconds: what it last said, and the time
   * since it said it. The router's own clock, which a pending change and an event are stamped
   * with; `undefined` until the router has said.
   */
  sinceBootMs: ComputedRef<number | undefined>
  /** Start listening (when the shell mounts). */
  start(): void
  /** Stop (when it unmounts). */
  stop(): void
}

export function useLive(router: PanelRouter): LiveData {
  const state = ref<State | null>(null)
  const rates = ref<Map<string, LinkRate> | null>(null)
  const samples = shallowRef(new Map<string, LinkSample[]>())
  const historyFailed = ref(false)
  const leases = ref<Leases | null>(null)
  const history = computed(() => {
    const wan = state.value === null ? undefined : defaultWan(state.value)
    return lastMinute((wan === undefined ? undefined : samples.value.get(wan.interface)) ?? [])
  })
  const conntrack = ref<{ count: number; max: number } | null>(null)
  const events = ref<Event[]>([])
  const connection = ref<Connection>(router.connection)
  const lostAt = ref<Date | null>(null)
  const now = ref(new Date())
  /** The browser's clock when the state last arrived. */
  let stateAt = now.value.getTime()
  // The time since the state arrived is never taken to be negative: a browser clock that was
  // set back holds the uptime where it was until the router speaks again.
  const sinceBootMs = computed(() => {
    const system = state.value?.system
    return system === undefined ? undefined : Number(system.uptimeSecs) * 1000 + Math.max(0, now.value.getTime() - stateAt)
  })

  /** The browser's clock when the lease table last arrived. */
  let leasesAt = now.value.getTime()
  const routerClock = computed(() =>
    leases.value === null ? undefined : Number(leases.value.timeUnix) + Math.floor(Math.max(0, now.value.getTime() - leasesAt) / 1000),
  )

  let ticking: ReturnType<typeof setInterval> | undefined
  let listening = false
  /** The links whose history has been asked for since the socket last opened. */
  const asked = new Set<string>()
  /** Which boot of the router the samples are of: an answer asked of an earlier one is not joined on. */
  let boot = 0
  let previous: Counters | undefined
  let subscriptions: Subscription[] = []
  let eventsSubscription: Subscription | undefined
  let unhear: (() => void) | undefined

  /**
   * The links the samples are kept of: each WAN's interface. The router names one for every
   * WAN, a PPPoE WAN's between sessions too, when the kernel has no such link and there is
   * nothing to read of it; a name that is empty is no link to ask about.
   */
  function wanted(): string[] {
    return [...new Set((state.value?.wans ?? []).map((wan) => wan.interface).filter((link) => link !== ''))]
  }

  /** A link's samples with those over an hour older than its newest left out. */
  function hourOf(of: LinkSample[]): LinkSample[] {
    const newest = of.at(-1)
    return newest === undefined ? of : of.filter((sample) => sample.atMs >= newest.atMs - HOUR_MS)
  }

  /** What the router kept, joined to what is kept here: in order of time, no reading twice. */
  function join(found: LinkHistory[]): void {
    const links = wanted()
    const next = new Map(samples.value)
    for (const history of found) {
      if (links.includes(history.name)) {
        const byTime = new Map<number, LinkSample>()
        for (const sample of [...samplesOf(history), ...(next.get(history.name) ?? [])]) {
          byTime.set(sample.atMs, sample)
        }
        next.set(history.name, hourOf([...byTime.values()].sort((a, b) => a.atMs - b.atMs)))
      }
    }
    samples.value = next
  }

  /** Ask for the history of each wanted link not yet asked for since the socket opened, eight links a call. */
  function ask(): void {
    const links = wanted().filter((link) => !asked.has(link))
    const of = boot
    for (let at = 0; at < links.length; at += MOST_LINKS) {
      const some = links.slice(at, at + MOST_LINKS)
      for (const link of some) {
        asked.add(link)
      }
      router.history(some).then(
        (found) => {
          if (listening && of === boot) {
            historyFailed.value = false
            join(found)
          }
        },
        () => {
          // The chart says so and draws from now; it is asked again when the socket next opens.
          if (listening && of === boot) {
            historyFailed.value = true
          }
        },
      )
    }
  }

  /** The state named the WANs: what is kept of a link that is no longer one goes, and a new one is asked about. */
  function follow(): void {
    const links = wanted()
    if ([...samples.value.keys()].some((link) => !links.includes(link))) {
      samples.value = new Map([...samples.value].filter(([link]) => links.includes(link)))
    }
    for (const link of [...asked]) {
      if (!links.includes(link)) {
        asked.delete(link)
      }
    }
    ask()
  }

  /** Keep a live sample of each wanted link, after what is already kept of it. */
  function keep(sample: Counters): void {
    const atMs = Number(sample.monotonicMs)
    const links = wanted()
    if ([...samples.value.values()].some((kept) => (kept.at(-1)?.atMs ?? 0) > atMs)) {
      // The router's boot clock went back: it restarted, and what was kept is of another
      // boot, on another clock and other counters. Start again from this boot's history.
      boot += 1
      samples.value = new Map()
      asked.clear()
      ask()
    }
    const next = new Map(samples.value)
    let changed = false
    for (const link of sample.links) {
      if (links.includes(link.name)) {
        const kept = next.get(link.name) ?? []
        if ((kept.at(-1)?.atMs ?? -1) < atMs) {
          next.set(link.name, hourOf([...kept, { atMs, rxBytes: link.rxBytes, txBytes: link.txBytes }]))
          changed = true
        }
      }
    }
    if (changed) {
      samples.value = next
    }
  }

  function sampled(sample: Counters): void {
    conntrack.value = { count: sample.conntrack, max: sample.conntrackMax }
    if (previous !== undefined) {
      rates.value = new Map(ratesOf(previous, sample).map((rate) => [rate.name, rate]))
    }
    previous = sample
    keep(sample)
  }

  function listenToEvents(): void {
    eventsSubscription = router.subscribe(
      'events',
      (event) => {
        events.value = [event, ...events.value].slice(0, KEPT_EVENTS)
      },
      {
        backlog: KEPT_EVENTS,
        // Some were dropped, or passed while the socket was away: start the list again from
        // the router's own record rather than show one with a hole in it.
        onLost: () => {
          eventsSubscription?.close()
          events.value = []
          listenToEvents()
        },
      },
    )
  }

  function heard(now: Connection): void {
    connection.value = now
    if (now === 'open') {
      lostAt.value = null
      // The router went on reading while the socket was away: what it kept fills the time.
      asked.clear()
      ask()
    } else {
      if (now === 'reconnecting') {
        lostAt.value ??= new Date()
      }
      // The numbers stop: a rate left on screen would read as though still true. The first
      // sample after the gap starts afresh.
      rates.value = null
      conntrack.value = null
      previous = undefined
    }
  }

  return {
    state,
    rates,
    history,
    samples,
    historyFailed,
    leases,
    routerClock,
    conntrack,
    events,
    connection,
    lostAt,
    now,
    sinceBootMs,
    start: () => {
      listening = true
      connection.value = router.connection
      unhear = router.onConnection(heard)
      now.value = new Date()
      ticking = setInterval(() => {
        now.value = new Date()
      }, 1_000)
      subscriptions = [
        router.subscribe('state', (pushed) => {
          now.value = new Date()
          stateAt = now.value.getTime()
          state.value = pushed
          follow()
        }),
        router.subscribe('leases', (pushed) => {
          now.value = new Date()
          leasesAt = now.value.getTime()
          leases.value = pushed
        }),
        router.subscribe('counters', sampled),
      ]
      listenToEvents()
    },
    stop: () => {
      listening = false
      clearInterval(ticking)
      ticking = undefined
      unhear?.()
      unhear = undefined
      for (const subscription of subscriptions) {
        subscription.close()
      }
      subscriptions = []
      eventsSubscription?.close()
      eventsSubscription = undefined
    },
  }
}

export const LIVE: InjectionKey<LiveData> = Symbol('what the router is doing')
