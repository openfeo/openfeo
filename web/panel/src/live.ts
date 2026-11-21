// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the panel watches (SPEC §8.4, §10): the router's state as it changes, its counters
// each second, and its events as they happen. The shell listens once and every page behind
// the login reads from it. The router keeps no history, so the last minute of the default
// WAN's rates is kept here, for the sparklines; and it says its uptime only when its state
// changes, so the clock that counts on from there is kept here too.

import { rates as ratesOf, type Connection, type Counters, type Event, type LinkRate, type State, type Subscription } from '@openfeo/client'
import { computed, ref, type ComputedRef, type InjectionKey, type Ref } from 'vue'

import { defaultWan } from './model/dashboard'
import type { PanelRouter } from './session'

/** How many events the dashboard shows, and asks for when it opens. */
const RECENT = 8
/** A minute of rates at one a second. */
const HISTORY = 60

export interface LiveData {
  /** What the router last said of itself; `null` until it first has. */
  state: Ref<State | null>
  /** The rate of each link by its name; `null` when there are none to show. */
  rates: Ref<Map<string, LinkRate> | null>
  /** The default WAN's last minute of rates, oldest first. */
  history: Ref<{ rx: number[]; tx: number[] }>
  conntrack: Ref<{ count: number; max: number } | null>
  /** The most recent events, newest first. */
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
  const history = ref<{ rx: number[]; tx: number[] }>({ rx: [], tx: [] })
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

  let ticking: ReturnType<typeof setInterval> | undefined
  let previous: Counters | undefined
  let subscriptions: Subscription[] = []
  let eventsSubscription: Subscription | undefined
  let unhear: (() => void) | undefined

  function sampled(sample: Counters): void {
    conntrack.value = { count: sample.conntrack, max: sample.conntrackMax }
    if (previous !== undefined) {
      const found = new Map(ratesOf(previous, sample).map((rate) => [rate.name, rate]))
      rates.value = found
      const wan = state.value === null ? undefined : defaultWan(state.value)
      const rate = wan === undefined ? undefined : found.get(wan.interface)
      if (rate !== undefined) {
        history.value = {
          rx: [...history.value.rx, rate.rxBitsPerSec].slice(-HISTORY),
          tx: [...history.value.tx, rate.txBitsPerSec].slice(-HISTORY),
        }
      }
    }
    previous = sample
  }

  function listenToEvents(): void {
    eventsSubscription = router.subscribe(
      'events',
      (event) => {
        events.value = [event, ...events.value].slice(0, RECENT)
      },
      {
        backlog: RECENT,
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
    conntrack,
    events,
    connection,
    lostAt,
    now,
    sinceBootMs,
    start: () => {
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
        }),
        router.subscribe('counters', sampled),
      ]
      listenToEvents()
    },
    stop: () => {
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
