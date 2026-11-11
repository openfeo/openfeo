// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the dashboard watches (SPEC §8.4, §10): the router's state as it changes, its
// counters each second, and its events as they happen. The router keeps no history, so the
// last minute of the default WAN's rates is kept here, for the sparklines.

import { rates as ratesOf, type Connection, type Counters, type Event, type LinkRate, type State, type Subscription } from '@openfeo/client'
import { ref, type Ref } from 'vue'

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
  /** Start listening (when the page mounts). */
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
    start: () => {
      connection.value = router.connection
      unhear = router.onConnection(heard)
      subscriptions = [
        router.subscribe('state', (pushed) => {
          state.value = pushed
        }),
        router.subscribe('counters', sampled),
      ]
      listenToEvents()
    },
    stop: () => {
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
