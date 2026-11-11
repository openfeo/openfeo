// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A router that is a script: the panel's pages and composables are tested against this, with
// no socket and no network. It has the client's surface as far as the panel uses it.

import {
  create,
  ErrorCode,
  GetStatusResponseSchema,
  RouterError,
  SessionSchema,
  type Connection,
  type Counters,
  type Event,
  type GetStatusResponse,
  type Session,
  type SessionEnd,
  type State,
  type Subscription,
} from '@openfeo/client'

import type { PanelRouter } from '../src/session'

type Listener = ((state: State) => void) | ((counters: Counters) => void) | ((event: Event) => void)

interface Listening {
  topic: 'state' | 'counters' | 'events'
  onPush: Listener
  backlog: number
  onLost: (() => void) | undefined
  closed: boolean
}

/** A promise a test settles when it chooses. */
function held<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

export class FakeRouter implements PanelRouter {
  authenticated = false
  connection: Connection = 'idle'

  /** What `status` answers; set `unreachable` to make it fail as a router that is not there. */
  statusNow: Partial<Pick<GetStatusResponse, 'hostname' | 'domain' | 'needsPassword' | 'configRefused' | 'configUnreadable' | 'tlsFingerprint'>> = {
    hostname: 'openfeo',
    domain: 'home.arpa',
    tlsFingerprint: Array.from({ length: 32 }, (_, i) => i.toString(16).toUpperCase().padStart(2, '0')).join(':'),
  }
  unreachable = false
  /** What the next password call does: succeed, or fail with this. */
  refuse: RouterError | null = null
  /** When set, password calls wait on it: a test can look at the page while a call is under way. */
  gate: ReturnType<typeof held<void>> | null = null
  stateNow: State | null = null

  readonly calls = { status: 0, login: [] as string[], setInitialPassword: [] as string[], logout: 0, state: 0 }
  readonly listening: Listening[] = []
  readonly #connectionListeners = new Set<(connection: Connection) => void>()
  readonly #endListeners = new Set<(reason: SessionEnd) => void>()

  status(): Promise<GetStatusResponse> {
    this.calls.status += 1
    if (this.unreachable) {
      return Promise.reject(new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer'))
    }
    return Promise.resolve(create(GetStatusResponseSchema, this.statusNow))
  }

  async #enter(): Promise<Session> {
    if (this.gate !== null) {
      await this.gate.promise
    }
    if (this.refuse !== null) {
      throw this.refuse
    }
    this.authenticated = true
    this.statusNow = { ...this.statusNow, needsPassword: false }
    return create(SessionSchema, { token: 'fake-token', idleSecs: 1800 })
  }

  setInitialPassword(password: string): Promise<Session> {
    this.calls.setInitialPassword.push(password)
    return this.#enter()
  }

  login(password: string): Promise<Session> {
    this.calls.login.push(password)
    return this.#enter()
  }

  logout(): Promise<void> {
    this.calls.logout += 1
    this.endSession('logout')
    return Promise.resolve()
  }

  state(): Promise<State> {
    this.calls.state += 1
    return this.stateNow === null
      ? Promise.reject(new RouterError(ErrorCode.UNAVAILABLE, 'no state in this script'))
      : Promise.resolve(this.stateNow)
  }

  subscribe(topic: 'state', onPush: (state: State) => void): Subscription
  subscribe(topic: 'counters', onPush: (counters: Counters) => void): Subscription
  subscribe(topic: 'events', onPush: (event: Event) => void, options?: { backlog?: number; onLost?: () => void }): Subscription
  subscribe(topic: 'state' | 'counters' | 'events', onPush: Listener, options: { backlog?: number; onLost?: () => void } = {}): Subscription {
    const entry: Listening = { topic, onPush, backlog: options.backlog ?? 0, onLost: options.onLost, closed: false }
    this.listening.push(entry)
    return {
      close: () => {
        entry.closed = true
      },
    }
  }

  onConnection(listener: (connection: Connection) => void): () => void {
    this.#connectionListeners.add(listener)
    return () => this.#connectionListeners.delete(listener)
  }

  onSessionEnd(listener: (reason: SessionEnd) => void): () => void {
    this.#endListeners.add(listener)
    return () => this.#endListeners.delete(listener)
  }

  // What a test does to it.

  /** The open subscriptions to a topic. */
  open(topic: 'state' | 'counters' | 'events'): Listening[] {
    return this.listening.filter((entry) => entry.topic === topic && !entry.closed)
  }

  push(topic: 'state', value: State): void
  push(topic: 'counters', value: Counters): void
  push(topic: 'events', value: Event): void
  push(topic: 'state' | 'counters' | 'events', value: State | Counters | Event): void {
    for (const entry of this.open(topic)) {
      ;(entry.onPush as (value: State | Counters | Event) => void)(value)
    }
  }

  /** The router says events were dropped. */
  lose(): void {
    for (const entry of this.open('events')) {
      entry.onLost?.()
    }
  }

  setConnection(connection: Connection): void {
    this.connection = connection
    for (const listener of [...this.#connectionListeners]) {
      listener(connection)
    }
  }

  endSession(reason: SessionEnd): void {
    this.authenticated = false
    this.connection = 'idle'
    for (const entry of this.listening) {
      entry.closed = true
    }
    for (const listener of [...this.#endListeners]) {
      listener(reason)
    }
  }

  /** Make the next password call wait until the returned function is called. */
  hold(): () => void {
    const gate = held<void>()
    this.gate = gate
    return () => {
      this.gate = null
      gate.resolve()
    }
  }
}
