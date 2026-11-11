// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { RouterError } from './errors.js'
import {
  ErrorCode,
  GetStatusResponseSchema,
  LoginRequestSchema,
  LoginResponseSchema,
  SetInitialPasswordRequestSchema,
  SetInitialPasswordResponseSchema,
  type GetStatusResponse,
  type Session,
} from './gen/openfeo/v1/api_pb.js'
import type { Event } from './gen/openfeo/v1/events_pb.js'
import type { Counters, State } from './gen/openfeo/v1/state_pb.js'
import { call, type Http } from './http.js'
import type { RouterOptions, Timers, WebSocketLike } from './options.js'
import { Link, type Connection, type SessionEnd, type Subscription } from './socket.js'
import { memoryTokenStore, type TokenStore } from './token-store.js'

/**
 * How long a socket may be silent before it is probed, and how long the router may then go
 * unanswered: by a probe, by a socket that is opening, or by a plain call.
 */
const PROBE_AFTER_MS = 30_000
const PROBE_TIMEOUT_MS = 10_000

const realTimers: Timers = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
  now: () => Date.now(),
  random: () => Math.random(),
}

/** The page's origin when there is a page (a browser), and nothing when there is not (Node). */
function pageOrigin(): string | undefined {
  const page = (globalThis as { location?: { origin?: string } }).location
  return page?.origin
}

/**
 * One router, as a client reaches it (SPEC §8.4). It holds no state outside itself: two
 * routers are two objects, each with its own session.
 */
export class Router {
  readonly #http: Http
  readonly #store: TokenStore
  readonly #link: Link

  constructor(options: RouterOptions = {}) {
    const base = options.baseUrl ?? pageOrigin()
    if (base === undefined) {
      throw new TypeError('Router needs a baseUrl when there is no page to take it from')
    }
    const timers = options.timers ?? realTimers
    const probeTimeoutMs = options.probeTimeoutMs ?? PROBE_TIMEOUT_MS
    this.#http = {
      baseUrl: new URL(base).origin,
      fetch: options.fetch ?? ((input, init) => globalThis.fetch(input, init)),
      timers,
      timeoutMs: probeTimeoutMs,
    }
    this.#store = options.tokenStore ?? memoryTokenStore()
    const socket = new URL('/ws', this.#http.baseUrl)
    socket.protocol = socket.protocol === 'http:' ? 'ws:' : 'wss:'
    this.#link = new Link({
      url: socket.href,
      store: this.#store,
      webSocket: options.webSocket ?? ((url) => new WebSocket(url) as unknown as WebSocketLike),
      timers,
      probeAfterMs: options.probeAfterMs ?? PROBE_AFTER_MS,
      probeTimeoutMs,
    })
  }

  /** Where the socket stands: nothing open, on its way, open, or lost and being remade. */
  get connection(): Connection {
    return this.#link.connection
  }

  /** Hear each change of {@link connection}. Returns the way to stop listening. */
  onConnection(listener: (connection: Connection) => void): () => void {
    return this.#link.onConnection(listener)
  }

  /** Hear the session end, and why. Returns the way to stop listening. */
  onSessionEnd(listener: (reason: SessionEnd) => void): () => void {
    return this.#link.onSessionEnd(listener)
  }

  /** Whether a session's token is held. The router may still refuse it. */
  get authenticated(): boolean {
    return this.#store.get() !== null
  }

  /** What anyone on the LAN may know before logging in. */
  status(): Promise<GetStatusResponse> {
    return call(this.#http, '/api/status', GetStatusResponseSchema)
  }

  /** Set the admin password of a router that has none. This client is then logged in. */
  async setInitialPassword(password: string): Promise<Session> {
    const answer = await call(this.#http, '/api/password', SetInitialPasswordResponseSchema, {
      schema: SetInitialPasswordRequestSchema,
      init: { password },
    })
    return this.#begin(answer.session)
  }

  /** Log in. A wrong password is a {@link RouterError} that carries the wait, when there is one. */
  async login(password: string): Promise<Session> {
    const answer = await call(this.#http, '/api/login', LoginResponseSchema, {
      schema: LoginRequestSchema,
      init: { password },
    })
    return this.#begin(answer.session)
  }

  /** One snapshot of the router's state. */
  async state(): Promise<State> {
    const reply = await this.#link.request({ case: 'getState', value: {} })
    if (reply.body.case !== 'getState' || reply.body.value.state === undefined) {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without a state')
    }
    return reply.body.value.state
  }

  /** End this session, here and on the router. */
  logout(): Promise<void> {
    return this.#link.logout()
  }

  /**
   * Change the admin password. Every other session ends; this one stays. A wrong old password
   * is `INVALID_ARGUMENT`, and this session stays then too.
   */
  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    await this.#link.request({ case: 'changePassword', value: { oldPassword, newPassword } })
  }

  /**
   * Listen to a topic until the subscription is closed: `state` is the whole state now and
   * after every change, `counters` a sample each second, `events` each event as it happens
   * (with the last `backlog` first; `onLost` when the router had to drop some).
   */
  subscribe(topic: 'state', onPush: (state: State) => void): Subscription
  subscribe(topic: 'counters', onPush: (counters: Counters) => void): Subscription
  subscribe(topic: 'events', onPush: (event: Event) => void, options?: { backlog?: number; onLost?: () => void }): Subscription
  subscribe(
    topic: 'state' | 'counters' | 'events',
    onPush: ((state: State) => void) | ((counters: Counters) => void) | ((event: Event) => void),
    options: { backlog?: number; onLost?: () => void } = {},
  ): Subscription {
    switch (topic) {
      case 'state':
        return this.#link.subscribeState(onPush as (state: State) => void)
      case 'counters':
        return this.#link.subscribeCounters(onPush as (counters: Counters) => void)
      case 'events':
        return this.#link.subscribeEvents(onPush as (event: Event) => void, options.backlog ?? 0, options.onLost)
    }
  }

  /** Drop the socket and every subscription. The session and its token stay. */
  close(): void {
    this.#link.close()
  }

  #begin(session: Session | undefined): Session {
    if (session === undefined || session.token === '') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without a session')
    }
    this.#store.set(session.token)
    return session
  }
}
