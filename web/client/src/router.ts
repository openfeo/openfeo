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
  LogLevel,
  type Caller,
  type GetStatusResponse,
  type LogBatch,
  type LogsResponse,
  type Response as Reply,
  type Route,
  type Session,
} from './gen/openfeo/v1/api_pb.js'
import type { Config } from './gen/openfeo/v1/config_pb.js'
import type { Event } from './gen/openfeo/v1/events_pb.js'
import type { ConfigEffect, ConfigViolation, Counters, Leases, LinkHistory, State } from './gen/openfeo/v1/state_pb.js'
import { call, type Http } from './http.js'
import type { RouterOptions, Timers, WebSocketLike } from './options.js'
import { Link, type Ask, type Connection, type SessionEnd, type Subscription, type Topic } from './socket.js'
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

/** The running config as it is read: without its secrets, and with what an apply needs. */
export interface ConfigView {
  /** The admin's password hash and every PPPoE password are empty. */
  config: Config
  /** Tells this config from any other. An apply names the one it was edited from. */
  tag: string
  /** The window the router gives an apply that names none, in seconds. */
  confirmSecs: number
}

/** What the router makes of a config it was shown and did not apply. */
export interface Validation {
  /** What is wrong with it. When there is anything here the rest is empty. */
  violations: ConfigViolation[]
  /** What applying it would interrupt. */
  effects: ConfigEffect[]
  /** Whether applying it moves whoever asked, and where the router would then be. */
  caller: Caller | undefined
}

/**
 * How an apply ended. `answered: false` is no answer within the wait, or a socket lost before
 * one: the router answers an apply once the config is published, and a change that takes away
 * the address the socket arrived at takes the answer's way home with it. It does not say the
 * change was refused or taken; the router's config and state, read when it is next reached,
 * say which.
 */
export type Applied = { answered: true; tag: string } | { answered: false }

/** How a revert ended. No answer is likely a revert that was done: the address goes with the change. */
export interface Reverted {
  answered: boolean
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
  /** How long an apply, a confirm or a revert waits for its answer. */
  readonly #answerMs: number

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
    this.#answerMs = probeTimeoutMs
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

  /**
   * Every LAN's DHCPv4 leases, with the router's clock: ages are counted against that, not
   * against this machine's. At most 4096, the newest by when they joined; `truncated` says
   * when there were more.
   */
  async leases(): Promise<Leases> {
    const reply = await this.#link.request({ case: 'getLeases', value: {} })
    if (reply.body.case !== 'getLeases' || reply.body.value.leases === undefined) {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without the leases')
    }
    return reply.body.value.leases
  }

  /**
   * The last hour of some links' byte counters, a sample a second, for the links the router
   * has samples of, in the order asked. `links` are kernel names, as a WAN's `interface` in
   * the state gives them: at least one and at most eight (`INVALID_ARGUMENT` otherwise).
   * `samplesOf` and `ratesOver` make rates of an answer.
   */
  async history(links: string[]): Promise<LinkHistory[]> {
    const reply = await this.#link.request({ case: 'getHistory', value: { links } })
    if (reply.body.case !== 'getHistory') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered a call for the history with something else')
    }
    return reply.body.value.links
  }

  /** The running config without its secrets, the tag an apply must name, and the router's default window. */
  async config(): Promise<ConfigView> {
    const reply = await this.#link.request({ case: 'getConfig', value: {} })
    if (reply.body.case !== 'getConfig' || reply.body.value.config === undefined) {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without a config')
    }
    const { config, tag, confirmSecs } = reply.body.value
    return { config, tag, confirmSecs }
  }

  /**
   * What is wrong with a config, or what applying it would interrupt and whether it moves
   * whoever asks. Changes nothing.
   */
  async validate(config: Config): Promise<Validation> {
    const reply = await this.#link.request({ case: 'validateConfig', value: { config } })
    if (reply.body.case !== 'validateConfig') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered a validation with something else')
    }
    const { violations, effects, caller } = reply.body.value
    return { violations, effects, caller }
  }

  /**
   * Apply a config that was edited from the one `tag` names. It is pending until
   * {@link confirm}, and the router goes back by itself when its window runs out
   * (`timeoutSecs`, 10 to 600; the router's default when left out), unless `immediate`: then
   * it stands at once and nothing undoes it. A PPPoE password left empty keeps the one in
   * force. A refusal is a {@link RouterError}: `INVALID_ARGUMENT` for a config with
   * violations, `FAILED_PRECONDITION` for a stale tag or a change already pending. No answer
   * is not an error: see {@link Applied}.
   */
  async apply(config: Config, tag: string, options: { immediate?: boolean; timeoutSecs?: number } = {}): Promise<Applied> {
    const ask: Ask = {
      case: 'applyConfig',
      value: { config, tag, immediate: options.immediate ?? false, timeoutSecs: options.timeoutSecs ?? 0 },
    }
    const reply = await this.#unlessUnanswered(this.#link.request(ask, this.#answerMs))
    if (reply === undefined) {
      return { answered: false }
    }
    if (reply.body.case !== 'applyConfig') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered an apply with something else')
    }
    return { answered: true, tag: reply.body.value.tag }
  }

  /** Keep the pending change: it becomes the router's config. `UNAVAILABLE` when no answer comes. */
  async confirm(): Promise<void> {
    await this.#link.request({ case: 'confirmConfig', value: {} }, this.#answerMs)
  }

  /** Give the pending change up now: the router goes back to the config it had. */
  async revert(): Promise<Reverted> {
    const reply = await this.#unlessUnanswered(this.#link.request({ case: 'revertConfig', value: {} }, this.#answerMs))
    return { answered: reply !== undefined }
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
   * Restart the router. It answers first and begins about a second later, ending its PPPoE
   * sessions and writing its lease files before it goes. Every session ends with it, this one
   * too: its sessions are kept in memory. A change of config that is waiting to be confirmed is
   * not confirmed by a restart; the router comes back on the confirmed config.
   */
  async reboot(): Promise<void> {
    await this.#link.request({ case: 'reboot', value: {} })
  }

  /**
   * Every route the kernel holds, both families and every table: `main`, `local` (the
   * kernel's own entries for its addresses), and each WAN's own under that WAN's name. A page
   * that lists routes chooses which of them a person reads.
   */
  async dumpRoutes(): Promise<Route[]> {
    const reply = await this.#link.request({ case: 'dumpRoutes', value: {} })
    if (reply.body.case !== 'dumpRoutes') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered a call for the routes with something else')
    }
    return reply.body.value.routes
  }

  /**
   * The newest lines of the router's log that match, oldest first: `level` and everything more
   * serious, `contains` anywhere in the line without regard to ASCII case. At most `limit`
   * lines, and never more than the router's own cap (1000 lines, 512 KiB); `earlier` says that
   * older lines match, and `beforeSeq` set to the oldest line's number fetches them. The
   * answer carries the router's two clocks: a line was written `uptimeMs - line.uptimeMs`
   * before `timeUnixMs`, whatever the router's clock said at the time.
   */
  async logs(ask: { level?: LogLevel; contains?: string; beforeSeq?: bigint; limit?: number } = {}): Promise<LogsResponse> {
    const reply = await this.#link.request({
      case: 'logs',
      value: { level: ask.level ?? LogLevel.UNSPECIFIED, contains: ask.contains ?? '', beforeSeq: ask.beforeSeq ?? 0n, limit: ask.limit ?? 0 },
    })
    if (reply.body.case !== 'logs') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered a call for the log with something else')
    }
    return reply.body.value
  }

  /**
   * Listen to a topic until the subscription is closed: `state` is the whole state now and
   * after every change, `leases` the whole lease table now and whenever a lease in it
   * changes, `counters` a sample each second, `events` each event as it happens (with the
   * last `backlog` first; `onLost` when the router had to drop some), `logs` every line of
   * the log written from now on, in batches and at every level (`logMatches` picks; `onLost`
   * when lines were skipped, by the router or while the socket was away).
   */
  subscribe(topic: 'state', onPush: (state: State) => void): Subscription
  subscribe(topic: 'leases', onPush: (leases: Leases) => void): Subscription
  subscribe(topic: 'counters', onPush: (counters: Counters) => void): Subscription
  subscribe(topic: 'events', onPush: (event: Event) => void, options?: { backlog?: number; onLost?: () => void }): Subscription
  subscribe(topic: 'logs', onPush: (batch: LogBatch) => void, options?: { onLost?: () => void }): Subscription
  subscribe(
    topic: Topic,
    onPush:
      | ((state: State) => void)
      | ((leases: Leases) => void)
      | ((counters: Counters) => void)
      | ((event: Event) => void)
      | ((batch: LogBatch) => void),
    options: { backlog?: number; onLost?: () => void } = {},
  ): Subscription {
    switch (topic) {
      case 'state':
        return this.#link.subscribeState(onPush as (state: State) => void)
      case 'leases':
        return this.#link.subscribeLeases(onPush as (leases: Leases) => void)
      case 'counters':
        return this.#link.subscribeCounters(onPush as (counters: Counters) => void)
      case 'events':
        return this.#link.subscribeEvents(onPush as (event: Event) => void, options.backlog ?? 0, options.onLost)
      case 'logs':
        return this.#link.subscribeLogs(onPush as (batch: LogBatch) => void, options.onLost)
    }
  }

  /** Drop the socket and every subscription. The session and its token stay. */
  close(): void {
    this.#link.close()
  }

  /** A call's answer, or nothing when the router was not there to give one. A refusal stays an error. */
  async #unlessUnanswered(answer: Promise<Reply>): Promise<Reply | undefined> {
    try {
      return await answer
    } catch (error) {
      if (error instanceof RouterError && error.code === ErrorCode.UNAVAILABLE) {
        return undefined
      }
      throw error
    }
  }

  #begin(session: Session | undefined): Session {
    if (session === undefined || session.token === '') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without a session')
    }
    this.#store.set(session.token)
    return session
  }
}
