// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A router that is a script: the panel's pages and composables are tested against this, with
// no socket and no network. It has the client's surface as far as the panel uses it.

import {
  clone,
  ConfigSchema,
  create,
  ErrorCode,
  GetStatusResponseSchema,
  LeasesSchema,
  RouterError,
  SessionSchema,
  type Applied,
  type Config,
  type ConfigView,
  type Connection,
  type Counters,
  type Event,
  type GetStatusResponse,
  type Leases,
  type LinkHistory,
  type LogBatch,
  type Reverted,
  type Session,
  type SessionEnd,
  type State,
  type Subscription,
  type Validation,
} from '@openfeo/client'

import type { PanelRouter } from '../src/session'

type Pushed = State | Leases | Counters | Event | LogBatch
type Listener =
  | ((state: State) => void)
  | ((leases: Leases) => void)
  | ((counters: Counters) => void)
  | ((event: Event) => void)
  | ((batch: LogBatch) => void)
type Topic = 'state' | 'leases' | 'counters' | 'events' | 'logs'

interface Listening {
  topic: Topic
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
  /** What `config` answers: the running config, its tag and the router's window. */
  configNow: ConfigView = { config: create(ConfigSchema, {}), tag: 't0', confirmSecs: 120 }
  /** While set, `config` fails as a router that cannot be reached. */
  configUnreachable = false
  /** What `leases` answers. */
  leasesNow: Leases = create(LeasesSchema, {})
  /** What `history` answers for the links it is asked of, or the refusal it throws. */
  historyNow: LinkHistory[] | RouterError = []
  /** What `validate` answers. */
  validation: Validation = { violations: [], effects: [], caller: undefined }
  /** What `apply` answers, or the refusal it throws. */
  applyAnswer: Applied | RouterError = { answered: true, tag: 't-applied' }
  /** The refusal `confirm` throws, when it does. */
  confirmRefusal: RouterError | null = null
  /** What `revert` answers, or the refusal it throws. */
  revertAnswer: Reverted | RouterError = { answered: true }
  /** The refusal `changePassword` throws, when it does. */
  changeRefusal: RouterError | null = null
  /** The refusal `reboot` throws, when it does. */
  rebootRefusal: RouterError | null = null
  /** Calls that wait until a test lets them go, by name. */
  readonly #held = new Map<string, ReturnType<typeof held<void>>>()

  readonly calls = {
    status: 0,
    login: [] as string[],
    setInitialPassword: [] as string[],
    logout: 0,
    state: 0,
    leases: 0,
    history: [] as string[][],
    config: 0,
    validate: [] as Config[],
    apply: [] as { config: Config; tag: string; immediate: boolean }[],
    confirm: 0,
    revert: 0,
    /** Each change of password asked: the old one and the new, as they were given. */
    changePassword: [] as [old: string, next: string][],
    reboot: 0,
  }
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

  leases(): Promise<Leases> {
    this.calls.leases += 1
    return Promise.resolve(this.leasesNow)
  }

  async history(links: string[]): Promise<LinkHistory[]> {
    this.calls.history.push([...links])
    // What the router held when it was asked, however long the answer then takes.
    const known = this.historyNow
    await this.#held.get('history')?.promise
    if (known instanceof RouterError) {
      throw known
    }
    // As the router does: only the links asked for, in the order asked.
    return links.flatMap((link) => known.filter((history) => history.name === link))
  }

  async config(): Promise<ConfigView> {
    this.calls.config += 1
    await this.#held.get('config')?.promise
    if (this.configUnreachable) {
      throw new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
    }
    // A copy: what the page does to the config it was handed is not done to the router's.
    return { ...this.configNow, config: clone(ConfigSchema, this.configNow.config) }
  }

  async validate(config: Config): Promise<Validation> {
    this.calls.validate.push(clone(ConfigSchema, config))
    await this.#held.get('validate')?.promise
    return this.validation
  }

  async apply(config: Config, tag: string, options: { immediate?: boolean; timeoutSecs?: number } = {}): Promise<Applied> {
    this.calls.apply.push({ config: clone(ConfigSchema, config), tag, immediate: options.immediate ?? false })
    await this.#held.get('apply')?.promise
    if (this.applyAnswer instanceof RouterError) {
      throw this.applyAnswer
    }
    return this.applyAnswer
  }

  async confirm(): Promise<void> {
    this.calls.confirm += 1
    await this.#held.get('confirm')?.promise
    if (this.confirmRefusal !== null) {
      throw this.confirmRefusal
    }
  }

  async revert(): Promise<Reverted> {
    this.calls.revert += 1
    await this.#held.get('revert')?.promise
    if (this.revertAnswer instanceof RouterError) {
      throw this.revertAnswer
    }
    return this.revertAnswer
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    this.calls.changePassword.push([oldPassword, newPassword])
    await this.#held.get('changePassword')?.promise
    if (this.changeRefusal !== null) {
      throw this.changeRefusal
    }
  }

  async reboot(): Promise<void> {
    this.calls.reboot += 1
    await this.#held.get('reboot')?.promise
    if (this.rebootRefusal !== null) {
      throw this.rebootRefusal
    }
  }

  subscribe(topic: 'state', onPush: (state: State) => void): Subscription
  subscribe(topic: 'leases', onPush: (leases: Leases) => void): Subscription
  subscribe(topic: 'counters', onPush: (counters: Counters) => void): Subscription
  subscribe(topic: 'events', onPush: (event: Event) => void, options?: { backlog?: number; onLost?: () => void }): Subscription
  subscribe(topic: 'logs', onPush: (batch: LogBatch) => void, options?: { onLost?: () => void }): Subscription
  subscribe(topic: Topic, onPush: Listener, options: { backlog?: number; onLost?: () => void } = {}): Subscription {
    // As the client does: with no session there is nothing to subscribe on, and it says so at once.
    if (!this.authenticated) {
      throw new RouterError(ErrorCode.UNAUTHENTICATED, 'not logged in')
    }
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
  open(topic: Topic): Listening[] {
    return this.listening.filter((entry) => entry.topic === topic && !entry.closed)
  }

  push(topic: 'state', value: State): void
  push(topic: 'leases', value: Leases): void
  push(topic: 'counters', value: Counters): void
  push(topic: 'events', value: Event): void
  push(topic: 'logs', value: LogBatch): void
  push(topic: Topic, value: Pushed): void {
    for (const entry of this.open(topic)) {
      ;(entry.onPush as (value: Pushed) => void)(value)
    }
  }

  /** The router says events were dropped, or lines of the log. */
  lose(topic: 'events' | 'logs' = 'events'): void {
    for (const entry of this.open(topic)) {
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

  /** Make calls of one kind wait until the returned function is called. */
  holdCall(name: 'config' | 'validate' | 'apply' | 'confirm' | 'revert' | 'history' | 'changePassword' | 'reboot'): () => void {
    const gate = held<void>()
    this.#held.set(name, gate)
    return () => {
      this.#held.delete(name)
      gate.resolve()
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
