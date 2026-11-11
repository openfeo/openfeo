// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The envelope over a WebSocket (SPEC §8.3). One socket for everything after login: the first
// frame is `Auth` with the session's token, requests are numbered and answered under their
// number, and pushes (state, counters, events) arrive under number 0. The router acknowledges
// `Auth`, `Subscribe` and `Unsubscribe` with an empty reply.

import { create, fromBinary, toBinary, type MessageInitShape } from '@bufbuild/protobuf'

import { RouterError } from './errors.js'
import {
  ClientMsgSchema,
  ErrorCode,
  ServerMsgSchema,
  type RequestSchema,
  type Response as Reply,
  type ServerMsg,
} from './gen/openfeo/v1/api_pb.js'
import type { Event } from './gen/openfeo/v1/events_pb.js'
import type { Counters, State } from './gen/openfeo/v1/state_pb.js'
import type { Timers, WebSocketLike } from './options.js'
import type { TokenStore } from './token-store.js'

/** Where the socket stands. */
export type Connection = 'idle' | 'connecting' | 'open' | 'reconnecting'
/** Why a session ended: this client logged out, the router no longer knew it, or it was ended from elsewhere. */
export type SessionEnd = 'logout' | 'lapsed' | 'revoked'
export type Topic = 'state' | 'counters' | 'events'

export interface Subscription {
  /** Stop listening. The topic is unsubscribed when its last listener closes. */
  close(): void
}

/** What a `Request` may carry. */
export type Ask = NonNullable<MessageInitShape<typeof RequestSchema>['body']>

interface Waiting {
  resolve: (reply: Reply) => void
  reject: (error: RouterError) => void
}

interface EventListener {
  onPush: (event: Event) => void
  onLost: (() => void) | undefined
}

export interface LinkDeps {
  /** `wss://<host>/ws`. */
  url: string
  store: TokenStore
  webSocket: (url: string) => WebSocketLike
  timers: Timers
  probeAfterMs: number
  probeTimeoutMs: number
}

/** The close code the router ends a socket with when its token is not, or is no longer, a session. */
const CLOSE_UNAUTHENTICATED = 4401

/** A listener's own fault is the listener's: it is reported, and the socket carries on. */
function report(error: unknown): void {
  const reporter = (globalThis as { reportError?: (error: unknown) => void }).reportError
  if (reporter === undefined) {
    console.error(error)
  } else {
    reporter(error)
  }
}

function deliver<T>(listeners: Iterable<(value: T) => void>, value: T): void {
  for (const listener of [...listeners]) {
    try {
      listener(value)
    } catch (error) {
      report(error)
    }
  }
}

function bytes(data: unknown): Uint8Array | null {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data)
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  }
  return null
}

/** One router's socket and everything that rides on it. */
export class Link {
  readonly #deps: LinkDeps
  #socket: WebSocketLike | null = null
  #connection: Connection = 'idle'
  /** The `Auth` frame has been acknowledged. */
  #authenticated = false
  #authId = 0
  #nextId = 1
  /** This client asked to log out: a 4401 that follows is that, not a revocation. */
  #leaving = false
  readonly #waiting = new Map<number, Waiting>()
  /** Requests made before the socket was ready, sent once `Auth` is acknowledged. */
  #held: { id: number; ask: Ask }[] = []
  readonly #state = new Set<(state: State) => void>()
  readonly #counters = new Set<(counters: Counters) => void>()
  readonly #events = new Set<EventListener>()
  #backlog = 0
  readonly #onConnection = new Set<(connection: Connection) => void>()
  readonly #onSessionEnd = new Set<(reason: SessionEnd) => void>()

  constructor(deps: LinkDeps) {
    this.#deps = deps
  }

  get connection(): Connection {
    return this.#connection
  }

  onConnection(listener: (connection: Connection) => void): () => void {
    this.#onConnection.add(listener)
    return () => this.#onConnection.delete(listener)
  }

  onSessionEnd(listener: (reason: SessionEnd) => void): () => void {
    this.#onSessionEnd.add(listener)
    return () => this.#onSessionEnd.delete(listener)
  }

  /** Ask the router something and wait for its answer. */
  request(ask: Ask): Promise<Reply> {
    try {
      this.#open()
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error(String(error)))
    }
    const id = this.#nextId++
    const answer = new Promise<Reply>((resolve, reject) => this.#waiting.set(id, { resolve, reject }))
    if (this.#authenticated) {
      this.#send(id, { case: 'request', value: { body: ask } })
    } else {
      this.#held.push({ id, ask })
    }
    return answer
  }

  subscribeState(listener: (state: State) => void): Subscription {
    return this.#listen('state', this.#state, listener)
  }

  subscribeCounters(listener: (counters: Counters) => void): Subscription {
    return this.#listen('counters', this.#counters, listener)
  }

  /** `backlog` is asked for when this listener is the topic's first. */
  subscribeEvents(onPush: (event: Event) => void, backlog: number, onLost: (() => void) | undefined): Subscription {
    if (this.#events.size === 0) {
      this.#backlog = backlog
    }
    return this.#listen('events', this.#events, { onPush, onLost })
  }

  /** Tell the router, then end the session here whether or not it heard. */
  async logout(): Promise<void> {
    if (this.#deps.store.get() === null) {
      return
    }
    this.#leaving = true
    try {
      await this.request({ case: 'logout', value: {} })
    } catch {
      // A router that did not hear lets the session lapse; here it is over either way.
    }
    this.#end('logout')
  }

  /** Drop the socket and every subscription. The session and its token stay. */
  close(): void {
    this.#forget()
    this.#drop('the socket was closed')
    this.#set('idle')
  }

  #listen<L>(topic: Topic, listeners: Set<L>, listener: L): Subscription {
    this.#open()
    const first = listeners.size === 0
    listeners.add(listener)
    if (first && this.#authenticated) {
      this.#subscribe(topic)
    }
    return {
      close: () => {
        if (listeners.delete(listener) && listeners.size === 0 && this.#authenticated) {
          this.#send(this.#nextId++, { case: 'unsubscribe', value: { topic } })
        }
      },
    }
  }

  #wanted(): Topic[] {
    const topics: Topic[] = []
    if (this.#state.size > 0) {
      topics.push('state')
    }
    if (this.#counters.size > 0) {
      topics.push('counters')
    }
    if (this.#events.size > 0) {
      topics.push('events')
    }
    return topics
  }

  #subscribe(topic: Topic): void {
    const backlog = topic === 'events' ? this.#backlog : 0
    this.#send(this.#nextId++, { case: 'subscribe', value: { topic, backlog } })
  }

  #send(id: number, body: NonNullable<MessageInitShape<typeof ClientMsgSchema>['body']>): void {
    this.#socket?.send(toBinary(ClientMsgSchema, create(ClientMsgSchema, { id, body })))
  }

  #set(connection: Connection): void {
    if (this.#connection !== connection) {
      this.#connection = connection
      deliver(this.#onConnection, connection)
    }
  }

  /** Make sure a socket is there or on its way. Without a token there is no session to open one for. */
  #open(): void {
    if (this.#socket !== null) {
      return
    }
    const token = this.#deps.store.get()
    if (token === null) {
      throw new RouterError(ErrorCode.UNAUTHENTICATED, 'not logged in')
    }
    const socket = this.#deps.webSocket(this.#deps.url)
    socket.binaryType = 'arraybuffer'
    socket.onopen = () => {
      if (this.#socket === socket) {
        this.#authId = this.#nextId++
        this.#send(this.#authId, { case: 'auth', value: { token } })
      }
    }
    socket.onmessage = (event) => {
      if (this.#socket === socket) {
        this.#received(event.data)
      }
    }
    socket.onclose = (event) => {
      if (this.#socket === socket) {
        this.#closed(event.code)
      }
    }
    this.#socket = socket
    this.#set('connecting')
  }

  #received(data: unknown): void {
    const frame = bytes(data)
    let message: ServerMsg
    try {
      if (frame === null) {
        throw new TypeError('not a binary frame')
      }
      message = fromBinary(ServerMsgSchema, frame)
    } catch {
      return
    }
    if (message.id === 0) {
      this.#pushed(message)
    } else if (message.id === this.#authId) {
      if (message.body.case === 'response') {
        this.#ready()
      }
    } else {
      const waiting = this.#waiting.get(message.id)
      if (waiting !== undefined) {
        this.#waiting.delete(message.id)
        if (message.body.case === 'response') {
          waiting.resolve(message.body.value)
        } else if (message.body.case === 'error') {
          const { code, message: text, retryAfterSecs } = message.body.value
          waiting.reject(new RouterError(code, text, { retryAfterSecs }))
        } else {
          waiting.reject(new RouterError(ErrorCode.INTERNAL, 'the router answered a request with something else'))
        }
      }
    }
  }

  /** `Auth` was acknowledged: subscribe what is wanted, then send what was held. */
  #ready(): void {
    this.#authenticated = true
    this.#set('open')
    for (const topic of this.#wanted()) {
      this.#subscribe(topic)
    }
    const held = this.#held
    this.#held = []
    for (const { id, ask } of held) {
      this.#send(id, { case: 'request', value: { body: ask } })
    }
  }

  #pushed(message: ServerMsg): void {
    const body = message.body
    if (body.case === 'telemetry') {
      const pushed = body.value.body
      if (pushed.case === 'state') {
        deliver(this.#state, pushed.value)
      } else if (pushed.case === 'counters') {
        deliver(this.#counters, pushed.value)
      }
    } else if (body.case === 'event') {
      deliver(
        [...this.#events].map((listener) => listener.onPush),
        body.value,
      )
    } else if (body.case === 'error' && body.value.code === ErrorCode.DATA_LOSS) {
      this.#lost()
    }
  }

  #lost(): void {
    deliver(
      [...this.#events].flatMap((listener) => (listener.onLost === undefined ? [] : [() => listener.onLost?.()])),
      undefined,
    )
  }

  /** The socket ended from the far side, or the network's. */
  #closed(code: number): void {
    const wasAuthenticated = this.#authenticated
    if (code === CLOSE_UNAUTHENTICATED) {
      this.#end(this.#leaving ? 'logout' : wasAuthenticated ? 'revoked' : 'lapsed')
      return
    }
    this.#drop('the connection to the router was lost')
    this.#set('idle')
  }

  /** Let go of the socket; whatever was waiting on it is told the router is not there. */
  #drop(why: string): void {
    const socket = this.#socket
    this.#socket = null
    this.#authenticated = false
    this.#held = []
    if (socket !== null) {
      socket.onopen = null
      socket.onmessage = null
      socket.onclose = null
      socket.onerror = null
      socket.close()
    }
    const waiting = [...this.#waiting.values()]
    this.#waiting.clear()
    for (const { reject } of waiting) {
      reject(new RouterError(ErrorCode.UNAVAILABLE, why))
    }
  }

  #forget(): void {
    this.#state.clear()
    this.#counters.clear()
    this.#events.clear()
  }

  /** The session is over: nothing is kept, nothing reconnects, and whoever listens is told why. */
  #end(reason: SessionEnd): void {
    this.#leaving = false
    this.#deps.store.clear()
    this.#forget()
    this.#drop('the session ended')
    this.#set('idle')
    deliver(this.#onSessionEnd, reason)
  }
}
