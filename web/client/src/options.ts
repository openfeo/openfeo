// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import type { TokenStore } from './token-store.js'

/** As much of a `WebSocket` as the client uses: a browser's, Node's, or a test's script. */
export interface WebSocketLike {
  binaryType: string
  onopen: (() => void) | null
  onmessage: ((event: { data: unknown }) => void) | null
  onclose: ((event: { code: number }) => void) | null
  onerror: (() => void) | null
  send(data: Uint8Array): void
  close(code?: number): void
}

/** The clock and the dice, so a test can turn both by hand. */
export interface Timers {
  set(fn: () => void, ms: number): unknown
  clear(handle: unknown): void
  now(): number
  random(): number
}

export interface RouterOptions {
  /** Where the router is: `https://openfeo.home.arpa`. Default: the page's own origin. */
  baseUrl?: string
  /** Where the session's token is kept. Default: in memory. */
  tokenStore?: TokenStore
  /** Default: the global `fetch`. */
  fetch?: typeof fetch
  /** Default: `new WebSocket(url)`. */
  webSocket?: (url: string) => WebSocketLike
  /** Default: `setTimeout`, `clearTimeout`, `Date.now` and `Math.random`. */
  timers?: Timers
  /** How long a socket may be silent before it is probed, in milliseconds. Default: 30000. */
  probeAfterMs?: number
  /**
   * How long the router may go unanswered before it is taken not to be there, in
   * milliseconds: a probe on a silent socket, a socket that is opening, and each plain call
   * (status, login, the first password). Default: 10000.
   */
  probeTimeoutMs?: number
}
