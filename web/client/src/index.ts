// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The OpenFeO API from JavaScript (SPEC §8.3, §8.4): the wire and nothing else. Nothing here
// imports Vue or touches the DOM beyond `fetch` and `WebSocket`, so it runs in a browser and
// in Node, and a panel other than OpenFeO's own can be built on it.

export { RouterError } from './errors.js'
export * from './messages.js'
export type { RouterOptions, Timers, WebSocketLike } from './options.js'
export { Router } from './router.js'
export { memoryTokenStore, type TokenStore } from './token-store.js'
