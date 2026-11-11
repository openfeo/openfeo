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
import { call, type Http } from './http.js'
import type { RouterOptions } from './options.js'
import { memoryTokenStore, type TokenStore } from './token-store.js'

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

  constructor(options: RouterOptions = {}) {
    const base = options.baseUrl ?? pageOrigin()
    if (base === undefined) {
      throw new TypeError('Router needs a baseUrl when there is no page to take it from')
    }
    this.#http = {
      baseUrl: new URL(base).origin,
      fetch: options.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    }
    this.#store = options.tokenStore ?? memoryTokenStore()
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

  #begin(session: Session | undefined): Session {
    if (session === undefined || session.token === '') {
      throw new RouterError(ErrorCode.INTERNAL, 'the router answered without a session')
    }
    this.#store.set(session.token)
    return session
  }
}
