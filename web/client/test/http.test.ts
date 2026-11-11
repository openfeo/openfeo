// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create, fromBinary, toBinary, type DescMessage, type MessageInitShape } from '@bufbuild/protobuf'
import { afterEach, expect, test, vi } from 'vitest'

import {
  ErrorCode,
  ErrorSchema,
  GetStatusResponseSchema,
  LoginRequestSchema,
  LoginResponseSchema,
  SetInitialPasswordRequestSchema,
  SetInitialPasswordResponseSchema,
} from '../src/gen/openfeo/v1/api_pb.js'
import { memoryTokenStore, Router, RouterError } from '../src/index.js'
import { ManualTimers, settle } from './scripted.js'

const BASE = 'https://openfeo.home.arpa'
const PROTOBUF = 'application/x-protobuf'
const PASSWORD = 'correct horse battery'

interface Call {
  url: string
  method: string
  headers: Headers
  body: Uint8Array | undefined
  init: RequestInit
}

/** A `fetch` that records what it is asked and answers from a script. */
function scripted(...answers: (Response | Error)[]) {
  const calls: Call[] = []
  const fetch: typeof globalThis.fetch = (input, init = {}) => {
    const raw = init.body
    calls.push({
      url: typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      method: init.method ?? 'GET',
      headers: new Headers(init.headers),
      body: raw instanceof Uint8Array ? raw : undefined,
      init,
    })
    const next = answers.shift()
    if (next === undefined) {
      return Promise.reject(new Error('the script has no more answers'))
    }
    return next instanceof Response ? Promise.resolve(next) : Promise.reject(next)
  }
  return { fetch, calls }
}

function answer<D extends DescMessage>(
  status: number,
  schema: D,
  init: MessageInitShape<D>,
  headers: Record<string, string> = {},
): Response {
  return new Response(toBinary(schema, create(schema, init)), {
    status,
    headers: { 'content-type': PROTOBUF, ...headers },
  })
}

function router(...answers: (Response | Error)[]) {
  const { fetch, calls } = scripted(...answers)
  const store = memoryTokenStore()
  return { router: new Router({ baseUrl: BASE, fetch, tokenStore: store }), calls, store }
}

async function refusal(work: Promise<unknown>): Promise<RouterError> {
  const error: unknown = await work.then(
    () => undefined,
    (thrown: unknown) => thrown,
  )
  expect(error).toBeInstanceOf(RouterError)
  return error as RouterError
}

afterEach(() => {
  vi.unstubAllGlobals()
})

test('status reads the protobuf answer', async () => {
  const { router: r, calls } = router(
    answer(200, GetStatusResponseSchema, {
      hostname: 'openfeo',
      domain: 'home.arpa',
      needsPassword: true,
      tlsFingerprint: '3F:9A',
    }),
  )
  const status = await r.status()
  expect(status.hostname).toBe('openfeo')
  expect(status.needsPassword).toBe(true)
  expect(status.configRefused).toBe(false)
  expect(status.configUnreadable).toBe(false)
  expect(status.tlsFingerprint).toBe('3F:9A')
  expect(calls).toHaveLength(1)
  expect(calls[0]?.url).toBe(`${BASE}/api/status`)
  expect(calls[0]?.method).toBe('GET')
  expect(calls[0]?.headers.get('accept')).toBe(PROTOBUF)
  expect(calls[0]?.headers.has('authorization')).toBe(false)
  // Nothing a browser would add by itself rides along: no cookie, no cached answer.
  expect(calls[0]?.init.credentials).toBe('omit')
  expect(calls[0]?.init.cache).toBe('no-store')
})

test('login sends the password as a LoginRequest, stores the token and returns the session', async () => {
  const { router: r, calls, store } = router(
    answer(200, LoginResponseSchema, { session: { token: 'tok', idleSecs: 1800 } }),
  )
  expect(r.authenticated).toBe(false)
  const session = await r.login(PASSWORD)
  expect(session.token).toBe('tok')
  expect(session.idleSecs).toBe(1800)
  expect(store.get()).toBe('tok')
  expect(r.authenticated).toBe(true)
  expect(calls[0]?.url).toBe(`${BASE}/api/login`)
  expect(calls[0]?.method).toBe('POST')
  expect(calls[0]?.headers.get('content-type')).toBe(PROTOBUF)
  expect(fromBinary(LoginRequestSchema, calls[0]?.body ?? new Uint8Array()).password).toBe(PASSWORD)
})

test('setting the first password logs this client in', async () => {
  const { router: r, calls, store } = router(
    answer(200, SetInitialPasswordResponseSchema, { session: { token: 'first', idleSecs: 1800 } }),
  )
  const session = await r.setInitialPassword(PASSWORD)
  expect(session.token).toBe('first')
  expect(store.get()).toBe('first')
  expect(calls[0]?.url).toBe(`${BASE}/api/password`)
  expect(calls[0]?.method).toBe('POST')
  expect(fromBinary(SetInitialPasswordRequestSchema, calls[0]?.body ?? new Uint8Array()).password).toBe(PASSWORD)
})

test('an answer with no session in it is not a login', async () => {
  const { router: r, store } = router(answer(200, LoginResponseSchema, {}))
  const error = await refusal(r.login(PASSWORD))
  expect(error.code).toBe(ErrorCode.INTERNAL)
  expect(store.get()).toBeNull()
})

test('a wrong password is a typed error that carries the wait', async () => {
  const waiting = router(
    answer(
      429,
      ErrorSchema,
      { code: ErrorCode.RESOURCE_EXHAUSTED, message: 'wait before the next attempt', retryAfterSecs: 8 },
      { 'retry-after': '8' },
    ),
  )
  const error = await refusal(waiting.router.login(PASSWORD))
  expect(error.code).toBe(ErrorCode.RESOURCE_EXHAUSTED)
  expect(error.retryAfterSecs).toBe(8)
  expect(error.httpStatus).toBe(429)
  expect(error.message).toBe('wait before the next attempt')
  expect(waiting.store.get()).toBeNull()

  // The wait is taken from the header when the body does not say.
  const header = router(new Response(null, { status: 429, headers: { 'retry-after': '8' } }))
  const fromHeader = await refusal(header.router.login(PASSWORD))
  expect(fromHeader.code).toBe(ErrorCode.RESOURCE_EXHAUSTED)
  expect(fromHeader.retryAfterSecs).toBe(8)

  // A plain wrong password, with or without a wait in it.
  const wrong = router(
    answer(401, ErrorSchema, { code: ErrorCode.UNAUTHENTICATED, message: 'wrong password', retryAfterSecs: 2 }),
  )
  const unauthenticated = await refusal(wrong.router.login(PASSWORD))
  expect(unauthenticated.code).toBe(ErrorCode.UNAUTHENTICATED)
  expect(unauthenticated.retryAfterSecs).toBe(2)
  const noWait = router(answer(401, ErrorSchema, { code: ErrorCode.UNAUTHENTICATED, message: 'wrong password' }))
  expect((await refusal(noWait.router.login(PASSWORD))).retryAfterSecs).toBeUndefined()
})

test('a second first password is FAILED_PRECONDITION', async () => {
  const { router: r, store } = router(
    answer(409, ErrorSchema, { code: ErrorCode.FAILED_PRECONDITION, message: 'a password is already set' }),
  )
  const error = await refusal(r.setInitialPassword(PASSWORD))
  expect(error.code).toBe(ErrorCode.FAILED_PRECONDITION)
  expect(error.httpStatus).toBe(409)
  expect(store.get()).toBeNull()
})

test('a refusal with no Error in it keeps its status', async () => {
  // The host check answers 421 with no body; so does anything in front of the router.
  const { router: r } = router(new Response('misdirected', { status: 421, headers: { 'content-type': 'text/plain' } }))
  const error = await refusal(r.status())
  expect(error.code).toBe(ErrorCode.UNSPECIFIED)
  expect(error.httpStatus).toBe(421)
  expect(error.message).toContain('421')
  const garbage = router(new Response(new Uint8Array([0xff, 0xff, 0xff]), { status: 500, headers: { 'content-type': PROTOBUF } }))
  const unreadable = await refusal(garbage.router.status())
  expect(unreadable.httpStatus).toBe(500)
})

test('an answer that is not the message asked for is an error, not a guess', async () => {
  const { router: r } = router(new Response(new Uint8Array([0xff, 0xff, 0xff]), { status: 200, headers: { 'content-type': PROTOBUF } }))
  expect((await refusal(r.status())).code).toBe(ErrorCode.INTERNAL)
})

test('a router that cannot be reached is UNAVAILABLE', async () => {
  const { router: r } = router(new TypeError('fetch failed'))
  const error = await refusal(r.status())
  expect(error.code).toBe(ErrorCode.UNAVAILABLE)
  expect(error.httpStatus).toBeUndefined()
})

test('no error message carries the password', async () => {
  for (const response of [
    answer(401, ErrorSchema, { code: ErrorCode.UNAUTHENTICATED, message: 'wrong password' }),
    new Response('nope', { status: 500 }),
    new TypeError('fetch failed'),
  ]) {
    const { router: r } = router(response)
    const error = await refusal(r.login(PASSWORD))
    expect(`${error.name} ${error.message} ${String(error)} ${JSON.stringify(error)}`).not.toContain(PASSWORD)
  }
})

test("the base address defaults to the page's origin", async () => {
  vi.stubGlobal('location', { origin: 'https://192.168.1.1' })
  const { fetch, calls } = scripted(answer(200, GetStatusResponseSchema, {}))
  await new Router({ fetch }).status()
  expect(calls[0]?.url).toBe('https://192.168.1.1/api/status')
})

test('a base address with a path or a trailing slash is still the router', async () => {
  const { fetch, calls } = scripted(answer(200, GetStatusResponseSchema, {}))
  await new Router({ baseUrl: 'https://192.168.1.1/', fetch }).status()
  expect(calls[0]?.url).toBe('https://192.168.1.1/api/status')
})

test('with no page and no address there is nothing to talk to, and that is said at once', () => {
  expect(() => new Router({ fetch: scripted().fetch })).toThrow(/baseUrl/)
})

test('two routers share nothing', async () => {
  const first = router(answer(200, LoginResponseSchema, { session: { token: 'one', idleSecs: 1800 } }))
  const second = router()
  await first.router.login(PASSWORD)
  expect(first.router.authenticated).toBe(true)
  expect(second.router.authenticated).toBe(false)
  expect(second.store.get()).toBeNull()
  // And a router given no store keeps its own.
  const { fetch } = scripted(answer(200, LoginResponseSchema, { session: { token: 'mine', idleSecs: 1800 } }))
  const own = new Router({ baseUrl: BASE, fetch })
  await own.login(PASSWORD)
  expect(own.authenticated).toBe(true)
  expect(second.router.authenticated).toBe(false)
})

test('a call the router never answers is given up after ten seconds, as UNAVAILABLE', async () => {
  // A router that has just lost power: the request goes down a connection that is still open
  // and nothing comes back. Without a limit of its own the client waits as long as the
  // browser does, with a login button that says "Logging in…" for minutes.
  const timers = new ManualTimers()
  let signal: AbortSignal | undefined
  const fetch: typeof globalThis.fetch = (_input, init) =>
    new Promise<Response>((_resolve, reject) => {
      signal = init?.signal ?? undefined
      signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
    })
  const r = new Router({ baseUrl: BASE, fetch, timers })
  const pending = refusal(r.login(PASSWORD))
  await settle()
  timers.advance(9_999)
  await settle()
  expect(signal?.aborted).toBe(false)
  timers.advance(1)
  const error = await pending
  expect(error.code).toBe(ErrorCode.UNAVAILABLE)
  expect(error.message).not.toContain(PASSWORD)
  // The request itself is told to stop, so nothing is left running behind the error.
  expect(signal?.aborted).toBe(true)
  expect(timers.pending).toBe(0)
  expect(r.authenticated).toBe(false)
})

test('an answer whose body never arrives is given up too', async () => {
  const timers = new ManualTimers()
  const never = new ReadableStream<Uint8Array>({ start: () => undefined })
  const fetch: typeof globalThis.fetch = () => Promise.resolve(new Response(never, { status: 200, headers: { 'content-type': PROTOBUF } }))
  const pending = refusal(new Router({ baseUrl: BASE, fetch, timers }).status())
  await settle()
  timers.advance(10_000)
  expect((await pending).code).toBe(ErrorCode.UNAVAILABLE)
})

test('a call that is answered leaves no timer behind, and the limit is the one given', async () => {
  const timers = new ManualTimers()
  const answered = scripted(answer(200, GetStatusResponseSchema, { hostname: 'openfeo' }))
  await new Router({ baseUrl: BASE, fetch: answered.fetch, timers }).status()
  expect(timers.pending).toBe(0)

  const hung: typeof globalThis.fetch = () => new Promise<Response>(() => undefined)
  const pending = refusal(new Router({ baseUrl: BASE, fetch: hung, timers, probeTimeoutMs: 2_000 }).status())
  await settle()
  timers.advance(2_000)
  expect((await pending).code).toBe(ErrorCode.UNAVAILABLE)
})
