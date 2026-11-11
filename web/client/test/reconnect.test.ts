// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create, toBinary } from '@bufbuild/protobuf'
import { expect, test } from 'vitest'

import { delayMs } from '../src/backoff.js'
import { LoginResponseSchema } from '../src/gen/openfeo/v1/api_pb.js'
import {
  CountersSchema,
  ErrorCode,
  EventSchema,
  memoryTokenStore,
  Router,
  RouterError,
  StateSchema,
  type Connection,
  type Counters,
  type Event,
  type SessionEnd,
  type State,
} from '../src/index.js'
import { ManualTimers, scripted, settle } from './scripted.js'

function setup(options: { probeAfterMs?: number; probeTimeoutMs?: number } = {}) {
  const { factory, sockets } = scripted()
  const store = memoryTokenStore()
  store.set('tok')
  const timers = new ManualTimers()
  const router = new Router({
    baseUrl: 'https://openfeo.home.arpa',
    tokenStore: store,
    webSocket: factory,
    timers,
    fetch: () =>
      Promise.resolve(
        new Response(toBinary(LoginResponseSchema, create(LoginResponseSchema, { session: { token: 'again', idleSecs: 1800 } })), {
          status: 200,
          headers: { 'content-type': 'application/x-protobuf' },
        }),
      ),
    ...options,
  })
  const connections: Connection[] = []
  const ends: SessionEnd[] = []
  router.onConnection((connection) => connections.push(connection))
  router.onSessionEnd((reason) => ends.push(reason))
  const socket = () => {
    const last = sockets.at(-1)
    if (last === undefined) {
      throw new Error('no socket was opened')
    }
    return last
  }
  return { router, sockets, socket, store, timers, connections, ends }
}

async function refusal(work: Promise<unknown>): Promise<RouterError> {
  const error: unknown = await work.then(
    () => undefined,
    (thrown: unknown) => thrown,
  )
  expect(error).toBeInstanceOf(RouterError)
  return error as RouterError
}

const pushState = (generation: bigint) =>
  ({
    id: 0,
    body: { case: 'telemetry', value: { topic: 'state', body: { case: 'state', value: create(StateSchema, { generation }) } } },
  }) as const
const pushCounters = (monotonicMs: bigint) =>
  ({
    id: 0,
    body: { case: 'telemetry', value: { topic: 'counters', body: { case: 'counters', value: create(CountersSchema, { monotonicMs }) } } },
  }) as const

test('the wait doubles from half a second to ten, and is never under half its step', () => {
  expect(delayMs(0, 1)).toBe(500)
  expect(delayMs(0, 0)).toBe(250)
  expect(delayMs(1, 1)).toBe(1_000)
  expect(delayMs(3, 1)).toBe(4_000)
  expect(delayMs(4, 0.5)).toBe(6_000)
  expect(delayMs(5, 1)).toBe(10_000)
  expect(delayMs(9, 1)).toBe(10_000)
  expect(delayMs(1_000, 1)).toBe(10_000)
  expect(delayMs(9, 0)).toBe(5_000)
})

test('a dropped socket is replaced, authenticated and subscribed again, and the listener keeps receiving', () => {
  const { router, sockets, socket, timers, connections, ends } = setup()
  const states: State[] = []
  const counters: Counters[] = []
  router.subscribe('state', (state) => states.push(state))
  router.subscribe('counters', (sample) => counters.push(sample))
  socket().accept()
  socket().receive(pushState(1n))
  socket().drop(1006)
  expect(router.connection).toBe('reconnecting')
  expect(sockets).toHaveLength(1)
  timers.advance(499)
  expect(sockets).toHaveLength(1)
  timers.advance(1)
  expect(sockets).toHaveLength(2)
  expect(router.connection).toBe('reconnecting')
  socket().open()
  expect(socket().kinds()).toEqual(['auth'])
  socket().ack()
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'subscribe'])
  expect(router.connection).toBe('open')
  socket().receive(pushState(2n))
  socket().receive(pushCounters(9n))
  expect(states.map((state) => state.generation)).toEqual([1n, 2n])
  expect(counters.map((sample) => sample.monotonicMs)).toEqual([9n])
  expect(connections).toEqual(['connecting', 'open', 'reconnecting', 'open'])
  expect(ends).toEqual([])
})

test('what was waiting when the socket dropped is rejected UNAVAILABLE and not sent again', async () => {
  const { router, socket, timers } = setup()
  router.subscribe('state', () => undefined)
  socket().accept()
  const pending = router.state()
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'request'])
  socket().drop(1006)
  expect((await refusal(pending)).code).toBe(ErrorCode.UNAVAILABLE)
  timers.advance(500)
  socket().accept()
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
})

test('with nothing subscribed a dropped socket is not remade until it is needed', async () => {
  const { router, sockets, socket, timers } = setup()
  const pending = router.state()
  socket().accept()
  socket().drop(1006)
  expect((await refusal(pending)).code).toBe(ErrorCode.UNAVAILABLE)
  expect(router.connection).toBe('idle')
  timers.advance(60_000)
  expect(sockets).toHaveLength(1)
  void router.state().catch(() => undefined)
  expect(sockets).toHaveLength(2)
})

test('events are subscribed again without a backlog and the listener is told some may be lost', () => {
  const { router, socket, timers } = setup()
  const events: Event[] = []
  let lost = 0
  router.subscribe('events', (event) => events.push(event), { backlog: 8, onLost: () => (lost += 1) })
  socket().accept()
  const first = socket().last()
  expect(first.body.case === 'subscribe' && first.body.value.backlog).toBe(8)
  socket().drop(1006)
  expect(lost).toBe(0)
  timers.advance(500)
  socket().accept()
  const again = socket().last()
  expect(again.body.case === 'subscribe' && [again.body.value.topic, again.body.value.backlog]).toEqual(['events', 0])
  expect(lost).toBe(1)
  socket().receive({ id: 0, body: { case: 'event', value: create(EventSchema, { topic: 'wan.wan0.up' }) } })
  expect(events.map((event) => event.topic)).toEqual(['wan.wan0.up'])
})

test('a socket that never opens is tried again, later each time', () => {
  const { router, sockets, socket, timers } = setup()
  router.subscribe('state', () => undefined)
  socket().drop(1006) // refused before it opened
  expect(router.connection).toBe('reconnecting')
  timers.advance(500)
  expect(sockets).toHaveLength(2)
  socket().drop(1006)
  timers.advance(999)
  expect(sockets).toHaveLength(2)
  timers.advance(1)
  expect(sockets).toHaveLength(3)
  socket().drop(1006)
  timers.advance(2_000)
  expect(sockets).toHaveLength(4)
})

test('the wait starts over once a socket has authenticated', () => {
  const { router, sockets, socket, timers } = setup()
  router.subscribe('state', () => undefined)
  socket().drop(1006)
  timers.advance(500)
  socket().drop(1006)
  timers.advance(1_000)
  expect(sockets).toHaveLength(3)
  socket().accept()
  socket().drop(1006)
  timers.advance(500)
  expect(sockets).toHaveLength(4)
})

test('the wait is spread by the dice, down to half its step', () => {
  const { router, sockets, socket, timers } = setup()
  timers.roll = 0
  router.subscribe('state', () => undefined)
  socket().drop(1006)
  timers.advance(249)
  expect(sockets).toHaveLength(1)
  timers.advance(1)
  expect(sockets).toHaveLength(2)
})

test('a token refused at Auth ends the session as lapsed, clears the store and does not reconnect', () => {
  const { router, sockets, socket, store, timers, ends, connections } = setup()
  let pushes = 0
  router.subscribe('state', () => (pushes += 1))
  socket().open()
  socket().receive({ id: socket().last().id, body: { case: 'error', value: { code: ErrorCode.UNAUTHENTICATED, message: 'no such session' } } })
  socket().drop(4401)
  expect(ends).toEqual(['lapsed'])
  expect(store.get()).toBeNull()
  expect(router.authenticated).toBe(false)
  expect(router.connection).toBe('idle')
  expect(connections.at(-1)).toBe('idle')
  timers.advance(60_000)
  expect(sockets).toHaveLength(1)
  expect(timers.pending).toBe(0)
  expect(pushes).toBe(0)
})

test('a 4401 on an authenticated socket ends the session as revoked', async () => {
  const { router, sockets, socket, store, timers, ends } = setup()
  router.subscribe('state', () => undefined)
  socket().accept()
  const pending = router.state()
  socket().drop(4401)
  expect(ends).toEqual(['revoked'])
  expect(store.get()).toBeNull()
  expect((await refusal(pending)).code).toBe(ErrorCode.UNAVAILABLE)
  timers.advance(60_000)
  expect(sockets).toHaveLength(1)
})

test('no place free (1013) is a drop, not the end of the session', () => {
  const { router, sockets, socket, store, timers, ends } = setup()
  router.subscribe('state', () => undefined)
  socket().open()
  socket().drop(1013)
  expect(ends).toEqual([])
  expect(store.get()).toBe('tok')
  expect(router.connection).toBe('reconnecting')
  timers.advance(500)
  expect(sockets).toHaveLength(2)
})

test('a frame that is not a ServerMsg drops the socket', () => {
  const { router, sockets, socket, timers, ends } = setup()
  router.subscribe('state', () => undefined)
  socket().accept()
  const first = socket()
  first.receiveRaw(new Uint8Array([0xff, 0xff, 0xff, 0xff]).buffer)
  expect(first.closedWith).toBeDefined()
  expect(router.connection).toBe('reconnecting')
  timers.advance(500)
  expect(sockets).toHaveLength(2)
  // A text frame is no better.
  socket().accept()
  socket().receiveRaw('hello')
  expect(router.connection).toBe('reconnecting')
  expect(ends).toEqual([])
})

test('a silent socket is probed and then dropped', async () => {
  // A laptop that slept, a Wi-Fi link that went: no close ever arrives, and a browser cannot
  // see the router's pings. Thirty seconds of nothing and the client asks; ten more and it
  // stops believing the socket.
  const { router, sockets, socket, timers } = setup()
  router.subscribe('counters', () => undefined)
  socket().accept()
  socket().ack()
  timers.advance(29_999)
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
  timers.advance(1)
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'request'])
  const probe = socket().last()
  expect(probe.body.case === 'request' && probe.body.value.body.case).toBe('getState')
  expect(router.connection).toBe('open')
  timers.advance(9_999)
  expect(router.connection).toBe('open')
  timers.advance(1)
  expect(router.connection).toBe('reconnecting')
  expect(socket().closedWith).toBeDefined()
  await settle()
  timers.advance(500)
  expect(sockets).toHaveLength(2)
})

test('any frame quiets the watchdog', () => {
  const { router, socket, timers } = setup()
  router.subscribe('counters', () => undefined)
  socket().accept()
  timers.advance(29_000)
  socket().receive(pushCounters(1n))
  timers.advance(29_000)
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
  timers.advance(1_000)
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'request'])
  // The probe's own answer is a frame like any other.
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'getState', value: { state: create(StateSchema, {}) } } } },
  })
  timers.advance(10_000)
  expect(router.connection).toBe('open')
})

test('the watchdog keeps the times it was given', () => {
  const { router, socket, timers } = setup({ probeAfterMs: 2_000, probeTimeoutMs: 1_000 })
  router.subscribe('counters', () => undefined)
  socket().accept()
  timers.advance(2_000)
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'request'])
  timers.advance(1_000)
  expect(router.connection).toBe('reconnecting')
})

test('close() while waiting to reconnect stops the waiting', () => {
  const { router, sockets, socket, timers } = setup()
  router.subscribe('state', () => undefined)
  socket().accept()
  socket().drop(1006)
  router.close()
  expect(router.connection).toBe('idle')
  timers.advance(60_000)
  expect(sockets).toHaveLength(1)
  expect(timers.pending).toBe(0)
})

test('after the session ends, a new login and a new subscribe work on the same router', async () => {
  const { router, sockets, socket, store, ends } = setup()
  const before: State[] = []
  router.subscribe('state', (state) => before.push(state))
  socket().accept()
  socket().drop(4401)
  expect(ends).toEqual(['revoked'])
  await router.login('a password of some length')
  expect(store.get()).toBe('again')
  const after: State[] = []
  router.subscribe('state', (state) => after.push(state))
  expect(sockets).toHaveLength(2)
  socket().open()
  const auth = socket().last()
  expect(auth.body.case === 'auth' && auth.body.value.token).toBe('again')
  socket().ack()
  socket().receive(pushState(5n))
  expect(after.map((state) => state.generation)).toEqual([5n])
  // The listener from before the session ended is gone with it.
  expect(before).toEqual([])
})
