// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { create } from '@bufbuild/protobuf'
import { expect, test, vi } from 'vitest'

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

function setup(token: string | null = 'tok') {
  const { factory, sockets } = scripted()
  const store = memoryTokenStore()
  if (token !== null) {
    store.set(token)
  }
  const timers = new ManualTimers()
  const router = new Router({
    baseUrl: 'https://openfeo.home.arpa',
    tokenStore: store,
    webSocket: factory,
    timers,
    fetch: () => Promise.reject(new Error('no plain call is made here')),
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

const state = (generation: bigint) => create(StateSchema, { generation })

test('the socket is opened by the first call that needs it, at wss://<host>/ws, in binary', () => {
  const { router, sockets, socket } = setup()
  expect(sockets).toHaveLength(0)
  expect(router.connection).toBe('idle')
  void router.state().catch(() => undefined)
  expect(sockets).toHaveLength(1)
  expect(socket().url).toBe('wss://openfeo.home.arpa/ws')
  expect(socket().binaryType).toBe('arraybuffer')
  expect(router.connection).toBe('connecting')
  // A second call does not open a second socket.
  void router.state().catch(() => undefined)
  expect(sockets).toHaveLength(1)
})

test('the first frame is Auth with the stored token, and nothing else is sent before it is acknowledged', async () => {
  const { router, socket } = setup('the-token')
  const pending = router.state()
  expect(socket().sent).toHaveLength(0)
  socket().open()
  expect(socket().kinds()).toEqual(['auth'])
  const auth = socket().sent[0]
  expect(auth?.id).toBeGreaterThan(0)
  expect(auth?.body.case === 'auth' && auth.body.value.token).toBe('the-token')
  expect(router.connection).toBe('connecting')
  socket().ack()
  expect(router.connection).toBe('open')
  expect(socket().kinds()).toEqual(['auth', 'request'])
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'getState', value: { state: state(7n) } } } },
  })
  expect((await pending).generation).toBe(7n)
})

test('without a token no socket is opened and the call is refused as UNAUTHENTICATED', async () => {
  const { router, sockets, connections } = setup(null)
  expect((await refusal(router.state())).code).toBe(ErrorCode.UNAUTHENTICATED)
  expect(() => router.subscribe('state', () => undefined)).toThrow(RouterError)
  expect(sockets).toHaveLength(0)
  expect(connections).toEqual([])
})

test('requests are numbered and each reply finds its own, in any order', async () => {
  const { router, socket } = setup()
  const first = router.state()
  const second = router.state()
  socket().accept()
  const [a, b] = socket().sent.slice(1)
  expect(a?.id).not.toBe(b?.id)
  expect(new Set(socket().sent.map((frame) => frame.id)).size).toBe(3)
  const reply = (id: number | undefined, generation: bigint) =>
    socket().receive({
      id: id ?? 0,
      body: { case: 'response', value: { body: { case: 'getState', value: { state: state(generation) } } } },
    })
  reply(b?.id, 2n)
  reply(a?.id, 1n)
  expect((await first).generation).toBe(1n)
  expect((await second).generation).toBe(2n)
})

test('an Error reply rejects with its code', async () => {
  const { router, socket } = setup()
  const pending = router.state()
  socket().accept()
  socket().receive({ id: socket().last().id, body: { case: 'error', value: { code: ErrorCode.INTERNAL, message: 'no state' } } })
  const error = await refusal(pending)
  expect(error.code).toBe(ErrorCode.INTERNAL)
  expect(error.message).toBe('no state')
})

test('a reply that is not the one asked for is an error, not a guess', async () => {
  const { router, socket } = setup()
  const pending = router.state()
  socket().accept()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'logout', value: {} } } } })
  expect((await refusal(pending)).code).toBe(ErrorCode.INTERNAL)
})

test('logout tells the router, clears the store, closes the socket and ends the session as logout', async () => {
  const { router, socket, store, ends, connections } = setup()
  void router.state().catch(() => undefined)
  socket().accept()
  const out = router.logout()
  const frame = socket().last()
  expect(frame.body.case === 'request' && frame.body.value.body.case).toBe('logout')
  socket().receive({ id: frame.id, body: { case: 'response', value: { body: { case: 'logout', value: {} } } } })
  await out
  expect(store.get()).toBeNull()
  expect(router.authenticated).toBe(false)
  expect(socket().closedWith).toBeDefined()
  expect(ends).toEqual(['logout'])
  expect(router.connection).toBe('idle')
  expect(connections.at(-1)).toBe('idle')
  // The router closes its end with 4401 after a logout; that is not a second ending.
  socket().drop(4401)
  await settle()
  expect(ends).toEqual(['logout'])
})

test('logging out when not logged in is nothing', async () => {
  const { router, sockets, ends } = setup(null)
  await router.logout()
  expect(sockets).toHaveLength(0)
  expect(ends).toEqual([])
})

test('a wrong old password is INVALID_ARGUMENT and the session stays', async () => {
  const { router, socket, store, ends } = setup()
  const change = router.changePassword('the old one, mistyped', 'a new password of length')
  socket().accept()
  const frame = socket().last()
  expect(frame.body.case === 'request' && frame.body.value.body.case).toBe('changePassword')
  if (frame.body.case === 'request' && frame.body.value.body.case === 'changePassword') {
    expect(frame.body.value.body.value.oldPassword).toBe('the old one, mistyped')
    expect(frame.body.value.body.value.newPassword).toBe('a new password of length')
  }
  socket().receive({ id: frame.id, body: { case: 'error', value: { code: ErrorCode.INVALID_ARGUMENT, message: 'wrong password' } } })
  expect((await refusal(change)).code).toBe(ErrorCode.INVALID_ARGUMENT)
  expect(store.get()).toBe('tok')
  expect(ends).toEqual([])
  expect(router.connection).toBe('open')
})

test('a changed password resolves and the session stays', async () => {
  const { router, socket, store, ends } = setup()
  const change = router.changePassword('the old password', 'a new password of length')
  socket().accept()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'changePassword', value: {} } } } })
  await change
  expect(store.get()).toBe('tok')
  expect(ends).toEqual([])
})

test('a topic is subscribed once however many listen, and unsubscribed when the last one closes', () => {
  const { router, socket } = setup()
  const first = router.subscribe('state', () => undefined)
  const second = router.subscribe('state', () => undefined)
  socket().accept()
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
  const frame = socket().last()
  expect(frame.body.case === 'subscribe' && frame.body.value.topic).toBe('state')
  socket().ack()
  first.close()
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
  first.close() // closing twice is closing once
  second.close()
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'unsubscribe'])
  const gone = socket().last()
  expect(gone.body.case === 'unsubscribe' && gone.body.value.topic).toBe('state')
  // Subscribing again asks again.
  router.subscribe('state', () => undefined)
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'unsubscribe', 'subscribe'])
})

test('state and counters pushes reach every listener of their topic', () => {
  const { router, socket } = setup()
  const states: State[] = []
  const more: State[] = []
  const counters: Counters[] = []
  router.subscribe('state', (pushed) => states.push(pushed))
  router.subscribe('state', (pushed) => more.push(pushed))
  router.subscribe('counters', (pushed) => counters.push(pushed))
  socket().accept()
  expect(socket().kinds()).toEqual(['auth', 'subscribe', 'subscribe'])
  socket().receive({ id: 0, body: { case: 'telemetry', value: { topic: 'state', body: { case: 'state', value: state(3n) } } } })
  socket().receive({
    id: 0,
    body: { case: 'telemetry', value: { topic: 'counters', body: { case: 'counters', value: create(CountersSchema, { monotonicMs: 5n }) } } },
  })
  expect(states.map((pushed) => pushed.generation)).toEqual([3n])
  expect(more.map((pushed) => pushed.generation)).toEqual([3n])
  expect(counters.map((pushed) => pushed.monotonicMs)).toEqual([5n])
})

test('a listener that throws does not stop the others or the socket, and its error is reported', () => {
  const reported = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  const { router, socket } = setup()
  const states: State[] = []
  router.subscribe('state', () => {
    throw new Error('a listener of its own making')
  })
  router.subscribe('state', (pushed) => states.push(pushed))
  socket().accept()
  socket().receive({ id: 0, body: { case: 'telemetry', value: { topic: 'state', body: { case: 'state', value: state(1n) } } } })
  socket().receive({ id: 0, body: { case: 'telemetry', value: { topic: 'state', body: { case: 'state', value: state(2n) } } } })
  expect(states.map((pushed) => pushed.generation)).toEqual([1n, 2n])
  expect(router.connection).toBe('open')
  expect(reported).toHaveBeenCalledTimes(2)
  expect(String(reported.mock.calls[0]?.[0])).toContain('a listener of its own making')
  reported.mockRestore()
})

test('events ask for their backlog on the first subscribe', () => {
  const { router, socket } = setup()
  const events: Event[] = []
  router.subscribe('events', (event) => events.push(event), { backlog: 8 })
  socket().accept()
  const frame = socket().last()
  expect(frame.body.case === 'subscribe' && [frame.body.value.topic, frame.body.value.backlog]).toEqual(['events', 8])
  socket().receive({ id: 0, body: { case: 'event', value: create(EventSchema, { topic: 'wan.wan0.up' }) } })
  expect(events.map((event) => event.topic)).toEqual(['wan.wan0.up'])
})

test('word of lost events calls onLost and the subscription lives on', () => {
  const { router, socket } = setup()
  const events: Event[] = []
  let lost = 0
  router.subscribe('events', (event) => events.push(event), { onLost: () => (lost += 1) })
  socket().accept()
  socket().receive({ id: 0, body: { case: 'error', value: { code: ErrorCode.DATA_LOSS, message: 'events were dropped' } } })
  expect(lost).toBe(1)
  socket().receive({ id: 0, body: { case: 'event', value: create(EventSchema, { topic: 'wan.wan0.down' }) } })
  expect(events.map((event) => event.topic)).toEqual(['wan.wan0.down'])
  expect(router.connection).toBe('open')
})

test('the connection goes idle, connecting, open, and each change is heard once', () => {
  const { router, socket, connections } = setup()
  const stop = router.onConnection(() => undefined)
  router.subscribe('state', () => undefined)
  expect(connections).toEqual(['connecting'])
  socket().open()
  expect(connections).toEqual(['connecting'])
  socket().ack()
  expect(connections).toEqual(['connecting', 'open'])
  stop()
})

test('a listener that stopped listening hears no more', () => {
  const { router, socket } = setup()
  const heard: Connection[] = []
  const stop = router.onConnection((connection) => heard.push(connection))
  router.subscribe('state', () => undefined)
  stop()
  socket().accept()
  expect(heard).toEqual(['connecting'])
})

test('close() goes idle without ending the session', () => {
  const { router, socket, store, ends, connections } = setup()
  router.subscribe('state', () => undefined)
  socket().accept()
  router.close()
  expect(router.connection).toBe('idle')
  expect(connections.at(-1)).toBe('idle')
  expect(socket().closedWith).toBeDefined()
  expect(store.get()).toBe('tok')
  expect(ends).toEqual([])
})
