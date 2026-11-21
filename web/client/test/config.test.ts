// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The config calls (SPEC §8.3) against a scripted socket. An apply that takes away the
// address it arrived at may never be answered, so no answer within the wait is a result
// here, not an error.

import { expect, test } from 'vitest'

import {
  ConfigEffectKind,
  ConfigSchema,
  create,
  ErrorCode,
  memoryTokenStore,
  Router,
  RouterError,
  type Config,
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
  const socket = () => {
    const last = sockets.at(-1)
    if (last === undefined) {
      throw new Error('no socket was opened')
    }
    return last
  }
  return { router, sockets, socket, timers }
}

/** A router that is listened to, as the panel listens: a lost socket is then made again. */
function listening() {
  const all = setup()
  all.router.subscribe('state', () => undefined)
  all.socket().accept()
  all.socket().ack()
  return all
}

async function refusal(work: Promise<unknown>): Promise<RouterError> {
  const error: unknown = await work.then(
    () => undefined,
    (thrown: unknown) => thrown,
  )
  expect(error).toBeInstanceOf(RouterError)
  return error as RouterError
}

function aConfig(): Config {
  return create(ConfigSchema, {
    wans: [{ name: 'wan0', port: 'p0', priority: 10, kind: { case: 'dhcp', value: {} } }],
    lans: [
      {
        name: 'lan0',
        ports: ['p2'],
        ipv4: '192.168.1.1/24',
        dhcp: { range: ['192.168.1.100', '192.168.1.200'] },
      },
    ],
  })
}

test('config() hands back the config, its tag and the window', async () => {
  const { router, socket } = setup()
  const asked = router.config()
  socket().accept()
  expect(socket().last().body).toMatchObject({ case: 'request', value: { body: { case: 'getConfig' } } })
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'getConfig', value: { config: aConfig(), tag: 't1', confirmSecs: 120 } } } },
  })
  const view = await asked
  expect(view.tag).toBe('t1')
  expect(view.confirmSecs).toBe(120)
  expect(view.config.lans[0]?.ipv4).toBe('192.168.1.1/24')
})

test('an answer with no config in it is the router\'s fault, not a config', async () => {
  const { router, socket } = setup()
  const asked = router.config()
  socket().accept()
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'getConfig', value: { tag: 't1' } } } },
  })
  expect((await refusal(asked)).code).toBe(ErrorCode.INTERNAL)
  // And an answer of another kind.
  const again = router.config()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'getState', value: {} } } } })
  expect((await refusal(again)).code).toBe(ErrorCode.INTERNAL)
})

test('validate() hands back violations, or effects and the caller', async () => {
  const { router, socket } = setup()
  const config = aConfig()
  const refused = router.validate(config)
  socket().accept()
  const sent = socket().last().body
  expect(sent).toMatchObject({ case: 'request', value: { body: { case: 'validateConfig' } } })
  if (sent.case !== 'request' || sent.value.body.case !== 'validateConfig') {
    throw new Error('not a validation')
  }
  expect(sent.value.body.value.config?.lans[0]?.dhcp?.range).toEqual(['192.168.1.100', '192.168.1.200'])
  socket().receive({
    id: socket().last().id,
    body: {
      case: 'response',
      value: {
        body: {
          case: 'validateConfig',
          value: { violations: [{ path: 'lans[0].dhcp.range', code: 'range_outside_subnet', message: 'the pool is not in the subnet' }] },
        },
      },
    },
  })
  const bad = await refused
  expect(bad.violations.map((violation) => violation.path)).toEqual(['lans[0].dhcp.range'])
  expect(bad.effects).toEqual([])
  expect(bad.caller).toBeUndefined()

  const accepted = router.validate(config)
  socket().receive({
    id: socket().last().id,
    body: {
      case: 'response',
      value: {
        body: {
          case: 'validateConfig',
          value: {
            effects: [{ subject: 'lan0', kind: ConfigEffectKind.LAN_ADDRESS_MOVES }],
            caller: { connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' },
          },
        },
      },
    },
  })
  const good = await accepted
  expect(good.violations).toEqual([])
  expect(good.effects.map((effect) => [effect.subject, effect.kind])).toEqual([['lan0', ConfigEffectKind.LAN_ADDRESS_MOVES]])
  expect(good.caller).toMatchObject({ connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' })
})

test('apply() sends the config, the tag, immediate and the window, and answers with the tag now running', async () => {
  const { router, socket } = setup()
  const applied = router.apply(aConfig(), 't1', { immediate: true, timeoutSecs: 30 })
  socket().accept()
  const sent = socket().last().body
  if (sent.case !== 'request' || sent.value.body.case !== 'applyConfig') {
    throw new Error('not an apply')
  }
  expect(sent.value.body.value).toMatchObject({ tag: 't1', immediate: true, timeoutSecs: 30 })
  expect(sent.value.body.value.config?.lans[0]?.ipv4).toBe('192.168.1.1/24')
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'applyConfig', value: { tag: 't2' } } } },
  })
  expect(await applied).toEqual({ answered: true, tag: 't2' })

  // Left out, the apply is commit-confirmed with the router's own window.
  const plain = router.apply(aConfig(), 't2')
  const next = socket().last().body
  if (next.case !== 'request' || next.value.body.case !== 'applyConfig') {
    throw new Error('not an apply')
  }
  expect(next.value.body.value).toMatchObject({ tag: 't2', immediate: false, timeoutSecs: 0 })
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'applyConfig', value: { tag: 't3' } } } },
  })
  expect(await plain).toEqual({ answered: true, tag: 't3' })
})

test("an apply the router refuses is a RouterError with the router's code and words", async () => {
  const { router, socket } = setup()
  const applied = router.apply(aConfig(), 'stale')
  socket().accept()
  socket().receive({
    id: socket().last().id,
    body: {
      case: 'error',
      value: { code: ErrorCode.FAILED_PRECONDITION, message: 'the config has changed since it was read; read it again' },
    },
  })
  const error = await refusal(applied)
  expect(error.code).toBe(ErrorCode.FAILED_PRECONDITION)
  expect(error.message).toBe('the config has changed since it was read; read it again')
})

test('an apply with no answer within the wait is unanswered, and the socket is remade', async () => {
  const { router, sockets, socket, timers } = listening()
  const applied = router.apply(aConfig(), 't1')
  let outcome: unknown
  void applied.then((value) => (outcome = value))
  expect(socket().kinds().at(-1)).toBe('request')
  timers.advance(9_999)
  await settle()
  expect(outcome).toBeUndefined()
  timers.advance(1)
  await settle()
  expect(outcome).toEqual({ answered: false })
  // The socket that swallowed it is not believed: it is closed and another is on its way.
  expect(router.connection).toBe('reconnecting')
  expect(sockets[0]?.closedWith).toBeDefined()
  expect(sockets).toHaveLength(1)
  timers.advance(500)
  expect(sockets).toHaveLength(2)
  // The apply is not sent a second time on the new socket.
  socket().accept()
  expect(socket().kinds()).toEqual(['auth', 'subscribe'])
})

test('an apply whose socket closes before the answer is unanswered', async () => {
  const { router, socket } = listening()
  const applied = router.apply(aConfig(), 't1')
  socket().drop(1006)
  expect(await applied).toEqual({ answered: false })
})

test('a revert with no answer is unanswered; a confirm with no answer is an error', async () => {
  const { router, socket, timers } = listening()
  const reverted = router.revert()
  expect(socket().last().body).toMatchObject({ case: 'request', value: { body: { case: 'revertConfig' } } })
  timers.advance(10_000)
  expect(await reverted).toEqual({ answered: false })

  timers.advance(500)
  socket().accept()
  socket().ack()
  const confirmed = router.confirm()
  expect(socket().last().body).toMatchObject({ case: 'request', value: { body: { case: 'confirmConfig' } } })
  timers.advance(10_000)
  const error = await refusal(confirmed)
  expect(error.code).toBe(ErrorCode.UNAVAILABLE)
  expect(error.message).toBe('the router did not answer')
})

test('a revert and a confirm that are answered say so', async () => {
  const { router, socket } = listening()
  const reverted = router.revert()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'revertConfig', value: {} } } } })
  expect(await reverted).toEqual({ answered: true })
  const confirmed = router.confirm()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'confirmConfig', value: {} } } } })
  await expect(confirmed).resolves.toBeUndefined()
  // A refusal of either is the router's own.
  const refused = router.revert()
  socket().receive({
    id: socket().last().id,
    body: { case: 'error', value: { code: ErrorCode.FAILED_PRECONDITION, message: 'no change of config is pending' } },
  })
  expect((await refusal(refused)).message).toBe('no change of config is pending')
})

test('an answer that comes in time stops the wait', async () => {
  const { router, sockets, socket, timers } = listening()
  const applied = router.apply(aConfig(), 't1')
  timers.advance(9_000)
  socket().receive({
    id: socket().last().id,
    body: { case: 'response', value: { body: { case: 'applyConfig', value: { tag: 't2' } } } },
  })
  expect(await applied).toEqual({ answered: true, tag: 't2' })
  timers.advance(10_000)
  expect(router.connection).toBe('open')
  expect(sockets).toHaveLength(1)
})

test('the config calls need a session', async () => {
  const { router, sockets } = setup(null)
  for (const call of [
    () => router.config(),
    () => router.validate(aConfig()),
    () => router.apply(aConfig(), 't1'),
    () => router.confirm(),
    () => router.revert(),
  ]) {
    expect((await refusal(call())).code).toBe(ErrorCode.UNAUTHENTICATED)
  }
  expect(sockets).toHaveLength(0)
})
