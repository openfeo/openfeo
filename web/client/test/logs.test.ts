// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { readFileSync } from 'node:fs'

import { expect, test } from 'vitest'

import { logMatches, LogLevel, memoryTokenStore, Router, RouteKind, type LogBatch } from '../src/index.js'
import { ManualTimers, scripted } from './scripted.js'

function setup() {
  const { factory, sockets } = scripted()
  const store = memoryTokenStore()
  store.set('tok')
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
  return { router, socket, timers }
}

const LEVELS: Record<string, LogLevel> = {
  '': LogLevel.UNSPECIFIED,
  error: LogLevel.ERROR,
  warn: LogLevel.WARN,
  info: LogLevel.INFO,
  debug: LogLevel.DEBUG,
}

interface Case {
  level: string
  text: string
  wanted: string
  contains: string
  matches: boolean
}

// The router's rule and this one are held to the same cases (SPEC §8.3): the router matches
// what is past, and a page matches what arrives.
test('the rule is held to the shared cases', () => {
  const cases = JSON.parse(readFileSync(new URL('./log-rule.cases.json', import.meta.url), 'utf8')) as Case[]
  expect(cases.length).toBeGreaterThanOrEqual(13)
  for (const each of cases) {
    const level = LEVELS[each.level]
    const wanted = LEVELS[each.wanted]
    if (level === undefined || wanted === undefined) {
      throw new Error(`no such level in the cases: ${JSON.stringify(each)}`)
    }
    expect(logMatches({ level, text: each.text }, wanted, each.contains), JSON.stringify(each)).toBe(each.matches)
  }
})

test('logs asks with what it was given and answers the lines', async () => {
  const { router, socket } = setup()
  const asked = router.logs({ level: LogLevel.WARN, contains: 'pppoe', beforeSeq: 40n, limit: 200 })
  socket().accept()
  const frame = socket().last()
  expect(frame.body.case === 'request' && frame.body.value.body.case === 'logs' && frame.body.value.body.value).toMatchObject({
    level: LogLevel.WARN,
    contains: 'pppoe',
    beforeSeq: 40n,
    limit: 200,
  })
  socket().receive({
    id: frame.id,
    body: {
      case: 'response',
      value: {
        body: {
          case: 'logs',
          value: {
            lines: [{ seq: 38n, uptimeMs: 5_000n, level: LogLevel.WARN, text: 'pppoe wan0: 3 echoes unanswered' }],
            earlier: true,
            uptimeMs: 9_000n,
            timeUnixMs: 1_795_000_000_000n,
          },
        },
      },
    },
  })
  const answer = await asked
  expect(answer.lines.map((line) => [line.seq, line.level, line.text])).toEqual([[38n, LogLevel.WARN, 'pppoe wan0: 3 echoes unanswered']])
  expect([answer.earlier, answer.uptimeMs, answer.timeUnixMs]).toEqual([true, 9_000n, 1_795_000_000_000n])

  // With nothing said, every line and the newest of them.
  const all = router.logs()
  const plain = socket().last()
  expect(plain.body.case === 'request' && plain.body.value.body.case === 'logs' && plain.body.value.body.value).toMatchObject({
    level: LogLevel.UNSPECIFIED,
    contains: '',
    beforeSeq: 0n,
    limit: 0,
  })
  socket().receive({ id: plain.id, body: { case: 'response', value: { body: { case: 'logs', value: {} } } } })
  expect((await all).lines).toEqual([])
})

test('dumpRoutes answers the routes', async () => {
  const { router, socket } = setup()
  const asked = router.dumpRoutes()
  socket().accept()
  const frame = socket().last()
  expect(frame.body.case === 'request' && frame.body.value.body.case).toBe('dumpRoutes')
  socket().receive({
    id: frame.id,
    body: {
      case: 'response',
      value: {
        body: {
          case: 'dumpRoutes',
          value: { routes: [{ table: 'main', gateway: '203.0.113.1', interface: 'ppp-wan0', protocol: 'openfeo', metric: 10, kind: RouteKind.UNICAST }] },
        },
      },
    },
  })
  const routes = await asked
  expect(routes.map((route) => [route.table, route.destination, route.gateway, route.interface, route.kind])).toEqual([
    ['main', '', '203.0.113.1', 'ppp-wan0', RouteKind.UNICAST],
  ])
})

test('an answer of another kind to a call for the log or the routes is an error, not a guess', async () => {
  const { router, socket } = setup()
  const logs = router.logs().then(
    () => 'answered',
    (error: unknown) => (error as Error).message,
  )
  socket().accept()
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'getState', value: {} } } } })
  expect(await logs).toContain('log')
  const routes = router.dumpRoutes().then(
    () => 'answered',
    (error: unknown) => (error as Error).message,
  )
  socket().receive({ id: socket().last().id, body: { case: 'response', value: { body: { case: 'getState', value: {} } } } })
  expect(await routes).toContain('routes')
})

const batch = (seqs: bigint[]) => ({
  lines: seqs.map((seq) => ({ seq, uptimeMs: 5_000n + seq, level: LogLevel.INFO, text: `line ${String(seq)}` })),
  uptimeMs: 9_000n,
  timeUnixMs: 1_795_000_000_000n,
})

test('a batch pushed on logs reaches its listeners', () => {
  const { router, socket } = setup()
  const got: LogBatch[] = []
  const subscription = router.subscribe('logs', (pushed) => got.push(pushed))
  socket().accept()
  const frame = socket().last()
  expect(frame.body.case === 'subscribe' && [frame.body.value.topic, frame.body.value.backlog]).toEqual(['logs', 0])
  socket().receive({ id: 0, body: { case: 'logs', value: batch([7n, 8n]) } })
  expect(got.map((pushed) => pushed.lines.map((line) => line.seq))).toEqual([[7n, 8n]])
  expect([got[0]?.uptimeMs, got[0]?.timeUnixMs]).toEqual([9_000n, 1_795_000_000_000n])
  subscription.close()
  const last = socket().last()
  expect(last.body.case === 'unsubscribe' && last.body.value.topic).toBe('logs')
})

test('a loss that names logs is told to the logs listeners and not the events ones', () => {
  const { router, socket } = setup()
  let eventsLost = 0
  let logsLost = 0
  router.subscribe('events', () => undefined, { onLost: () => (eventsLost += 1) })
  router.subscribe('logs', () => undefined, { onLost: () => (logsLost += 1) })
  socket().accept()
  const loss = (topic: string) => socket().receive({ id: 0, body: { case: 'error', value: { code: 6, message: 'dropped', topic } } })
  loss('logs')
  expect([eventsLost, logsLost]).toEqual([0, 1])
  loss('events')
  expect([eventsLost, logsLost]).toEqual([1, 1])
  // A loss that names nothing is the events', as it was before a loss said its topic.
  loss('')
  expect([eventsLost, logsLost]).toEqual([2, 1])
  expect(router.connection).toBe('open')
})

test('a logs subscription made again after a reconnect says lines may have passed', () => {
  const { router, socket, timers } = setup()
  const got: LogBatch[] = []
  let lost = 0
  router.subscribe('logs', (pushed) => got.push(pushed), { onLost: () => (lost += 1) })
  socket().accept()
  socket().drop(1006)
  expect(lost).toBe(0)
  timers.advance(500)
  socket().accept()
  const again = socket().last()
  expect(again.body.case === 'subscribe' && again.body.value.topic).toBe('logs')
  expect(lost).toBe(1)
  socket().receive({ id: 0, body: { case: 'logs', value: batch([9n]) } })
  expect(got).toHaveLength(1)
})
