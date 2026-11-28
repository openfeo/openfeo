// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The routes and the log against the router in the lab (SPEC §8.3, §11; M4 part 3c): from a
// LAN host, over the socket. The tests run in order on one router.

import { afterAll, expect, test } from 'vitest'

import { ask } from '../../scripts/labctl.mjs'
import { LogLevel, logMatches, Router, RouteKind, WanPhase, type LogLine } from '../src/index.js'
import { stateWhere, waitFor } from './support.js'

const BASE = process.env.OPENFEO_ROUTER ?? ''
const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''

const a = new Router({ baseUrl: BASE })

afterAll(() => {
  a.close()
})

test('the routes have the default route and the LAN', async () => {
  await a.setInitialPassword(PASSWORD)
  const up = await stateWhere(a, 'wan0 to be up with the default route', 30_000, (found) => found.wans[0]?.phase === WanPhase.UP && found.wans[0].default4)
  const wan = up.wans[0]
  const routes = await a.dumpRoutes()
  const defaults = routes.filter((route) => !route.v6 && route.table === 'main' && route.destination === '' && route.kind === RouteKind.UNICAST)
  expect(defaults.map((route) => [route.gateway, route.interface, route.protocol])).toEqual([[wan?.gateway4, wan?.interface, 'openfeo']])
  const lan = routes.find((route) => route.table === 'main' && route.destination === '192.168.1.0/24')
  expect([lan?.gateway, lan?.interface, lan?.protocol, lan?.kind]).toEqual(['', 'br-lan0', 'kernel', RouteKind.UNICAST])
  // The kernel's own entries are there too, for whoever wants every route.
  expect(routes.some((route) => route.table === 'local' && route.kind === RouteKind.LOCAL && route.destination === '192.168.1.1/32')).toBe(true)
})

test('the log is read back, and a cut WAN is pushed as its line', async () => {
  await a.login(PASSWORD)
  const logins = await a.logs({ level: LogLevel.INFO, contains: 'ADMIN: LOGIN FROM' })
  expect(logins.lines.length).toBeGreaterThan(0)
  expect(logins.lines.every((line) => line.text.includes('admin: login from 192.168.1.') && line.level === LogLevel.INFO)).toBe(true)
  expect(logins.timeUnixMs > 0n && logins.lines.every((line) => line.uptimeMs <= logins.uptimeMs)).toBe(true)
  // Further back, a page at a time: the lines before the oldest one read.
  const newest = await a.logs({ limit: 5 })
  expect(newest.lines).toHaveLength(5)
  expect(newest.earlier).toBe(true)
  const before = await a.logs({ limit: 5, beforeSeq: newest.lines[0]?.seq ?? 0n })
  expect(before.lines.at(-1)?.seq).toBe((newest.lines[0]?.seq ?? 0n) - 1n)

  const seen: LogLine[] = []
  let lost = 0
  const subscription = a.subscribe('logs', (batch) => seen.push(...batch.lines), { onLost: () => (lost += 1) })
  const lineSaying = (text: string, ms: number) =>
    waitFor<LogLine>(`the line ${text}`, ms, (done) => {
      const look = () => {
        const found = seen.find((line) => line.text === text)
        if (found !== undefined) {
          done(found)
        }
      }
      look()
      const more = a.subscribe('logs', look)
      return () => more.close()
    })
  try {
    // The subscription is acknowledged before the lab is asked: what follows is after it.
    await a.state()
    const down = lineSaying('link p0 down', 15_000)
    await ask('wan-down')
    const line = await down
    expect(line.seq > (newest.lines.at(-1)?.seq ?? 0n)).toBe(true)
    expect(logMatches(line, LogLevel.INFO, 'P0 DOWN')).toBe(true)
    expect(logMatches(line, LogLevel.ERROR, '')).toBe(false)
    expect(logMatches(line, LogLevel.INFO, 'p1')).toBe(false)
    // The call finds the line that was pushed, under the same number.
    const readBack = await a.logs({ contains: 'link p0 down' })
    expect(readBack.lines.map((found) => found.seq)).toContain(line.seq)

    const up = lineSaying('link p0 up', 60_000)
    await ask('wan-up')
    await up
    expect(lost).toBe(0)
  } finally {
    subscription.close()
  }
})
