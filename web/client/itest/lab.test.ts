// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The client against the router in the lab (SPEC §11): from a LAN host, over HTTPS and the
// socket, with the router's own certificate (the harness sets Node to accept it; the `m4`
// suite compares its fingerprint). The tests run in order and share what they set up.

import { afterAll, expect, test } from 'vitest'

import { ask } from '../../scripts/labctl.mjs'
import {
  ErrorCode,
  rates,
  ratesOver,
  Router,
  RouterError,
  samplesOf,
  WanPhase,
  type Connection,
  type Counters,
  type Event,
  type Leases,
  type RouterOptions,
  type SessionEnd,
} from '../src/index.js'
import { stateWhere, waitFor } from './support.js'

const BASE = process.env.OPENFEO_ROUTER ?? ''
const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''
const OTHER_PASSWORD = 'lab-other-password'

const routers: Router[] = []
function router(options: RouterOptions = {}): Router {
  const made = new Router({ baseUrl: BASE, ...options })
  routers.push(made)
  return made
}

function connectionIs(of: Router, wanted: Connection, ms: number): Promise<Connection> {
  return waitFor<Connection>(`the connection to be ${wanted}`, ms, (done) => {
    if (of.connection === wanted) {
      done(wanted)
    }
    return of.onConnection((connection) => {
      if (connection === wanted) {
        done(connection)
      }
    })
  })
}

/**
 * Do something that checks a password, waiting as long as the router says when an earlier
 * wrong one made this source wait (SPEC §9): the wait arrives typed, in `retryAfterSecs`.
 */
async function afterAnyWait<T>(work: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await work()
    } catch (error) {
      const wait = error instanceof RouterError && error.code === ErrorCode.RESOURCE_EXHAUSTED ? error.retryAfterSecs : undefined
      if (wait === undefined || attempt >= 3) {
        throw error
      }
      await new Promise((resolve) => setTimeout(resolve, wait * 1000 + 200))
    }
  }
}

const a = router()
const b = router()

afterAll(() => {
  for (const each of routers) {
    each.close()
  }
})

test('sets the first password, is logged in, and reads the state', async () => {
  expect(BASE, 'OPENFEO_ROUTER').not.toBe('')
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  const status = await a.status()
  expect(status.hostname).toBe('openfeo')
  expect(status.needsPassword).toBe(true)
  expect(status.tlsFingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)

  const session = await a.setInitialPassword(PASSWORD)
  expect(session.token).not.toBe('')
  expect(session.idleSecs).toBe(1800)
  expect(a.authenticated).toBe(true)
  expect((await a.status()).needsPassword).toBe(false)

  const state = await stateWhere(a, 'wan0 to be up', 30_000, (found) => found.wans[0]?.phase === WanPhase.UP)
  expect(state.wans[0]?.name).toBe('wan0')
  expect(state.wans[0]?.ipv4).toMatch(/^203\.0\.113\.\d+/)
  expect(state.lans[0]?.name).toBe('lan0')
  const once = await a.state()
  expect(once.system?.hostname).toBe('openfeo')
  expect(once.system?.tlsFingerprint).toBe(status.tlsFingerprint)
  // Which resolvers the forwarder is asking, and where each came from: the lab's, by wan0's lease.
  expect(once.dns?.resolvers.map((resolver) => [resolver.address, resolver.wan])).toEqual([['203.0.113.1', 'wan0']])
})

test('a second router logs in, and counters a second apart give finite rates', async () => {
  // A second first password is refused: the router has one now.
  const second = await b.setInitialPassword('someone-elses-password').then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(second).toBeInstanceOf(RouterError)
  expect((second as RouterError).code).toBe(ErrorCode.FAILED_PRECONDITION)

  await b.login(PASSWORD)
  const samples: Counters[] = []
  await waitFor<void>('two samples of the counters', 15_000, (done) => {
    const subscription = b.subscribe('counters', (sample) => {
      samples.push(sample)
      if (samples.length === 2) {
        done()
      }
    })
    return () => subscription.close()
  })
  const [first, second2] = samples
  expect(first).toBeDefined()
  expect(second2).toBeDefined()
  if (first === undefined || second2 === undefined) {
    return
  }
  expect(Number(second2.monotonicMs - first.monotonicMs)).toBeGreaterThanOrEqual(500)
  const found = rates(first, second2)
  expect(found.length).toBeGreaterThan(0)
  for (const rate of found) {
    expect(Number.isFinite(rate.rxBitsPerSec) && rate.rxBitsPerSec >= 0, rate.name).toBe(true)
    expect(Number.isFinite(rate.txBitsPerSec) && rate.txBitsPerSec >= 0, rate.name).toBe(true)
  }
})

test('the history reaches back before this test asked', async () => {
  // The router reads its counters every second whether or not anyone is subscribed (SPEC §10).
  const wan = (await b.state()).wans[0]
  expect(wan?.interface).toBeTruthy()
  if (wan === undefined) {
    return
  }
  const links = await b.history([wan.interface, 'no-such-link'])
  expect(links.map((link) => link.name)).toEqual([wan.interface])
  const [hour] = links
  if (hour === undefined) {
    return
  }
  const samples = samplesOf(hour)
  expect(samples.length).toBeGreaterThanOrEqual(3)
  for (const [at, sample] of samples.entries()) {
    const before = samples[at - 1]
    if (before !== undefined) {
      const apart = sample.atMs - before.atMs
      expect(apart >= 800 && apart <= 2_500, `samples ${apart} ms apart`).toBe(true)
    }
  }
  // A rate for every sample but the first, by the rule the live samples are read by.
  const points = ratesOver(samples)
  expect(points).toHaveLength(samples.length - 1)
  expect(points.every((point) => Number.isFinite(point.rxBitsPerSec) && point.rxBitsPerSec >= 0)).toBe(true)
  // A call that names no link is refused.
  const none = await b.history([]).then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(none).toBeInstanceOf(RouterError)
  expect((none as RouterError).code).toBe(ErrorCode.INVALID_ARGUMENT)
})

test('a device that joins is pushed in the lease table, and the call agrees', async () => {
  const named = (table: Leases) => table.leases.find((lease) => lease.hostname === 'plug-kitchen')
  const pushed = waitFor<Leases>('a lease named plug-kitchen', 30_000, (done) => {
    const subscription = b.subscribe('leases', (table) => {
      if (named(table) !== undefined) {
        done(table)
      }
    })
    return () => subscription.close()
  })
  await ask('join plug-kitchen')
  const table = await pushed
  const lease = named(table)
  expect(lease?.lan).toBe('lan0')
  expect(lease?.address).toMatch(/^192\.168\.1\.\d+$/)
  expect(lease?.mac).toMatch(/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/)
  // Joined just now and still running, by the table's own clock.
  expect(Math.abs(Number(table.timeUnix - (lease?.joinedUnix ?? 0n)))).toBeLessThanOrEqual(30)
  expect((lease?.expiresUnix ?? 0n) > table.timeUnix).toBe(true)
  expect(named(await b.leases())?.address).toBe(lease?.address)
})

test('a lost carrier is pushed as an event and a state, and its return too', async () => {
  const events: Event[] = []
  const subscription = a.subscribe('events', (event) => events.push(event))
  const eventNamed = (topic: string, ms: number) =>
    waitFor<Event>(`the event ${topic}`, ms, (done) => {
      const seen = events.find((event) => event.topic === topic)
      if (seen !== undefined) {
        done(seen)
      }
      const more = a.subscribe('events', (event) => {
        if (event.topic === topic) {
          done(event)
        }
      })
      return () => more.close()
    })
  try {
    await connectionIs(a, 'open', 10_000)
    const down = eventNamed('wan.wan0.down', 15_000)
    const stateDown = stateWhere(a, 'wan0 to be down', 15_000, (found) => found.wans[0]?.phase === WanPhase.DOWN)
    await ask('wan-down')
    expect((await down).fields.reason).toBe('no carrier')
    expect((await stateDown).wans[0]?.reason).toBe('no carrier')

    const up = eventNamed('wan.wan0.up', 60_000)
    const stateUp = stateWhere(a, 'wan0 to be up again', 60_000, (found) => found.wans[0]?.phase === WanPhase.UP)
    await ask('wan-up')
    await up
    expect((await stateUp).wans[0]?.reason).toBe('')
  } finally {
    subscription.close()
  }
})

test('a link that goes silent is noticed and survived', async () => {
  // The LAN port loses its carrier: nothing is closed and nothing arrives. The client asks
  // after two seconds of silence, gives the router two more, and then makes the socket again
  // until the link is back.
  const c = router({ probeAfterMs: 2_000, probeTimeoutMs: 2_000 })
  await c.login(PASSWORD)
  let pushes = 0
  c.subscribe('counters', () => (pushes += 1))
  await waitFor<void>('a first sample', 15_000, (done) => {
    const subscription = c.subscribe('counters', () => done())
    return () => subscription.close()
  })
  expect(c.connection).toBe('open')

  const lost = connectionIs(c, 'reconnecting', 20_000)
  await ask('lan-down')
  await lost
  const whenLost = pushes

  const back = connectionIs(c, 'open', 60_000)
  await ask('lan-up')
  await back
  await waitFor<void>('a sample after the link came back', 15_000, (done) => {
    const subscription = c.subscribe('counters', () => done())
    return () => subscription.close()
  })
  expect(pushes).toBeGreaterThan(whenLost)
  c.close()
})

test('a session ended from elsewhere is reported', async () => {
  // a has an open socket; b changes the password, which ends every session but b's.
  const keep = a.subscribe('state', () => undefined)
  await connectionIs(a, 'open', 10_000)
  const ended = waitFor<SessionEnd>("a's session to end", 15_000, (done) => a.onSessionEnd(done))

  // A wrong old password changes nothing and ends nothing.
  const wrong = await b.changePassword('not-the-old-password', OTHER_PASSWORD).then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(wrong).toBeInstanceOf(RouterError)
  expect((wrong as RouterError).code).toBe(ErrorCode.INVALID_ARGUMENT)
  expect(a.authenticated).toBe(true)

  await afterAnyWait(() => b.changePassword(PASSWORD, OTHER_PASSWORD))
  expect(await ended).toBe('revoked')
  expect(a.authenticated).toBe(false)
  expect(a.connection).toBe('idle')
  keep.close()
  // b's own session stays.
  expect((await b.state()).system?.hostname).toBe('openfeo')

  // The old password no longer logs in; the new one does.
  const old = await afterAnyWait(() => a.login(PASSWORD)).then(
    () => undefined,
    (error: unknown) => error,
  )
  expect(old).toBeInstanceOf(RouterError)
  expect((old as RouterError).code).toBe(ErrorCode.UNAUTHENTICATED)
  await afterAnyWait(() => a.login(OTHER_PASSWORD))
  expect((await a.state()).wans[0]?.name).toBe('wan0')
})
