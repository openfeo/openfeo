// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The config store (SPEC §8.4): one draft of the whole config in the tab's memory, what
// differs between it and the router's config, and what becomes of an apply: answered or not,
// confirmed or reverted, by this tab or another.

import {
  clone,
  ConfigEffectKind,
  ConfigSchema,
  create,
  equals,
  ErrorCode,
  RouterError,
  WanSchema,
  type Config,
} from '@openfeo/client'
import { THEME_KEY } from '@openfeo/ui'
import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { useConfig, type ConfigStore, type Review } from '../src/config'
import { useLive } from '../src/live'
import { TOKEN_KEY } from '../src/session'
import type { FakeRouter } from './fake-router'
import { event, labConfig, NOW, pendingState, state, UPTIME_SECS } from './fixtures'
import { signedIn } from './mounting'

const stores: { store: ConfigStore; live: ReturnType<typeof useLive> }[] = []

/** A store on a router whose config is the lab's, started and read once. */
async function started(config: Config = labConfig()) {
  const router = signedIn()
  router.configNow = { config, tag: 't1', confirmSecs: 120 }
  const live = useLive(router)
  live.start()
  const store = useConfig(router, live, () => 'openfeo.home.arpa')
  store.start()
  stores.push({ store, live })
  router.push('state', state())
  await flushPromises()
  return { router, live, store }
}

/** The lab's config with one more reservation. */
function reserved(config: Config = labConfig()): Config {
  const next = clone(ConfigSchema, config)
  next.lans[0]!.dhcp!.static.push(create(ConfigSchema, { lans: [{ dhcp: { static: [{ mac: '02:00:00:aa:01:22', ip: '192.168.1.20', hostname: 'printer' }] } }] }).lans[0]!.dhcp!.static[0]!)
  return next
}

const reserve = (draft: Config) => {
  draft.lans[0]!.dhcp!.static.push(create(ConfigSchema, { lans: [{ dhcp: { static: [{ mac: '02:00:00:aa:01:22', ip: '192.168.1.20', hostname: 'printer' }] } }] }).lans[0]!.dhcp!.static[0]!)
}

/** The router takes what was applied: its config, its tag, and a state that says a change is pending. */
async function taken(router: FakeRouter, config: Config, tag: string, agoSecs = 0) {
  router.configNow = { config: clone(ConfigSchema, config), tag, confirmSecs: 120 }
  router.push('events', event('config.applied', { mode: 'pending' }, new Date(NOW.getTime() - agoSecs * 1000)))
  router.push('state', pendingState(agoSecs))
  await flushPromises()
}

/** The pending change is gone: the router's config is now this, and it says why (and when it said so). */
async function settled(router: FakeRouter, config: Config, tag: string, topic: string, fields: Record<string, string> = {}, at: Date = NOW) {
  router.configNow = { config: clone(ConfigSchema, config), tag, confirmSecs: 120 }
  router.push('state', state())
  router.push('events', event(topic, fields, at))
  await flushPromises()
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  window.localStorage.clear()
  window.sessionStorage.clear()
})
afterEach(() => {
  for (const { store, live } of stores.splice(0)) {
    store.stop()
    live.stop()
  }
  vi.useRealTimers()
})

test("the draft starts as the router's config and counts nothing", async () => {
  const router = signedIn()
  router.configNow = { config: labConfig(), tag: 't1', confirmSecs: 40 }
  const live = useLive(router)
  const store = useConfig(router, live, () => 'openfeo.home.arpa')
  stores.push({ store, live })
  // Until it has been read there is nothing to edit.
  expect(store.base.value).toBeNull()
  expect(store.draft.value).toBeNull()
  expect(store.changes.value).toEqual([])
  live.start()
  store.start()
  await flushPromises()
  expect(router.calls.config).toBe(1)
  expect(equals(ConfigSchema, store.base.value!, labConfig())).toBe(true)
  expect(equals(ConfigSchema, store.draft.value!, labConfig())).toBe(true)
  // The draft is its own copy.
  expect(store.draft.value).not.toBe(store.base.value)
  expect(store.changes.value).toEqual([])
  expect(store.confirmSecs.value).toBe(40)
  expect(store.notice.value).toBeNull()
  expect(store.readOnly.value).toBeNull()
  expect(store.pending.value).toBeUndefined()
})

test('an edit is counted; put back by hand, or discarded, it counts nothing', async () => {
  const { store } = await started()
  store.edit((draft) => (draft.lans[0]!.dhcp!.range[1] = '192.168.1.220'))
  expect(store.changes.value).toEqual([{ subject: 'lan0', what: 'pool', before: '192.168.1.100 – 192.168.1.200', after: '192.168.1.100 – 192.168.1.220' }])
  store.edit(reserve)
  expect(store.changes.value).toHaveLength(2)
  // The router's config is untouched by an edit.
  expect(store.base.value!.lans[0]!.dhcp!.range[1]).toBe('192.168.1.200')

  store.edit((draft) => {
    draft.lans[0]!.dhcp!.range[1] = '192.168.1.200'
    draft.lans[0]!.dhcp!.static.pop()
  })
  expect(store.changes.value).toEqual([])

  store.edit(reserve)
  expect(store.changes.value).toHaveLength(1)
  store.discard()
  expect(store.changes.value).toEqual([])
  expect(equals(ConfigSchema, store.draft.value!, labConfig())).toBe(true)
})

test('a config changed elsewhere is followed silently by a draft with no changes', async () => {
  const { router, store } = await started()
  router.configNow = { config: reserved(), tag: 't2', confirmSecs: 120 }
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  expect(router.calls.config).toBe(2)
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.changes.value).toEqual([])
  expect(store.notice.value).toBeNull()
})

test('a draft with changes is kept when the config changes elsewhere, and says so', async () => {
  const { router, store } = await started()
  store.edit((draft) => (draft.lans[0]!.dhcp!.range[1] = '192.168.1.220'))
  router.configNow = { config: reserved(), tag: 't2', confirmSecs: 120 }
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  // The draft is whole: its own change, and without the reservation the other session added.
  expect(store.draft.value!.lans[0]!.dhcp!.range[1]).toBe('192.168.1.220')
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(1)
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.notice.value).toEqual({ kind: 'changed-elsewhere' })
  // What the other session changed shows as a change back, for the dialog to list.
  expect(store.changes.value).toEqual([
    { subject: 'lan0', what: 'pool', before: '192.168.1.100 – 192.168.1.200', after: '192.168.1.100 – 192.168.1.220' },
    { subject: 'lan0', what: 'reservations', before: '', after: '1 removed' },
  ])
  // An apply now names the tag just read.
  const review = await store.review()
  await store.apply(review!, false)
  expect(router.calls.apply[0]?.tag).toBe('t2')
})

test('a review hands back the changes, the effects and the caller; with violations it hands back nothing and keeps them', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  router.validation = {
    violations: [],
    effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_DHCP_RESTARTS }],
    caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: false, lanChanges: false, lan: 'lan0', routerAfter: '192.168.1.1' },
  }
  const review = await store.review()
  expect(review?.changes).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 added' }])
  expect(review?.effects.map((effect) => [effect.subject, effect.kind])).toEqual([['lan0', ConfigEffectKind.LAN_DHCP_RESTARTS]])
  expect(review?.caller?.lan).toBe('lan0')
  // What was validated is the draft, whole.
  expect(equals(ConfigSchema, router.calls.validate[0]!, store.draft.value!)).toBe(true)
  expect(store.violations.value).toEqual([])
  expect(store.busy.value).toBe(false)

  store.edit((draft) => (draft.lans[0]!.dhcp!.range[0] = '192.168.9.100'))
  router.validation = {
    violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.range', code: 'range_outside_subnet', message: 'the pool is not inside 192.168.1.0/24' }],
    effects: [],
    caller: undefined,
  }
  expect(await store.review()).toBeNull()
  expect(store.violations.value.map((violation) => violation.path)).toEqual(['lans[0].dhcp.range'])
  // A review that passes clears them.
  router.validation = { violations: [], effects: [], caller: undefined }
  expect(await store.review()).not.toBeNull()
  expect(store.violations.value).toEqual([])
})

test('a violation is found at its path and beneath it', async () => {
  const { router, store } = await started()
  router.validation = {
    violations: [
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.range[1]', code: 'x', message: 'not an address' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'lans[0].dhcp.static[1].ip', code: 'y', message: 'outside the subnet' },
      { $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0]', code: 'z', message: 'no kind' },
    ],
    effects: [],
    caller: undefined,
  }
  await store.review()
  expect(store.problemAt('lans[0].dhcp.range')).toBe('not an address')
  expect(store.problemAt('lans[0].dhcp.range[1]')).toBe('not an address')
  expect(store.problemAt('lans[0].dhcp.static[1]')).toBe('outside the subnet')
  expect(store.problemAt('lans[0].dhcp.static[1].ip')).toBe('outside the subnet')
  expect(store.problemAt('wans[0]')).toBe('no kind')
  // Not a path that only begins the same, and not one above where the violation is.
  expect(store.problemAt('lans[0].dhcp.static[10]')).toBeUndefined()
  expect(store.problemAt('lans[0].dhcp.static[1].ip.more')).toBeUndefined()
  expect(store.problemAt('lans[0].dhcp.ra')).toBeUndefined()
  expect(store.problemAt('wans[0].port')).toBeUndefined()
})

/** The lab's config with `wan0` as PPPoE, as the router hands it out: no password. */
function pppoeConfig(): Config {
  const config = labConfig()
  config.wans[0]!.kind = create(WanSchema, { kind: { case: 'pppoe', value: { username: 'openfeo@isp.example' } } }).kind
  return config
}

const typePassword = (draft: Config) => {
  const kind = draft.wans[0]!.kind
  if (kind.case === 'pppoe') {
    kind.value.password = 'a-typed-secret'
  }
}

const passwordOf = (config: Config | null) => {
  const kind = config?.wans[0]?.kind
  return kind?.case === 'pppoe' ? kind.value.password : undefined
}

test('an answered apply makes the draft the base and empties the typed password', async () => {
  const { router, store } = await started(pppoeConfig())
  store.edit(typePassword)
  store.edit(reserve)
  expect(store.changes.value).toHaveLength(2)
  router.applyAnswer = { answered: true, tag: 't2' }
  const letGo = router.holdCall('apply')
  const applying = store.apply((await store.review())!, false)
  await flushPromises()
  expect(store.busy.value).toBe(true)
  letGo()
  await applying
  expect(store.busy.value).toBe(false)
  // What was sent is the draft, password and all, against the tag it was edited from.
  expect(router.calls.apply).toHaveLength(1)
  expect(router.calls.apply[0]?.tag).toBe('t1')
  expect(router.calls.apply[0]?.immediate).toBe(false)
  expect(passwordOf(router.calls.apply[0]!.config)).toBe('a-typed-secret')
  expect(router.calls.apply[0]!.config.lans[0]!.dhcp!.static).toHaveLength(2)
  // Now it is the router's config: nothing left to apply, and no password left in the draft.
  expect(store.changes.value).toEqual([])
  expect(passwordOf(store.draft.value)).toBe('')
  expect(passwordOf(store.base.value)).toBe('')
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.notice.value).toBeNull()
  // A second apply would name the tag the router answered with.
  store.edit((draft) => (draft.lans[0]!.dhcp!.range[1] = '192.168.1.220'))
  await store.apply((await store.review())!, true)
  expect(router.calls.apply[1]?.tag).toBe('t2')
  expect(router.calls.apply[1]?.immediate).toBe(true)
})

test('an apply the router refuses reads the config again and keeps the draft', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  const review = (await store.review())!
  router.applyAnswer = new RouterError(ErrorCode.FAILED_PRECONDITION, 'the config has changed since it was read; read it again')
  // Meanwhile the router's config is another, as the refusal says.
  const other = labConfig()
  other.lans[0]!.dhcp!.leaseSecs = 3600
  router.configNow = { config: other, tag: 't9', confirmSecs: 120 }
  const reads = router.calls.config
  await store.apply(review, false)
  await flushPromises()
  expect(store.notice.value).toEqual({ kind: 'refused', message: 'the config has changed since it was read; read it again' })
  expect(router.calls.config).toBe(reads + 1)
  expect(store.base.value!.lans[0]!.dhcp!.leaseSecs).toBe(3600)
  // The draft is as it was typed, so its changes now include the one made elsewhere, back.
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.draft.value!.lans[0]!.dhcp!.leaseSecs).toBe(43200)
  expect(store.changes.value.map((change) => change.what)).toEqual(['lease time', 'reservations'])
  expect(store.busy.value).toBe(false)

  // A config with violations is refused in the router's words too.
  router.applyAnswer = new RouterError(ErrorCode.INVALID_ARGUMENT, 'the config has 1 violation(s): lans[0].dhcp.range: the pool is not in the subnet')
  await store.apply(review, false)
  expect(store.notice.value).toEqual({ kind: 'refused', message: 'the config has 1 violation(s): lans[0].dhcp.range: the pool is not in the subnet' })
})

/** A draft that moves `lan0` to 192.168.2.1/24, and a review that says the caller's connection drops. */
async function moving(store: ConfigStore, router: FakeRouter) {
  store.setLanAddress('lan0', '192.168.2.1/24')
  router.validation = {
    violations: [],
    effects: [{ $typeName: 'openfeo.v1.ConfigEffect', subject: 'lan0', kind: ConfigEffectKind.LAN_ADDRESS_MOVES }],
    caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' },
  }
  return (await store.review())!
}

test('an unanswered apply is settled by what the router then says', async () => {
  // Taken: the router is found again with the change pending and another tag.
  {
    const { router, store } = await started()
    const review = await moving(store, router)
    const sent = clone(ConfigSchema, store.draft.value!)
    router.applyAnswer = { answered: false }
    router.configUnreachable = true
    await store.apply(review, false)
    await flushPromises()
    // Sent once, and the tab says where the router went.
    expect(router.calls.apply).toHaveLength(1)
    expect(store.notice.value).toEqual({ kind: 'moved', name: 'openfeo.home.arpa', address: '192.168.2.1' })
    // Until the router says, the draft is as it was sent.
    expect(equals(ConfigSchema, store.draft.value!, sent)).toBe(true)
    expect(store.busy.value).toBe(false)

    router.setConnection('reconnecting')
    router.configUnreachable = false
    router.configNow = { config: sent, tag: 't2', confirmSecs: 120 }
    router.setConnection('open')
    router.push('state', pendingState(20))
    await flushPromises()
    expect(store.base.value!.lans[0]!.ipv4).toBe('192.168.2.1/24')
    expect(store.changes.value).toEqual([])
    expect(store.pending.value?.windowSecs).toBe(120)
    // Reached again, the tab no longer says where to look.
    expect(store.notice.value).toBeNull()
    // Never sent a second time.
    expect(router.calls.apply).toHaveLength(1)
  }
  // Not taken: the router is found with the config and the tag it had.
  {
    const { router, store } = await started()
    const review = await moving(store, router)
    router.applyAnswer = { answered: false }
    router.configUnreachable = true
    await store.apply(review, false)
    await flushPromises()
    router.setConnection('reconnecting')
    router.configUnreachable = false
    router.setConnection('open')
    router.push('state', state())
    await flushPromises()
    expect(store.base.value!.lans[0]!.ipv4).toBe('192.168.1.1/24')
    // The draft is back with its changes, and the tab says the change is not in force.
    expect(store.draft.value!.lans[0]!.ipv4).toBe('192.168.2.1/24')
    expect(store.changes.value.map((change) => change.what)).toEqual(['address', 'pool', 'reservations', 'target'])
    expect(store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: null, draftKept: true })
    expect(router.calls.apply).toHaveLength(1)
  }
})

test('a change that is reverted leaves its changes as a draft again', async () => {
  // By the timer.
  {
    const { router, store } = await started()
    store.edit(reserve)
    router.applyAnswer = { answered: true, tag: 't2' }
    await store.apply((await store.review())!, false)
    await taken(router, reserved(), 't2')
    expect(store.pending.value).toBeDefined()
    expect(store.changes.value).toEqual([])

    await settled(router, labConfig(), 't1', 'config.reverted', { why: 'timeout' })
    expect(store.pending.value).toBeUndefined()
    expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(1)
    expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
    expect(store.changes.value).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 added' }])
    expect(store.notice.value).toEqual({ kind: 'reverted', why: 'timeout', appliedAt: NOW, draftKept: true })
  }
  // By hand, with the password that was typed for it.
  {
    const { router, store } = await started(pppoeConfig())
    store.edit(typePassword)
    router.applyAnswer = { answered: true, tag: 't1' }
    await store.apply((await store.review())!, false)
    // A password alone moves no tag: the router's config reads the same before and after.
    await taken(router, pppoeConfig(), 't1', 30)
    expect(passwordOf(store.draft.value)).toBe('')
    await store.revert()
    expect(router.calls.revert).toBe(1)
    await settled(router, pppoeConfig(), 't1', 'config.reverted', { why: 'asked' })
    expect(passwordOf(store.draft.value)).toBe('a-typed-secret')
    expect(store.changes.value).toEqual([{ subject: 'wan0', what: 'password', before: '', after: 'changed' }])
    expect(store.notice.value).toEqual({ kind: 'reverted', why: 'asked', appliedAt: new Date(NOW.getTime() - 30_000), draftKept: true })
  }
})

test('a reverted change whose event comes late is still known, and then says why', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store.apply((await store.review())!, false)
  await taken(router, reserved(), 't2')
  // The state and the config say it is gone before any event does.
  router.configNow = { config: labConfig(), tag: 't1', confirmSecs: 120 }
  router.push('state', state())
  await flushPromises()
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: NOW, draftKept: true })
  expect(store.changes.value).toHaveLength(1)
  router.push('events', event('config.reverted', { why: 'timeout' }))
  await flushPromises()
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'timeout', appliedAt: NOW, draftKept: true })
  // A reason this page does not know is not guessed at.
  const other = await started()
  other.store.edit(reserve)
  other.router.applyAnswer = { answered: true, tag: 't2' }
  await other.store.apply((await other.store.review())!, false)
  await taken(other.router, reserved(), 't2')
  await settled(other.router, labConfig(), 't1', 'config.reverted', { why: 'restart' })
  expect(other.store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: NOW, draftKept: true })
})

test('what was typed while a change waited is kept when it goes back', async () => {
  const { router, store } = await started(pppoeConfig())
  store.edit(typePassword)
  store.edit(reserve)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store.apply((await store.review())!, false)
  await taken(router, reserved(pppoeConfig()), 't2')
  // The fields stay open while the change waits, and the person goes on.
  store.edit((draft) => (draft.lans[0]!.dhcp!.range[1] = '192.168.1.220'))
  expect(store.changes.value.map((change) => change.what)).toEqual(['pool'])
  await settled(router, pppoeConfig(), 't1', 'config.reverted', { why: 'timeout' })
  // Everything is still there: what was sent, what was typed since, and the password.
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.draft.value!.lans[0]!.dhcp!.range[1]).toBe('192.168.1.220')
  expect(passwordOf(store.draft.value)).toBe('a-typed-secret')
  expect(store.changes.value.map((change) => change.what)).toEqual(['password', 'pool', 'reservations'])
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'timeout', appliedAt: NOW, draftKept: true })
})

test('an apply that was not taken keeps what was typed since it was sent', async () => {
  const { router, store } = await started()
  const review = await moving(store, router)
  router.applyAnswer = { answered: false }
  router.configUnreachable = true
  await store.apply(review, false)
  await flushPromises()
  store.edit(reserve)
  router.setConnection('reconnecting')
  router.configUnreachable = false
  router.setConnection('open')
  router.push('state', state())
  await flushPromises()
  expect(store.draft.value!.lans[0]!.ipv4).toBe('192.168.2.1/24')
  expect(store.draft.value!.lans[0]!.dhcp!.static.map((lease) => lease.hostname)).toEqual(['nas', 'printer'])
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: null, draftKept: true })
})

test('an apply names the config and the tag that were reviewed, whatever was read since', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  const review = (await store.review())!
  // While the dialog is open another session changes the config, and this tab reads it.
  const other = labConfig()
  other.lans[0]!.dhcp!.leaseSecs = 3600
  router.configNow = { config: other, tag: 't2', confirmSecs: 120 }
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  expect(store.base.value!.lans[0]!.dhcp!.leaseSecs).toBe(3600)
  // What is sent is what the dialog showed, against the config it was shown against: the
  // router refuses it as stale, and the other session's change is not undone unseen.
  router.applyAnswer = new RouterError(ErrorCode.FAILED_PRECONDITION, 'the config has changed since it was read; read it again')
  await store.apply(review, false)
  await flushPromises()
  expect(router.calls.apply).toHaveLength(1)
  expect(router.calls.apply[0]?.tag).toBe('t1')
  expect(equals(ConfigSchema, router.calls.apply[0]!.config, reserved())).toBe(true)
  expect(store.notice.value).toEqual({ kind: 'refused', message: 'the config has changed since it was read; read it again' })
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  // Reviewed again, it is shown the other session's change as one it would undo, and names the new tag.
  const again = (await store.review())!
  expect(again.changes.map((change) => change.what)).toEqual(['lease time', 'reservations'])
  router.applyAnswer = { answered: true, tag: 't3' }
  await store.apply(again, true)
  expect(router.calls.apply[1]?.tag).toBe('t2')
})

test('a change this tab applied and never saw pending is still known to have gone back', async () => {
  // The answer got out, and the address went before the state that says "pending" could
  // follow it. The tab finds the router again after the window ran out.
  const { router, store } = await started()
  store.edit(reserve)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store.apply((await store.review())!, false)
  expect(store.changes.value).toEqual([])
  router.setConnection('reconnecting')
  router.configNow = { config: labConfig(), tag: 't1', confirmSecs: 120 }
  router.setConnection('open')
  router.push('state', state())
  await flushPromises()
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(1)
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.changes.value).toEqual([{ subject: 'lan0', what: 'reservations', before: '', after: '1 added' }])
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: null, draftKept: true })
  // It is settled once: a later read brings nothing back a second time.
  store.discard()
  store.notice.value = null
  router.push('events', event('config.applied', { mode: 'immediate' }, new Date(NOW.getTime() + 5)))
  await flushPromises()
  expect(store.changes.value).toEqual([])
  expect(store.notice.value).toBeNull()
})

test("what became of this tab's change is the first word after it, not a later change's", async () => {
  const { router, store } = await started()
  store.edit(reserve)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store.apply((await store.review())!, false)
  await taken(router, reserved(), 't2', 50)
  // While this tab was away its change ran out, and another session applied one and confirmed it.
  const theirs = labConfig()
  theirs.lans[0]!.dhcp!.leaseSecs = 3600
  router.configNow = { config: theirs, tag: 't3', confirmSecs: 120 }
  router.push('state', state())
  router.push('events', event('config.reverted', { why: 'timeout' }, new Date(NOW.getTime() - 30_000)))
  router.push('events', event('config.confirmed', {}, new Date(NOW.getTime() - 10_000)))
  await flushPromises()
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'timeout', appliedAt: new Date(NOW.getTime() - 50_000), draftKept: true })
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
})

test('a change that is confirmed is forgotten', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  router.applyAnswer = { answered: true, tag: 't2' }
  await store.apply((await store.review())!, false)
  // Applied twenty seconds ago, confirmed ten seconds ago.
  await taken(router, reserved(), 't2', 20)
  await store.confirm()
  expect(router.calls.confirm).toBe(1)
  await settled(router, reserved(), 't2', 'config.confirmed', {}, new Date(NOW.getTime() - 10_000))
  expect(store.pending.value).toBeUndefined()
  expect(store.notice.value).toBeNull()
  expect(store.changes.value).toEqual([])
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  // A later change by someone else, reverted, brings nothing of this one back.
  const third = reserved()
  third.lans[0]!.dhcp!.leaseSecs = 3600
  await taken(router, third, 't3')
  await settled(router, reserved(), 't2', 'config.reverted', { why: 'asked' })
  expect(store.changes.value).toEqual([])
  // (Said of the later change, and not answered by the earlier one's confirmation.)
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'asked', appliedAt: NOW, draftKept: false })
})

test("another session's revert is said, with no draft to keep", async () => {
  const { router, store } = await started()
  // Someone else applies: this tab has changed nothing and follows.
  await taken(router, reserved(), 't2', 40)
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.changes.value).toEqual([])
  expect(store.notice.value).toBeNull()
  await settled(router, labConfig(), 't1', 'config.reverted', { why: 'timeout' })
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'timeout', appliedAt: new Date(NOW.getTime() - 40_000), draftKept: false })
  expect(store.base.value!.lans[0]!.dhcp!.static).toHaveLength(1)
  expect(store.changes.value).toEqual([])
})

test("setting a LAN's address carries what follows it and keeps what does not fit", async () => {
  const { store } = await started()
  store.setLanAddress('lan0', '192.168.2.1/24')
  const lan = store.draft.value!.lans[0]!
  expect(lan.ipv4).toBe('192.168.2.1/24')
  expect(lan.dhcp!.range).toEqual(['192.168.2.100', '192.168.2.200'])
  expect(lan.dhcp!.static[0]!.ip).toBe('192.168.2.10')
  expect(store.draft.value!.firewall!.portForwards[0]!.to).toBe('192.168.2.2')
  expect(store.unfit.value).toEqual([])
  expect(store.changes.value.map((change) => `${change.subject} ${change.what}`)).toEqual(['lan0 address', 'lan0 pool', 'lan0 reservations', 'port forward lan-http target'])

  // A subnet too small for the pool: what does not fit is left and kept for the page to mark.
  store.setLanAddress('lan0', '192.168.2.1/26')
  expect(store.draft.value!.lans[0]!.ipv4).toBe('192.168.2.1/26')
  expect(store.unfit.value).toEqual([
    { path: 'lans[0].dhcp.range[0]', value: '192.168.2.100' },
    { path: 'lans[0].dhcp.range[1]', value: '192.168.2.200' },
  ])
  expect(store.draft.value!.lans[0]!.dhcp!.range).toEqual(['192.168.2.100', '192.168.2.200'])

  // An address that is not one yet is set as typed and carries nothing; what an earlier move
  // left without a place is still without one.
  store.setLanAddress('lan0', '192.168.5')
  expect(store.draft.value!.lans[0]!.ipv4).toBe('192.168.5')
  expect(store.draft.value!.lans[0]!.dhcp!.static[0]!.ip).toBe('192.168.2.10')
  expect(store.unfit.value).toHaveLength(2)
  // A LAN that is not there is nobody's.
  store.setLanAddress('nothing', '192.168.9.1/24')
  expect(store.draft.value!.lans).toHaveLength(1)
  // Discarding forgets what did not fit.
  store.setLanAddress('lan0', '192.168.1.1/26')
  store.discard()
  expect(store.unfit.value).toEqual([])
})

test('a typed password is in no storage and not in the list of changes', async () => {
  window.sessionStorage.setItem(TOKEN_KEY, 'fake-token')
  window.localStorage.setItem(THEME_KEY, 'dark')
  const { router, store } = await started(pppoeConfig())
  store.edit(typePassword)
  const everywhere = () =>
    [window.localStorage, window.sessionStorage].flatMap((storage) => Array.from({ length: storage.length }, (_, at) => [storage.key(at), storage.getItem(storage.key(at) ?? '')]))
  const clean = () => {
    expect(everywhere().map(([key]) => key).sort()).toEqual([THEME_KEY, TOKEN_KEY].sort())
    expect(JSON.stringify(everywhere())).not.toContain('a-typed-secret')
    expect(JSON.stringify(store.changes.value)).not.toContain('a-typed-secret')
    expect(JSON.stringify(store.notice.value)).not.toContain('a-typed-secret')
  }
  clean()
  const review = (await store.review())!
  expect(JSON.stringify(review.changes)).not.toContain('a-typed-secret')
  router.applyAnswer = { answered: true, tag: 't1' }
  await store.apply(review, false)
  clean()
  await taken(router, pppoeConfig(), 't1')
  await settled(router, pppoeConfig(), 't1', 'config.reverted', { why: 'timeout' })
  clean()
  expect(window.location.href).not.toContain('a-typed-secret')
})

test('nothing may be changed on a router running on defaults', async () => {
  const { router, store } = await started()
  const refused = state()
  refused.system!.configProblem = { $typeName: 'openfeo.v1.ConfigProblem', reason: 'invalid (1 error)', violations: [] }
  router.push('state', refused)
  await flushPromises()
  expect(store.readOnly.value).toBe('The router refused its config file and runs on defaults. Mend or remove the file to change settings here.')
  store.edit(reserve)
  store.setLanAddress('lan0', '192.168.2.1/24')
  expect(store.changes.value).toEqual([])
  expect(store.draft.value!.lans[0]!.ipv4).toBe('192.168.1.1/24')
  // Once the file is mended (and the router restarted on it) the pages edit again.
  router.push('state', state())
  await flushPromises()
  expect(store.readOnly.value).toBeNull()
  store.edit(reserve)
  expect(store.changes.value).toHaveLength(1)
})

test('the draft goes when the session ends', async () => {
  const { router, store } = await started(pppoeConfig())
  store.edit(typePassword)
  router.applyAnswer = { answered: true, tag: 't1' }
  await store.apply((await store.review())!, false)
  store.edit(typePassword)
  router.endSession('lapsed')
  await flushPromises()
  expect(store.draft.value).toBeNull()
  expect(store.base.value).toBeNull()
  expect(store.notice.value).toBeNull()
  expect(store.changes.value).toEqual([])
  // What was remembered of the apply went too: a revert seen later restores nothing.
  router.authenticated = true
  router.push('state', state())
  await flushPromises()
  expect(passwordOf(store.draft.value)).not.toBe('a-typed-secret')
})

test('leaving the page asks only while there are changes', async () => {
  const added = vi.spyOn(window, 'addEventListener')
  const removed = vi.spyOn(window, 'removeEventListener')
  const count = (spy: typeof added | typeof removed) => spy.mock.calls.filter(([type]) => type === 'beforeunload').length
  const { store } = await started()
  expect(count(added)).toBe(0)
  store.edit(reserve)
  await flushPromises()
  expect(count(added)).toBe(1)
  // The listener asks: it marks the event as one to be confirmed.
  const leaving = new Event('beforeunload', { cancelable: true })
  window.dispatchEvent(leaving)
  expect(leaving.defaultPrevented).toBe(true)
  store.edit(reserve)
  await flushPromises()
  expect(count(added)).toBe(1)

  store.discard()
  await flushPromises()
  expect(count(removed)).toBe(1)
  const free = new Event('beforeunload', { cancelable: true })
  window.dispatchEvent(free)
  expect(free.defaultPrevented).toBe(false)

  // Stopped with changes still there, it lets go as well.
  store.edit(reserve)
  await flushPromises()
  store.stop()
  expect(count(removed)).toBe(2)
  added.mockRestore()
  removed.mockRestore()
})

test('leaving the page does not ask about changes that were sent and await the router', async () => {
  // An apply that had no answer has moved the router, most likely, and the tab says where it
  // went: following it there must not be met with "leave this page?" over changes that are
  // already the router's. A draft edited since is asked about.
  const { router, store } = await started()
  const review = await moving(store, router)
  await flushPromises()
  const leaving = () => {
    const event = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(event)
    return event.defaultPrevented
  }
  expect(leaving()).toBe(true)
  router.applyAnswer = { answered: false }
  router.configUnreachable = true
  await store.apply(review, false)
  await flushPromises()
  expect(store.changes.value.length).toBeGreaterThan(0)
  expect(leaving()).toBe(false)
  store.edit(reserve)
  await flushPromises()
  expect(leaving()).toBe(true)
})

test('a read that fails is made again when the socket opens, and reads are one at a time', async () => {
  const router = signedIn()
  router.configNow = { config: labConfig(), tag: 't1', confirmSecs: 120 }
  router.configUnreachable = true
  const live = useLive(router)
  live.start()
  const store = useConfig(router, live, () => 'openfeo.home.arpa')
  store.start()
  stores.push({ store, live })
  await flushPromises()
  expect(store.base.value).toBeNull()
  router.setConnection('reconnecting')
  router.configUnreachable = false
  router.setConnection('open')
  await flushPromises()
  expect(store.base.value).not.toBeNull()

  // Three reasons to read while one read is under way are one read more, not three.
  const reads = router.calls.config
  const letGo = router.holdCall('config')
  router.push('events', event('config.applied', { mode: 'immediate' }, new Date(NOW.getTime() + 1)))
  await flushPromises()
  router.push('events', event('config.confirmed', {}, new Date(NOW.getTime() + 2)))
  router.push('events', event('config.applied', { mode: 'immediate' }, new Date(NOW.getTime() + 3)))
  router.push('events', event('config.confirmed', {}, new Date(NOW.getTime() + 4)))
  await flushPromises()
  expect(router.calls.config).toBe(reads + 1)
  letGo()
  await flushPromises()
  expect(router.calls.config).toBe(reads + 2)
  // An event that is not about the config asks for nothing.
  router.push('events', event('wan.wan0.up', {}, new Date(NOW.getTime() + 5)))
  await flushPromises()
  expect(router.calls.config).toBe(reads + 2)
})

test('a confirm or a revert the router refuses says so in its words', async () => {
  const { router, store } = await started()
  router.confirmRefusal = new RouterError(ErrorCode.FAILED_PRECONDITION, 'no change of config is pending')
  await store.confirm()
  expect(store.notice.value).toEqual({ kind: 'refused', message: 'no change of config is pending' })
  expect(store.busy.value).toBe(false)
  store.notice.value = null
  router.revertAnswer = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  await store.revert()
  expect(store.notice.value).toEqual({ kind: 'refused', message: 'the router did not answer' })
  // A revert that is not answered is not a refusal: the state will say what became of it.
  store.notice.value = null
  router.revertAnswer = { answered: false }
  await store.revert()
  expect(store.notice.value).toBeNull()
})

test('nothing is left when the session ends while the router is being asked', async () => {
  // Each of the four asks waits on the router. Whichever is in flight when the session ends
  // must leave nothing behind when its answer comes: the draft may hold a typed password.
  const asks: [name: 'validate' | 'apply' | 'confirm' | 'revert', prepare: (router: FakeRouter) => void, ask: (store: ConfigStore, review: Review) => Promise<unknown>][] = [
    [
      'validate',
      (router) => {
        router.validation = { violations: [{ $typeName: 'openfeo.v1.ConfigViolation', path: 'wans[0]', code: 'x', message: 'refused' }], effects: [], caller: undefined }
      },
      (store) => store.review(),
    ],
    ['apply', (router) => (router.applyAnswer = { answered: true, tag: 't2' }), (store, review) => store.apply(review, false)],
    ['apply', (router) => (router.applyAnswer = { answered: false }), (store, review) => store.apply(review, false)],
    ['apply', (router) => (router.applyAnswer = new RouterError(ErrorCode.FAILED_PRECONDITION, 'stale')), (store, review) => store.apply(review, false)],
    ['confirm', (router) => (router.confirmRefusal = new RouterError(ErrorCode.INTERNAL, 'not written')), (store) => store.confirm()],
    ['revert', (router) => (router.revertAnswer = new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')), (store) => store.revert()],
  ]
  for (const [name, prepare, ask] of asks) {
    const { router, store } = await started(pppoeConfig())
    store.edit(typePassword)
    // A change that moves the caller, so that an apply would have something to say.
    router.validation = {
      violations: [],
      effects: [],
      caller: { $typeName: 'openfeo.v1.Caller', connectionDrops: true, lanChanges: true, lan: 'lan0', routerAfter: '192.168.2.1' },
    }
    const review = (await store.review())!
    prepare(router)
    const letGo = router.holdCall(name)
    const asked = ask(store, review)
    await flushPromises()
    expect(store.busy.value, name).toBe(true)
    router.endSession('lapsed')
    await flushPromises()
    letGo()
    await asked
    await flushPromises()
    expect(store.base.value, name).toBeNull()
    expect(store.draft.value, name).toBeNull()
    expect(store.notice.value, name).toBeNull()
    expect(store.violations.value, name).toEqual([])
    expect(store.awaiting.value, name).toBe(false)
    expect(store.busy.value, name).toBe(false)
  }
})

test('a read that is answered after the session ended brings nothing back', async () => {
  const { router, store } = await started()
  const letGo = router.holdCall('config')
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  router.endSession('revoked')
  letGo()
  await flushPromises()
  expect(store.base.value).toBeNull()
  expect(store.draft.value).toBeNull()
})

test('a read that brings what the draft already is leaves the draft alone', async () => {
  // The pages keep what is half typed beside the draft, and start afresh when the draft is
  // another one: a read that changes nothing must not look like another draft.
  const { router, store } = await started()
  const before = store.draft.value
  router.push('events', event('config.applied', { mode: 'immediate' }))
  await flushPromises()
  expect(router.calls.config).toBe(2)
  expect(store.draft.value).toBe(before)
  // One that brings another config still replaces it.
  router.configNow = { config: reserved(), tag: 't2', confirmSecs: 120 }
  router.push('events', event('config.confirmed', {}, new Date(NOW.getTime() + 1)))
  await flushPromises()
  expect(store.draft.value).not.toBe(before)
  expect(store.draft.value!.lans[0]!.dhcp!.static).toHaveLength(2)
  expect(store.changes.value).toEqual([])
})

test('what had no place is still marked after a move that gives it none', async () => {
  const { store } = await started()
  const ends = [
    { path: 'lans[0].dhcp.range[0]', value: '192.168.1.100' },
    { path: 'lans[0].dhcp.range[1]', value: '192.168.1.200' },
  ]
  store.setLanAddress('lan0', '192.168.2.1/26')
  expect(store.unfit.value).toEqual(ends)
  // The same address again is no move at all.
  store.setLanAddress('lan0', '192.168.2.1/26')
  expect(store.unfit.value).toEqual(ends)
  // The router moves within the same small subnet: the pool's ends still have no place in it.
  store.setLanAddress('lan0', '192.168.2.2/26')
  expect(store.unfit.value).toEqual(ends)
  // One of them put right by hand is no longer the renumbering's to report.
  store.edit((draft) => (draft.lans[0]!.dhcp!.range[0] = '192.168.2.10'))
  store.setLanAddress('lan0', '192.168.2.3/26')
  expect(store.unfit.value).toEqual([ends[1]])
  // A subnet that has room for what was left over stops marking it.
  store.setLanAddress('lan0', '192.168.1.1/24')
  expect(store.unfit.value).toEqual([])
})

test('a second ask while one is under way is not sent', async () => {
  const { router, store } = await started()
  store.edit(reserve)
  const review = (await store.review())!
  let letGo = router.holdCall('apply')
  const first = store.apply(review, false)
  const second = store.apply(review, false)
  await flushPromises()
  letGo()
  await Promise.all([first, second])
  expect(router.calls.apply).toHaveLength(1)

  letGo = router.holdCall('confirm')
  const confirms = [store.confirm(), store.confirm(), store.revert()]
  await flushPromises()
  letGo()
  await Promise.all(confirms)
  expect(router.calls.confirm).toBe(1)
  expect(router.calls.revert).toBe(0)

  letGo = router.holdCall('validate')
  const validated = router.calls.validate.length
  const reviews = [store.review(), store.review()]
  await flushPromises()
  letGo()
  expect((await Promise.all(reviews)).filter((found) => found !== null)).toHaveLength(1)
  expect(router.calls.validate).toHaveLength(validated + 1)
})

test('an apply that awaits the router says so', async () => {
  const { router, store } = await started()
  expect(store.awaiting.value).toBe(false)
  const review = await moving(store, router)
  router.applyAnswer = { answered: false }
  router.configUnreachable = true
  await store.apply(review, false)
  await flushPromises()
  expect(store.awaiting.value).toBe(true)
  router.setConnection('reconnecting')
  router.configUnreachable = false
  router.configNow = { config: clone(ConfigSchema, store.draft.value!), tag: 't2', confirmSecs: 120 }
  router.setConnection('open')
  router.push('state', pendingState(20))
  await flushPromises()
  expect(store.awaiting.value).toBe(false)
  // An answered apply never awaited anything.
  const other = await started()
  other.store.edit(reserve)
  other.router.applyAnswer = { answered: true, tag: 't2' }
  await other.store.apply((await other.store.review())!, false)
  expect(other.store.awaiting.value).toBe(false)
})

test('a router that restarted with a change pending is known by its clock', async () => {
  // A password alone moves no tag, and a reboot's event is stamped with a new uptime: what
  // says the change is gone is that the router has been up for less time than when it was applied.
  const { router, store } = await started(pppoeConfig())
  store.edit(typePassword)
  router.applyAnswer = { answered: true, tag: 't1' }
  await store.apply((await store.review())!, false)
  await taken(router, pppoeConfig(), 't1')
  const rebooted = state()
  rebooted.system!.uptimeSecs = 12n
  expect(UPTIME_SECS).toBeGreaterThan(12)
  router.push('state', rebooted)
  router.push('events', event('config.discarded', {}, NOW, 3_000n))
  await flushPromises()
  expect(store.notice.value).toEqual({ kind: 'reverted', why: 'unknown', appliedAt: NOW, draftKept: true })
  expect(passwordOf(store.draft.value)).toBe('a-typed-secret')
})
