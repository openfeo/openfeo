// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The config calls against the router in the lab (SPEC §5.5, §8.3, §11): from a LAN host,
// over the socket. The tests run in order on one router and each builds on the config the
// one before it left. The last one moves the router's own address, follows it, and confirms
// from there.

import { afterAll, expect, test } from 'vitest'

import { ask } from '../../scripts/labctl.mjs'
import {
  clone,
  ConfigEffectKind,
  ConfigSchema,
  create,
  ErrorCode,
  memoryTokenStore,
  Router,
  RouterError,
  StaticLeaseSchema,
  type Config,
} from '../src/index.js'
import { stateWhere } from './support.js'

const BASE = process.env.OPENFEO_ROUTER ?? ''
const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''
/** Where the router is once `lan0` has moved. */
const MOVED = 'https://192.168.2.1'

/** The tag of the config as it was first read, which three changes later is no longer the one running. */
let firstTag = ''

const store = memoryTokenStore()
const a = new Router({ baseUrl: BASE, tokenStore: store })
const routers = [a]

afterAll(() => {
  for (const each of routers) {
    each.close()
  }
})

/** `config` with one more reservation on `lan0`. */
function withReservation(config: Config, hostname: string, last: number): Config {
  const next = clone(ConfigSchema, config)
  next.lans[0]?.dhcp?.static.push(
    create(StaticLeaseSchema, { mac: `02:00:00:aa:01:${last.toString(16).padStart(2, '0')}`, ip: `192.168.1.${last}`, hostname }),
  )
  return next
}

/** `config` with `lan0` in 192.168.2.0/24 and everything that pointed into the old subnet moved with it. */
function moved(config: Config): Config {
  const next = clone(ConfigSchema, config)
  const renumber = (address: string) => address.replace('192.168.1.', '192.168.2.')
  const lan = next.lans[0]
  if (lan !== undefined) {
    lan.ipv4 = renumber(lan.ipv4)
    if (lan.dhcp !== undefined) {
      lan.dhcp.range = lan.dhcp.range.map(renumber)
      for (const lease of lan.dhcp.static) {
        lease.ip = renumber(lease.ip)
      }
    }
  }
  for (const forward of next.firewall?.portForwards ?? []) {
    forward.to = renumber(forward.to)
  }
  return next
}

async function refusal(work: Promise<unknown>): Promise<RouterError> {
  const error: unknown = await work.then(
    () => undefined,
    (thrown: unknown) => thrown,
  )
  expect(error).toBeInstanceOf(RouterError)
  return error as RouterError
}

function names(config: Config): string[] {
  return config.lans[0]?.dhcp?.static.map((lease) => lease.hostname) ?? []
}

test('the config comes without its secrets, with a tag and the window', async () => {
  expect(BASE, 'OPENFEO_ROUTER').not.toBe('')
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  await a.setInitialPassword(PASSWORD)
  const view = await a.config()
  // A password is set, and its hash stays on the router.
  expect(view.config.admin?.passwordHash ?? '').toBe('')
  expect(view.tag).not.toBe('')
  firstTag = view.tag
  expect(view.confirmSecs).toBe(120)
  expect(view.config.lans[0]?.ipv4).toBe('192.168.1.1/24')
  expect(names(view.config)).toEqual(['nas'])
})

test('a validation says what is wrong, and what a change interrupts', async () => {
  const { config } = await a.config()
  const outside = clone(ConfigSchema, config)
  const dhcp = outside.lans[0]?.dhcp
  expect(dhcp).toBeDefined()
  if (dhcp !== undefined) {
    dhcp.range = ['192.168.9.100', '192.168.9.200']
  }
  const bad = await a.validate(outside)
  expect(bad.violations).toHaveLength(1)
  expect(bad.violations[0]?.path.startsWith('lans[0].dhcp.range')).toBe(true)
  expect(bad.violations[0]?.message).not.toBe('')
  expect(bad.effects).toEqual([])

  const good = await a.validate(withReservation(config, 'printer', 20))
  expect(good.violations).toEqual([])
  expect(good.effects.map((effect) => [effect.subject, effect.kind])).toEqual([['lan0', ConfigEffectKind.LAN_DHCP_RESTARTS]])
  expect(good.caller?.connectionDrops).toBe(false)
  expect(good.caller?.lanChanges).toBe(false)
  expect(good.caller?.lan).toBe('lan0')
  // Nothing was changed by asking.
  expect(names((await a.config()).config)).toEqual(['nas'])
})

test('an apply is pending until it is confirmed', async () => {
  const before = await a.config()
  const applied = await a.apply(withReservation(before.config, 'printer', 20), before.tag, { timeoutSecs: 30 })
  expect(applied.answered).toBe(true)
  if (!applied.answered) {
    return
  }
  expect(applied.tag).not.toBe(before.tag)

  const pending = await stateWhere(a, 'a pending change', 10_000, (state) => state.system?.pendingConfig !== undefined)
  const change = pending.system?.pendingConfig
  expect(change).toBeDefined()
  if (change !== undefined) {
    expect(change.revertsUptimeMs - change.appliedUptimeMs).toBe(30_000n)
    expect(change.windowSecs).toBe(30)
    expect(change.effects.map((effect) => [effect.subject, effect.kind])).toEqual([['lan0', ConfigEffectKind.LAN_DHCP_RESTARTS]])
  }

  await a.confirm()
  await stateWhere(a, 'the change to be confirmed', 10_000, (state) => state.system?.pendingConfig === undefined)
  const after = await a.config()
  expect(names(after.config)).toEqual(['nas', 'printer'])
  expect(after.tag).toBe(applied.tag)
})

test('a revert puts back what was confirmed', async () => {
  const before = await a.config()
  const applied = await a.apply(withReservation(before.config, 'camera', 21), before.tag, { timeoutSecs: 30 })
  expect(applied.answered).toBe(true)
  expect(names((await a.config()).config)).toEqual(['nas', 'printer', 'camera'])

  // The router's address does not move, so this revert is answered.
  expect(await a.revert()).toEqual({ answered: true })
  await stateWhere(a, 'the change to be reverted', 10_000, (state) => state.system?.pendingConfig === undefined)
  const after = await a.config()
  expect(after.tag).toBe(before.tag)
  expect(names(after.config)).toEqual(['nas', 'printer'])
  // With nothing pending there is nothing to confirm or revert.
  expect((await refusal(a.confirm())).code).toBe(ErrorCode.FAILED_PRECONDITION)
  expect((await refusal(a.revert())).code).toBe(ErrorCode.FAILED_PRECONDITION)
})

test('an immediate apply stands at once', async () => {
  const before = await a.config()
  const applied = await a.apply(withReservation(before.config, 'camera', 21), before.tag, { immediate: true })
  expect(applied.answered).toBe(true)
  const state = await a.state()
  expect(state.system?.pendingConfig).toBeUndefined()
  expect(names((await a.config()).config)).toEqual(['nas', 'printer', 'camera'])
})

test('an apply against a tag that has gone stale is refused', async () => {
  const now = await a.config()
  expect(now.tag).not.toBe(firstTag)
  const error = await refusal(a.apply(now.config, firstTag))
  expect(error.code).toBe(ErrorCode.FAILED_PRECONDITION)
  expect(error.message).toBe('the config has changed since it was read; read it again')
  expect((await a.config()).tag).toBe(now.tag)
})

test('a change that moves the router is taken, answered or not, and confirmed from the new address', async () => {
  const before = await a.config()
  const next = moved(before.config)
  expect(next.lans[0]?.ipv4).toBe('192.168.2.1/24')
  expect(next.firewall?.portForwards[0]?.to).toBe('192.168.2.2')

  const told = await a.validate(next)
  expect(told.violations).toEqual([])
  expect(told.effects.map((effect) => [effect.subject, effect.kind])).toEqual([['lan0', ConfigEffectKind.LAN_ADDRESS_MOVES]])
  expect(told.caller?.connectionDrops).toBe(true)
  expect(told.caller?.lanChanges).toBe(true)
  expect(told.caller?.routerAfter).toBe('192.168.2.1')

  // The router answers once the config is published, and by then the address this socket
  // arrived at may be gone: answered or not is the router's to choose, but it does not hang.
  const started = Date.now()
  const applied = await a.apply(next, before.tag, { timeoutSecs: 60 })
  expect(Date.now() - started).toBeLessThan(15_000)
  expect(typeof applied.answered).toBe('boolean')
  a.close()

  // What a person does next: take an address in the new subnet and go to the router there.
  await ask('lan-to 192.168.2.50/24 192.168.2.1')
  const b = new Router({ baseUrl: MOVED, tokenStore: store })
  routers.push(b)
  const pending = await stateWhere(b, 'the pending change at the new address', 30_000, (state) => state.system?.pendingConfig !== undefined)
  expect(pending.system?.pendingConfig?.windowSecs).toBe(60)
  expect(pending.lans[0]?.ipv4).toBe('192.168.2.1/24')

  await b.confirm()
  await stateWhere(b, 'the move to be confirmed', 10_000, (state) => state.system?.pendingConfig === undefined)
  const after = await b.config()
  expect(after.config.lans[0]?.ipv4).toBe('192.168.2.1/24')
  expect(after.config.lans[0]?.dhcp?.range).toEqual(['192.168.2.100', '192.168.2.200'])
  expect(after.tag).not.toBe(before.tag)
})
