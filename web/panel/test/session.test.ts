// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { passwordProblem, screenFor, sessionStore, storageOr, TOKEN_KEY, useSession } from '../src/session'
import { FakeRouter } from './fake-router'

const settled = async () => {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve()
  }
}

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

test('an unreadable config comes before everything', () => {
  expect(screenFor({ needsPassword: false, configUnreadable: true }, true)).toBe('config-unreadable')
  expect(screenFor({ needsPassword: false, configUnreadable: true }, false)).toBe('config-unreadable')
  expect(screenFor({ needsPassword: true, configUnreadable: true }, false)).toBe('config-unreadable')
})

test('no password yet is the first-password screen, token or not', () => {
  expect(screenFor({ needsPassword: true, configUnreadable: false }, false)).toBe('first-password')
  // A token kept from before a router was reset is not a session on it.
  expect(screenFor({ needsPassword: true, configUnreadable: false }, true)).toBe('first-password')
})

test('otherwise the token decides between login and the dashboard', () => {
  expect(screenFor({ needsPassword: false, configUnreadable: false }, false)).toBe('login')
  expect(screenFor({ needsPassword: false, configUnreadable: false }, true)).toBe('dashboard')
})

test('the first answer chooses the screen, and until then there is none', async () => {
  const router = new FakeRouter()
  router.statusNow = { ...router.statusNow, needsPassword: true }
  const session = useSession(router)
  expect(session.screen.value).toBeNull()
  await session.refresh()
  expect(session.screen.value).toBe('first-password')
  expect(session.status.value?.hostname).toBe('openfeo')
  expect(session.unreachable.value).toBe(false)
})

test('after the session ends the screen is chosen again from status', async () => {
  const router = new FakeRouter()
  router.authenticated = true
  const session = useSession(router)
  await session.refresh()
  expect(session.screen.value).toBe('dashboard')
  expect(session.ended.value).toBeNull()

  router.endSession('revoked')
  await settled()
  expect(session.ended.value).toBe('revoked')
  expect(router.calls.status).toBe(2)
  expect(session.screen.value).toBe('login')

  // A router that was reset meanwhile has no password at all: that screen, not a login that cannot work.
  router.authenticated = true
  await session.refresh()
  router.statusNow = { ...router.statusNow, needsPassword: true }
  router.endSession('lapsed')
  await settled()
  expect(session.ended.value).toBe('lapsed')
  expect(session.screen.value).toBe('first-password')
})

test('entering clears why the last session ended and goes to the dashboard', async () => {
  const router = new FakeRouter()
  const session = useSession(router)
  await session.refresh()
  router.authenticated = true
  router.endSession('lapsed')
  await settled()
  expect(session.screen.value).toBe('login')
  session.notice.value = 'A password was set a moment ago. Log in with it.'
  router.authenticated = true
  await session.entered()
  expect(session.ended.value).toBeNull()
  expect(session.notice.value).toBeNull()
  expect(session.screen.value).toBe('dashboard')
})

test('a router that does not answer is said to be unreachable, and asked again', async () => {
  const router = new FakeRouter()
  router.unreachable = true
  const session = useSession(router)
  await session.refresh()
  expect(session.unreachable.value).toBe(true)
  expect(session.screen.value).toBeNull()
  expect(router.calls.status).toBe(1)
  await vi.advanceTimersByTimeAsync(4_999)
  expect(router.calls.status).toBe(1)
  await vi.advanceTimersByTimeAsync(1)
  expect(router.calls.status).toBe(2)
  // Still not there: asked again, five seconds on.
  await vi.advanceTimersByTimeAsync(5_000)
  expect(router.calls.status).toBe(3)
  router.unreachable = false
  router.statusNow = { ...router.statusNow, needsPassword: false }
  await vi.advanceTimersByTimeAsync(5_000)
  expect(session.unreachable.value).toBe(false)
  expect(session.screen.value).toBe('login')
  // And once it has answered, nothing keeps asking.
  await vi.advanceTimersByTimeAsync(60_000)
  expect(router.calls.status).toBe(4)
})

test('a session that stops being used lets go of the router', async () => {
  const router = new FakeRouter()
  router.unreachable = true
  const session = useSession(router)
  await session.refresh()
  session.dispose()
  await vi.advanceTimersByTimeAsync(60_000)
  expect(router.calls.status).toBe(1)
  router.endSession('revoked')
  await settled()
  expect(session.ended.value).toBeNull()
})

test('twelve code points are enough, whatever their bytes', () => {
  // The router counts characters (SPEC §9), so the form counts code points: a password of
  // twelve emoji is twelve, though it is forty-eight bytes and twenty-four UTF-16 units.
  expect(passwordProblem('🔑'.repeat(12), '🔑'.repeat(12))).toBeNull()
  expect(passwordProblem('🔑'.repeat(11), '🔑'.repeat(11))).toBe('12 characters or more.')
  expect(passwordProblem('a'.repeat(11), 'a'.repeat(11))).toBe('12 characters or more.')
  expect(passwordProblem('a'.repeat(12), 'a'.repeat(12))).toBeNull()
  expect(passwordProblem('', '')).toBe('12 characters or more.')
})

test('257 characters are too many and a differing repeat is said', () => {
  expect(passwordProblem('a'.repeat(256), 'a'.repeat(256))).toBeNull()
  expect(passwordProblem('a'.repeat(257), 'a'.repeat(257))).toBe('256 characters or fewer.')
  expect(passwordProblem('🔑'.repeat(256), '🔑'.repeat(256))).toBeNull()
  expect(passwordProblem('correct horse battery', 'correct horse batterx')).toBe('The two passwords differ.')
  // A space is a character like any other: nothing is trimmed before the two are compared.
  expect(passwordProblem('correct horse battery', 'correct horse battery ')).toBe('The two passwords differ.')
  // The length is said before the difference.
  expect(passwordProblem('short', 'other')).toBe('12 characters or more.')
})

test('the token is kept in sessionStorage under openfeo.token', () => {
  expect(TOKEN_KEY).toBe('openfeo.token')
  window.sessionStorage.clear()
  const store = sessionStore(window.sessionStorage)
  expect(store.get()).toBeNull()
  store.set('a-token')
  expect(window.sessionStorage.getItem('openfeo.token')).toBe('a-token')
  expect(store.get()).toBe('a-token')
  // A second store over the same storage is the same session: a reload keeps it.
  expect(sessionStore(window.sessionStorage).get()).toBe('a-token')
  store.clear()
  expect(window.sessionStorage.getItem('openfeo.token')).toBeNull()
  expect(window.localStorage.length).toBe(0)
})

test('storage that refuses is a session kept for this page only', () => {
  const refusing = {
    getItem: () => {
      throw new Error('blocked')
    },
    setItem: () => {
      throw new Error('blocked')
    },
    removeItem: () => {
      throw new Error('blocked')
    },
  }
  const store = sessionStore(refusing)
  expect(store.get()).toBeNull()
  store.set('a-token')
  expect(store.get()).toBe('a-token')
  store.clear()
  expect(store.get()).toBeNull()
})

test('storage the browser will not hand over at all is no storage, not an error', () => {
  // With site data blocked, reading `window.sessionStorage` itself throws. The panel must
  // still come up: the session is then kept for this page only.
  const denied = storageOr(() => {
    throw new DOMException('The operation is insecure.', 'SecurityError')
  })
  expect(denied.getItem('anything')).toBeNull()
  const store = sessionStore(denied)
  expect(store.get()).toBeNull()
  store.set('a-token')
  expect(store.get()).toBe('a-token')
  store.clear()
  expect(store.get()).toBeNull()
  // Storage that is there is used as it is.
  expect(storageOr(() => window.sessionStorage)).toBe(window.sessionStorage)
})
