// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { sentence, when, type Part } from '../src/model/events'
import { event, NOW } from './fixtures'

const text = (parts: Part[]) => parts.map((part) => part.text).join('')
const mono = (parts: Part[]) => parts.filter((part) => part.mono === true).map((part) => part.text)
const said = (topic: string, fields: Record<string, string> = {}) => sentence({ topic, fields })

test('each topic part 1 emits has its sentence', () => {
  expect(text(said('wan.wan0.up'))).toBe('wan0 up.')
  expect(text(said('wan.wan0.down', { reason: 'no carrier' }))).toBe('wan0 down: no carrier.')
  expect(text(said('wan.wan0.down'))).toBe('wan0 down.')
  expect(text(said('wan.wan0.down', { reason: '' }))).toBe('wan0 down.')
  expect(text(said('wan.wan0.addr', { address: '203.0.113.100', change: 'added' }))).toBe('wan0 has 203.0.113.100.')
  expect(text(said('wan.wan0.addr', { address: '203.0.113.100', change: 'withdrawn' }))).toBe('wan0 lost 203.0.113.100.')
  expect(text(said('wan.wan0.prefix', { prefix: '2001:db8:1::/48', change: 'added' }))).toBe('wan0 was given 2001:db8:1::/48.')
  expect(text(said('wan.wan0.prefix', { prefix: '2001:db8:1::/48', change: 'withdrawn' }))).toBe('wan0 lost 2001:db8:1::/48.')
  expect(text(said('lan.lan0.lease.granted', { address: '192.168.1.23', host: 'pixel-8', mac: '02:00:00:00:00:0a' }))).toBe(
    'lan0 leased 192.168.1.23 to pixel-8.',
  )
  expect(text(said('lan.iot.lease.released', { address: '192.168.20.7', host: 'plug', mac: '02:00:00:00:00:0b' }))).toBe(
    'iot took back 192.168.20.7 from plug.',
  )
  expect(text(said('health.ok'))).toBe('The router is healthy again.')
  expect(text(said('health.degraded', { unhealthy: 'dns, nft' }))).toBe('The router is degraded: dns, nft.')
})

test('names and values are set apart as what a machine produced', () => {
  expect(mono(said('wan.wan0.down', { reason: 'no carrier' }))).toEqual(['wan0'])
  expect(mono(said('wan.wan0.addr', { address: '203.0.113.100', change: 'added' }))).toEqual(['wan0', '203.0.113.100'])
  expect(mono(said('lan.lan0.lease.granted', { address: '192.168.1.23', host: 'pixel-8' }))).toEqual(['lan0', '192.168.1.23', 'pixel-8'])
  expect(mono(said('health.degraded', { unhealthy: 'dns, nft' }))).toEqual(['dns, nft'])
  expect(mono(said('health.ok'))).toEqual([])
})

test('a lease with no host name names the MAC', () => {
  expect(text(said('lan.lan0.lease.granted', { address: '192.168.1.23', host: '', mac: '02:00:00:00:00:0a' }))).toBe(
    'lan0 leased 192.168.1.23 to 02:00:00:00:00:0a.',
  )
  expect(text(said('lan.lan0.lease.released', { address: '192.168.1.23', mac: '02:00:00:00:00:0a' }))).toBe(
    'lan0 took back 192.168.1.23 from 02:00:00:00:00:0a.',
  )
})

test('an unknown topic is shown as it came', () => {
  // A later part's event, or a newer router behind a page that was cached: shown, not dropped.
  expect(said('config.applied', { by: 'panel' })).toEqual([{ text: 'config.applied', mono: true }, { text: ' ' }, { text: 'by=panel', mono: true }])
  expect(said('update.staged')).toEqual([{ text: 'update.staged', mono: true }])
  expect(text(said('config.applied', { b: '2', a: '1' }))).toBe('config.applied a=1 b=2')
  // A topic of a known family with a part this code has not met is unknown too.
  expect(said('wan.wan0.probe', { loss: '3' })[0]).toEqual({ text: 'wan.wan0.probe', mono: true })
  expect(said('wan.wan0.addr', { address: '203.0.113.100', change: 'renumbered' })[0]).toEqual({ text: 'wan.wan0.addr', mono: true })
  expect(said('')).toEqual([{ text: '(no topic)', mono: true }])
})

test('an event is timed by the clock once it is synced', () => {
  expect(when(event('wan.wan0.up', {}, new Date(2026, 10, 10, 19, 42, 7)), true, NOW)).toBe('19:42:07')
  expect(when(event('wan.wan0.up', {}, new Date(2026, 10, 7, 21, 3, 0)), true, NOW)).toBe('7 Nov 21:03')
})

test('before the clock is synced an event shows the uptime', () => {
  // Until SNTP answers the wall clock is the build's; the time since boot is what is true.
  expect(when(event('wan.wan0.up', {}, NOW, 192_000n), false, NOW)).toBe('up 3m 12s')
  expect(when(event('wan.wan0.up', {}, NOW, 999n), false, NOW)).toBe('up 0s')
})
