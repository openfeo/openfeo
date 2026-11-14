// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { contains, format4, hostCount, hostRange, isCidr6, isIp6, network, parse4, parseCidr4, parseMac } from '../src/model/ip'

test('an address is read strictly and written back the same', () => {
  expect(parse4('192.168.1.1')).toBe(3232235777)
  expect(format4(3232235777)).toBe('192.168.1.1')
  expect(parse4('0.0.0.0')).toBe(0)
  expect(parse4('255.255.255.255')).toBe(4294967295)
  expect(format4(4294967295)).toBe('255.255.255.255')
  for (const not of ['192.168.01.1', '1.2.3', '1.2.3.4.5', '256.1.1.1', ' 1.2.3.4', '1.2.3.4 ', '1.2.3.', '1..3.4', 'a.b.c.d', '1.2.3.-4', '+1.2.3.4', '']) {
    expect(parse4(not), JSON.stringify(not)).toBeNull()
  }
  for (const text of ['10.0.0.1', '203.0.113.254', '198.51.100.7']) {
    expect(format4(parse4(text) ?? -1)).toBe(text)
  }
})

test('a block knows its network, its hosts and what it holds', () => {
  const lan = parseCidr4('192.168.1.1/24')
  expect(lan).toEqual({ address: 3232235777, prefix: 24 })
  if (lan === null) {
    return
  }
  expect(format4(network(lan))).toBe('192.168.1.0')
  expect(hostCount(24)).toBe(254)
  expect(hostRange(lan).map(format4)).toEqual(['192.168.1.1', '192.168.1.254'])
  expect(contains(lan, parse4('192.168.1.255') ?? 0)).toBe(true)
  expect(contains(lan, parse4('192.168.2.0') ?? 0)).toBe(false)
  expect(contains(lan, parse4('192.168.0.255') ?? 0)).toBe(false)

  expect(hostCount(16)).toBe(65534)
  expect(hostCount(30)).toBe(2)
  expect(hostCount(31)).toBe(0)
  expect(hostCount(32)).toBe(0)
  const half = parseCidr4('192.168.1.129/25')
  expect(half === null ? null : hostRange(half).map(format4)).toEqual(['192.168.1.129', '192.168.1.254'])
  // The top of the address space is still a positive number.
  const top = parseCidr4('255.255.255.1/24')
  expect(top === null ? null : format4(network(top))).toBe('255.255.255.0')
  const all = parseCidr4('10.1.2.3/0')
  expect(all === null ? null : format4(network(all))).toBe('0.0.0.0')
  expect(all === null ? null : contains(all, 4294967295)).toBe(true)

  for (const not of ['192.168.1.1', '192.168.1.1/', '192.168.1.1/33', '192.168.1.1/-1', '192.168.1.1/024', '192.168.1/24', '/24', '192.168.1.1/2 4', '192.168.1.1/24/8']) {
    expect(parseCidr4(not), not).toBeNull()
  }
})

test('a MAC address is read in either case and with either separator', () => {
  expect(parseMac('02:00:00:aa:01:10')).toBe('02:00:00:aa:01:10')
  expect(parseMac('02:00:00:AA:01:10')).toBe('02:00:00:aa:01:10')
  expect(parseMac('02-00-00-AA-01-10')).toBe('02:00:00:aa:01:10')
  for (const not of ['02:00:00:aa:01', '02:00:00:aa:01:10:11', '02:00:00:aa:01:1g', '0200.00aa.0110', '02:00-00:aa:01:10', ' 02:00:00:aa:01:10', '2:0:0:aa:1:10', '']) {
    expect(parseMac(not), JSON.stringify(not)).toBeNull()
  }
})

test('an IPv6 address or prefix is told from what is not one', () => {
  for (const good of ['2001:db8::1', '::', '::1', 'fe80::1', '2001:db8:1:2:3:4:5:6', '2001:db8::', '::ffff:192.0.2.1', '2001:DB8::a']) {
    expect(isIp6(good), good).toBe(true)
  }
  for (const not of ['2001:db8', '2001:db8:::1', '1:2:3:4:5:6:7:8:9', '2001:db8::1::2', '2001:db8::g', '12345::1', '192.0.2.1', '', ' ::1', '::1 ', '1:2:3:4:5:6:7::8']) {
    expect(isIp6(not), JSON.stringify(not)).toBe(false)
  }
  expect(isCidr6('2001:db8:1::/48')).toBe(true)
  expect(isCidr6('2001:db8:1:222::1/64')).toBe(true)
  for (const not of ['2001:db8:1::', '2001:db8:1::/129', '2001:db8:1::/', '2001:db8:1::/4 8', '192.168.1.1/24', '2001:db8:1::/048']) {
    expect(isCidr6(not), not).toBe(false)
  }
})
