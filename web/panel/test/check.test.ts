// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What is wrong with a field as typed, in the words the page shows. An empty field is "not
// set" and is fine here: whether it is needed is the router's to say.

import { expect, test } from 'vitest'

import { address4, address6, addressList, between, cidr4, cidr6, inSubnet, mac, pool } from '../src/model/check'

test('an IPv4 address', () => {
  expect(address4('203.0.113.1')).toBeNull()
  expect(address4('')).toBeNull()
  expect(address4('203.0.113')).toBe('Not an IPv4 address.')
  expect(address4('203.0.113.1/24')).toBe('Not an IPv4 address.')
})

test('an IPv6 address', () => {
  expect(address6('fe80::1')).toBeNull()
  expect(address6('')).toBeNull()
  expect(address6('fe80::zz')).toBe('Not an IPv6 address.')
  expect(address6('203.0.113.1')).toBe('Not an IPv6 address.')
})

test('a list of addresses of either family', () => {
  expect(addressList('203.0.113.1')).toBeNull()
  expect(addressList('203.0.113.1, 2001:db8::53')).toBeNull()
  expect(addressList('203.0.113.1,198.51.100.1')).toBeNull()
  expect(addressList('')).toBeNull()
  expect(addressList('203.0.113.1, dns.example')).toBe('dns.example is not an address.')
  expect(addressList('203.0.113.1,,198.51.100.1')).toBe('One or more addresses, separated by commas.')
  expect(addressList('203.0.113.1,')).toBe('One or more addresses, separated by commas.')
})

test('an address with the size of its subnet', () => {
  expect(cidr4('192.168.1.1/24')).toBeNull()
  expect(cidr4('')).toBeNull()
  expect(cidr4('192.168.1.1')).toBe('An address and a size, such as 192.168.1.1/24.')
  expect(cidr4('192.168.1.1/33')).toBe('An address and a size, such as 192.168.1.1/24.')
})

test('an IPv6 prefix', () => {
  expect(cidr6('2001:db8:1::/48')).toBeNull()
  expect(cidr6('')).toBeNull()
  expect(cidr6('2001:db8:1::')).toBe('A prefix and its length, such as 2001:db8:1::/48.')
  expect(cidr6('192.168.1.0/24')).toBe('A prefix and its length, such as 2001:db8:1::/48.')
})

test('a MAC address', () => {
  expect(mac('02:00:00:aa:01:10')).toBeNull()
  expect(mac('02-00-00-AA-01-10')).toBeNull()
  expect(mac('')).toBeNull()
  expect(mac('02:00:00:aa:01')).toBe('A MAC address is six pairs of hex digits, such as 02:00:00:aa:01:10.')
})

test('a whole number between two bounds', () => {
  expect(between('911', 1, 4094)).toBeNull()
  expect(between('1', 1, 4094)).toBeNull()
  expect(between('4094', 1, 4094)).toBeNull()
  expect(between('', 1, 4094)).toBeNull()
  expect(between('0', 1, 4094)).toBe('1 to 4094.')
  expect(between('4095', 1, 4094)).toBe('1 to 4094.')
  expect(between('9.5', 1, 4094)).toBe('1 to 4094.')
  expect(between('tag', 1, 4094)).toBe('1 to 4094.')
  expect(between('-1', 1, 4094)).toBe('1 to 4094.')
  expect(between(' 5', 1, 4094)).toBe('1 to 4094.')
  expect(between('1e3', 1, 4094)).toBe('1 to 4094.')
  expect(between('47', 48, 64)).toBe('48 to 64.')
})

test('an address a device can have in a LAN', () => {
  expect(inSubnet('192.168.1.20', '192.168.1.1/24')).toBeNull()
  expect(inSubnet('', '192.168.1.1/24')).toBeNull()
  expect(inSubnet('192.168.2.20', '192.168.1.1/24')).toBe('Not in 192.168.1.0/24.')
  expect(inSubnet('192.168.1', '192.168.1.1/24')).toBe('Not an IPv4 address.')
  // The subnet's own first and last address are nobody's.
  expect(inSubnet('192.168.1.0', '192.168.1.1/24')).toBe('Not an address a device can have in 192.168.1.0/24.')
  expect(inSubnet('192.168.1.255', '192.168.1.1/24')).toBe('Not an address a device can have in 192.168.1.0/24.')
  // With no usable LAN address there is nothing to hold it to but its form.
  expect(inSubnet('192.168.2.20', '')).toBeNull()
  expect(inSubnet('192.168.2', 'nonsense')).toBe('Not an IPv4 address.')
})

test('a pool is checked as the router checks it', () => {
  const lan = '192.168.1.1/24'
  expect(pool('192.168.1.100', '192.168.1.200', lan)).toEqual({ start: null, end: null })
  expect(pool('', '', lan)).toEqual({ start: null, end: null })
  // Start after end.
  expect(pool('192.168.1.200', '192.168.1.100', lan)).toEqual({ start: 'The pool starts after it ends.', end: null })
  // An end outside.
  expect(pool('192.168.1.100', '192.168.2.200', lan)).toEqual({ start: null, end: 'Not in 192.168.1.0/24.' })
  expect(pool('192.168.0.100', '192.168.1.200', lan)).toEqual({ start: 'Not in 192.168.1.0/24.', end: null })
  expect(pool('192.168.1', '192.168.1.200', lan)).toEqual({ start: 'Not an IPv4 address.', end: null })
  // The router inside.
  expect(pool('192.168.1.1', '192.168.1.50', lan)).toEqual({ start: "The router's own address, 192.168.1.1, is inside the pool.", end: null })
  expect(pool('192.168.1.100', '192.168.1.200', '192.168.1.150/24')).toEqual({
    start: "The router's own address, 192.168.1.150, is inside the pool.",
    end: null,
  })
  // One address is a pool.
  expect(pool('192.168.1.100', '192.168.1.100', lan)).toEqual({ start: null, end: null })
})
