// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { clock, duration, portSpeed, rate, since } from '../src/model/format'

test('rates step by a thousand and keep one decimal', () => {
  expect(rate(941_200_000)).toEqual({ value: '941.2', unit: 'Mbit/s' })
  expect(rate(0)).toEqual({ value: '0.0', unit: 'bit/s' })
  expect(rate(999)).toEqual({ value: '999.0', unit: 'bit/s' })
  expect(rate(1_000)).toEqual({ value: '1.0', unit: 'kbit/s' })
  expect(rate(38_240_000)).toEqual({ value: '38.2', unit: 'Mbit/s' })
  expect(rate(2_500_000_000)).toEqual({ value: '2.5', unit: 'Gbit/s' })
  expect(rate(40_000_000_000_000)).toEqual({ value: '40000.0', unit: 'Gbit/s' })
})

test('a rate that rounds up to a thousand moves to the next unit', () => {
  // 999.96 kbit/s to one decimal is 1000.0: that is 1.0 Mbit/s, not "1000.0 kbit/s".
  expect(rate(999_960)).toEqual({ value: '1.0', unit: 'Mbit/s' })
  expect(rate(999_949)).toEqual({ value: '999.9', unit: 'kbit/s' })
})

test('a rate that is not a finite number is a dash', () => {
  expect(rate(Number.NaN).value).toBe('—')
  expect(rate(Number.POSITIVE_INFINITY).value).toBe('—')
  expect(rate(-5).value).toBe('—')
})

test('durations name their two largest units', () => {
  expect(duration(273_600)).toBe('3d 4h')
  expect(duration(42)).toBe('42s')
  expect(duration(0)).toBe('0s')
  expect(duration(725)).toBe('12m 5s')
  expect(duration(15_120)).toBe('4h 12m')
  expect(duration(60)).toBe('1m 0s')
  expect(duration(86_400)).toBe('1d 0h')
  expect(duration(-3)).toBe('0s')
  expect(duration(Number.NaN)).toBe('0s')
  expect(duration(59.9)).toBe('59s')
})

test('a time today is a clock, another day carries its date', () => {
  const now = new Date(2026, 10, 10, 19, 42, 30)
  expect(clock(BigInt(new Date(2026, 10, 10, 19, 42, 7).getTime()), now)).toBe('19:42:07')
  expect(clock(BigInt(new Date(2026, 10, 10, 0, 0, 0).getTime()), now)).toBe('00:00:00')
  expect(clock(BigInt(new Date(2026, 10, 7, 21, 3, 59).getTime()), now)).toBe('7 Nov 21:03')
  expect(clock(BigInt(new Date(2025, 10, 10, 9, 5, 0).getTime()), now)).toBe('10 Nov 09:05')
})

test('since when is a date and a time, today or not', () => {
  expect(since(BigInt(new Date(2026, 10, 7, 9, 14, 22).getTime()))).toBe('7 Nov 09:14')
  expect(since(BigInt(new Date(2026, 0, 31, 23, 59, 59).getTime()))).toBe('31 Jan 23:59')
})

test('a port says its speed, a dash without a cable, and up when the driver does not say', () => {
  expect(portSpeed({ carrier: false, speedMbps: 1000 })).toBe('—')
  expect(portSpeed({ carrier: false })).toBe('—')
  expect(portSpeed({ carrier: true })).toBe('up')
  expect(portSpeed({ carrier: true, speedMbps: 0 })).toBe('up')
  expect(portSpeed({ carrier: true, speedMbps: 10 })).toBe('10M')
  expect(portSpeed({ carrier: true, speedMbps: 100 })).toBe('100M')
  expect(portSpeed({ carrier: true, speedMbps: 1000 })).toBe('1G')
  expect(portSpeed({ carrier: true, speedMbps: 2500 })).toBe('2.5G')
  expect(portSpeed({ carrier: true, speedMbps: 10_000 })).toBe('10G')
  expect(portSpeed({ carrier: true, speedMbps: 25_000 })).toBe('25G')
})
