// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from 'vitest'

import { bytes, clock, countdown, duration, durationWords, hourMinute, portSpeed, rate, since } from '../src/model/format'

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

test('a length of time in words is the largest unit that divides it', () => {
  expect(durationWords(120)).toBe('2 minutes')
  expect(durationWords(60)).toBe('1 minute')
  expect(durationWords(40)).toBe('40 seconds')
  expect(durationWords(90)).toBe('90 seconds')
  expect(durationWords(43200)).toBe('12 hours')
  expect(durationWords(86400)).toBe('1 day')
  expect(durationWords(604800)).toBe('1 week')
  expect(durationWords(3600)).toBe('1 hour')
  expect(durationWords(1)).toBe('1 second')
  expect(durationWords(1209600)).toBe('2 weeks')
  expect(durationWords(172800)).toBe('2 days')
  expect(durationWords(0)).toBe('0 seconds')
})

test('the time left is minutes and seconds, and never less than none', () => {
  expect(countdown(107_000)).toBe('1:47')
  expect(countdown(5_000)).toBe('0:05')
  expect(countdown(60_000)).toBe('1:00')
  expect(countdown(600_000)).toBe('10:00')
  // A part of a second is still time left.
  expect(countdown(400)).toBe('0:01')
  expect(countdown(0)).toBe('0:00')
  expect(countdown(-30_000)).toBe('0:00')
  expect(countdown(Number.NaN)).toBe('0:00')
})

test('a time of day is hours and minutes', () => {
  expect(hourMinute(new Date(2026, 10, 10, 22, 41, 59))).toBe('22:41')
  expect(hourMinute(new Date(2026, 10, 10, 9, 5, 0))).toBe('09:05')
})

test('bytes are said by thousands with one decimal', () => {
  expect(bytes(0n)).toBe('0 B')
  expect(bytes(999n)).toBe('999 B')
  expect(bytes(1_000n)).toBe('1.0 kB')
  expect(bytes(38_100_000n)).toBe('38.1 MB')
  expect(bytes(412_800_000_000n)).toBe('412.8 GB')
  expect(bytes(7_240_000_000_000n)).toBe('7.2 TB')
  // A count that rounds up to a thousand moves to the next unit, and there is none past TB.
  expect(bytes(999_960n)).toBe('1.0 MB')
  expect(bytes(2_500_000_000_000_000n)).toBe('2500.0 TB')
})

