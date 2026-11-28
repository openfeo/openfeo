// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The Logs page (SPEC §8.4), in the shell at /logs: what the router wrote down, as it writes
// it. The router answers the past by a level and a text; what arrives after is matched here
// by the same rule.

import { create, ErrorCode, LogBatchSchema, LogLevel, LogLineSchema, LogsResponseSchema, RouterError, type LogLine, type LogsResponse } from '@openfeo/client'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

import { fileLine, fileName } from '../src/model/logs'
import { SAVE } from '../src/save'
import type { FakeRouter, LogsAsk } from './fake-router'
import { NOW, state } from './fixtures'
import { panelAt, signedIn, unmountAll } from './mounting'

/** The router's two clocks when the browser's says NOW: it has been up ten minutes. */
const CLOCKS = { uptimeMs: 600_000n, timeUnixMs: BigInt(NOW.getTime()) }

/** A line written `agoMs` before the clocks were read. */
const line = (seq: number, text: string, level = LogLevel.INFO, agoMs = 0): LogLine =>
  create(LogLineSchema, { seq: BigInt(seq), uptimeMs: CLOCKS.uptimeMs - BigInt(agoMs), level, text })
const answer = (lines: LogLine[], earlier = false): LogsResponse => create(LogsResponseSchema, { lines, earlier, ...CLOCKS })
const batch = (lines: LogLine[]) => create(LogBatchSchema, { lines, ...CLOCKS })

const LINES = [
  line(38, 'pppoe wan0: 3 echoes unanswered, ending the session', LogLevel.WARN, 120_000),
  line(39, 'wan0: down (the ISP stopped answering)', LogLevel.INFO, 120_000),
  line(41, 'sntp: no answer from 203.0.113.1, trying the next server', LogLevel.ERROR, 60_000),
  line(42, 'admin: login from 192.168.1.142', LogLevel.INFO, 0),
]

async function page(prepare: (router: FakeRouter) => void = () => undefined) {
  const router = signedIn()
  router.logsNow = () => answer(LINES)
  prepare(router)
  const saved: [name: string, text: string][] = []
  const made = await panelAt('/logs', router, { [SAVE as symbol]: (name: string, text: string) => saved.push([name, text]) })
  router.push('state', state())
  await flushPromises()
  return { ...made, saved }
}

const two = (n: number) => String(n).padStart(2, '0')
/** A time of day as the page writes it, in this machine's zone. */
const hms = (agoMs = 0) => {
  const at = new Date(NOW.getTime() - agoMs)
  return `${two(at.getHours())}:${two(at.getMinutes())}:${two(at.getSeconds())}`
}
/** What the log shows, line by line. */
const shown = (wrapper: VueWrapper) => (wrapper.find('.ofo-code').element.textContent ?? '').split('\n').slice(0, -1)
/** The same without the times: the level and the text of each line. */
const texts = (wrapper: VueWrapper) => shown(wrapper).map((each) => each.replace(/^\d\d:\d\d:\d\d /, ''))
const button = (wrapper: VueWrapper, label: RegExp | string) => {
  const found = wrapper.findAll('.page button').find((each) => (typeof label === 'string' ? each.text() === label : label.test(each.text())))
  if (found === undefined) {
    throw new Error(`no button ${String(label)}`)
  }
  return found
}
const level = (wrapper: VueWrapper, label: string) => {
  const found = wrapper.findAll('.ofo-seg button').find((each) => each.text() === label)
  if (found === undefined) {
    throw new Error(`no level ${label}`)
  }
  return found
}
const box = (wrapper: VueWrapper) => wrapper.find('.logs__filter')
/** A promise a test settles when it chooses. */
function later<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((yes) => {
    resolve = yes
  })
  return { promise, resolve }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})
afterEach(() => {
  unmountAll()
  vi.useRealTimers()
})

test('the page opens at Info, following', async () => {
  let subscribedWhenAsked = -1
  const { wrapper, router, errors } = await page((fake) => {
    fake.logsNow = () => {
      subscribedWhenAsked = fake.open('logs').length
      return answer(LINES)
    }
  })
  expect(wrapper.find('h1').text()).toBe('Logs')
  expect(wrapper.find('.ofo-pagehead').text()).toContain('What the router wrote down, as it writes it.')
  const show = wrapper.find('.ofo-seg')
  expect(show.attributes('aria-label')).toBe('Show')
  expect(show.findAll('button').map((each) => [each.text(), each.attributes('aria-pressed')])).toEqual([
    ['Errors', 'false'],
    ['Warnings', 'false'],
    ['Info', 'true'],
    ['Debug', 'false'],
  ])
  expect(box(wrapper).attributes('placeholder')).toBe('Filter by text')
  expect(button(wrapper, 'Pause').exists()).toBe(true)
  expect(button(wrapper, 'Download').exists()).toBe(true)
  // One question, asked once the subscription was made: nothing written between the two is missed.
  expect(router.calls.logs).toEqual([{ level: LogLevel.INFO, contains: '', limit: 200 }])
  expect(subscribedWhenAsked).toBe(1)
  // Each line: its time, its level as a word, its text.
  expect(shown(wrapper)).toEqual([
    `${hms(120_000)} warn  pppoe wan0: 3 echoes unanswered, ending the session`,
    `${hms(120_000)} info  wan0: down (the ISP stopped answering)`,
    `${hms(60_000)} error sntp: no answer from 203.0.113.1, trying the next server`,
    `${hms()} info  admin: login from 192.168.1.142`,
  ])
  // The times are quiet, a warning and an error are coloured, and nothing else is.
  const code = wrapper.find('.ofo-code')
  expect(code.findAll('.ofo-code__dim')).toHaveLength(4)
  expect(code.findAll('.ofo-code__warn').map((each) => each.text())).toEqual(['warn'])
  expect(code.findAll('.ofo-code__err').map((each) => each.text())).toEqual(['error'])
  expect(code.findAll('.ofo-code__ok')).toHaveLength(0)
  expect([code.attributes('role'), code.classes().includes('ofo-code--wrap')]).toEqual(['log', true])
  expect(wrapper.find('.logs__note').text()).toBe(
    'Following: new lines appear at the bottom. Pause holds the view still while you read. The router keeps about the last 8 MiB in memory, so a restart clears it.',
  )
  expect(wrapper.find('.ofo-savebar').exists()).toBe(false)
  expect(errors).toEqual([])
})

test('a line’s time is counted back from the router’s two clocks', async () => {
  // The router booted with its clock a year out and SNTP set it since: its stamps are times
  // since boot, and the clocks it sends now place them.
  const { wrapper, router } = await page((fake) => {
    fake.logsNow = () => answer([line(1, 'router mode=vm', LogLevel.INFO, 599_000), line(2, 'time: clock set', LogLevel.INFO, 30_000)])
  })
  expect(shown(wrapper)).toEqual([`${hms(599_000)} info  router mode=vm`, `${hms(30_000)} info  time: clock set`])
  // A batch brings newer clocks; what is on screen is placed by them from then on.
  const later = { uptimeMs: 660_000n, timeUnixMs: BigInt(NOW.getTime() + 60_000) }
  router.push('logs', create(LogBatchSchema, { lines: [create(LogLineSchema, { seq: 3n, uptimeMs: 660_000n, level: LogLevel.INFO, text: 'link p0 down' })], ...later }))
  await flushPromises()
  expect(shown(wrapper)).toEqual([`${hms(599_000)} info  router mode=vm`, `${hms(30_000)} info  time: clock set`, `${hms(-60_000)} info  link p0 down`])
})

test('a line that arrives is shown if it matches', async () => {
  const { wrapper, router } = await page()
  router.push('logs', batch([line(43, 'apply links ops=3', LogLevel.DEBUG), line(44, 'link p0 down', LogLevel.INFO), line(45, 'counters: cannot be read', LogLevel.WARN)]))
  await flushPromises()
  expect(texts(wrapper).slice(4)).toEqual(['info  link p0 down', 'warn  counters: cannot be read'])
  // With a text typed, only the lines that hold it, whatever their case.
  router.logsNow = () => answer([])
  await box(wrapper).setValue('P0')
  vi.advanceTimersByTime(300)
  await flushPromises()
  router.push('logs', batch([line(46, 'link p0 up', LogLevel.INFO), line(47, 'link p1 up', LogLevel.INFO)]))
  await flushPromises()
  expect(texts(wrapper)).toEqual(['info  link p0 up'])
})

test('text is text: markup in a line is shown, not made', async () => {
  const { wrapper } = await page((fake) => {
    fake.logsNow = () => answer([line(1, 'dhcp lan0: leased to <img src=x onerror=alert(1)>')])
  })
  expect(texts(wrapper)).toEqual(['info  dhcp lan0: leased to <img src=x onerror=alert(1)>'])
  expect(wrapper.find('.ofo-code img').exists()).toBe(false)
})

test('choosing a level asks the router again', async () => {
  const { wrapper, router } = await page()
  router.logsNow = (ask) => answer(LINES.filter((each) => each.level <= (ask.level ?? LogLevel.DEBUG)))
  await level(wrapper, 'Errors').trigger('click')
  await flushPromises()
  expect(router.calls.logs.at(-1)).toEqual({ level: LogLevel.ERROR, contains: '', limit: 200 })
  expect(router.calls.logs).toHaveLength(2)
  expect(texts(wrapper)).toEqual(['error sntp: no answer from 203.0.113.1, trying the next server'])
  expect(level(wrapper, 'Errors').attributes('aria-pressed')).toBe('true')
  await level(wrapper, 'Warnings').trigger('click')
  await flushPromises()
  expect(router.calls.logs.at(-1)?.level).toBe(LogLevel.WARN)
  await level(wrapper, 'Debug').trigger('click')
  await flushPromises()
  expect(router.calls.logs.at(-1)?.level).toBe(LogLevel.DEBUG)
})

test('typed text is asked for after a pause', async () => {
  const { wrapper, router } = await page()
  await box(wrapper).setValue('p')
  vi.advanceTimersByTime(100)
  await box(wrapper).setValue('pp')
  vi.advanceTimersByTime(100)
  await box(wrapper).setValue(' pppoe ')
  vi.advanceTimersByTime(299)
  await flushPromises()
  expect(router.calls.logs).toHaveLength(1)
  vi.advanceTimersByTime(1)
  await flushPromises()
  expect(router.calls.logs).toHaveLength(2)
  expect(router.calls.logs.at(-1)).toEqual({ level: LogLevel.INFO, contains: 'pppoe', limit: 200 })
  // A change that is only spaces at its ends asks nothing.
  await box(wrapper).setValue('pppoe   ')
  vi.advanceTimersByTime(300)
  await flushPromises()
  expect(router.calls.logs).toHaveLength(2)
  // Cleared: every line again.
  await box(wrapper).setValue('')
  vi.advanceTimersByTime(300)
  await flushPromises()
  expect(router.calls.logs.at(-1)).toEqual({ level: LogLevel.INFO, contains: '', limit: 200 })
})

test('an answer to a filter since changed is dropped', async () => {
  const { wrapper, router } = await page()
  const initial = texts(wrapper)
  // Whichever way round the two answers come, only the one to the newest question is shown.
  for (const oldFirst of [true, false]) {
    const errors = later<LogsResponse>()
    const debug = later<LogsResponse>()
    router.logsNow = (ask) => (ask.level === LogLevel.ERROR ? errors.promise : debug.promise)
    await level(wrapper, 'Errors').trigger('click')
    await level(wrapper, 'Debug').trigger('click')
    await flushPromises()
    const before = texts(wrapper)
    const settle = [
      () => errors.resolve(answer([LINES[2]!])),
      () => debug.resolve(answer([line(50, oldFirst ? 'apply links ops=3' : 'apply links ops=4', LogLevel.DEBUG)])),
    ]
    const [first, second] = oldFirst ? settle : [settle[1]!, settle[0]!]
    first?.()
    await flushPromises()
    // The answer to a question nobody is asking any more changes nothing, early or late.
    expect(texts(wrapper), `old first: ${String(oldFirst)}`).toEqual(oldFirst ? before : [`debug apply links ops=4`])
    second?.()
    await flushPromises()
    expect(texts(wrapper), `old first: ${String(oldFirst)}`).toEqual([oldFirst ? 'debug apply links ops=3' : 'debug apply links ops=4'])
  }
  expect(initial).toHaveLength(4)
})

test('a line that came by both roads is shown once', async () => {
  const first = later<LogsResponse>()
  const { wrapper, router } = await page((fake) => {
    fake.logsNow = () => first.promise
  })
  expect(wrapper.find('.logs__waiting').exists()).toBe(true)
  // The subscription is open and the answer is on its way: lines arrive meanwhile.
  router.push('logs', batch([line(42, 'admin: login from 192.168.1.142'), line(43, 'link p0 down'), line(44, 'apply links ops=1', LogLevel.DEBUG)]))
  first.resolve(answer(LINES))
  await flushPromises()
  expect(texts(wrapper).slice(3)).toEqual(['info  admin: login from 192.168.1.142', 'info  link p0 down'])
})

test('Earlier lines fetches the ones before', async () => {
  const { wrapper, router } = await page((fake) => {
    fake.logsNow = (ask) => (ask.beforeSeq === undefined ? answer(LINES, true) : answer([line(30, 'link p0 up'), line(31, 'wan0: up, 203.0.113.100')], false))
  })
  await button(wrapper, 'Earlier lines').trigger('click')
  await flushPromises()
  expect(router.calls.logs.at(-1)).toEqual({ level: LogLevel.INFO, contains: '', limit: 200, beforeSeq: 38n })
  expect(texts(wrapper).slice(0, 3)).toEqual(['info  link p0 up', 'info  wan0: up, 203.0.113.100', 'warn  pppoe wan0: 3 echoes unanswered, ending the session'])
  // No more before these: the button goes. The reader is looking back, so the view holds still.
  expect(wrapper.findAll('.page button').some((each) => each.text() === 'Earlier lines')).toBe(false)
  expect(button(wrapper, 'Follow').exists()).toBe(true)
})

test('at two thousand lines the page says where the rest is', async () => {
  const many = Array.from({ length: 2000 }, (_, n) => line(n + 100, `line ${String(n)}`))
  const { wrapper } = await page((fake) => {
    fake.logsNow = () => answer(many, true)
  })
  expect(shown(wrapper)).toHaveLength(2000)
  expect(wrapper.findAll('.page button').some((each) => each.text() === 'Earlier lines')).toBe(false)
  expect(wrapper.find('.logs__earlier').text()).toBe('Download has the rest.')
})

test('Pause holds the view and counts what arrives', async () => {
  const { wrapper, router } = await page()
  await button(wrapper, 'Pause').trigger('click')
  expect(button(wrapper, 'Follow').exists()).toBe(true)
  router.push('logs', batch([line(43, 'link p0 down'), line(44, 'apply links ops=1', LogLevel.DEBUG)]))
  router.push('logs', batch([line(45, 'wan0: down (no carrier)')]))
  await flushPromises()
  expect(texts(wrapper)).toHaveLength(4)
  // Only what would be shown is counted.
  expect(button(wrapper, /^Follow/).text()).toBe('Follow (2 new)')
  await button(wrapper, /^Follow/).trigger('click')
  expect(texts(wrapper).slice(4)).toEqual(['info  link p0 down', 'info  wan0: down (no carrier)'])
  expect(button(wrapper, 'Pause').exists()).toBe(true)
  // And following again, a line is shown as it comes.
  router.push('logs', batch([line(46, 'link p0 up')]))
  await flushPromises()
  expect(texts(wrapper).at(-1)).toBe('info  link p0 up')
})

test('what waits while paused is bounded', async () => {
  const { wrapper, router } = await page()
  await button(wrapper, 'Pause').trigger('click')
  for (let from = 0; from < 2500; from += 250) {
    router.push('logs', batch(Array.from({ length: 250 }, (_, n) => line(100 + from + n, `line ${String(from + n)}`))))
  }
  await flushPromises()
  expect(button(wrapper, /^Follow/).text()).toBe('Follow (2000 new)')
  await button(wrapper, /^Follow/).trigger('click')
  const lines = texts(wrapper)
  // The page never holds more than two thousand lines, and the newest are the ones kept. The
  // top of the page is where what is kept ends, and it says where the rest is.
  expect(lines).toHaveLength(2000)
  expect(lines[0]).toBe('info  line 500')
  expect(lines.at(-1)).toBe('info  line 2499')
  expect(wrapper.find('.logs__earlier').text()).toBe('Download has the rest.')
})

test('a loss told by the router is marked where it happened', async () => {
  const { wrapper, router } = await page()
  router.push('logs', batch([line(43, 'link p0 down')]))
  router.lose('logs')
  router.push('logs', batch([line(900, 'link p0 up')]))
  await flushPromises()
  expect(texts(wrapper).slice(4)).toEqual(['info  link p0 down', 'Some lines were skipped here.', 'info  link p0 up'])
  expect(wrapper.find('.ofo-code').findAll('.ofo-code__dim').at(-2)?.text()).toBe('Some lines were skipped here.')
  // While paused, the mark keeps its place among what waits.
  await button(wrapper, 'Pause').trigger('click')
  router.push('logs', batch([line(901, 'a')]))
  router.lose('logs')
  router.push('logs', batch([line(950, 'b')]))
  await flushPromises()
  await button(wrapper, /^Follow/).trigger('click')
  expect(texts(wrapper).slice(-3)).toEqual(['info  a', 'Some lines were skipped here.', 'info  b'])
})

test('Download saves the whole log whatever the filter', async () => {
  const pages = new Map<bigint, LogsResponse>([
    [0n, answer([line(5, 'e', LogLevel.DEBUG), line(6, 'f', LogLevel.ERROR, 0)], true)],
    [5n, answer([line(3, 'c', LogLevel.WARN, 30_000), line(4, 'd')], true)],
    [3n, answer([line(1, 'a', LogLevel.INFO, 599_000), line(2, 'b', LogLevel.DEBUG, 598_000)], false)],
  ])
  const whole = [1, 2, 3, 4, 5, 6].flatMap((seq) => [...pages.values()].flatMap((each) => each.lines).filter((each) => each.seq === BigInt(seq)))
  const { wrapper, router, saved } = await page()
  router.logsNow = (ask) => (ask.limit === 0 ? (pages.get(ask.beforeSeq ?? 0n) ?? answer([])) : answer(LINES))
  await level(wrapper, 'Errors').trigger('click')
  await box(wrapper).setValue('sntp')
  vi.advanceTimersByTime(300)
  await flushPromises()
  const before = router.calls.logs.length
  const release = router.holdCall('logs')
  await button(wrapper, 'Download').trigger('click')
  await flushPromises()
  // While it runs the button is held, and says so.
  expect(button(wrapper, 'Downloading…').attributes('disabled')).toBeDefined()
  release()
  await flushPromises()
  // Every level and no text, a page at a time back to the first line.
  expect(router.calls.logs.slice(before)).toEqual<LogsAsk[]>([
    { limit: 0 },
    { limit: 0, beforeSeq: 5n },
    { limit: 0, beforeSeq: 3n },
  ])
  expect(saved).toHaveLength(1)
  expect(saved[0]?.[0]).toBe(fileName('openfeo', NOW))
  expect(saved[0]?.[1]).toBe(whole.map((each) => `${fileLine(each, CLOCKS)}\n`).join(''))
  expect(saved[0]?.[1].split('\n')).toHaveLength(7)
  expect(button(wrapper, 'Download').attributes('disabled')).toBeUndefined()
  // What is on screen is what it was.
  expect(level(wrapper, 'Errors').attributes('aria-pressed')).toBe('true')
})

test('a download that fails says so and saves nothing', async () => {
  const { wrapper, router, saved } = await page()
  router.logsNow = () => new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
  await button(wrapper, 'Download').trigger('click')
  await flushPromises()
  expect(wrapper.find('.logs__download-failed').text()).toContain('The log could not be downloaded.')
  expect(saved).toEqual([])
  // The next one that works takes the sentence away.
  router.logsNow = () => answer([line(1, 'a')])
  await button(wrapper, 'Download').trigger('click')
  await flushPromises()
  expect(wrapper.find('.logs__download-failed').exists()).toBe(false)
  expect(saved).toHaveLength(1)
})

test('a log that cannot be read says so', async () => {
  const { wrapper, router } = await page((fake) => {
    fake.logsNow = () => new RouterError(ErrorCode.UNAVAILABLE, 'the connection to the router was lost')
  })
  expect(wrapper.find('.logs__failed').text()).toContain('The log could not be read from the router.')
  expect(wrapper.find('.ofo-code').exists()).toBe(false)
  router.logsNow = () => answer(LINES)
  await button(wrapper, 'Try again').trigger('click')
  await flushPromises()
  expect(wrapper.find('.logs__failed').exists()).toBe(false)
  expect(texts(wrapper)).toHaveLength(4)
})

test('nothing matches', async () => {
  const { wrapper } = await page((fake) => {
    fake.logsNow = () => answer([])
  })
  expect(wrapper.find('.logs__none').text()).toBe('No lines match.')
  expect(wrapper.find('.ofo-code').exists()).toBe(false)
})

test('leaving the page ends the subscription', async () => {
  const { wrapper, router, routes } = await page()
  expect(router.open('logs')).toHaveLength(1)
  await routes.push('/')
  await flushPromises()
  expect(router.open('logs')).toHaveLength(0)
  expect(wrapper.find('h1').text()).toBe('Dashboard')
})
