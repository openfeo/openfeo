// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Status and leases in a real browser against a real router (SPEC §7.6, §8.4, §10, §12). The
// harness boots the router, lets it run a while before anyone looks, and runs this in
// Chromium inside the lab's LAN namespace, answering the test's requests to have a device
// join the LAN and to take the WAN port's carrier away and give it back. One test, in order:
// the chart drawn back to before the page was opened, a device that joins, the Leases page,
// a reservation made from it and confirmed, and the mark where the WAN came back.

import { mkdirSync } from 'node:fs'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { ask } from '../../scripts/labctl.mjs'
import { SHOTS, shots, watch } from './support'

const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''

const bar = (page: Page) => page.locator('.ofo-savebar')
const pending = (page: Page) => page.locator('.pending')
const dialog = (page: Page) => page.getByRole('alertdialog')

/** How many seconds of its five-minute range a chart's download line spans. */
async function drawnSecs(chart: Locator): Promise<number> {
  const path = (await chart.locator('path.line.rx').getAttribute('d')) ?? ''
  const across = [...path.matchAll(/[ML]([\d.]+) /g)].map((point) => Number(point[1]))
  const box = ((await chart.locator('svg').getAttribute('viewBox')) ?? '').split(' ')
  // The plot is the box less the room for the scale's labels.
  const plot = Number(box[2]) - 48
  return across.length < 2 || !(plot > 0) ? 0 : ((Math.max(...across) - Math.min(...across)) / plot) * 300
}

test('the hour and the leases, from the dashboard to a reservation', async ({ page, baseURL }) => {
  test.setTimeout(300_000)
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  mkdirSync(SHOTS, { recursive: true })
  const router = new URL(baseURL ?? '').host
  const { problems } = watch(page, [router])
  // Leaving a page with changes asks first; this test leaves none behind.
  page.on('dialog', (asked) => void (asked.type() === 'beforeunload' ? asked.accept() : asked.dismiss()))

  // 1. Set the password. The dashboard has a chart for the WAN, and it is drawn back to
  // before this page was opened: the router had been reading its counters all along.
  await page.goto('/')
  await page.getByLabel('New password').fill(PASSWORD)
  await page.getByLabel('Repeat password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.locator('.ofo-nav__item .ofo-nav__label')).toHaveText(['Dashboard', 'WAN', 'LAN & DHCP', 'Leases'])
  const chart = page.locator('.ofo-chart', { has: page.locator('h2', { hasText: /^wan0$/ }) })
  await expect(chart.locator('svg')).toHaveAttribute('aria-label', 'Download and upload on wan0 over the last hour')
  await expect(chart.getByRole('button', { name: '1 h' })).toHaveAttribute('aria-pressed', 'true')
  await chart.getByRole('button', { name: '5 min' }).click()
  await expect(chart.locator('svg')).toHaveAttribute('aria-label', 'Download and upload on wan0 over the last five minutes')
  // Fifteen seconds of line within a few seconds of the page opening cannot be the live samples.
  await expect.poll(() => drawnSecs(chart), { timeout: 8_000 }).toBeGreaterThanOrEqual(15)
  await expect(chart.locator('.ofo-chart__note')).toHaveCount(0)
  await expect(chart.locator('.ofo-chart__tick').first()).toHaveText(/^\d\d:\d\d$/)
  // What is now is in the legend once two live samples are in, and the hour's peak under the tile.
  await expect(chart.locator('.ofo-chart__key--rx b')).toHaveText(/^\d+\.\d$/, { timeout: 15_000 })
  await expect(page.locator('.ofo-stat').first().locator('.ofo-stat__foot')).toHaveText(/^peak \d+\.\d [kMG]?bit\/s in the last hour$/, { timeout: 15_000 })
  await shots(page, 'status-dashboard')

  // 2. No device has taken an address yet. One joins: it is there without a reload, marked.
  const newest = page.locator('.ofo-card', { has: page.locator('.ofo-card__title', { hasText: /^Newest leases$/ }) })
  await expect(newest).toContainText('No device has taken an address yet.')
  await page.evaluate(() => {
    ;(window as unknown as { openfeoMark?: number }).openfeoMark = 1
  })
  await ask('join plug-kitchen')
  const joined = newest.locator('tbody tr').filter({ hasText: 'plug-kitchen' })
  await expect(joined).toBeVisible({ timeout: 15_000 })
  await expect(joined).toHaveClass(/ofo-table__row--new/)
  await expect(joined.locator('td').first()).toHaveText('just now')
  await expect(joined.locator('td').nth(1)).toHaveText(/^192\.168\.1\.(1\d\d|200)$/)
  await expect(joined.locator('td').nth(4)).toHaveText('lan0')
  expect(await page.evaluate(() => (window as unknown as { openfeoMark?: number }).openfeoMark)).toBe(1)
  await shots(page, 'status-dashboard-joined')
  await newest.getByRole('link', { name: '1 lease' }).click()

  // 3. The Leases page has it, with when it expires; the filter narrows the table.
  await expect(page.getByRole('heading', { name: 'Leases' })).toBeVisible()
  await expect(page).toHaveURL(/\/leases$/)
  const lease = page.locator('.leases__table tbody tr').filter({ hasText: 'plug-kitchen' })
  await expect(lease).toHaveCount(1)
  await expect(lease.locator('td').nth(5)).toHaveText(/^in 11 h 5\d min$/)
  await expect(lease.locator('td').first().locator('span')).toHaveAttribute('title', /^\d\d:\d\d:\d\d$/)
  // One LAN hands out addresses here: there is no choice of LAN to make.
  await expect(page.locator('.leases__tools .ofo-seg')).toHaveCount(0)
  const filter = page.getByPlaceholder('Filter by name, address or MAC')
  await filter.fill('zzz')
  await expect(page.locator('.leases__table tbody tr')).toHaveText(['No leases match zzz'])
  await filter.fill('KITCHEN')
  await expect(lease).toHaveCount(1)
  await filter.fill('')
  await expect(page.locator('.leases__help')).toContainText('name.home.arpa')
  await shots(page, 'leases')

  // 4. Reserve: it joins the changes, is applied and confirmed, and the row says Reserved.
  await lease.getByRole('button', { name: 'Reserve' }).click()
  await expect(lease.locator('.ofo-pill')).toHaveText('Reserved, not applied yet')
  await expect(bar(page)).toContainText('1 change not applied yet')
  await shots(page, 'leases-reserving')
  await bar(page).getByRole('button', { name: 'Apply changes' }).click()
  await expect(dialog(page)).toBeVisible()
  await expect(dialog(page).locator('.ofo-dialog__title')).toHaveText('Apply 1 change to openfeo?')
  await expect(dialog(page).locator('.ofo-changes')).toContainText('lan0 reservations')
  await expect(dialog(page).locator('.ofo-changes')).toContainText('1 added')
  await dialog(page).getByRole('button', { name: 'Apply changes' }).click()
  await expect(dialog(page)).toHaveCount(0)
  await expect(pending(page)).toBeVisible()
  await pending(page).getByRole('button', { name: 'Confirm' }).click()
  await expect(pending(page)).toHaveCount(0)
  await expect(bar(page)).toHaveCount(0)
  // The LAN's server restarted twice on the way, and the lease is still the one that joined.
  await expect(lease.locator('.ofo-pill')).toHaveText('Reserved')
  await expect(lease.locator('td').first()).toHaveText(/^(just now|\d min ago)$/)
  await shots(page, 'leases-reserved')
  // The reservation is on LAN & DHCP, where reservations live.
  await page.getByRole('link', { name: 'LAN & DHCP' }).click()
  await expect(page.locator('table.res tbody tr').last().locator('input').nth(0)).toHaveValue('plug-kitchen')

  // 5. The ISP goes and comes back: the chart marks where.
  await page.getByRole('link', { name: 'Dashboard' }).click()
  const wan = page.locator('.ofo-iface', { has: page.locator('.ofo-iface__name', { hasText: /^wan0$/ }) })
  await expect(wan.locator('.ofo-pill')).toHaveText('Up')
  await ask('wan-down')
  await expect(wan.locator('.ofo-pill')).toHaveText('Down', { timeout: 20_000 })
  await ask('wan-up')
  await expect(wan.locator('.ofo-pill')).toHaveText('Up', { timeout: 90_000 })
  // (The hour also holds the WAN's first coming up, when the router started.)
  await expect(chart.locator('g.event text')).toHaveText([/^up \d\d:\d\d$/, /^reconnected \d\d:\d\d$/], { timeout: 15_000 })
  await shots(page, 'status-dashboard-reconnected')

  expect(problems).toEqual([])
})
