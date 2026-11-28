// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The views in a real browser against a real router (SPEC §8.3, §8.4, §12; M4 part 3c). The
// harness boots the router and runs this in Chromium inside the lab's LAN namespace,
// answering the test's requests to take the WAN port's carrier away and give it back. One
// test, in order: the routes with the default route as the WAN's; the ports with their
// counters moving; and the log, followed through a cut ISP, filtered by level and by text,
// paused, and downloaded.

import { mkdirSync, readFileSync } from 'node:fs'

import { expect, test } from '@playwright/test'

import { ask } from '../../scripts/labctl.mjs'
import { SHOTS, shots, watch } from './support'

const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''

test('the routes, the ports and the log', async ({ page, baseURL }) => {
  test.setTimeout(240_000)
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  mkdirSync(SHOTS, { recursive: true })
  const router = new URL(baseURL ?? '').host
  const { problems } = watch(page, [router])

  await page.goto('/')
  await page.getByLabel('New password').fill(PASSWORD)
  await page.getByLabel('Repeat password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.locator('.ofo-nav__item .ofo-nav__label')).toHaveText(['Dashboard', 'WAN', 'LAN & DHCP', 'Leases', 'Firewall', 'DNS', 'Routes', 'Ports', 'Logs', 'System'])
  const nav = page.getByRole('navigation', { name: 'Pages' })

  // 1. Routes. The default route is the WAN's, by the ISP's gateway; the LAN's subnet is on
  // its bridge. Nothing here is edited, and no save bar is offered.
  await nav.getByRole('link', { name: 'Routes' }).click()
  await expect(page.getByRole('heading', { name: 'Routes' })).toBeVisible()
  const routes = page.locator('.routes__table tbody tr')
  const byDefault = routes.filter({ has: page.locator('td', { hasText: /^default$/ }) })
  await expect(byDefault).toHaveCount(1)
  await expect(byDefault.locator('td')).toHaveText(['default', '203.0.113.1', 'p0', 'wan0'])
  await expect(routes.filter({ hasText: '192.168.1.0/24' }).locator('td')).toHaveText(['192.168.1.0/24', 'on the link', 'br-lan0', 'lan0'])
  // The kernel's own entries are in the router's answer and not on the page.
  await expect(routes.filter({ hasText: '192.168.1.1/32' })).toHaveCount(0)
  await expect(page.locator('.ofo-savebar')).toHaveCount(0)
  await shots(page, 'views-routes')
  const family = page.getByRole('group', { name: 'Family' })
  await family.getByRole('button', { name: 'IPv6' }).click()
  await expect(family.getByRole('button', { name: 'IPv6' })).toHaveAttribute('aria-pressed', 'true')
  // The other family: no IPv4 route among them, and the link-local ones every interface has
  // are not listed.
  await expect(routes.filter({ hasText: '192.168.1.0/24' })).toHaveCount(0)
  await expect(routes.filter({ hasText: 'fe80::' })).toHaveCount(0)
  await expect(page.locator('.routes__none').or(page.locator('.routes__table'))).toBeVisible()
  await family.getByRole('button', { name: 'IPv4' }).click()
  await expect(byDefault).toHaveCount(1)

  // 2. Ports. The WAN's port is up at the speed QEMU gives it and is the WAN's, a link to
  // where it is given to it; the LAN's port has carried this page, and what it has sent
  // moves when the page fetches something more.
  await nav.getByRole('link', { name: 'Ports' }).click()
  await expect(page.getByRole('heading', { name: 'Ports' })).toBeVisible()
  const ports = page.locator('.ports__table tbody tr')
  const p0 = ports.filter({ has: page.locator('td', { hasText: /^p0$/ }) })
  await expect(p0.locator('td').nth(1)).toHaveText(/Up\s+1000 Mbit\/s/)
  await expect(p0.getByRole('link', { name: 'wan0' })).toHaveAttribute('href', '/wan/wan0')
  await expect(page.locator('.ofo-ports .ofo-port__name').first()).toHaveText('p0')
  const lanPort = ports.filter({ has: page.getByRole('link', { name: 'lan0' }) }).filter({ hasText: 'Up' }).first()
  const sent = lanPort.locator('td').nth(6)
  await expect(sent).toHaveText(/^\d+(\.\d)? (B|kB|MB|GB)$/)
  await expect(sent).not.toHaveText('0 B')
  const before = (await sent.textContent()) ?? ''
  // The notices are some hundreds of kilobytes, sent from the router through that port.
  const fetched = await page.evaluate(async () => (await (await fetch('/licences.txt', { cache: 'no-store' })).text()).length)
  expect(fetched).toBeGreaterThan(100_000)
  await expect.poll(async () => sent.textContent(), { timeout: 15_000 }).not.toBe(before)
  await shots(page, 'views-ports')
  await p0.getByRole('link', { name: 'wan0' }).click()
  await expect(page.getByRole('heading', { name: 'WAN' })).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('heading', { name: 'Ports' })).toBeVisible()

  // 3. Logs. Lines are shown, and the ISP's cut appears among them without a reload.
  await nav.getByRole('link', { name: 'Logs' }).click()
  await expect(page.getByRole('heading', { name: 'Logs' })).toBeVisible()
  const log = page.getByRole('log')
  const show = page.getByRole('group', { name: 'Show' })
  /** How many of the lines shown end with `text`. */
  const saying = async (text: string) => ((await log.textContent()) ?? '').split('\n').filter((line) => line.endsWith(text)).length
  await expect(log).toContainText('admin: password set from 192.168.1.')
  await expect(show.getByRole('button', { name: 'Info' })).toHaveAttribute('aria-pressed', 'true')
  expect(await saying(' link p0 down')).toBe(0)
  await ask('wan-down')
  await expect.poll(() => saying(' link p0 down')).toBe(1)
  await shots(page, 'views-logs')
  // Errors hides it: the line is information.
  await show.getByRole('button', { name: 'Errors' }).click()
  await expect(page.locator('.page')).not.toContainText('link p0 down')
  await expect(page.locator('.page')).not.toContainText('admin: password set')
  // The text finds it, whatever its case, among every line that holds it and no other.
  await show.getByRole('button', { name: 'Info' }).click()
  await page.getByPlaceholder('Filter by text').fill('P0 DOWN')
  await expect.poll(() => saying(' link p0 down')).toBe(1)
  await expect.poll(async () => ((await log.textContent()) ?? '').split('\n').filter((line) => line !== '').every((line) => /p0 down/i.test(line))).toBe(true)
  await page.getByPlaceholder('Filter by text').fill('')
  await expect(log).toContainText('admin: password set from 192.168.1.')
  // Pause holds the view while the ISP comes back, and counts what arrived; Follow shows it.
  const ups = await saying(' link p0 up')
  await page.getByRole('button', { name: 'Pause' }).click()
  await ask('wan-up')
  await expect(page.getByRole('button', { name: /^Follow \(\d+ new\)$/ })).toBeVisible({ timeout: 60_000 })
  expect(await saying(' link p0 up')).toBe(ups)
  await page.getByRole('button', { name: /^Follow/ }).click()
  await expect.poll(() => saying(' link p0 up')).toBe(ups + 1)
  await expect(page.getByRole('button', { name: 'Pause' })).toBeVisible()

  // Download saves the whole log, every level, as a text file named for the router and the
  // time: under the page's content security policy as it stands.
  const downloading = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Download' }).click()
  const file = await downloading
  expect(file.suggestedFilename()).toMatch(/^[a-z0-9-]+-log-\d{8}-\d{6}\.txt$/)
  const saved = readFileSync(await file.path(), 'utf8').split('\n')
  expect(saved.at(-1)).toBe('')
  const lines = saved.slice(0, -1)
  expect(lines.length).toBeGreaterThan(20)
  expect(lines.every((line) => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z (error|warn |info |debug) ./.test(line))).toBe(true)
  expect(lines.some((line) => line.endsWith(' link p0 down'))).toBe(true)
  expect(lines.some((line) => / debug /.test(line))).toBe(true)
  expect(lines.some((line) => line.includes(PASSWORD))).toBe(false)
  await expect(page.locator('.logs__download-failed')).toHaveCount(0)

  expect(problems).toEqual([])
})
