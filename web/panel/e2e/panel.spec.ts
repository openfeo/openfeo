// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The panel in a real browser against a real router (SPEC §11, §12). The harness runs this in
// Chromium inside the lab's LAN namespace, reaching the booted VM by its name, and answers
// the test's requests to take the WAN port's carrier away and give it back. One test, one
// page, in order: a person's first evening with the router.

import { mkdirSync } from 'node:fs'

import { expect, test, type Page } from '@playwright/test'

import { ask } from '../../scripts/labctl.mjs'

const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''
const FINGERPRINT = process.env.OPENFEO_FINGERPRINT ?? ''
const SHOTS = process.env.OPENFEO_SHOTS ?? 'e2e-out/shots'

/** A screenshot of the page as it stands, in both themes: the panel follows the system until told. */
async function shots(page: Page, name: string): Promise<void> {
  for (const theme of ['dark', 'light'] as const) {
    await page.emulateMedia({ colorScheme: theme })
    await page.screenshot({ path: `${SHOTS}/${name}-${theme}.png`, fullPage: true })
  }
  await page.emulateMedia({ colorScheme: 'dark' })
}

test('from the first visit to a cut WAN, without a reload', async ({ page, baseURL }) => {
  test.setTimeout(300_000)
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  expect(FINGERPRINT, 'OPENFEO_FINGERPRINT').toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
  mkdirSync(SHOTS, { recursive: true })
  const router = new URL(baseURL ?? '').host

  // Whatever goes wrong on the page is a failure, whichever step it happens in: an error on
  // the console (the content security policy reports there), an uncaught exception, or
  // anything asked of a host that is not the router.
  const problems: string[] = []
  page.on('console', (message) => {
    // A refused login is the router saying no, which the browser also notes on the console.
    const refusedLogin = message.location().url.endsWith('/api/login') && /status of (401|429)/.test(message.text())
    if (message.type() === 'error' && !refusedLogin) {
      problems.push(`console: ${message.text()}`)
    }
  })
  page.on('pageerror', (error) => problems.push(`uncaught: ${error.message}`))
  const elsewhere = (url: string) => {
    if (new URL(url).host !== router) {
      problems.push(`asked of another host: ${url}`)
    }
  }
  page.on('request', (request) => elsewhere(request.url()))
  page.on('websocket', (socket) => elsewhere(socket.url()))

  // 1. The first visit: a router with no password says so, and shows whose router it is.
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Set the admin password' })).toBeVisible()
  await expect(page).toHaveURL(/\/first-password$/)
  expect((await page.locator('.fp__value span').allTextContents()).join(':')).toBe(FINGERPRINT)
  await shots(page, 'first-password')

  // A password that is too short is said at its field, and nothing is set.
  await page.getByLabel('New password').fill('too short')
  await page.getByLabel('Repeat password').fill('too short')
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.locator('.ofo-field--error')).toContainText('12 characters or more.')
  await expect(page).toHaveURL(/\/first-password$/)

  // 2. Set it: this browser is logged in, and the dashboard shows the WAN up with its lease.
  await page.getByLabel('New password').fill(PASSWORD)
  await page.getByLabel('Repeat password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page).toHaveURL(/\/$/)
  const wan = page.locator('.ofo-iface', { has: page.locator('.ofo-iface__name', { hasText: /^wan0$/ }) })
  await expect(wan.locator('.ofo-pill')).toHaveText('Up')
  await expect(wan).toContainText(/203\.0\.113\.\d+/)
  await expect(wan).toHaveClass(/ofo-iface--active/)
  await expect(page.locator('.ofo-pagehead__sub')).toContainText('wan0 up')
  await expect(page.locator('.ofo-topbar__host')).toHaveText('openfeo.home.arpa')
  await expect(page.locator('.ofo-iface', { hasText: 'lan0' }).locator('.ofo-pill')).toHaveText('Up')
  await expect(page.locator('.ofo-port')).toHaveCount(3)
  await expect(page.locator('.dash__addresses')).toContainText('192.168.1.1/24')
  // The counters are live: two samples a second apart make a rate.
  await expect(page.locator('.ofo-stat').first().locator('.ofo-stat__unit')).toHaveText(/bit\/s$/, { timeout: 15_000 })
  await expect(page.locator('.dash__events')).toContainText('wan0 up.')
  await shots(page, 'dashboard')

  // 3. A reload keeps the session: the token lives in the tab.
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(wan.locator('.ofo-pill')).toHaveText('Up')

  // 4. Log out, and in again: a wrong password is said, with the wait the router sets.
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible()
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.locator('.gate__host')).toHaveText('openfeo.home.arpa')
  await expect(page.locator('.gate__why')).toHaveCount(0)
  await shots(page, 'login')
  await page.getByLabel('Password').fill('not-the-password-at-all')
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.locator('.ofo-field__help')).toContainText('Wrong password.')
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole('button', { name: 'Log in' })).toBeEnabled({ timeout: 15_000 })
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(wan.locator('.ofo-pill')).toHaveText('Up')

  // 5. The ISP goes: the card says so and an event arrives, on the page as it stands. A mark
  // left on the window shows that nothing reloaded.
  await page.evaluate(() => {
    ;(window as unknown as { openfeoMark?: number }).openfeoMark = 1
  })
  await ask('wan-down')
  await expect(wan.locator('.ofo-pill')).toHaveText('Down', { timeout: 20_000 })
  await expect(wan).toContainText('no carrier')
  await expect(page.locator('.ofo-pagehead__sub')).toContainText('wan0 down: no carrier')
  await expect(page.locator('.dash__events tr').first()).toContainText('wan0 down: no carrier.')
  await ask('wan-up')
  await expect(wan.locator('.ofo-pill')).toHaveText('Up', { timeout: 90_000 })
  await expect(page.locator('.dash__events')).toContainText('wan0 up.')
  expect(await page.evaluate(() => (window as unknown as { openfeoMark?: number }).openfeoMark)).toBe(1)

  // 6. On a narrow screen the sidebar is the icon rail.
  await page.setViewportSize({ width: 800, height: 900 })
  await expect(page.locator('.ofo-nav__label').first()).toBeHidden()
  await expect(page.locator('.ofo-nav__item').first()).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/dashboard-narrow-dark.png`, fullPage: true })
  await page.setViewportSize({ width: 1280, height: 720 })

  // 7. The notices are one click from the gate, with no login.
  await page.getByRole('button', { name: 'Log out' }).click()
  await page.getByRole('link', { name: 'Licences' }).click()
  await expect(page).toHaveURL(/\/licences\.txt$/)
  await expect(page.locator('body')).toContainText('SIL OPEN FONT LICENSE')

  expect(problems).toEqual([])
})
