// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The settings pages in a real browser against a real router (SPEC §8.4, §12): Firewall, DNS
// and System. The harness boots the router with a 40 s window to confirm in and runs this in
// Chromium inside the lab's LAN namespace. One test, in order: a port forward added, applied
// and confirmed; a LAN that a forward points into, which cannot be removed until the forward
// is; a local name added; the password changed, the old one refused and the new one taken;
// and a restart asked, waited out, and ended at the login screen. What the router ended up
// with (the forward, the name a LAN host can now look up, the new password) the harness reads
// afterwards.

import { mkdirSync } from 'node:fs'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { SHOTS, shots, watch } from './support'

const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''
/** What the password is changed to. */
const NEW_PASSWORD = process.env.OPENFEO_NEW_PASSWORD ?? ''

/** The field with exactly this label: its wrapper, for its control and what it says beneath. */
function field(page: Page, label: string): Locator {
  return page.locator('.ofo-field').filter({ has: page.locator('.ofo-field__label', { hasText: new RegExp(`^${label}$`) }) })
}

/** Type into a field and leave it, as a person does. */
async function type(page: Page, label: string, text: string): Promise<void> {
  const box = field(page, label).locator('input')
  await box.fill(text)
  await box.blur()
}

/** Type into a control of a table's row and leave it. */
async function cell(row: Locator, at: number, text: string): Promise<void> {
  const box = row.locator('input').nth(at)
  await box.fill(text)
  await box.blur()
}

/** A page's entry in the sidebar: a page may itself link to another by the same word. */
const nav = (page: Page, name: string) => page.getByRole('navigation', { name: 'Pages' }).getByRole('link', { name, exact: true })
const bar = (page: Page) => page.locator('.ofo-savebar')
const pending = (page: Page) => page.locator('.pending')
const dialog = (page: Page) => page.getByRole('alertdialog')
const section = (page: Page, title: string) => page.locator('.ofo-formsec').filter({ has: page.locator('.ofo-formsec__title', { hasText: new RegExp(`^${title}$`) }) })

/** Press Apply changes, read the dialog, apply, and confirm from the banner that follows. */
async function applyAndConfirm(page: Page, listed: string[]): Promise<void> {
  await bar(page).getByRole('button', { name: 'Apply changes' }).click()
  const asking = dialog(page)
  await expect(asking).toBeVisible()
  for (const change of listed) {
    await expect(asking.locator('.ofo-changes')).toContainText(change)
  }
  await asking.getByRole('button', { name: 'Apply changes' }).click()
  await expect(asking).toHaveCount(0)
  await expect(pending(page)).toBeVisible()
  await pending(page).getByRole('button', { name: 'Confirm' }).click()
  await expect(pending(page)).toHaveCount(0)
  await expect(bar(page)).toHaveCount(0)
}

test('the firewall, a local name, the password and a restart', async ({ page, baseURL }) => {
  test.setTimeout(420_000)
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  expect(NEW_PASSWORD, 'OPENFEO_NEW_PASSWORD').not.toBe('')
  mkdirSync(SHOTS, { recursive: true })
  const router = new URL(baseURL ?? '').host
  const { problems, routerMoves } = watch(page, [router])
  // Leaving a page with changes asks first; where this test leaves one, it means to.
  page.on('dialog', (asked) => void (asked.type() === 'beforeunload' ? asked.accept() : asked.dismiss()))

  // 1. Set the password. The sidebar has Network's pages and, under Router, System.
  await page.goto('/')
  await page.getByLabel('New password').fill(PASSWORD)
  await page.getByLabel('Repeat password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.locator('.ofo-nav__group')).toHaveText(['Network', 'Router'])
  await expect(page.locator('.ofo-nav__item .ofo-nav__label')).toHaveText(['Dashboard', 'WAN', 'LAN & DHCP', 'Leases', 'Firewall', 'DNS', 'Routes', 'Ports', 'Logs', 'System'])

  // 2. Firewall: the grid says what the lab's one LAN may reach; a forward is added, applied
  // and confirmed.
  await nav(page, 'Firewall').click()
  await expect(page.getByRole('heading', { name: 'Firewall' })).toBeVisible()
  await expect(page).toHaveURL(/\/firewall$/)
  await expect(page.locator('table.reach').getByLabel('lan0 may reach the internet')).toBeChecked()
  const forwards = page.locator('table.fwd tbody tr')
  await expect(forwards).toHaveCount(1)
  await expect(forwards.first().locator('input').first()).toHaveValue('lan-http')
  await expect(section(page, 'The router itself').getByRole('checkbox')).toBeChecked()
  await page.getByRole('button', { name: 'Add forward' }).click()
  await expect(forwards).toHaveCount(2)
  await cell(forwards.last(), 0, 'e2e-ssh')
  await cell(forwards.last(), 1, '2022')
  await cell(forwards.last(), 2, '192.168.1.50')
  await cell(forwards.last(), 3, '22')
  await expect(forwards.last().locator('select')).toHaveValue('tcp')
  await expect(forwards.last().getByRole('alert')).toHaveCount(0)
  await expect(bar(page)).toContainText('1 change not applied yet')
  await shots(page, 'settings-firewall')
  await applyAndConfirm(page, ['port forward e2e-ssh', 'added: TCP 2022 to 192.168.1.50:22'])
  // Read again from the router, the forward is still there.
  await page.reload()
  await expect(forwards).toHaveCount(2)
  await expect(forwards.last().locator('input').first()).toHaveValue('e2e-ssh')

  // 3. A LAN that something points into, all in one draft: it cannot be removed until the
  // forward is, and what stands in the way is a link to where that is done.
  await nav(page, 'LAN & DHCP').click()
  await page.getByRole('button', { name: 'Add LAN' }).click()
  const naming = page.getByRole('dialog')
  await naming.locator('input').fill('iot')
  await naming.getByRole('button', { name: 'Add' }).click()
  await expect(page).toHaveURL(/\/lan\/iot$/)
  await type(page, 'Router address', '192.168.20.1')
  await nav(page, 'Firewall').click()
  // The grid has a row and a column for the LAN that is only in the draft.
  await expect(page.locator('table.reach').getByLabel('iot may reach lan0')).not.toBeChecked()
  await page.getByRole('button', { name: 'Add forward' }).click()
  await expect(forwards).toHaveCount(3)
  await cell(forwards.last(), 0, 'iot-cam')
  await cell(forwards.last(), 1, '8554')
  await cell(forwards.last(), 2, '192.168.20.5')
  await nav(page, 'LAN & DHCP').click()
  await page.getByRole('tab', { name: /iot/ }).click()
  const foot = page.locator('.page__foot')
  await expect(foot.getByRole('button', { name: 'Remove iot' })).toBeDisabled()
  await expect(foot).toContainText('Cannot be removed yet: port forward iot-cam points into it.')
  await foot.getByRole('link', { name: 'port forward iot-cam points into it' }).click()
  await expect(page).toHaveURL(/\/firewall$/)
  await forwards.last().getByRole('button', { name: 'Remove' }).click()
  await expect(forwards).toHaveCount(2)
  await nav(page, 'LAN & DHCP').click()
  await page.getByRole('tab', { name: /iot/ }).click()
  await expect(foot).not.toContainText('Cannot be removed')
  await foot.getByRole('button', { name: 'Remove iot' }).click()
  await expect(page.getByRole('tab')).toHaveCount(1)
  // Added and removed again: nothing is left to apply.
  await expect(bar(page)).toHaveCount(0)

  // 4. DNS: the resolver in use is the one the lab's ISP gave; a local name is added.
  await nav(page, 'DNS').click()
  await expect(page.getByRole('heading', { name: 'DNS' })).toBeVisible()
  await expect(page.locator('.dns__inuse')).toHaveText('In use now: 203.0.113.1 from wan0.')
  await expect(section(page, 'Resolvers').getByRole('checkbox')).toBeChecked()
  await page.getByRole('button', { name: 'Add name' }).click()
  const names = page.locator('table.names tbody tr')
  await cell(names.last(), 0, 'printer')
  await cell(names.last(), 1, '192.168.1.50')
  await expect(page.locator('.names__note')).toContainText('printer is printer.home.arpa')
  await expect(bar(page)).toContainText('1 change not applied yet')
  await shots(page, 'settings-dns')
  await applyAndConfirm(page, ['DNS record printer', 'added: 192.168.1.50'])

  // 5. System: what the router runs, with the notices of everything in it one click away.
  await nav(page, 'System').click()
  await expect(page.getByRole('heading', { name: 'System' })).toBeVisible()
  await expect(section(page, 'Name').locator('.ofo-formsec__text')).toContainText('The panel is at openfeo.home.arpa.')
  await expect(field(page, 'Hostname').locator('input')).toHaveValue('openfeo')
  await expect(section(page, 'Time').locator('.ofo-pill')).toHaveText(/^(Synced|Not set yet)$/)
  const about = section(page, 'About')
  await expect(about.locator('dd').nth(0)).toHaveText(/^\d+\.\d+\.\d+/)
  await expect(about.locator('dd').nth(1)).toHaveText(/^\d+m \d+s$|^\d+s$/)
  await expect(about.locator('dd').nth(2)).toHaveText(/^SHA-256 ([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
  await shots(page, 'settings-system')
  await about.getByRole('link', { name: 'Open-source notices' }).click()
  await expect(page).toHaveURL(/\/licences\.txt$/)
  await expect(page.locator('body')).toContainText('The router: Rust crates')
  await expect(page.locator('body')).toContainText('tokio ')
  await page.goBack()
  await expect(page.getByRole('heading', { name: 'System' })).toBeVisible()

  // The password: a wrong current one is said at its field; with the right one it is changed.
  await type(page, 'Current password', 'not-the-password-at-all')
  await type(page, 'New password', NEW_PASSWORD)
  await type(page, 'New password again', NEW_PASSWORD)
  const change = page.getByRole('button', { name: 'Change password' })
  await change.click()
  await expect(field(page, 'Current password').getByRole('alert')).toContainText('That is not the current password.')
  // The wrong try may have earned a wait: the button comes back when it is over.
  await type(page, 'Current password', PASSWORD)
  await expect(change).toBeEnabled({ timeout: 15_000 })
  await change.click()
  await expect(section(page, 'Password').locator('.changed')).toHaveText('The password was changed. Every other session was logged out.')
  await expect(field(page, 'Current password').locator('input')).toHaveValue('')
  await expect(field(page, 'New password').locator('input')).toHaveValue('')
  // It was no change of config: nothing waits to be applied.
  await expect(bar(page)).toHaveCount(0)
  // The old one no longer logs in, and the new one does.
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible()
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.locator('.ofo-field__help')).toContainText('Wrong password.')
  const login = page.getByRole('button', { name: 'Log in' })
  await page.getByLabel('Password').fill(NEW_PASSWORD)
  await expect(login).toBeEnabled({ timeout: 15_000 })
  await login.click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

  // 6. Restart: asked first; the page says the router is restarting, and is at the login
  // screen once the router answers again.
  await nav(page, 'System').click()
  await page.getByRole('button', { name: 'Restart the router' }).click()
  const asking = dialog(page)
  await expect(asking.locator('.ofo-dialog__title')).toHaveText('Restart openfeo.home.arpa?')
  await expect(asking.locator('.ofo-dialog__text')).toHaveText(['Every device loses the internet for about a minute.'])
  await shots(page, 'settings-restart')
  // From here the router goes away on purpose: a connection that fails is not a problem.
  routerMoves()
  await asking.getByRole('button', { name: 'Restart', exact: true }).click()
  await expect(asking).toHaveCount(0)
  await expect(page.locator('.said .ofo-banner')).toContainText('The router is restarting. You log in again when it is back.')
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible({ timeout: 150_000 })
  await page.getByLabel('Password').fill(NEW_PASSWORD)
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  // It has only just come up, and it kept what was confirmed before it went.
  await expect(page.locator('.ofo-topbar__meta')).toHaveText(/up (\d+s|1m \d+s|1m)$/, { timeout: 15_000 })
  await nav(page, 'Firewall').click()
  await expect(forwards.last().locator('input').first()).toHaveValue('e2e-ssh')

  expect(problems).toEqual([])
})
