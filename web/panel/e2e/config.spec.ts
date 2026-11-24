// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Changing the router's config from the panel, in a real browser against a real router
// (SPEC §5.5, §8.4, §12). The harness boots the router with a 40 s window to confirm in, runs
// this in Chromium inside the lab's LAN namespace, and answers the test's request to move
// the LAN host to another subnet. One test, in order: a change confirmed, one reverted by
// hand, one left to run out, a LAN added and removed with no going back, and the router's
// own address moved from under the page and confirmed from where it went.

import { mkdirSync } from 'node:fs'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { ask } from '../../scripts/labctl.mjs'
import { SHOTS, shots, watch } from './support'

const PASSWORD = process.env.OPENFEO_PASSWORD ?? ''
/** Where the router is once `lan0` has moved. */
const MOVED = '192.168.2.1'

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

const bar = (page: Page) => page.locator('.ofo-savebar')
const pending = (page: Page) => page.locator('.pending')
const notice = (page: Page) => page.locator('.notice')
const dialog = (page: Page) => page.getByRole('alertdialog')

/** Press Apply changes in the bar and wait for the dialog that follows the router's validation. */
async function review(page: Page): Promise<Locator> {
  await bar(page).getByRole('button', { name: 'Apply changes' }).click()
  await expect(dialog(page)).toBeVisible()
  return dialog(page)
}

/** Go to an address, again if the browser gave up because the host's own address had just changed. */
async function open(page: Page, url: string): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      await page.goto(url)
      return
    } catch (error) {
      if (attempt >= 8 || !/ERR_NETWORK_CHANGED|ERR_ADDRESS_UNREACHABLE|ERR_CONNECTION|ERR_INTERNET_DISCONNECTED|ERR_NETWORK_ACCESS/.test(String(error))) {
        throw error
      }
      await page.waitForTimeout(500)
    }
  }
}

test('a change confirmed, reverted, run out, made for good, and one that moves the router', async ({ page, baseURL }) => {
  test.setTimeout(300_000)
  expect(PASSWORD, 'OPENFEO_PASSWORD').not.toBe('')
  mkdirSync(SHOTS, { recursive: true })
  const router = new URL(baseURL ?? '').host
  const { problems, routerMoves } = watch(page, [router, MOVED])
  // Leaving a page with changes asks first; where this test leaves one, it means to.
  page.on('dialog', (asked) => void (asked.type() === 'beforeunload' ? asked.accept() : asked.dismiss()))

  // 1. Set the password. The sidebar has Network's pages and, under Router, System.
  await page.goto('/')
  await page.getByLabel('New password').fill(PASSWORD)
  await page.getByLabel('Repeat password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Set password' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.locator('.ofo-nav__group')).toHaveText(['Network', 'Router'])
  await expect(page.locator('.ofo-nav__item .ofo-nav__label')).toHaveText(['Dashboard', 'WAN', 'LAN & DHCP', 'Leases', 'Firewall', 'DNS', 'System'])

  // 2. Edit, apply, confirm.
  await page.getByRole('link', { name: 'LAN & DHCP' }).click()
  await expect(page.getByRole('heading', { name: 'LAN & DHCP' })).toBeVisible()
  await expect(page).toHaveURL(/\/lan$/)
  await expect(page.getByRole('tab')).toHaveCount(1)
  await expect(field(page, 'Router address').locator('input')).toHaveValue('192.168.1.1')
  await type(page, 'Pool end', '192.168.1.220')
  await page.getByRole('button', { name: 'Add reservation' }).click()
  const added = page.locator('table.res tbody tr').last().locator('input')
  await added.nth(0).fill('printer')
  await added.nth(1).fill('02:00:00:aa:01:22')
  await added.nth(2).fill('192.168.1.20')
  await expect(bar(page)).toContainText('2 changes not applied yet')
  await expect(field(page, 'Pool end').locator('.ofo-field__help')).toHaveText('Was 192.168.1.200.')
  await shots(page, 'lan')

  let asking = await review(page)
  await expect(asking.locator('.ofo-dialog__title')).toHaveText('Apply 2 changes to openfeo?')
  await expect(asking.locator('.ofo-changes li')).toHaveCount(2)
  await expect(asking.locator('.ofo-changes')).toContainText('lan0 pool')
  await expect(asking.locator('.ofo-changes')).toContainText('lan0 reservations')
  await expect(asking.locator('.ofo-changes')).toContainText('1 added')
  await expect(asking).toContainText("lan0's DHCP server restarts; leases are kept.")
  await expect(asking).toContainText('You have 40 seconds to confirm')
  await shots(page, 'apply')
  await asking.getByRole('button', { name: 'Apply changes' }).click()
  await expect(asking).toHaveCount(0)

  // The banner counts down on the router's clock.
  await expect(pending(page)).toBeVisible()
  await expect(pending(page)).toContainText('A change is waiting for you to confirm')
  const timer = pending(page).getByRole('timer')
  await expect(timer).toHaveText(/^0:[0-3]\d$/)
  const first = await timer.textContent()
  await expect(timer).not.toHaveText(first ?? '', { timeout: 5_000 })
  await expect(bar(page)).toHaveCount(0)
  await shots(page, 'pending')
  // It is on every page.
  await page.getByRole('link', { name: 'Dashboard' }).click()
  await expect(pending(page)).toBeVisible()
  await pending(page).getByRole('button', { name: 'Confirm' }).click()
  await expect(pending(page)).toHaveCount(0)
  await expect(notice(page)).toHaveCount(0)
  await expect(page.locator('.dash__events')).toContainText('The change of config was confirmed.')

  // A reload reads the router's config: the reservation is in it, and nothing waits to be applied.
  await page.getByRole('link', { name: 'LAN & DHCP' }).click()
  await page.reload()
  await expect(page.locator('table.res tbody tr')).toHaveCount(2)
  await expect(page.locator('table.res tbody tr').last().locator('input').nth(0)).toHaveValue('printer')
  await expect(field(page, 'Pool end').locator('input')).toHaveValue('192.168.1.220')
  await expect(bar(page)).toHaveCount(0)

  // 3. Apply and revert by hand.
  await page.getByRole('link', { name: 'WAN', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'WAN' })).toBeVisible()
  await expect(page.getByRole('tab', { name: /wan0/ })).toContainText('up')
  await shots(page, 'wan')
  // The lab's WAN sends a hostname, so its Advanced is open already.
  await expect(field(page, 'Hostname sent').locator('input')).toHaveValue('openfeo-lab')
  await type(page, 'Hostname sent', 'openfeo-lab-2')
  await expect(bar(page)).toContainText('1 change not applied yet')
  asking = await review(page)
  await expect(asking).toContainText('wan0 drops and comes back.')
  await asking.getByRole('button', { name: 'Apply changes' }).click()
  await expect(pending(page)).toBeVisible()
  await pending(page).getByRole('button', { name: 'Revert now' }).click()
  await expect(pending(page)).toHaveCount(0)
  await expect(notice(page)).toContainText('The router went back to how it was')
  await expect(notice(page)).toContainText('was reverted.')
  await expect(notice(page)).toContainText('Your changes are still here as a draft.')
  await expect(bar(page)).toContainText('1 change not applied yet')
  await expect(field(page, 'Hostname sent').locator('input')).toHaveValue('openfeo-lab-2')
  await bar(page).getByRole('button', { name: 'Discard' }).click()
  await expect(bar(page)).toHaveCount(0)
  await expect(field(page, 'Hostname sent').locator('input')).toHaveValue('openfeo-lab')
  await notice(page).getByRole('button', { name: 'Dismiss' }).click()
  await expect(notice(page)).toHaveCount(0)

  // 4. A window runs out with the page open.
  await page.getByRole('link', { name: 'LAN & DHCP' }).click()
  await field(page, 'Lease time').locator('select').selectOption('3600')
  await expect(bar(page)).toContainText('1 change not applied yet')
  asking = await review(page)
  await expect(asking.locator('.ofo-changes')).toContainText('lease time')
  await asking.getByRole('button', { name: 'Apply changes' }).click()
  await expect(pending(page)).toBeVisible()
  await expect(notice(page)).toContainText('The router went back to how it was', { timeout: 60_000 })
  await expect(notice(page)).toContainText('was not confirmed in time.')
  await expect(notice(page)).toContainText('Your changes are still here as a draft.')
  await expect(pending(page)).toHaveCount(0)
  await expect(bar(page)).toContainText('1 change not applied yet')
  await bar(page).getByRole('button', { name: 'Discard' }).click()
  await expect(field(page, 'Lease time').locator('select')).toHaveValue('43200')
  await notice(page).getByRole('button', { name: 'Dismiss' }).click()

  // 5. A LAN added and removed, each with no going back.
  await page.getByRole('button', { name: 'Add LAN' }).click()
  const naming = page.getByRole('dialog')
  await naming.locator('input').fill('guest')
  await naming.getByRole('button', { name: 'Add' }).click()
  await expect(page).toHaveURL(/\/lan\/guest$/)
  await type(page, 'Router address', '192.168.3.1')
  await expect(field(page, 'Subnet size').locator('select')).toHaveValue('24')
  await expect(field(page, 'Subnet size').locator('.ofo-field__help')).toHaveText('192.168.3.1 to 192.168.3.254.')
  // The lab's router has three ports: p0 is the WAN's, p2 is lan0's, and p1 is free.
  const free = page.locator('.ofo-formsec .ofo-choice')
  await expect(free).toHaveCount(1)
  await expect(free).toContainText('p1')
  await expect(free).toContainText('free')
  await free.locator('input').check()
  await expect(bar(page)).toContainText('1 change not applied yet')
  asking = await review(page)
  await expect(asking.locator('.ofo-changes')).toContainText('added: 192.168.3.1/24 on p1')
  await expect(asking).toContainText('guest is added.')
  await asking.getByLabel('Apply immediately, no confirmation countdown').check()
  await expect(asking).toContainText('Nothing will undo this change by itself.')
  const forGood = asking.getByRole('button', { name: 'Apply immediately' })
  await expect(forGood).toHaveClass(/ofo-btn--danger/)
  await shots(page, 'apply-immediately')
  await forGood.click()
  await expect(asking).toHaveCount(0)
  await expect(bar(page)).toHaveCount(0)
  // Nothing waits to be confirmed: it simply is.
  await expect(pending(page)).toHaveCount(0)
  await page.reload()
  await expect(page.getByRole('tab')).toHaveCount(2)
  await expect(page.getByRole('tab', { name: /guest/ })).toHaveAttribute('aria-selected', 'true')
  await expect(field(page, 'Router address').locator('input')).toHaveValue('192.168.3.1')

  await page.getByRole('button', { name: 'Remove guest' }).click()
  await expect(page.getByRole('tab')).toHaveCount(1)
  asking = await review(page)
  await expect(asking.locator('.ofo-changes')).toContainText('removed')
  await asking.getByLabel('Apply immediately, no confirmation countdown').check()
  await asking.getByRole('button', { name: 'Apply immediately' }).click()
  await expect(asking).toHaveCount(0)
  await expect(bar(page)).toHaveCount(0)
  await expect(pending(page)).toHaveCount(0)
  await expect(page.getByRole('tab')).toHaveCount(1)

  // 6. The subnet moves under the browser.
  await type(page, 'Router address', MOVED)
  await expect(field(page, 'Router address').locator('.ofo-field__help')).toHaveText('Was 192.168.1.1.')
  await expect(field(page, 'Pool start').locator('.ofo-field__help')).toHaveText('Was 192.168.1.100. Moved with the subnet.')
  await expect(field(page, 'Pool start').locator('input')).toHaveValue('192.168.2.100')
  await expect(page.locator('table.res tbody tr').last().locator('input').nth(2)).toHaveValue('192.168.2.20')
  asking = await review(page)
  await expect(asking.locator('.ofo-banner__title')).toHaveText('This moves the address you are using to reach the router')
  await expect(asking.locator('.ofo-banner')).toContainText(`https://${MOVED}`)
  await expect(asking.locator('.ofo-banner')).toContainText(`https://${router}`)
  await expect(asking.locator('.ofo-changes')).toContainText('port forward lan-http')
  await expect(asking.locator('.ofo-changes')).toContainText('lan0 address')
  await expect(asking).toContainText('lan0 moves: its devices need new addresses.')
  await shots(page, 'apply-moves')
  // From here the address this page was loaded from goes away, as it is meant to.
  routerMoves()
  await asking.getByRole('button', { name: 'Apply changes' }).click()
  // Answered or not (the answer's way home goes with the address), the page says where the router went.
  await expect(notice(page)).toContainText('The router is moving', { timeout: 20_000 })
  await expect(notice(page).getByRole('link')).toHaveText([`https://${router}`, `https://${MOVED}`])

  // What a person does next: take an address in the new subnet and go to the router there.
  await ask(`lan-to 192.168.2.50/24 ${MOVED}`)
  await open(page, `https://${MOVED}/`)
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible()
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Log in' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  // The change is still waiting, with time left, and is confirmed from here.
  await expect(pending(page)).toBeVisible()
  await expect(pending(page).getByRole('timer')).toHaveText(/^0:\d\d$/)
  await expect(pending(page).getByRole('timer')).not.toHaveText('0:00')
  await pending(page).getByRole('button', { name: 'Confirm' }).click()
  await expect(pending(page)).toHaveCount(0)
  await page.getByRole('link', { name: 'LAN & DHCP' }).click()
  await expect(field(page, 'Router address').locator('input')).toHaveValue(MOVED)
  await expect(field(page, 'Pool start').locator('input')).toHaveValue('192.168.2.100')
  await expect(field(page, 'Pool start').locator('.ofo-field__help')).toHaveCount(0)
  await expect(bar(page)).toHaveCount(0)

  // 7. On a narrow screen a settings page is one column.
  await page.setViewportSize({ width: 800, height: 900 })
  await expect(page.locator('.ofo-formsec').first()).toHaveCSS('grid-template-columns', /^\S+$/)
  await shots(page, 'lan-narrow')

  expect(problems).toEqual([])
})
