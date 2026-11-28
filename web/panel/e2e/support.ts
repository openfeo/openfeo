// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the browser tests against the lab's router share: a screenshot of a screen in both
// themes, and the watch that makes anything going wrong on the page a failure, whichever
// step it happens in.

import type { Page } from '@playwright/test'

export const SHOTS = process.env.OPENFEO_SHOTS ?? 'e2e-out/shots'

/**
 * A screenshot of the whole page as it stands, in both themes: the panel follows the system
 * until told. The window is made as tall as the page for it: a capture that reaches beyond
 * the window leaves what sticks to the window's edges (the top bar, the sidebar, the save
 * bar, a dialog's scrim) wherever the window happened to be.
 */
export async function shots(page: Page, name: string): Promise<void> {
  const window = page.viewportSize()
  const height = await page.evaluate(() => document.documentElement.scrollHeight)
  if (window !== null && height > window.height) {
    await page.setViewportSize({ width: window.width, height })
  }
  for (const theme of ['dark', 'light'] as const) {
    await page.emulateMedia({ colorScheme: theme })
    // (A colour that is in transition from the other theme is taken as it ends up.)
    await page.screenshot({ path: `${SHOTS}/${name}-${theme}.png`, animations: 'disabled' })
  }
  await page.emulateMedia({ colorScheme: 'dark' })
  if (window !== null) {
    await page.setViewportSize(window)
  }
}

export interface Watch {
  /** What went wrong, in the order it did. A test ends with `expect(problems).toEqual([])`. */
  problems: string[]
  /**
   * From now on a connection that fails is not a problem: the test is about to take the
   * router's address away from under the page, on purpose.
   */
  routerMoves(): void
}

/**
 * Watch a page: an error on the console (the content security policy reports there), an
 * uncaught exception, or anything asked of a host that is not one of the router's, is a
 * problem.
 */
export function watch(page: Page, hosts: string[]): Watch {
  const problems: string[] = []
  let moving = false
  page.on('console', (message) => {
    if (message.type() !== 'error') {
      return
    }
    // A refused login is the router saying no, which the browser also notes on the console.
    const refusedLogin = message.location().url.endsWith('/api/login') && /status of (401|429)/.test(message.text())
    const lostConnection = moving && /WebSocket connection|net::ERR_|Failed to load resource/.test(message.text())
    if (!refusedLogin && !lostConnection) {
      problems.push(`console: ${message.text()}`)
    }
  })
  page.on('pageerror', (error) => problems.push(`uncaught: ${error.message}`))
  const elsewhere = (url: string) => {
    const at = new URL(url)
    // A file the page made for the browser to save is the page's own: its address is `blob:`
    // and then the page's origin.
    const host = at.protocol === 'blob:' ? new URL(at.pathname).host : at.host
    if (!hosts.includes(host)) {
      problems.push(`asked of another host: ${url}`)
    }
  }
  page.on('request', (request) => elsewhere(request.url()))
  page.on('websocket', (socket) => elsewhere(socket.url()))
  return {
    problems,
    routerMoves: () => {
      moving = true
    },
  }
}
