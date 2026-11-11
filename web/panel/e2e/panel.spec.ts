// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { expect, test } from '@playwright/test'

test("the page loads by the router's name, and a socket to it opens", async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveTitle(/OpenFeO/)
  const opened = await page.evaluate(
    () =>
      new Promise<boolean>((resolve) => {
        const ws = new WebSocket(`wss://${location.host}/ws`)
        ws.onopen = () => resolve(true)
        ws.onerror = () => resolve(false)
      }),
  )
  expect(opened).toBe(true)
})
