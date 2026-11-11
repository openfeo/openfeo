// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { defineConfig } from '@playwright/test'

// The harness runs this inside the lab's LAN namespace (SPEC §11) and says where the router
// is: OPENFEO_PANEL_URL is the address to open, by the router's name; OPENFEO_PANEL_RESOLVE
// ("<name> <address>") tells Chromium what that name is, since the namespace has the host's
// resolver configuration and not the router's; OPENFEO_E2E_OUT is where traces go.
const resolve = process.env.OPENFEO_PANEL_RESOLVE

export default defineConfig({
  testDir: 'e2e',
  outputDir: process.env.OPENFEO_E2E_OUT ?? 'e2e-out',
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: 'line',
  use: {
    baseURL: process.env.OPENFEO_PANEL_URL,
    // The certificate is the router's own (SPEC §9); the harness compares its fingerprint.
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: resolve === undefined ? [] : [`--host-resolver-rules=MAP ${resolve}`],
    },
  },
})
