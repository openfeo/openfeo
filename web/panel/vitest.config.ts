// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import vue from '@vitejs/plugin-vue'
import { defaultClientConditions, defaultServerConditions } from 'vite'
import { defineConfig } from 'vitest/config'

// The panel's unit tests: pages and composables on a fake router, in a DOM that is not a
// browser. The run against a real router in a real browser is e2e/ (Playwright), which the
// harness starts inside the lab.
export default defineConfig({
  plugins: [vue()],
  resolve: { conditions: ['openfeo-source', ...defaultClientConditions] },
  ssr: { resolve: { conditions: ['openfeo-source', ...defaultServerConditions] } },
  build: { assetsInlineLimit: 0 },
  test: {
    environment: 'happy-dom',
    include: ['test/**/*.test.ts'],
  },
})
