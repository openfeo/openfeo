// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  // As the panel builds: a file is a file, never a `data:` address (the router's policy
  // refuses those).
  build: { assetsInlineLimit: 0 },
  test: {
    environment: 'happy-dom',
    include: ['test/**/*.test.ts'],
  },
})
