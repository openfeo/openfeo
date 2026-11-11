// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { defineConfig } from 'vitest/config'

// The unit tests: a scripted `fetch` and a scripted socket, no router. The tests that need a
// router are under itest/ and are run by the harness inside the lab.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
})
