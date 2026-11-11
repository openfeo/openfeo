// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { fileURLToPath } from 'node:url'

import { defineConfig } from 'vitest/config'

// The client against a real router (SPEC §11). The harness runs this inside the lab's LAN
// namespace, from web/, against the booted VM:
//
//   vitest run --config client/itest/vitest.config.ts
//
// with OPENFEO_ROUTER (the router's address), OPENFEO_PASSWORD and OPENFEO_LAB_CTL set. It is
// not part of `npm test`: without a router there is nothing to run it against.
export default defineConfig({
  root: fileURLToPath(new URL('..', import.meta.url)),
  test: {
    environment: 'node',
    include: ['itest/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 30_000,
    fileParallelism: false,
    // The tests share one router and build on each other: in order, and stop at the first failure.
    sequence: { concurrent: false },
    bail: 1,
  },
})
