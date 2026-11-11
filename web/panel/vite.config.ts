// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import vue from '@vitejs/plugin-vue'
import { defaultClientConditions, defineConfig } from 'vite'

// The router's content security policy allows nothing inline and nothing from elsewhere
// (SPEC §8.3), so no asset may become a `data:` URL, and every built file but the page sits
// under `assets/` with a hash in its name, where the router caches it for good.
export default defineConfig({
  plugins: [vue()],
  resolve: {
    // The workspace's packages are read as TypeScript, not from their built output.
    conditions: ['openfeo-source', ...defaultClientConditions],
  },
  build: {
    assetsInlineLimit: 0,
    assetsDir: 'assets',
    sourcemap: false,
  },
})
