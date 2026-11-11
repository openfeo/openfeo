// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import js from '@eslint/js'
import vue from 'eslint-plugin-vue'
import globals from 'globals'
import tseslint from 'typescript-eslint'

// The client is plain TypeScript and is linted with type information. The components and the
// panel are Vue: `vue-tsc` type-checks them (`npm run typecheck`), and ESLint adds what a type
// checker does not see.
export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'client/src/gen/**', 'panel/e2e-out/**'] },
  js.configs.recommended,
  {
    files: ['**/*.mjs', '**/*.js'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['panel/public/**/*.js'],
    languageOptions: { sourceType: 'script', globals: { ...globals.browser } },
  },
  {
    files: ['client/**/*.ts'],
    extends: [tseslint.configs.recommendedTypeChecked],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
  },
  {
    // The client has no DOM beyond `fetch` and `WebSocket` (SPEC §8.4): it must run in Node.
    files: ['client/src/**/*.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        ...['window', 'document', 'navigator', 'localStorage', 'sessionStorage', 'history'].map((name) => ({
          name,
          message: 'The client runs in Node as well as in a browser.',
        })),
      ],
    },
  },
  {
    files: ['ui/**/*.ts', 'panel/**/*.ts', '**/*.vue'],
    extends: [tseslint.configs.recommended, vue.configs['flat/recommended']],
    languageOptions: {
      globals: { ...globals.browser },
      parserOptions: { parser: tseslint.parser },
    },
    rules: {
      // The router's content security policy refuses a style attribute.
      'vue/no-static-inline-styles': ['error', { allowBinding: false }],
      // Formatting is not this linter's business.
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off',
      'vue/html-indent': 'off',
      'vue/html-closing-bracket-newline': 'off',
      'vue/multiline-html-element-content-newline': 'off',
      'vue/first-attribute-linebreak': 'off',
    },
  },
)
