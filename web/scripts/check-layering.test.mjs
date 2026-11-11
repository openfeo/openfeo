// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { violations } from './check-layering.mjs'

test('ui may not import the client', () => {
  const found = violations([{ path: 'ui/src/a.ts', source: "import { Router } from '@openfeo/client'" }])
  assert.equal(found.length, 1)
  assert.match(found[0], /ui\/src\/a\.ts/)
})

test('the client may not import vue, statically, as a type or dynamically', () => {
  for (const source of [
    "import { ref } from 'vue'",
    "import type { Ref } from 'vue'",
    "const v = await import('vue')",
    "export * from 'vue-router'",
    'import "vue"',
    "import {\n  ref,\n  computed,\n} from 'vue'",
  ]) {
    assert.equal(violations([{ path: 'client/src/a.ts', source }]).length, 1, source)
  }
})

test('the panel reaches generated code only through the client', () => {
  assert.equal(
    violations([
      { path: 'panel/src/a.ts', source: "import { StateSchema } from '../../client/src/gen/openfeo/v1/state_pb.js'" },
    ]).length,
    1,
  )
  assert.equal(
    violations([{ path: 'panel/src/a.ts', source: "import { StateSchema } from '@openfeo/client/src/gen/openfeo/v1/state_pb'" }])
      .length,
    1,
  )
  assert.equal(violations([{ path: 'panel/src/a.ts', source: "import { create } from '@bufbuild/protobuf'" }]).length, 1)
  assert.equal(violations([{ path: 'panel/src/a.ts', source: "import { Router } from '@openfeo/client'" }]).length, 0)
})

test('a comment that names a package is not an import', () => {
  assert.equal(violations([{ path: 'client/src/a.ts', source: '// unlike vue, this has no reactivity' }]).length, 0)
  assert.equal(violations([{ path: 'client/src/a.ts', source: "/* import { ref } from 'vue' */" }]).length, 0)
  assert.equal(violations([{ path: 'client/src/a.ts', source: "// import { ref } from 'vue'" }]).length, 0)
})

test('the script block of a vue file is read like any other source', () => {
  const source = "<script setup lang=\"ts\">\nimport { Router } from '@openfeo/client'\n</script>\n<template><p /></template>\n"
  assert.equal(violations([{ path: 'ui/src/components/A.vue', source }]).length, 1)
})

test('what each package may use passes', () => {
  assert.equal(
    violations([
      { path: 'client/src/a.ts', source: "import { create } from '@bufbuild/protobuf'\nimport { x } from './gen/openfeo/v1/api_pb.js'" },
      { path: 'ui/src/a.ts', source: "import { ref } from 'vue'" },
      { path: 'panel/src/a.ts', source: "import { OfoButton } from '@openfeo/ui'\nimport { createRouter } from 'vue-router'" },
    ]).length,
    0,
  )
})
