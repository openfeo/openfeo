// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The whole panel as main.ts assembles it, on a scripted router and a history kept in
// memory: what a test of a page behind the login mounts, since every such page sits in the
// shell and is reached by its address.

import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'

import App from '../src/App.vue'
import { CONFIG, type ConfigStore } from '../src/config'
import { panelRoutes } from '../src/routes'
import { ROUTER, SESSION, useSession } from '../src/session'
import { FakeRouter } from './fake-router'

/** A router someone is logged in to, with its socket open. */
export function signedIn(): FakeRouter {
  const router = new FakeRouter()
  router.authenticated = true
  router.connection = 'open'
  return router
}

const wrappers: VueWrapper[] = []

/** The panel at `path`. Anything a component threw is in `errors`. */
export async function panelAt(path: string, router: FakeRouter = signedIn()) {
  const session = useSession(router)
  await session.refresh()
  const routes = panelRoutes(session, createMemoryHistory())
  await routes.push(path)
  const errors: unknown[] = []
  const wrapper = mount(App, {
    global: {
      plugins: [routes],
      provide: { [ROUTER as symbol]: router, [SESSION as symbol]: session },
      config: { errorHandler: (error) => errors.push(error) },
    },
    attachTo: document.body,
  })
  wrappers.push(wrapper)
  await routes.isReady()
  await flushPromises()
  /** The config store the shell made, as its pages are handed it. */
  const store = (): ConfigStore => {
    const provided = (wrapper.findComponent({ name: 'Shell' }).vm.$ as unknown as { provides: Record<symbol, unknown> }).provides
    return provided[CONFIG as symbol] as ConfigStore
  }
  return { wrapper, router, session, routes, errors, store }
}

/** The field of a page with this label: its wrapper, for its input, its help and its error. */
export function fieldLabelled(within: { findAll: VueWrapper['findAll'] }, label: string) {
  const found = within.findAll('.ofo-field').filter((field) => field.find('.ofo-field__label').text() === label)
  if (found.length !== 1) {
    throw new Error(`${found.length} fields are labelled ${label}`)
  }
  return found[0]!
}

/** Take down every panel a test put up (for `afterEach`). */
export function unmountAll(): void {
  for (const wrapper of wrappers.splice(0)) {
    wrapper.unmount()
  }
}
