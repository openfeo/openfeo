// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The panel's addresses. The screen decides the address, never the reverse: what the router
// says of itself chooses the screen (session.ts), and an address typed or kept from before is
// corrected to it. Later parts add pages beside the dashboard; they are reachable only while
// the screen is the dashboard's.

import { watch } from 'vue'
import { createRouter, createWebHistory, type Router } from 'vue-router'

import ConfigUnreadable from './pages/ConfigUnreadable.vue'
import Dashboard from './pages/Dashboard.vue'
import FirstPassword from './pages/FirstPassword.vue'
import Login from './pages/Login.vue'
import type { PanelSession, Screen } from './session'

export const PATHS: Record<Screen, string> = {
  dashboard: '/',
  login: '/login',
  'first-password': '/first-password',
  'config-unreadable': '/config-unreadable',
}

/** The gates: a screen that is one of these has exactly one address. */
const GATES = new Set<string>([PATHS.login, PATHS['first-password'], PATHS['config-unreadable']])

/** Where a visit to `path` should end up while the screen is `screen`, or `null` to stay. */
export function correction(screen: Screen, path: string): string | null {
  if (screen === 'dashboard') {
    return GATES.has(path) ? PATHS.dashboard : null
  }
  return path === PATHS[screen] ? null : PATHS[screen]
}

export function panelRoutes(session: PanelSession): Router {
  const routes = createRouter({
    history: createWebHistory(),
    routes: [
      { path: PATHS.dashboard, component: Dashboard },
      { path: PATHS.login, component: Login },
      { path: PATHS['first-password'], component: FirstPassword },
      { path: PATHS['config-unreadable'], component: ConfigUnreadable },
      { path: '/:rest(.*)*', redirect: PATHS.dashboard },
    ],
  })
  routes.beforeEach((to) => {
    const screen = session.screen.value
    return screen === null ? true : (correction(screen, to.path) ?? true)
  })
  watch(session.screen, (screen) => {
    if (screen !== null) {
      const to = correction(screen, routes.currentRoute.value.path)
      if (to !== null) {
        void routes.replace(to)
      }
    }
  })
  return routes
}
