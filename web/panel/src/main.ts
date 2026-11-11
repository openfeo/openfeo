// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The OpenFeO panel (SPEC §8.4): the pages that join the client and the components. No
// protocol code lives here, and no styles beyond page layout.

import '@openfeo/ui/tokens.css'
import '@openfeo/ui/ofo.css'
import '@openfeo/ui/additions.css'
import './layout.css'

import { Router } from '@openfeo/client'
import { createApp } from 'vue'

import App from './App.vue'
import { panelRoutes } from './routes'
import { ROUTER, SESSION, sessionStore, useSession } from './session'

// The router is the one that served this page. The session's token is kept in the tab's own
// storage: it lasts a reload and ends with the tab, and it is never a cookie.
const router = new Router({ tokenStore: sessionStore(window.sessionStorage) })
const session = useSession(router)

createApp(App).provide(ROUTER, router).provide(SESSION, session).use(panelRoutes(session)).mount('#app')
void session.refresh()
