// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// Which screen the panel shows (SPEC §8.4), and why. The router says what state it is in
// before anyone logs in; that and whether this tab holds a token decide the screen, each time
// the answer could have changed.

import type { GetStatusResponse, Router, SessionEnd, TokenStore } from '@openfeo/client'
import { ref, type InjectionKey, type Ref } from 'vue'

/** As much of the client as the panel uses: what a test's fake has to be. */
export type PanelRouter = Pick<
  Router,
  'authenticated' | 'connection' | 'status' | 'setInitialPassword' | 'login' | 'logout' | 'state' | 'subscribe' | 'onConnection' | 'onSessionEnd'
>

export type Screen = 'first-password' | 'config-unreadable' | 'login' | 'dashboard'

/**
 * The screen for what the router says of itself and whether this tab holds a token. A config
 * file that cannot be read comes first: nobody can log in over it. Then a router with no
 * password, whatever token is left over from before it was reset.
 */
export function screenFor(status: { needsPassword: boolean; configUnreadable: boolean }, authenticated: boolean): Screen {
  if (status.configUnreadable) {
    return 'config-unreadable'
  }
  if (status.needsPassword) {
    return 'first-password'
  }
  return authenticated ? 'dashboard' : 'login'
}

/** The router counts a password's characters (SPEC §9): so does the form, as code points. */
const SHORTEST = 12
const LONGEST = 256

/** What is wrong with a password's length, or `null`. Nothing is trimmed: what is typed is the password. */
export function lengthProblem(password: string): string | null {
  const length = [...password].length
  if (length < SHORTEST) {
    return '12 characters or more.'
  }
  if (length > LONGEST) {
    return '256 characters or fewer.'
  }
  return null
}

/** What is wrong with a new password and its repeat, or `null`: its length first, then the repeat. */
export function passwordProblem(password: string, repeat: string): string | null {
  return lengthProblem(password) ?? (password === repeat ? null : 'The two passwords differ.')
}

/** What stands in for storage the browser will not hand over: nothing is kept, nothing fails. */
const NO_STORAGE: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> = {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
}

/**
 * The browser's storage, or a stand-in that keeps nothing. With site data blocked, reading
 * `window.sessionStorage` or `window.localStorage` itself throws; the panel must still come
 * up, with a session and a theme that last for this page.
 */
export function storageOr(get: () => Storage): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  try {
    return get()
  } catch {
    return NO_STORAGE
  }
}

/** The key the session's token is kept under. The theme aside, it is all the panel stores. */
export const TOKEN_KEY = 'openfeo.token'

/**
 * A token store over the tab's own storage (SPEC §8.4): the session lasts a reload and ends
 * with the tab. Storage that refuses (a private window may) is a session kept for this page.
 */
export function sessionStore(storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>): TokenStore {
  let held: string | null = null
  return {
    get: () => {
      try {
        return storage.getItem(TOKEN_KEY) ?? held
      } catch {
        return held
      }
    },
    set: (token) => {
      held = token
      try {
        storage.setItem(TOKEN_KEY, token)
      } catch {
        // Kept in `held`.
      }
    },
    clear: () => {
      held = null
      try {
        storage.removeItem(TOKEN_KEY)
      } catch {
        // Nothing was stored.
      }
    },
  }
}

/** How often a router that does not answer is asked again. */
const ASK_AGAIN_MS = 5_000

export interface PanelSession {
  /** The screen to show; `null` until the router has first answered. */
  screen: Ref<Screen | null>
  /** What the router last said of itself. */
  status: Ref<GetStatusResponse | null>
  /** Why the last session ended, for the login screen to say. */
  ended: Ref<SessionEnd | null>
  /** Something the login screen should say once (a password set by someone else meanwhile). */
  notice: Ref<string | null>
  /** The router is not answering; it is being asked again. */
  unreachable: Ref<boolean>
  /** Ask the router and choose the screen. */
  refresh(): Promise<void>
  /** A login or a first password just succeeded. */
  entered(): Promise<void>
  /** Stop listening and stop asking. */
  dispose(): void
}

export function useSession(router: PanelRouter): PanelSession {
  const screen = ref<Screen | null>(null)
  const status = ref<GetStatusResponse | null>(null)
  const ended = ref<SessionEnd | null>(null)
  const notice = ref<string | null>(null)
  const unreachable = ref(false)
  let again: ReturnType<typeof setTimeout> | undefined
  let disposed = false

  async function refresh(): Promise<void> {
    clearTimeout(again)
    try {
      const answer = await router.status()
      if (disposed) {
        return
      }
      status.value = answer
      unreachable.value = false
      screen.value = screenFor(answer, router.authenticated)
    } catch {
      if (disposed) {
        return
      }
      unreachable.value = true
      again = setTimeout(() => void refresh(), ASK_AGAIN_MS)
    }
  }

  // The session ending may be anything: a logout, a password changed elsewhere, a router that
  // restarted or was reset. What it is now is the router's to say, so it is asked again.
  const stop = router.onSessionEnd((reason) => {
    ended.value = reason
    void refresh()
  })

  return {
    screen,
    status,
    ended,
    notice,
    unreachable,
    refresh,
    entered: () => {
      ended.value = null
      notice.value = null
      return refresh()
    },
    dispose: () => {
      disposed = true
      clearTimeout(again)
      stop()
    },
  }
}

export const ROUTER: InjectionKey<PanelRouter> = Symbol('the router')
export const SESSION: InjectionKey<PanelSession> = Symbol('the session')
