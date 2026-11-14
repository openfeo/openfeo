// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// What the tests against the lab's router share: waiting for something the router pushes.

import type { Router, State } from '../src/index.js'

/** Wait for something a listener is told, or say what was being waited for. */
export function waitFor<T>(what: string, ms: number, arm: (done: (value: T) => void) => () => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      disarm()
      reject(new Error(`waited ${ms / 1000} s for ${what}`))
    }, ms)
    // (`done` may be called before `arm` has returned what disarms it: look that up later.)
    const disarm = arm((value) => {
      clearTimeout(timer)
      queueMicrotask(() => disarm())
      resolve(value)
    })
  })
}

export function stateWhere(from: Router, what: string, ms: number, wanted: (state: State) => boolean): Promise<State> {
  return waitFor<State>(what, ms, (done) => {
    const subscription = from.subscribe('state', (state) => {
      if (wanted(state)) {
        done(state)
      }
    })
    return () => subscription.close()
  })
}
