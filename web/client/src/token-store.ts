// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

/**
 * Where a router keeps its session's token: three functions, so a caller decides how long a
 * login lasts. The panel passes one over `sessionStorage`; a script keeps the default.
 */
export interface TokenStore {
  get(): string | null
  set(token: string): void
  clear(): void
}

/** A store that lives as long as the object does and no longer. */
export function memoryTokenStore(): TokenStore {
  let held: string | null = null
  return {
    get: () => held,
    set: (token) => {
      held = token
    },
    clear: () => {
      held = null
    },
  }
}
