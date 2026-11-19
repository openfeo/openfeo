// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// A place in the config as the router writes one: `lans[0].dhcp.static[2].ip`.

/** Whether `path` is `at` or beneath it: `lans[0].dhcp.range[1]` is beneath `lans[0].dhcp.range`. */
export function under(path: string, at: string): boolean {
  return path === at || path.startsWith(`${at}.`) || path.startsWith(`${at}[`)
}
