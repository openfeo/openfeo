// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The rule the router picks log lines by (SPEC §8.3), for a line that arrives live: the router
// matches what is past when it is asked, and whoever follows the log matches what comes after
// by the same rule. Both are held to the cases in `test/log-rule.cases.json`.

import { LogLevel } from './gen/openfeo/v1/api_pb.js'

/** ASCII's letters in lower case and nothing else changed: the router folds no other letter. */
function folded(text: string): string {
  return text.replace(/[A-Z]+/g, (letters) => letters.toLowerCase())
}

/**
 * Whether `line` is wanted by someone who asked for `level` and everything more serious, and
 * for `contains` anywhere in the text without regard to ASCII case. A level of
 * `LogLevel.UNSPECIFIED` and an empty text each want every line.
 */
export function logMatches(line: { level: LogLevel; text: string }, level: LogLevel, contains: string): boolean {
  // The more serious a level, the smaller its number; a line of no level is as serious as none.
  const serious = level === LogLevel.UNSPECIFIED || (line.level !== LogLevel.UNSPECIFIED && line.level <= level)
  return serious && (contains === '' || folded(line.text).includes(folded(contains)))
}
