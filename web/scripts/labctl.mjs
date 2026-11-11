// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// How a test running inside the lab asks the lab for something only the harness can do: take
// a port's carrier away, give it back. The harness names a directory in OPENFEO_LAB_CTL; a
// request is a file `<n>.req` holding a verb, numbered from 1, and its answer is `<n>.ack`:
// `ok`, or `error: <why>`. The other end is `LabCtl` in harness/src/web.rs.

import { readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const ANSWER_MS = 30_000
const POLL_MS = 25

let asked = 0

/**
 * Ask the lab to do `verb` and wait until it has.
 *
 * @param {'wan-down' | 'wan-up' | 'lan-down' | 'lan-up'} verb
 * @returns {Promise<void>}
 */
export async function ask(verb) {
  const dir = process.env.OPENFEO_LAB_CTL
  if (dir === undefined || dir === '') {
    throw new Error('OPENFEO_LAB_CTL is not set: this test runs under the harness (make test-harness)')
  }
  asked += 1
  const request = join(dir, `${asked}.req`)
  // Written beside and moved into place, so the harness never reads half a verb.
  await writeFile(`${request}.tmp`, verb)
  await rename(`${request}.tmp`, request)
  const ack = join(dir, `${asked}.ack`)
  const deadline = Date.now() + ANSWER_MS
  for (;;) {
    let answer
    try {
      answer = (await readFile(ack, 'utf8')).trim()
    } catch (error) {
      if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) {
        throw error
      }
    }
    if (answer === 'ok') {
      return
    }
    if (answer !== undefined) {
      throw new Error(`the lab refused ${verb}: ${answer}`)
    }
    if (Date.now() > deadline) {
      throw new Error(`the lab did not answer ${verb} within ${ANSWER_MS / 1000} s`)
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS))
  }
}
