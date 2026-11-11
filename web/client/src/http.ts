// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The plain HTTPS calls (SPEC §8.3): the three a client makes before it has a session. Bodies
// and answers are protobuf; a refusal carries an `Error` message when the router itself
// refused, and only a status when something in front of it did.

import { create, fromBinary, toBinary, type DescMessage, type MessageInitShape, type MessageShape } from '@bufbuild/protobuf'

import { RouterError } from './errors.js'
import { ErrorCode, ErrorSchema } from './gen/openfeo/v1/api_pb.js'

const PROTOBUF = 'application/x-protobuf'

export interface Http {
  baseUrl: string
  fetch: typeof fetch
}

/** The wait a refusal carries: in its `Error`, or in `Retry-After` as whole seconds. */
function retryAfter(response: Response, inBody: number): number | undefined {
  if (inBody > 0) {
    return inBody
  }
  const header = response.headers.get('retry-after')
  const secs = header === null ? Number.NaN : Number(header)
  return Number.isInteger(secs) && secs > 0 ? secs : undefined
}

async function refused(response: Response): Promise<RouterError> {
  const status = response.status
  let code = status === 429 ? ErrorCode.RESOURCE_EXHAUSTED : ErrorCode.UNSPECIFIED
  let message = `the router answered ${status}`
  let wait = 0
  if (response.headers.get('content-type')?.startsWith(PROTOBUF) === true) {
    try {
      const error = fromBinary(ErrorSchema, new Uint8Array(await response.arrayBuffer()))
      if (error.code !== ErrorCode.UNSPECIFIED) {
        code = error.code
        message = error.message
        wait = error.retryAfterSecs
      }
    } catch {
      // Not an Error after all: the status is what there is.
    }
  }
  const retryAfterSecs = retryAfter(response, wait)
  return new RouterError(code, message, { httpStatus: status, ...(retryAfterSecs === undefined ? {} : { retryAfterSecs }) })
}

/**
 * One call: `request` (when there is one) as the body of a POST, the answer decoded as
 * `answer`. Nothing a browser adds by itself goes with it: no cookie, no cached answer.
 */
export async function call<I extends DescMessage, O extends DescMessage>(
  http: Http,
  path: string,
  answer: O,
  request?: { schema: I; init: MessageInitShape<I> },
): Promise<MessageShape<O>> {
  const headers: Record<string, string> = { accept: PROTOBUF }
  const init: RequestInit = { method: 'GET', headers, credentials: 'omit', cache: 'no-store', redirect: 'error' }
  if (request !== undefined) {
    init.method = 'POST'
    headers['content-type'] = PROTOBUF
    init.body = toBinary(request.schema, create(request.schema, request.init))
  }
  let response: Response
  try {
    response = await http.fetch(`${http.baseUrl}${path}`, init)
  } catch {
    throw new RouterError(ErrorCode.UNAVAILABLE, 'the router did not answer')
  }
  if (!response.ok) {
    throw await refused(response)
  }
  try {
    return fromBinary(answer, new Uint8Array(await response.arrayBuffer()))
  } catch {
    throw new RouterError(ErrorCode.INTERNAL, 'the router answered with something that could not be read', {
      httpStatus: response.status,
    })
  }
}
