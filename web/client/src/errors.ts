// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

import { ErrorCode } from './gen/openfeo/v1/api_pb.js'

/**
 * A call the router refused, or one that never reached it. `code` is one of gRPC's names, the
 * same over HTTP and over the socket (SPEC §8.3), so a caller tells a wrong password from a
 * router that is not there without reading text.
 */
export class RouterError extends Error {
  override readonly name = 'RouterError'
  /** Why. `UNAVAILABLE` is the router not answering at all. */
  readonly code: ErrorCode
  /** How long to wait before trying again, when the router said. */
  readonly retryAfterSecs?: number
  /** The HTTP status, for a refusal that came over HTTP. */
  readonly httpStatus?: number

  constructor(code: ErrorCode, message: string, extra: { retryAfterSecs?: number; httpStatus?: number } = {}) {
    super(message)
    this.code = code
    if (extra.retryAfterSecs !== undefined && extra.retryAfterSecs > 0) {
      this.retryAfterSecs = extra.retryAfterSecs
    }
    if (extra.httpStatus !== undefined) {
      this.httpStatus = extra.httpStatus
    }
  }
}
