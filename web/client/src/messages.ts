// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The router's messages, for callers: the types and enums of what the client hands back, and
// the schemas with `create` for a caller that builds one (a test's fixtures). The generated
// code under gen/ is not imported from outside this package.

export { create } from '@bufbuild/protobuf'

export {
  ErrorCode,
  GetStatusResponseSchema,
  SessionSchema,
  type GetStatusResponse,
  type Session,
} from './gen/openfeo/v1/api_pb.js'
export { EventSchema, type Event } from './gen/openfeo/v1/events_pb.js'
export {
  AddressOrigin,
  CountersSchema,
  PortUseKind,
  StateSchema,
  WanKind,
  WanPhase,
  type AddressState,
  type ConfigProblem,
  type ConfigViolation,
  type Counters,
  type LanState,
  type LinkCounters,
  type PortState,
  type PortUse,
  type State,
  type SystemState,
  type WanState,
} from './gen/openfeo/v1/state_pb.js'
