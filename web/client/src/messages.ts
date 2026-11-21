// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The router's messages, for callers: the types and enums of what the client hands back, and
// the schemas with `create` for a caller that builds one (a test's fixtures, a config to
// apply), with `clone`, `equals` and `toJson` for one that edits a config and says what it
// changed. The generated code under gen/ is not imported from outside this package.

export { clone, create, equals, ScalarType, toJson } from '@bufbuild/protobuf'
// A schema's own account of its fields, for a caller that has to treat every field of a
// config alike (what a renumbered LAN carries with it) and so walks them.
export type { DescField, DescMessage } from '@bufbuild/protobuf'

export {
  ErrorCode,
  GetStatusResponseSchema,
  SessionSchema,
  type Caller,
  type GetStatusResponse,
  type Session,
} from './gen/openfeo/v1/api_pb.js'
export {
  ConfigSchema,
  DhcpWanSchema,
  Ipv6WanSchema,
  LanDhcpSchema,
  LanSchema,
  PppoeWanSchema,
  StaticLeaseSchema,
  StaticWanSchema,
  WanSchema,
  type Config,
  type Ipv6Wan,
  type Lan,
  type LanDhcp,
  type PortForward,
  type Record,
  type Rule,
  type StaticLease,
  type Wan,
} from './gen/openfeo/v1/config_pb.js'
export { EventSchema, type Event } from './gen/openfeo/v1/events_pb.js'
export {
  AddressOrigin,
  ConfigEffectKind,
  CountersSchema,
  PortUseKind,
  StateSchema,
  WanKind,
  WanPhase,
  type AddressState,
  type ConfigEffect,
  type ConfigProblem,
  type ConfigViolation,
  type Counters,
  type LanState,
  type LinkCounters,
  type PendingConfig,
  type PortState,
  type PortUse,
  type State,
  type SystemState,
  type WanState,
} from './gen/openfeo/v1/state_pb.js'
