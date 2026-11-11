// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Configuration for OpenFeO (SPEC §8). The protobuf schema in `proto/openfeo/v1/` is the single
//! source of truth; this crate holds its prost types with pbjson serde using the proto field
//! names, so the on-disk TOML (§8.2) is the canonical JSON mapping spelled in TOML.

#![forbid(unsafe_code)]

pub mod admin;
mod error;
pub mod file;
mod generated;
pub mod load;
pub mod migrate;
mod portmap;
pub mod portname;
pub mod rules;
pub mod validate;

pub use error::ConfigError;
pub use generated::{
    Admin, Config, Dhcp4Lease, Dhcp4Route, Dhcp4ServerLease, Dhcp4ServerLeases, Dhcp6Binding,
    Dhcp6Deprecated, Dhcp6Lease, DhcpWan, Dns, Firewall, Ipv6Wan, Lan, LanDhcp, PortForward,
    PortMap, PortMapEntry, PppoeWan, PublicIpv4, Record, Rule, StaticLease, StaticWan, System, Wan,
    wan,
};

/// Every generated type under one path, for code generated against this crate (`openfeo-api`'s
/// gRPC services map the whole `openfeo.v1` package here). Hand-written code uses the named
/// modules and the root re-exports.
#[doc(hidden)]
pub mod pb {
    pub use crate::generated::*;
}

/// What the router is doing now (`state.proto`): the messages of the API's state snapshot and
/// its counters.
pub mod state {
    pub use crate::generated::{
        AddressOrigin, AddressState, ConfigProblem, ConfigViolation, Counters, LanState,
        LinkCounters, PortState, PortUse, PortUseKind, State, SystemState, WanKind, WanPhase,
        WanState,
    };
}

/// Something that happened (`events.proto`).
pub mod events {
    pub use crate::generated::Event;
}

/// The API's envelope, requests and responses (`api.proto`). The gRPC service code lives in
/// `openfeo-api`, which generates it against these types.
pub mod api {
    pub use crate::generated::{
        Auth, ChangePasswordRequest, ChangePasswordResponse, ClientMsg, Error, ErrorCode,
        GetStateRequest, GetStateResponse, GetStatusResponse, LoginRequest, LoginResponse,
        LogoutRequest, LogoutResponse, Request, Response, ServerMsg, Session,
        SetInitialPasswordRequest, SetInitialPasswordResponse, Subscribe, SubscribeRequest,
        SubscribeResponse, Telemetry, Unsubscribe, client_msg, request, response, server_msg,
        subscribe_response, telemetry,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_uses_proto_field_names_and_round_trips() {
        let cfg = Config {
            config_version: 1,
            lans: vec![Lan {
                name: "lan0".into(),
                ports: vec!["p2".into()],
                ipv4: "192.168.1.1/24".into(),
                dhcp: None,
                reaches: Vec::new(),
                ipv6: String::new(),
                ra: None,
                ipv6_index: 0,
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["config_version"], 1);
        assert_eq!(json["lans"][0]["ipv4"], "192.168.1.1/24");
        assert_eq!(serde_json::from_value::<Config>(json).unwrap(), cfg);
    }

    #[test]
    fn state_json_uses_the_proto_field_names() {
        let wan = state::WanState {
            name: "wan0".into(),
            default4: true,
            phase_since_unix_ms: Some(5),
            ..Default::default()
        };
        let snapshot = state::State {
            generation: 7,
            wans: vec![wan],
            ..Default::default()
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        // The canonical mapping: 64-bit integers are strings.
        assert_eq!(json["generation"], "7");
        assert_eq!(json["wans"][0]["default4"], true);
        // snake_case, as config.toml's keys are.
        assert_eq!(json["wans"][0]["phase_since_unix_ms"], "5");
    }
}
