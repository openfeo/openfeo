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
pub mod secrets;
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
        AddressOrigin, AddressState, ConfigEffect, ConfigEffectKind, ConfigProblem,
        ConfigViolation, Counters, LanState, LinkCounters, PendingConfig, PortState, PortUse,
        PortUseKind, State, SystemState, WanKind, WanPhase, WanState,
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
        ApplyConfigRequest, ApplyConfigResponse, Auth, Caller, ChangePasswordRequest,
        ChangePasswordResponse, ClientMsg, ConfirmConfigRequest, ConfirmConfigResponse, Error,
        ErrorCode, GetConfigRequest, GetConfigResponse, GetStateRequest, GetStateResponse,
        GetStatusResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, Request,
        Response, RevertConfigRequest, RevertConfigResponse, ServerMsg, Session,
        SetInitialPasswordRequest, SetInitialPasswordResponse, Subscribe, SubscribeRequest,
        SubscribeResponse, Telemetry, Unsubscribe, ValidateConfigRequest, ValidateConfigResponse,
        client_msg, request, response, server_msg, subscribe_response, telemetry,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A protobuf `bool` left out is `false`, so the field is the one that asks for the path
    /// with no way back: a request that says nothing gets the countdown (SPEC §5.5, §8.3).
    #[test]
    fn a_request_that_says_nothing_asks_for_the_countdown() {
        let request = api::ApplyConfigRequest::default();
        assert!(!request.immediate);
        assert_eq!(request.timeout_secs, 0, "0 is the router's default window");
        assert_eq!(request.tag, "");
        // Decoded from no bytes at all it is the same.
        let decoded = <api::ApplyConfigRequest as prost::Message>::decode(&[][..]).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn a_pending_change_travels_in_the_state_under_its_json_name() {
        let system = state::SystemState {
            pending_config: Some(state::PendingConfig {
                applied_uptime_ms: 1_000,
                reverts_uptime_ms: 121_000,
                window_secs: 120,
                effects: vec![state::ConfigEffect {
                    subject: "lan0".to_owned(),
                    kind: state::ConfigEffectKind::LanAddressMoves.into(),
                }],
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&system).unwrap();
        // snake_case, as every state field is; 64-bit integers are strings.
        let pending = &json["pending_config"];
        assert_eq!(pending["window_secs"], 120);
        assert_eq!(pending["reverts_uptime_ms"], "121000");
        assert_eq!(pending["effects"][0]["subject"], "lan0");
        assert_eq!(
            pending["effects"][0]["kind"],
            "CONFIG_EFFECT_KIND_LAN_ADDRESS_MOVES"
        );
        assert_eq!(
            serde_json::from_value::<state::SystemState>(json).unwrap(),
            system
        );
        // With nothing pending the key is not there at all.
        let quiet = serde_json::to_value(state::SystemState::default()).unwrap();
        assert!(quiet.get("pending_config").is_none(), "{quiet}");
    }

    #[test]
    fn the_config_service_has_a_message_each_way_for_every_call() {
        // Each exists and is its own type; the envelope carries all five.
        let _ = (
            api::GetConfigRequest::default(),
            api::ValidateConfigRequest::default(),
            api::ConfirmConfigRequest::default(),
            api::RevertConfigRequest::default(),
            api::ConfirmConfigResponse::default(),
            api::RevertConfigResponse::default(),
        );
        let got = api::GetConfigResponse {
            config: Some(Config::default()),
            tag: "0".repeat(32),
            confirm_secs: 120,
        };
        assert_eq!(got.confirm_secs, 120);
        let said = api::ValidateConfigResponse {
            violations: Vec::new(),
            effects: Vec::new(),
            caller: Some(api::Caller {
                connection_drops: true,
                lan_changes: true,
                lan: "lan0".to_owned(),
                router_after: "192.168.2.1".to_owned(),
            }),
        };
        assert!(said.caller.is_some());
        let applied = api::ApplyConfigResponse {
            tag: "1".repeat(32),
        };
        assert_eq!(applied.tag.len(), 32);
        let asked = api::Request {
            body: Some(api::request::Body::ApplyConfig(
                api::ApplyConfigRequest::default(),
            )),
        };
        let answered = api::Response {
            body: Some(api::response::Body::ApplyConfig(applied)),
        };
        assert!(asked.body.is_some() && answered.body.is_some());
        for body in [
            api::request::Body::GetConfig(api::GetConfigRequest {}),
            api::request::Body::ValidateConfig(api::ValidateConfigRequest::default()),
            api::request::Body::ConfirmConfig(api::ConfirmConfigRequest {}),
            api::request::Body::RevertConfig(api::RevertConfigRequest {}),
        ] {
            let _ = api::Request { body: Some(body) };
        }
    }

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
