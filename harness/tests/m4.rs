// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M4 part 1a in QEMU: the router's API (SPEC §8.3, §9, §12) from the LAN side, on the DHCP WAN
//! fixture. The listener and its certificate, the first password and login, the refusals (a
//! foreign `Host`, a foreign `Origin`, no token), state over three transports, events and
//! counters as the WAN goes and comes and traffic flows. `harness = false`: this binary is its
//! own runner; an optional first argument filters scenarios by substring.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use openfeo_config::api::{GetStateResponse, GetStatusResponse};
use openfeo_config::state::{State, WanPhase};
use openfeo_harness::apiclient::Api;
use openfeo_harness::daemons;
use openfeo_harness::lab::{BOOT_TIMEOUT, ISP_HTTP_BODY, Lab};
use openfeo_harness::lanclient;
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_harness::web;
use serde_json::json;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "the_api_answers_on_the_lan_over_https_and_port_80_redirects",
        run: the_api_answers_on_the_lan_over_https_and_port_80_redirects,
    },
    Scenario {
        name: "the_certificate_is_the_one_the_console_printed",
        run: the_certificate_is_the_one_the_console_printed,
    },
    Scenario {
        name: "a_router_with_no_password_lets_one_lan_client_set_it_once",
        run: a_router_with_no_password_lets_one_lan_client_set_it_once,
    },
    Scenario {
        name: "a_wrong_password_waits_longer_each_time",
        run: a_wrong_password_waits_longer_each_time,
    },
    Scenario {
        name: "a_foreign_host_and_a_foreign_origin_are_refused",
        run: a_foreign_host_and_a_foreign_origin_are_refused,
    },
    Scenario {
        name: "a_websocket_that_says_nothing_for_five_seconds_is_closed",
        run: a_websocket_that_says_nothing_for_five_seconds_is_closed,
    },
    Scenario {
        name: "state_agrees_over_grpc_websocket_and_json",
        run: state_agrees_over_grpc_websocket_and_json,
    },
    Scenario {
        name: "losing_the_wan_carrier_pushes_down_and_its_return_pushes_up",
        run: losing_the_wan_carrier_pushes_down_and_its_return_pushes_up,
    },
    Scenario {
        name: "counters_rise_while_the_lan_fetches_from_the_isp",
        run: counters_rise_while_the_lan_fetches_from_the_isp,
    },
    Scenario {
        name: "changing_the_password_ends_the_other_session",
        run: changing_the_password_ends_the_other_session,
    },
    Scenario {
        name: "nothing_answers_on_the_wan_side",
        run: nothing_answers_on_the_wan_side,
    },
    Scenario {
        name: "a_restart_of_the_router_process_logs_everyone_out",
        run: a_restart_of_the_router_process_logs_everyone_out,
    },
    Scenario {
        name: "the_api_answers_by_name_over_ipv6",
        run: the_api_answers_by_name_over_ipv6,
    },
    Scenario {
        name: "a_refused_config_keeps_its_password",
        run: a_refused_config_keeps_its_password,
    },
    Scenario {
        name: "an_unreadable_config_offers_no_first_password",
        run: an_unreadable_config_offers_no_first_password,
    },
    Scenario {
        name: "the_panel_in_a_browser_on_the_lan",
        run: the_panel_in_a_browser_on_the_lan,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The lab's DHCP configuration: WAN A on p0 takes its address from isp0's Kea, LAN on p2.
const VM_DHCP: &str = include_str!("../fixtures/vm-dhcp.toml");
/// The router's LAN address and the API's port.
const ROUTER: &str = "192.168.1.1:443";
/// The router's name.
const HOST: &str = "openfeo.home.arpa";
/// The one password the lab uses.
const PASSWORD: &str = "lab-admin-password";
const SOON: Duration = Duration::from_secs(10);
/// The API is up.
const LISTENING: &str = r"openfeo: api: listening on :443 and :80";
/// The WAN's lease, with the address captured.
const BOUND: &str = r"openfeo: wan wan0 dhcp bound (203\.0\.113\.\d+)/24 ";
/// The certificate's fingerprint as the console prints it.
const FINGERPRINT: &str = r"openfeo: tls: fingerprint sha256 ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

/// Boot the DHCP fixture with Kea on the ISP side; wait for the API and the lease; make the
/// LAN namespace a LAN host. The leased WAN address.
fn boot(lab: &mut Lab, extra_cmdline: &str) -> anyhow::Result<String> {
    lab.start_kea()?;
    lab.with_config(VM_DHCP)?;
    lab.boot(extra_cmdline)?;
    let console = lab.console()?;
    console.wait_for(&mut Cursor::default(), &re(LISTENING), BOOT_TIMEOUT)?;
    let bound = console.wait_for(&mut Cursor::default(), &re(BOUND), BOOT_TIMEOUT)?;
    lab.lan_side_host()?;
    bound
        .groups
        .first()
        .cloned()
        .flatten()
        .context("no address in the bound line")
}

/// The API as the LAN host reaches it, by the router's name.
fn api(lab: &Lab) -> anyhow::Result<Api> {
    Ok(Api::on(&lab.lan0, ROUTER.parse::<SocketAddr>()?, HOST))
}

/// No console line may carry the password.
fn password_never_logged(lab: &Lab) -> anyhow::Result<()> {
    ensure!(
        lab.console()?.count(&re(PASSWORD)) == 0,
        "the password is on the console"
    );
    Ok(())
}

/// HTTPS answers on the LAN address, by the router's name and by its address; port 80 sends a
/// browser to HTTPS; the page is the placeholder until part 1b embeds the panel.
fn the_api_answers_on_the_lan_over_https_and_port_80_redirects(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    let status = api.get("/api/status?format=json", None)?;
    ensure!(
        status.status == 200,
        "status: {} {}",
        status.status,
        status.text()
    );
    let json: serde_json::Value = status.json()?;
    ensure!(
        json["hostname"] == "openfeo" && json["domain"] == "home.arpa",
        "{json}"
    );
    ensure!(json["needs_password"] == true, "{json}");
    for header in [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ] {
        ensure!(status.header(header).is_some(), "no {header} header");
    }
    let by_address = api.as_host("192.168.1.1").get("/api/status", None)?;
    ensure!(
        by_address.status == 200,
        "by address: {}",
        by_address.status
    );
    let page = api.get("/", None)?;
    ensure!(
        page.status == 200
            && page
                .text()
                .contains("The panel was not built into this binary"),
        "the page: {} {}",
        page.status,
        page.text()
    );
    let redirect = api.request(false, "GET", "/somewhere?x=1", &[], &[])?;
    ensure!(redirect.status == 308, "port 80: {}", redirect.status);
    ensure!(
        redirect.header("location") == Some("https://openfeo.home.arpa/somewhere?x=1"),
        "location {:?}",
        redirect.header("location")
    );
    Ok(())
}

/// The certificate the listener presents is the one whose fingerprint the console printed, and
/// one macOS accepts (ADR-0024): the two names, `serverAuth`, no more than 825 days.
fn the_certificate_is_the_one_the_console_printed(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let printed = lab
        .console()?
        .wait_for(&mut Cursor::default(), &re(FINGERPRINT), SOON)?
        .groups
        .first()
        .cloned()
        .flatten()
        .context("no fingerprint on the console")?;
    let reply = api(lab)?.get("/api/status?format=json", None)?;
    let der = reply
        .peer_cert_der
        .clone()
        .context("no certificate presented")?;
    ensure!(
        openfeo_api::cert::fingerprint(&der) == printed,
        "presented {} but the console printed {printed}",
        openfeo_api::cert::fingerprint(&der)
    );
    let json: serde_json::Value = reply.json()?;
    ensure!(
        json["tls_fingerprint"] == printed.as_str(),
        "status says {json}"
    );
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|err| anyhow::anyhow!("the certificate does not parse: {err}"))?;
    let names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .context("no subject alternative name")?
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            _ => None,
        })
        .collect();
    ensure!(names == ["openfeo", "openfeo.home.arpa"], "names {names:?}");
    ensure!(
        cert.extended_key_usage()
            .ok()
            .flatten()
            .is_some_and(|usage| usage.value.server_auth),
        "no serverAuth"
    );
    let days =
        (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) / 86_400;
    ensure!(days == 825, "valid for {days} days");
    Ok(())
}

/// Before any password the API answers only status and the first-password call; one LAN client
/// sets it and is logged in; a second attempt is refused; the hash is in the config file and
/// survives a reset; the password never reaches the console.
fn a_router_with_no_password_lets_one_lan_client_set_it_once(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    ensure!(
        api.get("/api/state", None)?.status == 401,
        "state without a password"
    );
    let early = api.post("/api/login", &json!({ "password": PASSWORD }))?;
    ensure!(
        early.status == 401,
        "login before a password: {}",
        early.status
    );
    let token = api.claim(PASSWORD)?;
    let state = api.get("/api/state?format=json", Some(&token))?;
    ensure!(
        state.status == 200,
        "state with the new session: {}",
        state.status
    );
    let again = api.post("/api/password", &json!({ "password": "another-password" }))?;
    ensure!(
        again.status == 409,
        "a second first password: {}",
        again.status
    );
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: admin: password set from 192\.168\.1\.2"),
        SOON,
    )?;
    let status = status(&api)?;
    ensure!(
        !status.needs_password && !status.config_refused,
        "{status:?}"
    );
    // A reset: the session is gone (sessions live in memory), the password is not.
    reset_and_wait(lab)?;
    ensure!(
        api.get("/api/state", Some(&token))?.status == 401,
        "the old session survived a reset"
    );
    let token = api.login(PASSWORD)?;
    let state = state_json(&api, &token)?;
    ensure!(
        state.wans.first().is_some_and(|wan| wan.name == "wan0"),
        "{state:?}"
    );
    password_never_logged(lab)
}

/// Reset the machine and wait for the API to come back.
fn reset_and_wait(lab: &mut Lab) -> anyhow::Result<()> {
    let before = lab.console()?.count(&re(LISTENING));
    lab.qmp()?.system_reset()?;
    wait_listening_again(lab, before)
}

/// Wait until the console has shown the listening line more than `before` times.
fn wait_listening_again(lab: &Lab, before: usize) -> anyhow::Result<()> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    while lab.console()?.count(&re(LISTENING)) <= before {
        ensure!(Instant::now() < deadline, "the API did not come back");
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// The state as `GET /api/state?format=json` gives it.
fn state_json(api: &Api, token: &str) -> anyhow::Result<State> {
    let reply = api.get("/api/state?format=json", Some(token))?;
    ensure!(
        reply.status == 200,
        "state: {} {}",
        reply.status,
        reply.text()
    );
    reply.json::<GetStateResponse>()?.state.context("no state")
}

/// `GET /api/status`, typed: the canonical JSON leaves out a field that is false.
fn status(api: &Api) -> anyhow::Result<GetStatusResponse> {
    let reply = api.get("/api/status?format=json", None)?;
    ensure!(
        reply.status == 200,
        "status: {} {}",
        reply.status,
        reply.text()
    );
    reply.json()
}

fn retry_after(reply: &openfeo_harness::apiclient::Reply) -> Option<&str> {
    reply.header("retry-after")
}

/// A wrong password is refused, and then even the right one must wait: 1 s after the first
/// failure, 2 s after the second.
fn a_wrong_password_waits_longer_each_time(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    api.claim(PASSWORD)?;
    let wrong = json!({ "password": "not-the-password" });
    let right = json!({ "password": PASSWORD });
    for longest in [1u64, 2] {
        let refused = api.post("/api/login", &wrong)?;
        ensure!(
            refused.status == 401,
            "a wrong password: {}",
            refused.status
        );
        let held = api.post("/api/login", &right)?;
        ensure!(
            held.status == 429,
            "the right password at once: {}",
            held.status
        );
        // What is left of the wait, in whole seconds rounded up: the full wait if the retry
        // was prompt, less on a slow runner, never more and never none.
        let left: u64 = retry_after(&held)
            .context("no retry-after")?
            .parse()
            .context("retry-after is not a number")?;
        ensure!(
            (1..=longest).contains(&left),
            "retry-after {left}, expected 1 to {longest}"
        );
        std::thread::sleep(Duration::from_millis(left * 1_000 + 100));
    }
    let token = api.login(PASSWORD)?;
    ensure!(
        api.get("/api/state", Some(&token))?.status == 200,
        "the session works"
    );
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: admin: login refused from 192\.168\.1\.2 \(wait 2 s\)"),
        SOON,
    )?;
    password_never_logged(lab)
}

/// SPEC §12's acceptance: a WebSocket upgrade with a foreign `Origin` is refused. So is any
/// request that calls the router by another name; a script, which sends no `Origin`, is taken.
fn a_foreign_host_and_a_foreign_origin_are_refused(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    let token = api.claim(PASSWORD)?;
    let foreign = api.request(true, "GET", "/api/status", &[("host", "evil.example")], &[])?;
    ensure!(foreign.status == 421, "a foreign Host: {}", foreign.status);
    match api.ws(Some("https://evil.example"))? {
        Err(403) => {}
        Err(status) => anyhow::bail!("a foreign Origin was answered {status}, not 403"),
        Ok(_) => anyhow::bail!("a foreign Origin was upgraded"),
    }
    ensure!(
        matches!(api.ws(Some("http://openfeo.home.arpa"))?, Err(403)),
        "an http origin was not refused"
    );
    ensure!(
        api.ws(Some("https://openfeo.home.arpa"))?.is_ok(),
        "the router's own origin was refused"
    );
    let mut script = api.ws_with(&token)?;
    let state = script.request_state()?;
    ensure!(
        state.wans.first().is_some_and(|wan| wan.name == "wan0"),
        "{state:?}"
    );
    Ok(())
}

/// A socket that never authenticates is closed with 4401 after five seconds.
fn a_websocket_that_says_nothing_for_five_seconds_is_closed(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    let mut ws = api
        .ws(None)?
        .map_err(|status| anyhow::anyhow!("the upgrade was refused with {status}"))?;
    let opened = Instant::now();
    let code = ws.closed_with(Duration::from_secs(12))?;
    let after = opened.elapsed();
    ensure!(code == Some(4401), "closed with {code:?}");
    ensure!(
        (Duration::from_secs(4)..Duration::from_secs(8)).contains(&after),
        "closed after {after:?}"
    );
    Ok(())
}

/// The same state over gRPC, over the WebSocket and as JSON: the WAN up with Kea's lease and
/// the default route, the LAN with its address, the WAN port with the speed the lab gave it.
fn state_agrees_over_grpc_websocket_and_json(lab: &mut Lab) -> anyhow::Result<()> {
    let leased = boot(lab, "")?;
    let api = api(lab)?;
    let token = api.claim(PASSWORD)?;
    let over_grpc = api.grpc_state(&token)?;
    let over_ws = api.ws_with(&token)?.request_state()?;
    let over_json = state_json(&api, &token)?;
    for (name, other) in [("the WebSocket", &over_ws), ("JSON", &over_json)] {
        ensure!(over_grpc.wans == other.wans, "wans differ over {name}");
        ensure!(over_grpc.lans == other.lans, "lans differ over {name}");
        ensure!(over_grpc.ports == other.ports, "ports differ over {name}");
        ensure!(
            over_grpc.addresses == other.addresses,
            "addresses differ over {name}"
        );
    }
    let wan = over_grpc.wans.first().context("no WAN")?;
    ensure!(wan.name == "wan0" && wan.phase() == WanPhase::Up, "{wan:?}");
    ensure!(wan.ipv4 == format!("{leased}/24"), "{wan:?}");
    ensure!(wan.default4 && wan.gateway4 == "203.0.113.1", "{wan:?}");
    ensure!(wan.phase_since_unix_ms.is_some(), "{wan:?}");
    let lan = over_grpc.lans.first().context("no LAN")?;
    ensure!(
        lan.name == "lan0" && lan.interface == "br-lan0" && lan.ipv4 == "192.168.1.1/24",
        "{lan:?}"
    );
    let p0 = over_grpc
        .ports
        .iter()
        .find(|port| port.name == "p0")
        .context("no p0")?;
    ensure!(p0.carrier && p0.speed_mbps == Some(1000), "{p0:?}");
    let p2 = over_grpc
        .ports
        .iter()
        .find(|port| port.name == "p2")
        .context("no p2")?;
    ensure!(p2.carrier && p2.speed_mbps.is_none(), "{p2:?}");
    let origin = |address: &str| {
        over_grpc
            .addresses
            .iter()
            .find(|held| held.address == address)
            .map(openfeo_config::state::AddressState::origin)
    };
    ensure!(
        origin(&format!("{leased}/24")) == Some(openfeo_config::state::AddressOrigin::Dhcp),
        "the lease's address: {:?}",
        over_grpc.addresses
    );
    ensure!(
        origin("192.168.1.1/24") == Some(openfeo_config::state::AddressOrigin::Config),
        "the LAN's address: {:?}",
        over_grpc.addresses
    );
    let system = over_grpc.system.context("no system")?;
    ensure!(system.healthy, "unhealthy: {:?}", system.unhealthy);
    ensure!(
        system.hostname == "openfeo" && !system.version.is_empty(),
        "{system:?}"
    );
    Ok(())
}

/// Taking the WAN port's carrier away pushes `wan.wan0.down` (no carrier) and a state with the
/// WAN down; its return pushes `up`. A subscriber that arrives afterwards gets both from the
/// backlog.
fn losing_the_wan_carrier_pushes_down_and_its_return_pushes_up(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    let token = api.claim(PASSWORD)?;
    let mut events = api.ws_with(&token)?;
    events.subscribe("events", 0)?;
    let mut states = api.ws_with(&token)?;
    states.subscribe("state", 0)?;
    states.state_where(SOON, |state| state.wans[0].phase() == WanPhase::Up)?;
    let mut qmp = lab.qmp()?;
    qmp.set_link("p0", false)?;
    let down = events.event(SOON, "wan.wan0.down")?;
    ensure!(
        down.fields.get("reason").map(String::as_str) == Some("no carrier"),
        "{down:?}"
    );
    ensure!(down.time_unix_ms > 0 && down.uptime_ms > 0, "{down:?}");
    let state = states.state_where(SOON, |state| state.wans[0].phase() == WanPhase::Down)?;
    ensure!(state.wans[0].reason == "no carrier", "{:?}", state.wans[0]);
    qmp.set_link("p0", true)?;
    events.event(Duration::from_secs(60), "wan.wan0.up")?;
    let state = states.state_where(SOON, |state| state.wans[0].phase() == WanPhase::Up)?;
    ensure!(state.wans[0].reason.is_empty(), "{:?}", state.wans[0]);
    let mut late = api.ws_with(&token)?;
    late.subscribe("events", 50)?;
    late.event(SOON, "wan.wan0.down")?;
    late.event(SOON, "wan.wan0.up")?;
    Ok(())
}

/// An HTTP target in the ISP namespace on `203.0.113.1:8080`, up before this returns.
fn isp_http_target(lab: &Lab) -> anyhow::Result<daemons::Daemon> {
    let server = daemons::http_server(
        &lab.isp0,
        "203.0.113.1",
        8080,
        &lab.run_dir.join("http-isp"),
        ISP_HTTP_BODY,
    )?;
    server
        .log
        .wait_for(&mut Cursor::default(), &re(r"Serving HTTP on"), SOON)?;
    Ok(server)
}

/// Counters are pushed about a second apart, and what the LAN host fetches through the router
/// shows on the WAN port; a connection is tracked.
fn counters_rise_while_the_lan_fetches_from_the_isp(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "")?;
    let api = api(lab)?;
    let token = api.claim(PASSWORD)?;
    let _server = isp_http_target(lab)?;
    let mut ws = api.ws_with(&token)?;
    ws.subscribe("counters", 0)?;
    let of = |counters: &openfeo_config::state::Counters, name: &str| {
        counters
            .links
            .iter()
            .find(|link| link.name == name)
            .cloned()
    };
    let first = ws.counters(SOON)?;
    let before = of(&first, "p0").context("no p0 in the counters")?;
    let second = ws.counters(SOON)?;
    let apart = second.monotonic_ms.saturating_sub(first.monotonic_ms);
    ensure!((800..=2_500).contains(&apart), "samples {apart} ms apart");
    for _ in 0..5 {
        let body = lanclient::http_get(
            &lab.lan0,
            "203.0.113.1:8080".parse()?,
            "/",
            Duration::from_secs(5),
        )?;
        ensure!(body == ISP_HTTP_BODY, "unexpected body {body:?}");
    }
    let deadline = Instant::now() + SOON;
    loop {
        let sample = ws.counters(SOON)?;
        let now = of(&sample, "p0").context("no p0 in the counters")?;
        let grew = now.rx_bytes.saturating_sub(before.rx_bytes);
        if grew >= 5 * ISP_HTTP_BODY.len() as u64
            && now.rx_packets > before.rx_packets
            && now.tx_packets > before.tx_packets
            && sample.conntrack >= 1
            && sample.conntrack_max > 0
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "the fetches did not show: {before:?} then {now:?}, conntrack {} of {}",
            sample.conntrack,
            sample.conntrack_max
        );
    }
}

/// Changing the password over one session's socket closes the other session's socket with
/// 4401 and ends its token; the caller's stays; the new password logs in and the old does not.
fn changing_the_password_ends_the_other_session(lab: &mut Lab) -> anyhow::Result<()> {
    use openfeo_config::api::{ChangePasswordRequest, request, server_msg};
    boot(lab, "")?;
    let api = api(lab)?;
    let mine = api.claim(PASSWORD)?;
    let other = api.login(PASSWORD)?;
    let mut my_socket = api.ws_with(&mine)?;
    let mut other_socket = api.ws_with(&other)?;
    let reply = my_socket.ask(request::Body::ChangePassword(ChangePasswordRequest {
        old_password: PASSWORD.to_owned(),
        new_password: "lab-admin-password-2".to_owned(),
    }))?;
    ensure!(
        matches!(reply, server_msg::Body::Response(_)),
        "the change: {reply:?}"
    );
    let code = other_socket.closed_with(SOON)?;
    ensure!(code == Some(4401), "the other socket closed with {code:?}");
    ensure!(
        api.get("/api/state", Some(&other))?.status == 401,
        "the other token lives"
    );
    ensure!(
        api.get("/api/state", Some(&mine))?.status == 200,
        "the caller's token died"
    );
    my_socket.request_state()?;
    api.login("lab-admin-password-2")?;
    let old = api.post("/api/login", &json!({ "password": PASSWORD }))?;
    ensure!(old.status == 401, "the old password: {}", old.status);
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: admin: password changed from 192\.168\.1\.2"),
        SOON,
    )?;
    ensure!(
        lab.console()?.count(&re("lab-admin-password")) == 0,
        "a password is on the console"
    );
    Ok(())
}

/// From the ISP side nothing answers on 443 or 80 at the WAN address; from the LAN both do.
fn nothing_answers_on_the_wan_side(lab: &mut Lab) -> anyhow::Result<()> {
    let leased = boot(lab, "")?;
    let from_isp = Api::on(&lab.isp0, format!("{leased}:443").parse()?, HOST);
    for port in [443, 80] {
        ensure!(
            !from_isp.connects(port, Duration::from_secs(3))?,
            "port {port} answered from the ISP side"
        );
    }
    let from_lan = api(lab)?;
    for port in [443, 80] {
        ensure!(
            from_lan.connects(port, Duration::from_secs(3))?,
            "port {port} did not answer from the LAN"
        );
    }
    // And the WAN address reached from the LAN is still the router: a LAN client may use it.
    let by_wan_address = Api::on(&lab.lan0, format!("{leased}:443").parse()?, &leased);
    ensure!(
        by_wan_address.get("/api/status", None)?.status == 200,
        "the WAN address from the LAN"
    );
    Ok(())
}

/// Sessions live in memory: when PID 1 restarts the router process, an old token is refused,
/// the API is back, the password still logs in and the certificate is the same one.
fn a_restart_of_the_router_process_logs_everyone_out(lab: &mut Lab) -> anyhow::Result<()> {
    boot(lab, "openfeo.chaos=child-exit:20")?;
    let api = api(lab)?;
    let token = api.claim(PASSWORD)?;
    let fingerprint_of = |api: &Api| -> anyhow::Result<String> {
        let status: serde_json::Value = api.get("/api/status?format=json", None)?.json()?;
        status["tls_fingerprint"]
            .as_str()
            .map(str::to_owned)
            .context("no fingerprint")
    };
    let before = fingerprint_of(&api)?;
    ensure!(
        api.get("/api/state", Some(&token))?.status == 200,
        "the session works"
    );
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: chaos child-exit: exiting with status 3"),
        Duration::from_secs(40),
    )?;
    wait_listening_again(lab, 1)?;
    ensure!(
        api.get("/api/state", Some(&token))?.status == 401,
        "the old session survived the restart"
    );
    ensure!(fingerprint_of(&api)? == before, "the certificate changed");
    let token = api.login(PASSWORD)?;
    ensure!(
        api.get("/api/state", Some(&token))?.status == 200,
        "the new session works"
    );
    Ok(())
}

/// The static IPv6 configuration of M2 part 2: lan0 at `2001:db8:1:222::1/64`.
const VM_IPV6: &str = include_str!("../fixtures/vm-ipv6.toml");

/// The router's name resolves to its LAN addresses and its loopback /128s; the API answers on
/// every one of them over IPv6, and by an address literal in brackets.
fn the_api_answers_by_name_over_ipv6(lab: &mut Lab) -> anyhow::Result<()> {
    use openfeo_harness::daemons::RadvdConfig;
    lab.add_lan1()?;
    lab.start_radvd(&RadvdConfig::isp("wan0"))?;
    lab.start_dnsmasq()?;
    lab.with_config(VM_IPV6)?;
    lab.boot("")?;
    lab.console()?
        .wait_for(&mut Cursor::default(), &re(LISTENING), BOOT_TIMEOUT)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: ready generation=\d+"),
        BOOT_TIMEOUT,
    )?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;
    Lab::host6(
        &lab.lan0,
        "lan0",
        "2001:db8:1:222::23/64",
        "2001:db8:1:222::1",
    )?;
    // The LAN host's own address has to pass duplicate address detection before it is used.
    std::thread::sleep(Duration::from_secs(3));
    let answer = lanclient::dig(
        &lab.lan0,
        "192.168.1.1".parse()?,
        HOST,
        "AAAA",
        &[],
        Duration::from_secs(6),
    )?;
    let addresses: Vec<String> = answer
        .answers
        .iter()
        .filter(|(_, _, kind, _)| kind == "AAAA")
        .map(|(_, _, _, address)| address.clone())
        .collect();
    ensure!(
        addresses
            .iter()
            .any(|address| address == "2001:db8:1:222::1"),
        "the name's AAAA records: {addresses:?}"
    );
    for address in &addresses {
        let by_name = Api::on(&lab.lan0, format!("[{address}]:443").parse()?, HOST);
        let reply = by_name
            .get("/api/status", None)
            .with_context(|| format!("by name at {address}"))?;
        ensure!(
            reply.status == 200,
            "by name at {address}: {}",
            reply.status
        );
    }
    let literal = Api::on(
        &lab.lan0,
        "[2001:db8:1:222::1]:443".parse()?,
        "[2001:db8:1:222::1]",
    );
    ensure!(
        literal.get("/api/status", None)?.status == 200,
        "by the address literal"
    );
    let redirect = literal.request(false, "GET", "/x", &[], &[])?;
    ensure!(
        redirect.status == 308
            && redirect.header("location") == Some("https://[2001:db8:1:222::1]/x"),
        "port 80 over IPv6: {} {:?}",
        redirect.status,
        redirect.header("location")
    );
    Ok(())
}

/// Boot `config` with nothing on the ISP side; wait for the API; make the LAN namespace a host.
fn boot_config(lab: &mut Lab, config: &str) -> anyhow::Result<()> {
    lab.with_config(config)?;
    lab.boot("")?;
    lab.console()?
        .wait_for(&mut Cursor::default(), &re(LISTENING), BOOT_TIMEOUT)?;
    lab.lan_side_host()
}

/// A config that is refused for one reason still holds its password: the router runs on
/// first-boot defaults, the owner logs in, the state says what is wrong, and nobody is offered
/// a first password.
fn a_refused_config_keeps_its_password(lab: &mut Lab) -> anyhow::Result<()> {
    let hash = openfeo_api::auth::password::hash(PASSWORD)
        .map_err(|err| anyhow::anyhow!("hashing the lab's password: {err}"))?;
    let config = format!(
        "{}\n[admin]\npassword_hash = \"{hash}\"\n",
        VM_DHCP.replace("ipv4 = \"192.168.1.1/24\"", "ipv4 = \"not-an-address\"")
    );
    ensure!(config != VM_DHCP, "the fixture's LAN address was not found");
    boot_config(lab, &config)?;
    lab.console()?.wait_for(
        &mut Cursor::default(),
        &re(r"openfeo: config: invalid \(\d+ errors\); using first-boot defaults"),
        SOON,
    )?;
    let api = api(lab)?;
    let status = status(&api)?;
    ensure!(
        !status.needs_password && status.config_refused && !status.config_unreadable,
        "{status:?}"
    );
    let first = api.post(
        "/api/password",
        &json!({ "password": "someone-elses-password" }),
    )?;
    ensure!(
        first.status == 409,
        "a first password over a refused config: {}",
        first.status
    );
    let token = api.login(PASSWORD)?;
    let state = state_json(&api, &token)?;
    let problem = state
        .system
        .and_then(|system| system.config_problem)
        .context("the state does not say the config was refused")?;
    ensure!(problem.reason.starts_with("invalid ("), "{problem:?}");
    ensure!(
        problem
            .violations
            .iter()
            .any(|violation| violation.path == "lans[0].ipv4" && violation.code == "invalid_cidr"),
        "{problem:?}"
    );
    password_never_logged(lab)
}

/// A config file that is not TOML has no password to honour, and none may be set over it.
fn an_unreadable_config_offers_no_first_password(lab: &mut Lab) -> anyhow::Result<()> {
    boot_config(lab, "config_version = = 1\n")?;
    let api = api(lab)?;
    let status = status(&api)?;
    ensure!(
        !status.needs_password && status.config_refused && status.config_unreadable,
        "{status:?}"
    );
    let first = api.post("/api/password", &json!({ "password": PASSWORD }))?;
    ensure!(first.status == 409, "a first password: {}", first.status);
    let login = api.post("/api/login", &json!({ "password": PASSWORD }))?;
    ensure!(login.status == 401, "a login: {}", login.status);
    Ok(())
}

/// Node and Chromium run inside the LAN namespace and reach the router as a LAN host does:
/// Node by the LAN address, the browser by the router's name, each trusting the router's own
/// certificate. Skipped, with the reason, on a machine without Node or Playwright's Chromium.
fn the_panel_in_a_browser_on_the_lan(lab: &mut Lab) -> anyhow::Result<()> {
    web::ready()?;
    boot(lab, "")?;
    let mut node = web::node(&lab.lan0)?;
    node.args([
        "--input-type=module",
        "-e",
        "const r = await fetch('https://192.168.1.1/api/status?format=json'); \
         console.log('hostname', (await r.json()).hostname)",
    ])
    .env("NODE_TLS_REJECT_UNAUTHORIZED", "0");
    let log = lab.run_dir.join("node.log");
    web::run_logged(node, &log, Duration::from_secs(30))?;
    let said = std::fs::read_to_string(&log)?;
    ensure!(
        said.contains("hostname openfeo"),
        "node did not read the status: {said}"
    );
    let mut playwright = web::tool(&lab.lan0, "playwright")?;
    playwright
        .args(["test", "--config", "panel/playwright.config.ts"])
        .env("OPENFEO_PANEL_URL", format!("https://{HOST}"))
        .env("OPENFEO_PANEL_RESOLVE", format!("{HOST} 192.168.1.1"))
        .env("OPENFEO_E2E_OUT", lab.run_dir.join("e2e"));
    web::run_logged(
        playwright,
        &lab.run_dir.join("playwright.log"),
        Duration::from_secs(180),
    )
}
