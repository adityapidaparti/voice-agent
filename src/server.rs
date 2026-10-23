//! Loopback-only simulation controller. Production identity and deployment are release gates.
use crate::controller::{Controller, Principal, Role};
use crate::provider::{verify_and_normalize, Simulation, SyntheticProvider};
use crate::{now, Error, Result};
use ring::hmac;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const MAX_BODY: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRequest {
    intent: crate::contract::Intent,
    via: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    intent: crate::contract::Intent,
    approval: String,
    idempotency_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndRequest {
    reason: String,
}

fn token_matches(candidate: &str, expected: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"voice-simulation-token-comparison");
    hmac::verify(
        &key,
        candidate.as_bytes(),
        hmac::sign(&key, expected.as_bytes()).as_ref(),
    )
    .is_ok()
}

fn authenticate(request: &Request) -> Result<Principal> {
    let values: Vec<_> = request
        .headers()
        .iter()
        .filter(|h| h.field.equiv("Authorization"))
        .collect();
    if values.len() != 1 {
        return Err(Error::new("authentication_required", 3));
    }
    let value = values[0].value.as_str();
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(Error::new("authentication_required", 3))?;
    let role = if token_matches(token, "synthetic-owner-token") {
        Role::User
    } else if token_matches(token, "synthetic-coordinator-token") {
        Role::Coordinator
    } else {
        return Err(Error::new("authentication_required", 3));
    };
    Ok(Principal {
        owner: "synthetic-owner".into(),
        role,
    })
}

fn body(request: &mut Request) -> Result<Vec<u8>> {
    if request.body_length().is_some_and(|size| size > MAX_BODY) {
        return Err(Error::new("request_too_large", 2));
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BODY {
        return Err(Error::new("request_too_large", 2));
    }
    Ok(bytes)
}

fn public_operation(mut operation: crate::contract::Operation) -> Result<Value> {
    // Status needs identifiers and observations, not another copy of the approved fact packet.
    operation.intent = None;
    Ok(serde_json::to_value(operation)?)
}

fn handle(
    request: &mut Request,
    controller: &mut Controller,
    last_tick: &AtomicI64,
) -> Result<Value> {
    if request.headers().iter().any(|h| h.field.equiv("Origin")) {
        return Err(Error::new("browser_origin_not_allowed", 4));
    }
    let route = request.url().to_string();
    let method = request.method().clone();
    if route == "/v1/webhooks/retell" && method == Method::Post {
        let signatures: Vec<_> = request
            .headers()
            .iter()
            .filter(|h| h.field.equiv("X-Retell-Signature"))
            .map(|h| h.value.as_str().to_owned())
            .collect();
        if signatures.len() != 1 {
            return Err(Error::new("invalid_webhook_signature", 4));
        }
        let raw = body(request)?;
        let event = verify_and_normalize(
            &raw,
            &signatures[0],
            b"synthetic-webhook-key",
            now().saturating_mul(1000),
        )?;
        controller.ingest(event)?;
        return Ok(json!({"accepted":true}));
    }
    let principal = authenticate(request)?;
    let clock = now();
    match (method, route.as_str()) {
        (Method::Get, "/health") => Ok(json!({"simulation":true,"live_calling":false,
            "worker_healthy":clock.saturating_sub(last_tick.load(Ordering::Acquire)) <= 5})),
        (Method::Post, "/v1/approvals") => {
            let input: ApprovalRequest = serde_json::from_slice(&body(request)?)?;
            if input.via != "user" {
                return Err(Error::new("user_approval_required", 3));
            }
            Ok(serde_json::to_value(controller.approve(
                &principal,
                &input.intent,
                clock,
            )?)?)
        }
        (Method::Post, "/v1/start") => {
            let input: StartRequest = serde_json::from_slice(&body(request)?)?;
            if clock.saturating_sub(last_tick.load(Ordering::Acquire)) > 5 {
                return Err(Error::new("worker_unavailable", 4));
            }
            public_operation(controller.start(
                &principal,
                &input.intent,
                &input.approval,
                &input.idempotency_key,
                clock,
            )?)
        }
        (method, _) => {
            let segments: Vec<_> = route.split('/').collect();
            if segments.len() >= 4
                && segments[1] == "v1"
                && !crate::contract::identifier(segments[3])
            {
                return Err(Error::new("invalid_identifier", 2));
            }
            match segments.as_slice() {
                ["", "v1", "operations", id] if method == Method::Get => {
                    public_operation(controller.get(&principal, id)?)
                }
                ["", "v1", "operations", id, "result"] if method == Method::Get => Ok(
                    serde_json::to_value(controller.get(&principal, id)?.result)?,
                ),
                ["", "v1", "operations", id, "end"] if method == Method::Post => {
                    let input: EndRequest = serde_json::from_slice(&body(request)?)?;
                    public_operation(controller.end(&principal, id, &input.reason, clock)?)
                }
                ["", "v1", "approvals", id, "revoke"] if method == Method::Post => {
                    controller.revoke(&principal, id, clock)?;
                    Ok(json!({"approval_id":id,"revoked":true}))
                }
                _ => Err(Error::new("route_not_found", 2)),
            }
        }
    }
}

/// Run a deliberately local simulation. No real credentials or provider sockets are used.
pub fn run(db: PathBuf, provider_db: PathBuf, listen: SocketAddr, simulation: bool) -> Result<()> {
    if !simulation {
        return Err(Error::new("live_calling_disabled", 4));
    }
    if !listen.ip().is_loopback() {
        return Err(Error::new("simulation_requires_loopback", 4));
    }
    if db == provider_db {
        return Err(Error::new("separate_provider_database_required", 2));
    }
    // Establish the control listener before recovering any queued work.
    let server = Server::http(listen).map_err(|_| Error::new("listen_unavailable", 6))?;
    let mut controller = Controller::open(&db)?;
    let mut provider = SyntheticProvider::open(&provider_db, Simulation::Success)?;
    let mut worker = Controller::open(&db)?;
    worker.tick(&mut provider, now())?;
    let last_tick = Arc::new(AtomicI64::new(now()));
    let worker_tick = Arc::clone(&last_tick);
    std::thread::Builder::new()
        .name("voice-worker".into())
        .spawn(move || loop {
            if worker.tick(&mut provider, now()).is_ok() {
                worker_tick.store(now(), Ordering::Release);
            }
            std::thread::sleep(Duration::from_millis(200));
        })?;
    println!(
        "{}",
        json!({"status":"ready","simulation":true,"listen":server.server_addr().to_string()})
    );
    for mut request in server.incoming_requests() {
        let (status, value) = match handle(&mut request, &mut controller, &last_tick) {
            Ok(value) => (200, value),
            Err(error) => {
                let status = match error.exit {
                    2 => 400,
                    3 => 401,
                    4 => 403,
                    5 => 502,
                    _ => 503,
                };
                (status, json!({"error":error}))
            }
        };
        let mut response =
            Response::from_string(value.to_string()).with_status_code(StatusCode(status));
        response.add_header(
            Header::from_bytes("Content-Type", "application/json").expect("constant header"),
        );
        response
            .add_header(Header::from_bytes("Cache-Control", "no-store").expect("constant header"));
        // A vanished CLI must not stop the hosted worker or cause a new call.
        let _ = request.respond(response);
    }
    Err(Error::new("server_stopped", 6))
}
