//! Durable controller runtime. Hosted mode is loopback-only behind an operator-managed TLS proxy.
use crate::config::{CredentialFile, HostedConfig};
use crate::controller::{Controller, Principal, Role};
use crate::provider::{verify_and_normalize, Simulation, SyntheticProvider};
use crate::retell::RetellProvider;
use crate::workflow::HttpWorkflow;
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

struct Runtime {
    credentials_file: Option<PathBuf>,
    webhook_key: Vec<u8>,
}
impl Runtime {
    fn simulation(&self) -> bool {
        self.credentials_file.is_none()
    }
}

fn authenticate(request: &Request, runtime: &Runtime, clock: i64) -> Result<Principal> {
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
    if let Some(path) = &runtime.credentials_file {
        // An atomic replacement of the private hash file revokes/rotates tokens immediately.
        return CredentialFile::load(path)?.authenticate(token, clock);
    }
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
    last_writeback: &AtomicI64,
    runtime: &Runtime,
) -> Result<Value> {
    if request.headers().iter().any(|h| h.field.equiv("Origin")) {
        return Err(Error::new("browser_origin_not_allowed", 4));
    }
    let route = request.url().to_string();
    let method = request.method().clone();
    if matches!(
        route.as_str(),
        "/v1/webhooks/retell" | "/v1/functions/observe" | "/v1/functions/report"
    ) && method == Method::Post
    {
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
        let clock_ms = now().saturating_mul(1000);
        if route == "/v1/functions/observe" {
            let observation = crate::observations::verify_phase(
                &raw,
                &signatures[0],
                &runtime.webhook_key,
                clock_ms,
            )?;
            controller.ingest_phase(observation)?;
        } else if route == "/v1/functions/report" {
            let observation = crate::observations::verify_report(
                &raw,
                &signatures[0],
                &runtime.webhook_key,
                clock_ms,
            )?;
            controller.ingest_report(observation)?;
        } else {
            let event = verify_and_normalize(&raw, &signatures[0], &runtime.webhook_key, clock_ms)?;
            controller.ingest(event)?;
        }
        return Ok(json!({"accepted":true}));
    }
    let clock = now();
    let principal = authenticate(request, runtime, clock)?;
    match (method, route.as_str()) {
        (Method::Get, "/health") => Ok(json!({"simulation":runtime.simulation(),
            "live_calling_configured":!runtime.simulation(),"live_acceptance_verified":false,
            "worker_healthy":clock.saturating_sub(last_tick.load(Ordering::Acquire)) <= 5,
            "writeback_healthy":runtime.simulation() || clock.saturating_sub(last_writeback.load(Ordering::Acquire)) <= 15})),
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
                    let mut result = public_operation(controller.get(&principal, id)?)?;
                    result["canonical_writeback"] =
                        serde_json::to_value(controller.writeback_status(&principal, id)?)?;
                    Ok(result)
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
    let controller = Controller::open(&db)?;
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
    let runtime = Runtime {
        credentials_file: None,
        webhook_key: b"synthetic-webhook-key".to_vec(),
    };
    serve_requests(
        server,
        controller,
        last_tick,
        Arc::new(AtomicI64::new(0)),
        runtime,
    )
}

fn serve_requests(
    server: Server,
    mut controller: Controller,
    last_tick: Arc<AtomicI64>,
    last_writeback: Arc<AtomicI64>,
    runtime: Runtime,
) -> Result<()> {
    for mut request in server.incoming_requests() {
        let (status, value) = match handle(
            &mut request,
            &mut controller,
            &last_tick,
            &last_writeback,
            &runtime,
        ) {
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

/// Start configured integration code. This function is never called by config-check.
/// Installing a host, secrets or provider resources remains an explicit operator action.
pub fn run_hosted(config: HostedConfig, enable_live_calling: bool) -> Result<()> {
    if !enable_live_calling {
        return Err(Error::new("explicit_live_runtime_enablement_required", 4));
    }
    config.validate(now())?;
    let (retell_key, workflow_token) = config.runtime_secrets()?;
    let authority = || HttpWorkflow::new(&config.workflow_base_url, workflow_token.clone());
    let mut controller = Controller::open_configured(
        &config.database,
        config.policy.clone(),
        Box::new(authority()?),
    )?;
    if let Err(error) = controller.set_starts_enabled(config.starts_enabled) {
        // Recovery must continue serving end/status even after a latched safety incident.
        if error.code != "safety_incident_requires_resolution" {
            return Err(error);
        }
    }
    let mut worker = Controller::open_configured(
        &config.database,
        config.policy.clone(),
        Box::new(authority()?),
    )?;
    let mut writer = Controller::open_configured(
        &config.database,
        config.policy.clone(),
        Box::new(authority()?),
    )?;
    let mut sink = authority()?;
    let mut provider = RetellProvider::new(config.retell.clone(), retell_key.clone())?;
    // A listener is established before queued work can be recovered.
    let server = Server::http(config.listen).map_err(|_| Error::new("listen_unavailable", 6))?;
    let last_tick = Arc::new(AtomicI64::new(0));
    let worker_tick = Arc::clone(&last_tick);
    std::thread::Builder::new()
        .name("voice-call-worker".into())
        .spawn(move || loop {
            if worker.tick(&mut provider, now()).is_ok() {
                worker_tick.store(now(), Ordering::Release);
            }
            std::thread::sleep(Duration::from_millis(500));
        })?;
    let last_writeback = Arc::new(AtomicI64::new(0));
    let writeback_tick = Arc::clone(&last_writeback);
    std::thread::Builder::new()
        .name("voice-writeback-worker".into())
        .spawn(move || loop {
            // The potentially slow RP sink cannot occupy the call/stop worker.
            if writer.flush_outbox(&mut sink).is_ok() {
                writeback_tick.store(now(), Ordering::Release);
            }
            std::thread::sleep(Duration::from_secs(1));
        })?;
    let runtime = Runtime {
        credentials_file: Some(config.credentials_file),
        webhook_key: retell_key.into_bytes(),
    };
    println!(
        "{}",
        json!({"status":"ready","simulation":false,
        "live_calling_configured":true,"live_acceptance_verified":false,
        "listen":server.server_addr().to_string()})
    );
    serve_requests(server, controller, last_tick, last_writeback, runtime)
}
