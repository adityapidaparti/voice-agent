mod common;

use hegel::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::thread::JoinHandle;
use std::time::Duration;
use tiny_http::{Header, Response, Server};
use voice_agent::contract::{hash, EventKind};
use voice_agent::controller::{CanonicalWorkflow, Controller, Writeback, WritebackAck};
use voice_agent::workflow::{
    GateDecision, GateRequest, GateStage, HttpWorkflow, WorkflowAuthority,
};

fn request(stage: GateStage) -> GateRequest {
    let intent = common::intent();
    GateRequest {
        owner: "synthetic-owner".into(),
        operation_id: "op_example".into(),
        digest: intent.digest().unwrap(),
        work_item: intent.work_item,
        policy_gate_ref: "gate_demo_v1".into(),
        purpose_digest: hash(b"Ask which documents are required"),
        stage,
        reservation_id: matches!(stage, GateStage::Dispatch | GateStage::Continue)
            .then(|| "reservation_example".into()),
    }
}

fn decision(request: &GateRequest) -> GateDecision {
    GateDecision {
        request_digest: request.request_digest().unwrap(),
        allowed: true,
        expires_at: 1060,
        reservation_id: (request.stage != GateStage::Preview).then(|| "reservation_example".into()),
    }
}

fn writeback() -> Writeback {
    let mut result = common::operation().result;
    result.result_version = 7;
    Writeback {
        call_ended: true,
        operation_id: result.operation_id.clone(),
        result_version: result.result_version,
        work_item: result.work_item.clone(),
        result,
    }
}

enum Reply {
    Body(u16, String),
    Redirect,
    DropBody,
    Delay,
}
struct ObservedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
    retried: bool,
}

// The independent HTTP peer captures bytes and returns a script, without calling
// adapter helpers to decide what the client should have sent or accepted.
fn peer(reply: Reply, timeout: Duration) -> (HttpWorkflow, JoinHandle<ObservedRequest>) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", server.server_addr().to_ip().unwrap());
    let client = HttpWorkflow::for_loopback_tests(&origin, timeout).unwrap();
    let worker = std::thread::spawn(move || {
        let mut incoming = server
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .expect("adapter did not send a request");
        let method = incoming.method().as_str().to_owned();
        let path = incoming.url().to_owned();
        let headers = incoming
            .headers()
            .iter()
            .map(|header| {
                (
                    header.field.to_string().to_ascii_lowercase(),
                    header.value.to_string(),
                )
            })
            .collect();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(incoming.as_reader(), &mut bytes).unwrap();
        let body = serde_json::from_slice(&bytes).unwrap();
        match reply {
            Reply::Body(status, body) => {
                let _ = incoming.respond(Response::from_string(body).with_status_code(status));
            }
            Reply::Redirect => {
                let location = Header::from_bytes("Location", "/must-not-follow").unwrap();
                let _ = incoming.respond(
                    Response::from_string("")
                        .with_status_code(307)
                        .with_header(location),
                );
            }
            Reply::DropBody => {
                let mut stream = incoming.into_writer();
                let _ = std::io::Write::write_all(
                    &mut stream,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 256\r\nConnection: close\r\n\r\n{",
                );
                let _ = std::io::Write::flush(&mut stream);
            }
            Reply::Delay => {
                std::thread::sleep(Duration::from_millis(150));
                let _ = incoming.respond(Response::from_string("{}"));
            }
        }
        let retried = server
            .recv_timeout(Duration::from_millis(40))
            .unwrap()
            .is_some();
        ObservedRequest {
            method,
            path,
            headers,
            body,
            retried,
        }
    });
    (client, worker)
}

#[test]
fn authority_wire_binds_every_scope_field_and_uses_a_stable_stage_key() {
    for stage in [
        GateStage::Preview,
        GateStage::Reserve,
        GateStage::Dispatch,
        GateStage::Continue,
    ] {
        let request = request(stage);
        let response = serde_json::to_string(&decision(&request)).unwrap();
        let (mut client, worker) = peer(Reply::Body(200, response), Duration::from_secs(1));
        let allowed = client.authorize(&request, 1000).unwrap();
        assert!(allowed.allowed);
        let seen = worker.join().unwrap();
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.path, "/v1/voice/authorize");
        assert_eq!(
            seen.headers["authorization"],
            "Bearer synthetic-workflow-token"
        );
        assert_eq!(seen.headers["content-type"], "application/json");
        let stage_text = match stage {
            GateStage::Preview => "preview",
            GateStage::Reserve => "reserve",
            GateStage::Dispatch => "dispatch",
            GateStage::Continue => "continue",
        };
        let expected_key = format!(
            "voice_{}",
            hash(
                &serde_json::to_vec(&json!([request.operation_id, request.digest, stage_text]))
                    .unwrap()
            )
        );
        assert_eq!(seen.headers["idempotency-key"], expected_key);
        assert_eq!(seen.body, serde_json::to_value(&request).unwrap());
        assert!(!seen.body.as_object().unwrap().contains_key("facts"));
        assert!(!seen.retried);
    }
}

#[test]
fn authority_rejects_denial_stale_mismatched_or_missing_reservation_decisions() {
    let request = request(GateStage::Dispatch);
    let cases: &[fn(&mut GateDecision)] = &[
        |d| d.allowed = false,
        |d| d.expires_at = 1000,
        |d| d.expires_at = 1061,
        |d| d.request_digest = "different_request".into(),
        |d| d.reservation_id = None,
        |d| d.reservation_id = Some("another_reservation".into()),
        |d| d.reservation_id = Some("invalid/reservation".into()),
    ];
    for change in cases {
        let mut response = decision(&request);
        change(&mut response);
        let (mut client, worker) = peer(
            Reply::Body(200, serde_json::to_string(&response).unwrap()),
            Duration::from_secs(1),
        );
        assert!(client.authorize(&request, 1000).is_err());
        assert!(!worker.join().unwrap().retried);
    }
}

#[test]
fn failed_or_ambiguous_authority_responses_are_not_retried_or_followed() {
    for reply in [
        Reply::Body(500, "SYNTHETIC-UPSTREAM-DIAGNOSTIC".into()),
        Reply::Body(200, "not-json".into()),
        Reply::Body(200, "x".repeat(65_537)),
        Reply::Redirect,
        Reply::DropBody,
        Reply::Delay,
    ] {
        let (mut client, worker) = peer(reply, Duration::from_millis(80));
        let error = client
            .authorize(&request(GateStage::Reserve), 1000)
            .unwrap_err();
        assert!(!error.to_string().contains("SYNTHETIC-UPSTREAM-DIAGNOSTIC"));
        let observed = worker.join().unwrap();
        assert_eq!(observed.path, "/v1/voice/authorize");
        assert!(!observed.retried);
    }
}

#[test]
fn writeback_wire_is_versioned_conditional_and_accepts_only_matching_acknowledgements() {
    let message = writeback();
    for (http_status, status) in [(201, "applied"), (200, "already_applied")] {
        let body = json!({
            "operation_id":message.operation_id,
            "result_version":message.result_version,
            "status":status
        });
        let (mut client, worker) = peer(
            Reply::Body(http_status, body.to_string()),
            Duration::from_secs(1),
        );
        let ack = client.publish(&message).unwrap();
        assert!(matches!(
            (ack, status),
            (WritebackAck::Applied, "applied") | (WritebackAck::AlreadyApplied, "already_applied")
        ));
        let seen = worker.join().unwrap();
        assert_eq!(seen.method, "PUT");
        assert_eq!(seen.path, "/v1/voice/results/op_demo/7");
        assert_eq!(seen.headers["if-match"], "\"v1\"");
        assert_eq!(
            seen.headers["authorization"],
            "Bearer synthetic-workflow-token"
        );
        assert_eq!(seen.body, serde_json::to_value(&message).unwrap());
        assert!(!seen.retried);
    }
}

#[test]
fn conflict_and_failed_writebacks_never_acknowledge_delivery() {
    let message = writeback();
    let (mut client, worker) = peer(
        Reply::Body(409, "untrusted conflict details".into()),
        Duration::from_secs(1),
    );
    assert!(matches!(
        client.publish(&message).unwrap(),
        WritebackAck::Conflict
    ));
    assert!(!worker.join().unwrap().retried);
    for reply in [
        Reply::Body(500, "upstream error".into()),
        Reply::Body(200, "not-json".into()),
        Reply::Body(200, "x".repeat(65_537)),
        Reply::Body(
            200,
            json!({"operation_id":"different","result_version":7,"status":"applied"}).to_string(),
        ),
        Reply::Body(
            200,
            json!({"operation_id":"op_demo","result_version":8,"status":"applied"}).to_string(),
        ),
        Reply::Body(
            200,
            json!({"operation_id":"op_demo","result_version":7,"status":"unknown"}).to_string(),
        ),
        Reply::Body(
            200,
            json!({"operation_id":"op_demo","result_version":7,"status":"applied","extra":true})
                .to_string(),
        ),
        Reply::Redirect,
        Reply::DropBody,
        Reply::Delay,
    ] {
        let (mut client, worker) = peer(reply, Duration::from_millis(80));
        assert!(client.publish(&message).is_err());
        assert!(!worker.join().unwrap().retried);
    }
}

#[test]
fn uncertain_writeback_retries_only_the_durable_outbox_without_creating_another_call() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("state.db");
    let mut controller = Controller::open(&database).unwrap();
    let intent = common::intent();
    let approval = controller.approve(&common::user(), &intent, 1000).unwrap();
    let operation = controller
        .start(
            &common::user(),
            &intent,
            &approval.id,
            "workflow_retry",
            1000,
        )
        .unwrap();
    let mut provider = common::CountingProvider::default();
    controller.tick(&mut provider, 1000).unwrap();
    controller
        .ingest(common::event(&operation, EventKind::Ended, 1001))
        .unwrap();
    controller.process_events().unwrap();
    let pending = controller.pending_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    let (mut uncertain, first) = peer(Reply::DropBody, Duration::from_millis(80));
    assert!(controller.flush_outbox(&mut uncertain).is_err());
    let original_request = first.join().unwrap();
    drop(controller);
    let mut controller = Controller::open(&database).unwrap();
    assert_eq!(
        serde_json::to_value(controller.pending_outbox().unwrap()).unwrap(),
        serde_json::to_value(&pending).unwrap()
    );
    let ack = json!({
        "operation_id":pending[0].operation_id,
        "result_version":pending[0].result_version,
        "status":"already_applied"
    });
    let (mut retry, second) = peer(Reply::Body(200, ack.to_string()), Duration::from_secs(1));
    controller.flush_outbox(&mut retry).unwrap();
    let repeated_request = second.join().unwrap();
    assert_eq!(original_request.path, repeated_request.path);
    assert_eq!(original_request.body, repeated_request.body);
    assert!(!original_request.retried && !repeated_request.retried);
    assert!(controller.pending_outbox().unwrap().is_empty());
    controller.tick(&mut provider, 1002).unwrap();
    assert_eq!(provider.creates, 1);
}

#[test]
fn constructors_reject_unsafe_origins_and_only_allow_synthetic_loopback_http() {
    for url in [
        "http://example.invalid",
        "https://user@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid/?query=value",
        "https://example.invalid/#fragment",
    ] {
        assert!(HttpWorkflow::new(url, "synthetic-config-only".into()).is_err());
    }
    assert!(HttpWorkflow::new("https://example.invalid", "synthetic-config-only".into()).is_ok());
    for token in ["", "line\nbreak", "space inside"] {
        assert!(HttpWorkflow::new("https://example.invalid", token.into()).is_err());
    }
    for url in [
        "http://localhost",
        "http://192.0.2.1",
        "https://127.0.0.1",
        "http://127.0.0.1/path",
    ] {
        assert!(HttpWorkflow::for_loopback_tests(url, Duration::from_secs(1)).is_err());
    }
    assert!(HttpWorkflow::for_loopback_tests("http://127.0.0.1", Duration::ZERO).is_err());
    assert!(HttpWorkflow::for_loopback_tests("http://127.0.0.1", Duration::from_secs(6)).is_err());
}

#[test]
fn locally_inconsistent_writebacks_are_rejected_before_network_access() {
    let mut client =
        HttpWorkflow::for_loopback_tests("http://127.0.0.1:1", Duration::from_millis(10)).unwrap();
    let changes: &[fn(&mut Writeback)] = &[
        |w| w.operation_id = "path/escape".into(),
        |w| {
            w.operation_id = ".".into();
            w.result.operation_id = ".".into();
        },
        |w| {
            w.operation_id = "..".into();
            w.result.operation_id = "..".into();
        },
        |w| w.work_item.version = "invalid\"etag".into(),
        |w| w.result_version = 0,
        |w| w.result.operation_id = "wrong_operation".into(),
        |w| w.result.result_version += 1,
        |w| w.result.work_item.reference = "other_work".into(),
    ];
    for change in changes {
        let mut message = writeback();
        change(&mut message);
        assert_eq!(
            client
                .publish(&message)
                .err()
                .expect("invalid writeback was accepted")
                .code,
            "invalid_workflow_writeback"
        );
    }
}

/// The independent clock oracle uses wider arithmetic, including i64 edge cases.
#[hegel::test]
fn decisions_require_matching_authority_and_a_positive_lifetime_of_at_most_sixty_seconds(
    tc: TestCase,
) {
    let now = tc.draw(gs::integers::<i64>());
    let offset = tc.draw(gs::sampled_from(&[-1_i64, 0, 1, 59, 60, 61][..]));
    let expires_at = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::just(now.saturating_add(offset))
    ));
    let allowed = tc.draw(gs::booleans());
    let matches = tc.draw(gs::booleans());
    let lifetime = i128::from(expires_at) - i128::from(now);
    let expected = allowed && matches && (1..=60).contains(&lifetime);
    tc.event(if expected {
        "valid decision"
    } else {
        "rejected decision"
    });
    for stage in [
        GateStage::Preview,
        GateStage::Reserve,
        GateStage::Dispatch,
        GateStage::Continue,
    ] {
        let request = request(stage);
        let mut response = decision(&request);
        response.allowed = allowed;
        response.expires_at = expires_at;
        if !matches {
            response.request_digest.push('x');
        }
        assert_eq!(response.validate(&request, now).is_ok(), expected);
    }
}

/// Reservations are opaque bounded identifiers and cannot change once supplied by RP.
#[hegel::test]
fn reservation_validation_accepts_only_valid_opaque_identifiers_and_preserves_binding(
    tc: TestCase,
) {
    let text = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(&["", "r", "reservation_example", "a/b", "é"][..]).map(str::to_owned),
        gs::sampled_from(&[128_usize, 129][..]).map(|n| "r".repeat(n))
    ));
    let present = tc.draw(gs::booleans());
    let bound = tc.draw(gs::booleans());
    let valid_text = (1..=128).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:".contains(c));
    for stage in [
        GateStage::Preview,
        GateStage::Reserve,
        GateStage::Dispatch,
        GateStage::Continue,
    ] {
        let mut request = request(stage);
        request.reservation_id = bound.then(|| "reservation_example".into());
        let mut response = decision(&request);
        response.reservation_id = present.then(|| text.clone());
        let expected = (!present || valid_text)
            && (stage == GateStage::Preview || present)
            && (!bound || (present && text == "reservation_example"));
        assert_eq!(response.validate(&request, 1000).is_ok(), expected);
    }
}

#[test]
fn older_durable_writebacks_do_not_infer_termination_from_a_result() {
    let mut message = serde_json::to_value(writeback()).unwrap();
    message.as_object_mut().unwrap().remove("call_ended");
    let restored: Writeback = serde_json::from_value(message).unwrap();
    assert!(!restored.call_ended);
}
