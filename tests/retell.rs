//! Independent HTTP fixtures exercise the actual reqwest transport without Retell.
mod common;
use common::operation;
use hegel::prelude::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tiny_http::{Header, Response, Server, StatusCode};
use voice_agent::contract::EventKind;
use voice_agent::provider::{retell_llm_template, CreateOutcome, Provider};
use voice_agent::retell::{
    bounded_duration_seconds, snapshot_digest, RetellConfig, RetellProvider,
};

struct Reply {
    status: u16,
    body: String,
    delay_ms: u64,
    headers: Vec<(&'static str, &'static str)>,
}
impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: body.to_string(),
            delay_ms: 0,
            headers: vec![],
        }
    }
}
#[derive(Debug)]
struct RequestRecord {
    method: String,
    path: String,
    body: Value,
    authorization: String,
}
struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<RequestRecord>>>,
    thread: JoinHandle<()>,
}
impl Fake {
    fn new(replies: Vec<Reply>) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let worker_seen = seen.clone();
        let thread = std::thread::spawn(move || {
            for reply in replies {
                let mut request = server
                    .recv_timeout(Duration::from_secs(4))
                    .unwrap()
                    .expect("expected HTTP request");
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                let authorization = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_owned())
                    .unwrap_or_default();
                worker_seen.lock().unwrap().push(RequestRecord {
                    method: request.method().to_string(),
                    path: request.url().to_owned(),
                    body: serde_json::from_str(&body).unwrap_or(Value::Null),
                    authorization,
                });
                if reply.delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(reply.delay_ms));
                }
                let mut response =
                    Response::from_string(reply.body).with_status_code(StatusCode(reply.status));
                for (name, value) in reply.headers {
                    response.add_header(Header::from_bytes(name, value).unwrap());
                }
                let _ = request.respond(response);
            }
            // An automatic retry or a redirect is observable as an extra request.
            assert!(
                server
                    .recv_timeout(Duration::from_millis(100))
                    .unwrap()
                    .is_none(),
                "unexpected retry"
            );
        });
        Self { url, seen, thread }
    }
    fn finish(self) -> Vec<RequestRecord> {
        self.thread.join().unwrap();
        Arc::try_unwrap(self.seen).unwrap().into_inner().unwrap()
    }
}
fn snapshots() -> (Value, Value) {
    let agent = json!({"agent_id":"agent_demo","version":1,"is_published":true,"is_transfer_agent":false,
        "response_engine":{"type":"retell-llm","llm_id":"llm_demo","version":2},
        "data_storage_setting":"basic_attributes_only","data_storage_retention_days":30,
        "contact_memory_config":{"enable_read":false,"enable_update":false},
        "allow_user_dtmf":false,"reminder_max_count":0,"voicemail_option":{"action":{"type":"hangup"}},
        "pre_session_tools":null,"post_session_tools":null,"post_call_analysis_data":[],"webhook_url":null});
    let mut llm = retell_llm_template();
    llm["llm_id"] = json!("llm_demo");
    llm["version"] = json!(2);
    llm["is_published"] = json!(true);
    (agent, llm)
}
fn configuration(agent: &Value, llm: &Value) -> RetellConfig {
    RetellConfig {
        from_number: "+12025550101".into(),
        agent_id: "agent_demo".into(),
        agent_version: 1,
        llm_id: "llm_demo".into(),
        llm_version: 2,
        agent_snapshot_sha256: snapshot_digest(agent).unwrap(),
        llm_snapshot_sha256: snapshot_digest(llm).unwrap(),
        webhook_url: None,
    }
}
fn config() -> RetellConfig {
    let (a, l) = snapshots();
    configuration(&a, &l)
}
fn call(status: &str) -> Value {
    let op = operation();
    json!({"call_id":"call_demo","call_type":"phone_call","direction":"outbound",
        "from_number":"+12025550101","to_number":"+12025550100","agent_id":"agent_demo","agent_version":1,
        "metadata":{"operation_id":op.id,"intent_digest":op.digest},"call_status":status,
        "start_timestamp":1000000,"end_timestamp":1010000,"disconnection_reason":"agent_hangup",
        "call_cost":{"combined_cost":1.2},"transcript":"SYNTHETIC WORDS THAT MUST NOT BE RETAINED",
        "call_analysis":{"call_successful":true}})
}
fn create_replies(last: Reply) -> Vec<Reply> {
    let (a, l) = snapshots();
    vec![Reply::json(200, a), Reply::json(200, l), last]
}

#[test]
fn create_checks_exact_published_versions_and_sends_one_approved_request() {
    let fake = Fake::new(create_replies(Reply::json(201, call("registered"))));
    let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert_eq!(
        provider.create(&operation(), 1000),
        CreateOutcome::Accepted("call_demo".into())
    );
    let requests = fake.finish();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].path, "/get-agent/agent_demo?version=1");
    assert_eq!(requests[1].path, "/get-retell-llm/llm_demo?version=2");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "GET");
    let sent = &requests[2];
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.path, "/v2/create-phone-call");
    assert!(requests
        .iter()
        .all(|r| r.authorization == "Bearer synthetic-retell-test-credential"));
    assert_eq!(sent.body["to_number"], "+12025550100");
    assert_eq!(sent.body["idempotency_key"], "provider_demo");
    assert_eq!(sent.body["override_agent_version"], 1);
    assert_eq!(sent.body["metadata"]["intent_digest"], operation().digest);
    assert_eq!(
        sent.body["agent_override"]["agent"]["allow_user_dtmf"],
        false
    );
    assert_eq!(
        sent.body["agent_override"]["agent"]["data_storage_setting"],
        "basic_attributes_only"
    );
    assert_eq!(
        sent.body["agent_override"]["agent"]["ring_duration_ms"],
        30000
    );
    let duration = sent.body["agent_override"]["agent"]["max_call_duration_ms"]
        .as_u64()
        .unwrap();
    assert!((60000..=143000).contains(&duration));
    assert!(duration + 30000 + 2000 + 5000 <= 180000);
    assert!(sent.body["agent_override"]["retell_llm"]
        .get("general_tools")
        .is_none());
}

#[test]
fn pins_are_rechecked_before_each_new_submission() {
    let (mut a, l) = snapshots();
    let mut replies = create_replies(Reply::json(201, call("registered")));
    a["version"] = json!(3);
    replies.extend([Reply::json(200, a), Reply::json(200, l)]);
    let fake = Fake::new(replies);
    let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert!(matches!(
        provider.create(&operation(), 1000),
        CreateOutcome::Accepted(_)
    ));
    let mut next = operation();
    next.id = "op_other".into();
    next.provider_key = "other_provider".into();
    assert_eq!(provider.create(&next, 1000), CreateOutcome::Rejected);
    assert_eq!(
        fake.finish()
            .iter()
            .filter(|r| r.path == "/v2/create-phone-call")
            .count(),
        1
    );
}

#[test]
fn local_scope_and_deadline_rejections_never_touch_the_network() {
    let mut provider = RetellProvider::for_loopback_tests(config(), "http://127.0.0.1:9").unwrap();
    for field in 0..8 {
        let mut op = operation();
        match field {
            0 => op.attempt_consumed = false,
            1 => op.submitted_at = None,
            2 => op.call_id = Some("call_bound".into()),
            3 => op.stop_reason = Some("user_requested".into()),
            4 => op.ai_stopped = true,
            5 => op.all_legs_ended = true,
            6 => op.digest = "bad".into(),
            _ => op.deadline = 1096,
        }
        assert_eq!(
            provider.create(&op, 1000),
            CreateOutcome::Rejected,
            "case {field}"
        );
    }
}

#[test]
fn definite_create_errors_consume_the_attempt_without_retry() {
    for status in [400, 401, 402, 422, 429] {
        let fake = Fake::new(create_replies(Reply::json(
            status,
            json!({"status":"error"}),
        )));
        let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
        assert_eq!(p.create(&operation(), 1000), CreateOutcome::Rejected);
        assert_eq!(fake.finish().len(), 3);
    }
}

#[test]
fn ambiguous_responses_never_retry_or_claim_rejection() {
    for kind in 0..6 {
        let mut reply = Reply::json(201, call("registered"));
        match kind {
            0 => reply.status = 500,
            1 => reply.status = 200,
            2 => reply.body = "not json".into(),
            3 => {
                let mut v = call("registered");
                v["metadata"]["intent_digest"] = json!("foreign");
                reply.body = v.to_string();
            }
            4 => {
                reply.status = 307;
                reply.headers.push(("Location", "/v2/create-phone-call"));
            }
            _ => reply.delay_ms = 2200,
        }
        let fake = Fake::new(create_replies(reply));
        let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
        assert_eq!(
            p.create(&operation(), 1000),
            CreateOutcome::Unknown,
            "case {kind}"
        );
        assert_eq!(fake.finish().len(), 3);
    }
}

#[test]
fn lookup_uses_minimal_evidence_and_never_model_success() {
    let fake = Fake::new(vec![Reply::json(200, call("ended"))]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    let mut op = operation();
    op.call_id = Some("call_demo".into());
    let events = p.lookup(&op, 1020).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, EventKind::Started);
    assert_eq!(events[0].observed_at, 1000);
    assert_eq!(events[1].kind, EventKind::Ended);
    assert!(events[1].all_legs_ended);
    assert_eq!(events[2].kind, EventKind::Analyzed);
    assert_eq!(events[2].actual_cost_cents, Some(2));
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains("SYNTHETIC WORDS"));
    assert!(!serialized.contains("call_successful"));
    let seen = fake.finish();
    assert_eq!(seen[0].path, "/v2/get-call/call_demo");
    assert_eq!(seen[0].method, "GET");
}

#[test]
fn polling_distinguishes_cost_updates_without_delivery_order_authority() {
    let mut older = call("ended");
    older["call_cost"]["combined_cost"] = json!(100);
    let mut newer = call("ended");
    newer["call_cost"]["combined_cost"] = json!(2000);
    let fake = Fake::new(vec![Reply::json(200, newer), Reply::json(200, older)]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    let mut op = operation();
    op.call_id = Some("call_demo".into());
    let first = p.lookup(&op, 1020).unwrap();
    let second = p.lookup(&op, 1021).unwrap();
    assert_eq!(first[0].key, second[0].key);
    assert_eq!(first[1].key, second[1].key);
    assert_ne!(first[2].key, second[2].key);
    assert_eq!(first[2].actual_cost_cents, Some(2000));
    assert_eq!(second[2].actual_cost_cents, Some(100));
    fake.finish();
}

#[test]
fn known_call_with_wrong_metadata_or_destination_is_a_binding_conflict() {
    for field in 0..5 {
        let mut v = call("ended");
        match field {
            0 => v["metadata"]["intent_digest"] = json!("wrong"),
            1 => v["metadata"]["operation_id"] = json!("op_other"),
            2 => v["call_id"] = json!("call_other"),
            3 => v["to_number"] = json!("+12025550102"),
            _ => v["agent_version"] = json!(2),
        };
        let fake = Fake::new(vec![Reply::json(200, v)]);
        let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
        let mut op = operation();
        op.call_id = Some("call_demo".into());
        assert_eq!(
            p.lookup(&op, 1020).unwrap_err().code,
            "event_mapping_conflict"
        );
        fake.finish();
    }
}

#[test]
fn unknown_create_is_reconciled_by_paginated_metadata_search() {
    let mut foreign = call("ended");
    foreign["metadata"]["operation_id"] = json!("op_other");
    let fake = Fake::new(vec![
        Reply::json(
            200,
            json!({"items":[foreign],"has_more":true,"pagination_key":"cursor_1"}),
        ),
        Reply::json(200, json!({"items":[call("ended")],"has_more":false})),
    ]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert_eq!(p.lookup(&operation(), 1020).unwrap().len(), 3);
    let seen = fake.finish();
    assert_eq!(seen.len(), 2);
    assert!(seen
        .iter()
        .all(|r| r.path == "/v3/list-calls" && r.method == "POST"));
    assert_eq!(
        seen[0].body["filter_criteria"]["metadata"][0],
        json!({"type":"string","key":"operation_id","value":"op_demo"})
    );
    assert_eq!(seen[1].body["pagination_key"], "cursor_1");
}

#[test]
fn duplicate_call_identity_or_conflicting_records_cannot_be_selected_arbitrarily() {
    for same_identity in [false, true] {
        let mut other = call("ended");
        if same_identity {
            other["call_cost"]["combined_cost"] = json!(200);
        } else {
            other["call_id"] = json!("call_other");
        }
        let fake = Fake::new(vec![Reply::json(
            200,
            json!({"items":[call("ended"),other],"has_more":false}),
        )]);
        let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
        assert_eq!(
            p.lookup(&operation(), 1020).unwrap_err().code,
            "event_mapping_conflict"
        );
        fake.finish();
    }
}

#[test]
fn missing_and_incomplete_searches_preserve_unknown_outcomes() {
    let fake = Fake::new(vec![Reply::json(200, json!({"items":[],"has_more":false}))]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert!(p.lookup(&operation(), 1020).unwrap().is_empty());
    fake.finish();
    let replies=(0..3).map(|n|Reply::json(200,json!({"items":[call("ended")],"has_more":true,"pagination_key":format!("cursor_{n}")}))).collect();
    let fake = Fake::new(replies);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert_eq!(
        p.lookup(&operation(), 1020).unwrap_err().code,
        "retell_lookup_unresolved"
    );
    assert_eq!(fake.finish().len(), 3);
}

#[test]
fn absent_timestamps_and_costs_are_not_fabricated() {
    let mut v = call("registered");
    v.as_object_mut().unwrap().remove("start_timestamp");
    v.as_object_mut().unwrap().remove("end_timestamp");
    v.as_object_mut().unwrap().remove("call_cost");
    let fake = Fake::new(vec![Reply::json(
        200,
        json!({"items":[v],"has_more":false}),
    )]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert!(p.lookup(&operation(), 1020).unwrap().is_empty());
    fake.finish();
}

#[test]
fn stop_receipt_is_only_a_receipt_and_uses_a_known_safe_path() {
    let fake = Fake::new(vec![Reply::json(204, Value::Null)]);
    let mut p = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    let mut op = operation();
    op.call_id = Some("call_demo".into());
    p.stop(&op, 1020).unwrap();
    assert!(!op.all_legs_ended);
    let seen = fake.finish();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v2/stop-call/call_demo");
    op.call_id = Some("../../foreign".into());
    assert!(p.stop(&op, 1020).is_err());
    op.call_id = None;
    assert!(p.stop(&op, 1020).is_err());
}

#[test]
fn test_constructor_cannot_send_credentials_to_a_remote_host() {
    for url in [
        "http://example.com",
        "https://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1@evil.example",
        "http://127.0.0.1/path",
        "http://127.0.0.1?query=x",
        "http://127.0.0.1#fragment",
    ] {
        assert!(
            RetellProvider::for_loopback_tests(config(), url).is_err(),
            "{url}"
        );
    }
}

/// Accepted values retain enough independently counted seconds for call, ring,
/// submission and stop; malformed elapsed clocks and short windows are rejected.
#[hegel::test]
fn provider_duration_never_exceeds_the_absolute_approved_window(tc: TestCase) {
    let remaining = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[59_i64, 60, 96, 97, 98, 179, 180, 181, 300][..])
    ));
    let elapsed = tc.draw(gs::sampled_from(&[-1_i64, 0, 1, 2, 5, 10, 60][..]));
    let mut op = operation();
    op.deadline = 1000_i64.saturating_add(remaining);
    let result = bounded_duration_seconds(&op, 1000, elapsed);
    let available = i128::from(op.deadline) - 1000 - i128::from(elapsed) - 30 - 2 - 5;
    let accepted = elapsed >= 0 && available >= 60;
    tc.event(if accepted {
        "accepted duration"
    } else {
        "rejected duration"
    });
    assert_eq!(result.is_ok(), accepted);
    if let Ok(seconds) = result {
        assert!((60..=180).contains(&seconds));
        assert!(i128::from(seconds) <= available);
        assert!(seconds == 180 || i128::from(seconds) == available);
    }
}

/// A correct hash is necessary but cannot bless prohibited tools or retention.
#[hegel::test]
fn reviewed_hashes_do_not_override_the_semantic_agent_policy(tc: TestCase) {
    let change = tc.draw(gs::sampled_from((0_u8..=18).collect::<Vec<_>>()));
    let (mut a, mut l) = snapshots();
    match change {
        0 => {}
        1 => a["is_published"] = json!(false),
        2 => l["is_published"] = json!(false),
        3 => a["data_storage_setting"] = json!("everything"),
        4 => a["contact_memory_config"]["enable_read"] = json!(true),
        5 => a["allow_user_dtmf"] = json!(true),
        6 => a["pre_session_tools"] = json!([{"type":"custom"}]),
        7 => l["general_tools"] = json!([{"type":"press_digit","name":"digits"}]),
        8 => l["general_tools"] = json!([{"type":"transfer_call","name":"transfer"}]),
        9 => l["general_prompt"] = json!("Impersonate the caller"),
        10 => l["states"] = json!([{"name":"arbitrary","tools":[]}]),
        11 => l["knowledge_base_ids"] = json!(["kb_unapproved"]),
        12 => l["mcps"] = json!([{"url":"https://example.com"}]),
        13 => a["data_storage_retention_days"] = json!(31),
        14 => a["response_engine"]["version"] = json!(9),
        15 => a["webhook_url"] = json!("https://unapproved.example/callback"),
        16 => l["default_dynamic_variables"] = json!({"private_context":"unapproved"}),
        17 => a["post_call_analysis_data"] = json!([{"name":"unbounded_notes"}]),
        _ => a["voice_id"] = json!("synthetic-reviewed-voice"),
    }
    let config = configuration(&a, &l);
    let accepted = change == 0 || change == 18;
    tc.event(if accepted {
        "safe reviewed config"
    } else {
        "prohibited reviewed config"
    });
    assert_eq!(config.validate_snapshots(&a, &l).is_ok(), accepted);
}

#[test]
fn optional_observation_tools_must_match_the_exact_controller_templates() {
    let (mut agent, mut llm) = snapshots();
    let url = "https://voice.example/v1/webhooks/retell";
    agent["webhook_url"] = json!(url);
    let tools = llm["general_tools"].as_array_mut().unwrap();
    tools.push(voice_agent::observations::phase_tool(
        "https://voice.example/v1/functions/observe",
    ));
    tools.push(voice_agent::observations::report_tool(
        "https://voice.example/v1/functions/report",
    ));
    let mut config = configuration(&agent, &llm);
    config.webhook_url = Some(url.into());
    assert!(config.validate_snapshots(&agent, &llm).is_ok());
    for changed_tool in [1, 2] {
        let mut changed = llm.clone();
        changed["general_tools"][changed_tool]["url"] = json!("https://foreign.example/callback");
        config.llm_snapshot_sha256 = snapshot_digest(&changed).unwrap();
        assert!(config.validate_snapshots(&agent, &changed).is_err());
    }
    let mut changed = llm.clone();
    changed["general_tools"][2]["parameters"]["properties"]["free_text"] = json!({"type":"string"});
    config.llm_snapshot_sha256 = snapshot_digest(&changed).unwrap();
    assert!(config.validate_snapshots(&agent, &changed).is_err());
    changed = llm;
    changed["general_tools"].as_array_mut().unwrap().pop();
    config.llm_snapshot_sha256 = snapshot_digest(&changed).unwrap();
    assert!(config.validate_snapshots(&agent, &changed).is_err());
}

#[test]
fn a_dispatch_lease_that_expires_during_pin_reads_cannot_dial() {
    let (a, l) = snapshots();
    let mut first = Reply::json(200, a);
    first.delay_ms = 100;
    let fake = Fake::new(vec![first, Reply::json(200, l)]);
    let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    assert_eq!(
        provider.create_guarded(&operation(), 1000, 1001),
        CreateOutcome::Rejected
    );
    let seen = fake.finish();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|request| request.method == "GET"));
}

#[test]
fn an_expired_dispatch_lease_is_rejected_before_reading_vendor_configuration() {
    let mut provider = RetellProvider::for_loopback_tests(config(), "http://127.0.0.1:9").unwrap();
    assert_eq!(
        provider.create_guarded(&operation(), 1000, 1000),
        CreateOutcome::Rejected
    );
}

#[test]
fn a_verified_registered_call_can_be_bound_without_inventing_a_start_event() {
    let mut registered = call("registered");
    for name in ["start_timestamp", "end_timestamp", "call_cost"] {
        registered.as_object_mut().unwrap().remove(name);
    }
    let fake = Fake::new(vec![Reply::json(
        200,
        json!({"items":[registered],"has_more":false}),
    )]);
    let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    let result = provider.reconcile(&operation(), 1020).unwrap();
    assert_eq!(result.call_id, Some("call_demo".into()));
    assert!(result.events.is_empty());
    assert_eq!(fake.finish().len(), 1);
}

#[test]
fn reconciliation_absence_has_neither_a_call_binding_nor_events() {
    let fake = Fake::new(vec![Reply::json(200, json!({"items":[],"has_more":false}))]);
    let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
    let result = provider.reconcile(&operation(), 1020).unwrap();
    assert!(result.call_id.is_none());
    assert!(result.events.is_empty());
    fake.finish();
}

#[test]
fn registered_call_scope_and_uniqueness_are_checked_before_exposing_its_identity() {
    for scenario in 0..4 {
        let mut registered = call("registered");
        for name in ["start_timestamp", "end_timestamp", "call_cost"] {
            registered.as_object_mut().unwrap().remove(name);
        }
        let mut records = vec![];
        match scenario {
            0 => registered["metadata"]["intent_digest"] = json!("foreign"),
            1 => registered["agent_version"] = json!(2),
            2 => registered["to_number"] = json!("+12025550102"),
            _ => {
                let mut second = registered.clone();
                second["call_id"] = json!("call_second");
                records.push(second);
            }
        }
        records.push(registered);
        let fake = Fake::new(vec![Reply::json(
            200,
            json!({"items":records,"has_more":false}),
        )]);
        let mut provider = RetellProvider::for_loopback_tests(config(), &fake.url).unwrap();
        assert_eq!(
            provider.reconcile(&operation(), 1020).err().unwrap().code,
            "event_mapping_conflict"
        );
        fake.finish();
    }
}
