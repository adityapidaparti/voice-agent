//! Offline composition test: both HTTP peers are independent synthetic servers.
//! Signed callbacks cross the verification functions, not a public HTTP listener.
mod common;

use ring::hmac;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tiny_http::{Response, Server};
use voice_agent::contract::{hash, Lifecycle, Phase, ResultStatus};
use voice_agent::controller::Controller;
use voice_agent::observations::{
    phase_tool, report_tool, verify_phase, verify_report, DocumentKind, ReportedStatus,
    Verification,
};
use voice_agent::policy::{ControllerPolicy, DirectoryEntry};
use voice_agent::provider::{retell_llm_template, verify_and_normalize};
use voice_agent::retell::{snapshot_digest, RetellConfig, RetellProvider};
use voice_agent::workflow::HttpWorkflow;

const RETELL_TOKEN: &str = "Bearer synthetic-retell-test-credential";
const RP_TOKEN: &str = "Bearer synthetic-workflow-token";
const CALLBACK_KEY: &[u8] = b"synthetic-retell-test-credential";
const CALL_ID: &str = "call_integrated_example";
const TRANSCRIPT_MARKER: &str = "SYNTHETIC-TRANSCRIPT-MUST-NOT-BE-STORED";

#[derive(Clone)]
struct RequestRecord {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    raw: Vec<u8>,
    body: Value,
}

struct FakeHttp {
    origin: String,
    records: Arc<Mutex<Vec<RequestRecord>>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl FakeHttp {
    fn start(mut handler: impl FnMut(&RequestRecord) -> (u16, Value) + Send + 'static) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", server.server_addr().to_ip().unwrap());
        let records = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_records = records.clone();
        let worker_shutdown = shutdown.clone();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !worker_shutdown.load(Ordering::SeqCst) && Instant::now() < deadline {
                let Some(mut incoming) = server.recv_timeout(Duration::from_millis(40)).unwrap()
                else {
                    continue;
                };
                let mut raw = Vec::new();
                std::io::Read::read_to_end(incoming.as_reader(), &mut raw).unwrap();
                assert!(raw.len() <= 65_536, "unexpectedly large synthetic request");
                let record = RequestRecord {
                    method: incoming.method().to_string(),
                    path: incoming.url().to_owned(),
                    headers: incoming
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.to_string().to_ascii_lowercase(),
                                h.value.to_string(),
                            )
                        })
                        .collect(),
                    body: if raw.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&raw).unwrap()
                    },
                    raw,
                };
                {
                    let mut seen = worker_records.lock().unwrap();
                    assert!(seen.len() < 80, "unexpected retry loop");
                    seen.push(record.clone());
                }
                let (status, body) = handler(&record);
                let _ = incoming
                    .respond(Response::from_string(body.to_string()).with_status_code(status));
            }
        });
        Self {
            origin,
            records,
            shutdown,
            worker: Some(worker),
        }
    }
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("synthetic HTTP peer failed");
            }
        }
    }
    fn requests(&self) -> Vec<RequestRecord> {
        self.records.lock().unwrap().clone()
    }
}
impl Drop for FakeHttp {
    fn drop(&mut self) {
        self.stop();
    }
}

fn policy() -> ControllerPolicy {
    let intent = common::intent();
    ControllerPolicy {
        daily_budget_cents: 2500,
        directory: vec![DirectoryEntry {
            work_system: intent.work_item.system,
            destination: intent.destination,
            agent_id: intent.agent_id,
            agent_version: intent.agent_version,
            rate_ref: intent.limits.rate_ref,
            rate_cents_per_minute: intent.limits.rate_cents_per_minute,
            handoff_recipient_ref: intent.handoff.recipient_ref,
            handoff_endpoint_ref: intent.handoff.endpoint_ref,
            consent_policy_ref: intent.consent_policy_ref,
            expires_at: 5000,
        }],
    }
}

fn snapshots() -> (Value, Value, RetellConfig) {
    let webhook = "https://voice.example.invalid/v1/webhooks/retell";
    let agent = json!({
        "agent_id":"agent_demo", "version":1, "is_published":true, "is_transfer_agent":false,
        "response_engine":{"type":"retell-llm","llm_id":"llm_demo","version":2},
        "data_storage_setting":"basic_attributes_only", "data_storage_retention_days":30,
        "contact_memory_config":{"enable_read":false,"enable_update":false},
        "allow_user_dtmf":false, "reminder_max_count":0,
        "voicemail_option":{"action":{"type":"hangup"}},
        "pre_session_tools":null, "post_session_tools":null, "post_call_analysis_data":[],
        "webhook_url":webhook
    });
    let mut llm = retell_llm_template();
    llm["llm_id"] = json!("llm_demo");
    llm["version"] = json!(2);
    llm["is_published"] = json!(true);
    let tools = llm["general_tools"].as_array_mut().unwrap();
    tools.push(phase_tool(
        "https://voice.example.invalid/v1/functions/observe",
    ));
    tools.push(report_tool(
        "https://voice.example.invalid/v1/functions/report",
    ));
    let config = RetellConfig {
        from_number: "+12025550101".into(),
        agent_id: "agent_demo".into(),
        agent_version: 1,
        llm_id: "llm_demo".into(),
        llm_version: 2,
        agent_snapshot_sha256: snapshot_digest(&agent).unwrap(),
        llm_snapshot_sha256: snapshot_digest(&llm).unwrap(),
        webhook_url: Some(webhook.into()),
    };
    (agent, llm, config)
}

#[derive(Default)]
struct RetellState {
    call: Option<Value>,
    visible: bool,
    creates: usize,
    stops: usize,
}
#[derive(Default)]
struct CanonicalState {
    reservation_operation: Option<String>,
    stages: Vec<String>,
    results: BTreeMap<u32, Value>,
    current_result: Option<Value>,
    acknowledged_versions: BTreeSet<u32>,
    lost_first_writeback_reply: bool,
}

fn sign(raw: &[u8], now_ms: i64) -> String {
    let timestamp = now_ms.to_string();
    let mut signed = raw.to_vec();
    signed.extend_from_slice(timestamp.as_bytes());
    let digest = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, CALLBACK_KEY), &signed);
    let tag: String = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("v={timestamp},d={tag}")
}

#[test]
fn hosted_flow_reconciles_a_lost_create_receipt_and_writes_only_unverified_evidence() {
    let intent = common::intent();
    let expected_digest = intent.digest().unwrap();
    let (agent, llm, config) = snapshots();
    let retell_state = Arc::new(Mutex::new(RetellState::default()));
    let retell_worker = retell_state.clone();
    let mut fake_retell = FakeHttp::start(move |request| {
        assert_eq!(request.headers["authorization"], RETELL_TOKEN);
        let mut state = retell_worker.lock().unwrap();
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/get-agent/agent_demo?version=1") => (200, agent.clone()),
            ("GET", "/get-retell-llm/llm_demo?version=2") => (200, llm.clone()),
            ("POST", "/v2/create-phone-call") => {
                state.creates += 1;
                assert_eq!(
                    state.creates, 1,
                    "a possibly accepted create must never be retried"
                );
                assert_eq!(request.body["from_number"], "+12025550101");
                assert_eq!(request.body["to_number"], "+12025550100");
                assert_eq!(request.body["metadata"]["intent_digest"], expected_digest);
                assert_eq!(request.body["override_agent_version"], 1);
                assert_eq!(
                    request.body["agent_override"]["agent"]["allow_user_dtmf"],
                    false
                );
                state.call = Some(json!({
                    "call_id":CALL_ID, "call_type":"phone_call", "direction":"outbound",
                    "from_number":"+12025550101", "to_number":"+12025550100",
                    "agent_id":"agent_demo", "agent_version":1,
                    "metadata":request.body["metadata"], "call_status":"registered"
                }));
                // The remote side accepted and recorded a call, but its HTTP response
                // conveys no receipt. This must remain ambiguous to the controller.
                (500, json!({"error":"synthetic_lost_receipt"}))
            }
            ("POST", "/v3/list-calls") => {
                let call = state.call.as_ref().unwrap();
                assert_eq!(
                    request.body["filter_criteria"]["metadata"][0]["value"],
                    call["metadata"]["operation_id"]
                );
                assert_eq!(
                    request.body["filter_criteria"]["agent"][0]["agent_id"],
                    "agent_demo"
                );
                let items = if state.visible {
                    vec![call.clone()]
                } else {
                    vec![]
                };
                (200, json!({"items":items,"has_more":false}))
            }
            ("GET", "/v2/get-call/call_integrated_example") => {
                (200, state.call.as_ref().unwrap().clone())
            }
            ("POST", "/v2/stop-call/call_integrated_example") => {
                state.stops += 1;
                (200, json!({}))
            }
            _ => panic!(
                "unexpected synthetic Retell request: {} {}",
                request.method, request.path
            ),
        }
    });

    let now = Arc::new(AtomicI64::new(1000));
    let rp_clock = now.clone();
    let canonical_state = Arc::new(Mutex::new(CanonicalState::default()));
    let canonical_worker = canonical_state.clone();
    let expected_work = serde_json::to_value(&intent.work_item).unwrap();
    let digest = intent.digest().unwrap();
    let purpose_digest = hash(intent.purpose.as_bytes());
    let mut fake_rp = FakeHttp::start(move |request| {
        assert_eq!(request.headers["authorization"], RP_TOKEN);
        let mut state = canonical_worker.lock().unwrap();
        if request.method == "POST" && request.path == "/v1/voice/authorize" {
            let stage = request.body["stage"].as_str().unwrap();
            let operation_id = request.body["operation_id"].as_str().unwrap();
            assert_eq!(request.body["owner"], "synthetic-owner");
            assert_eq!(request.body["digest"], digest);
            assert_eq!(request.body["purpose_digest"], purpose_digest);
            assert_eq!(request.body["work_item"], expected_work);
            assert_eq!(request.body["policy_gate_ref"], "gate_demo_v1");
            let idempotency = format!(
                "voice_{}",
                hash(&serde_json::to_vec(&json!([operation_id, digest, stage])).unwrap())
            );
            assert_eq!(request.headers["idempotency-key"], idempotency);
            match stage {
                "preview" => assert!(request.body["reservation_id"].is_null()),
                "reserve" => {
                    assert!(state.reservation_operation.is_none());
                    assert!(request.body["reservation_id"].is_null());
                    state.reservation_operation = Some(operation_id.into());
                }
                "dispatch" | "continue" => {
                    assert_eq!(state.reservation_operation.as_deref(), Some(operation_id));
                    assert_eq!(request.body["reservation_id"], "reservation_flow");
                }
                _ => panic!("unknown authority stage"),
            }
            state.stages.push(stage.into());
            (
                200,
                json!({
                    "request_digest":hash(&request.raw), "allowed":true,
                    "expires_at":rp_clock.load(Ordering::SeqCst)+60,
                    "reservation_id":if stage == "preview" { Value::Null } else { json!("reservation_flow") }
                }),
            )
        } else if request.method == "PUT" && request.path.starts_with("/v1/voice/results/") {
            let operation = request.body["operation_id"].as_str().unwrap();
            let version = request.body["result_version"].as_u64().unwrap() as u32;
            assert_eq!(
                request.path,
                format!("/v1/voice/results/{operation}/{version}")
            );
            assert_eq!(request.headers["if-match"], "\"v1\"");
            assert_eq!(state.reservation_operation.as_deref(), Some(operation));
            assert_eq!(request.body["work_item"], expected_work);
            let result = &request.body["result"];
            assert_eq!(result["operation_id"], operation);
            assert_eq!(result["result_version"], version);
            assert_eq!(result["status"], "needs_review");
            assert_ne!(result["outcome"], "objective_completed");
            assert_eq!(result["human_result"], "unobserved");
            let report = &result["reported_answers"][0];
            assert_eq!(report["verification"], "unverified_model_report");
            assert_eq!(report["answer"]["status"], "awaiting_documents");
            assert_eq!(report["answer"]["required_documents"], json!(["receipt"]));
            assert!(result["evidence_refs"]
                .as_array()
                .unwrap()
                .contains(&report["evidence_ref"]));
            assert!(!String::from_utf8_lossy(&request.raw).contains(TRANSCRIPT_MARKER));
            let already = state.results.contains_key(&version);
            if already {
                assert_eq!(state.results[&version], request.body);
            } else {
                // An unseen old version conflicts; a known historical duplicate
                // is acknowledged below without replacing the current correction.
                if state.current_result.as_ref().is_some_and(|current| {
                    current["result_version"].as_u64().unwrap() > u64::from(version)
                }) {
                    return (409, json!({"error":"stale_result_version"}));
                }
                state.results.insert(version, request.body.clone());
                state.current_result = Some(request.body.clone());
            }
            if !state.lost_first_writeback_reply {
                state.lost_first_writeback_reply = true;
                return (500, json!({"error":"synthetic_commit_without_ack"}));
            }
            state.acknowledged_versions.insert(version);
            (
                200,
                json!({"operation_id":operation,"result_version":version,"status":if already {"already_applied"} else {"applied"}}),
            )
        } else {
            panic!(
                "unexpected synthetic canonical request: {} {}",
                request.method, request.path
            )
        }
    });

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("state.db");
    let open = || {
        Controller::open_configured(
            &database,
            policy(),
            Box::new(
                HttpWorkflow::for_loopback_tests(&fake_rp.origin, Duration::from_secs(1)).unwrap(),
            ),
        )
        .unwrap()
    };
    let mut controller = open();
    let approval = controller.approve(&common::user(), &intent, 1000).unwrap();
    let operation = controller
        .start(
            &common::user(),
            &intent,
            &approval.id,
            "integrated_flow",
            1000,
        )
        .unwrap();
    let mut provider = RetellProvider::for_loopback_tests(config, &fake_retell.origin).unwrap();
    controller.tick(&mut provider, 1000).unwrap();
    let uncertain = controller.get(&common::user(), &operation.id).unwrap();
    assert_eq!(uncertain.lifecycle, Lifecycle::StartUnknown);
    assert!(uncertain.call_id.is_none() && uncertain.locked());
    assert!(uncertain.attempt_consumed);
    assert_eq!(retell_state.lock().unwrap().creates, 1);
    drop(controller);

    retell_state.lock().unwrap().visible = true;
    now.store(1001, Ordering::SeqCst);
    let mut controller = open();
    controller.tick(&mut provider, 1001).unwrap();
    let registered = controller.get(&common::user(), &operation.id).unwrap();
    assert_eq!(registered.call_id.as_deref(), Some(CALL_ID));
    assert_eq!(registered.lifecycle, Lifecycle::StartUnknown);
    assert_eq!(registered.result.status, ResultStatus::Pending);
    assert!(registered.result.evidence_refs.is_empty());
    assert!(registered.locked());
    assert!(retell_state
        .lock()
        .unwrap()
        .call
        .as_ref()
        .unwrap()
        .get("start_timestamp")
        .is_none());

    let started_call = {
        let mut state = retell_state.lock().unwrap();
        let call = state.call.as_mut().unwrap();
        call["call_status"] = json!("ongoing");
        call["start_timestamp"] = json!(1002000);
        call.clone()
    };
    let started = serde_json::to_vec(&json!({"event":"call_started","call":started_call})).unwrap();
    let signature = sign(&started, 1002000);
    controller
        .ingest(verify_and_normalize(&started, &signature, CALLBACK_KEY, 1002000).unwrap())
        .unwrap();
    controller.process_events().unwrap();
    assert_eq!(
        controller
            .get(&common::user(), &operation.id)
            .unwrap()
            .lifecycle,
        Lifecycle::Active
    );

    let phase = serde_json::to_vec(&json!({
        "operation_id":operation.id,"call_id":CALL_ID,"intent_digest":operation.digest,
        "sequence":1,"phase":"hold"
    }))
    .unwrap();
    let signature = sign(&phase, 1003000);
    let mut tampered = phase.clone();
    tampered.push(b' ');
    assert!(verify_phase(&tampered, &signature, CALLBACK_KEY, 1003000).is_err());
    controller
        .ingest_phase(verify_phase(&phase, &signature, CALLBACK_KEY, 1003000).unwrap())
        .unwrap();
    assert_eq!(
        controller
            .get(&common::user(), &operation.id)
            .unwrap()
            .phase,
        Some(Phase::Hold)
    );

    let report = serde_json::to_vec(&json!({
        "operation_id":operation.id,"call_id":CALL_ID,"intent_digest":operation.digest,
        "sequence":2,"answer":{"status":"awaiting_documents","required_documents":["receipt"],"next_step":"submit_documents"}
    })).unwrap();
    let signature = sign(&report, 1004000);
    for _ in 0..2 {
        controller
            .ingest_report(verify_report(&report, &signature, CALLBACK_KEY, 1004000).unwrap())
            .unwrap();
    }
    let reported = controller.get(&common::user(), &operation.id).unwrap();
    assert_eq!(reported.result.reported_answers.len(), 1);
    assert_eq!(
        reported.result.reported_answers[0].verification,
        Verification::UnverifiedModelReport
    );
    assert_eq!(
        reported.result.reported_answers[0].answer.status,
        ReportedStatus::AwaitingDocuments
    );
    assert_eq!(
        reported.result.reported_answers[0]
            .answer
            .required_documents,
        vec![DocumentKind::Receipt]
    );
    assert_eq!(controller.pending_outbox().unwrap().len(), 1);

    now.store(1006, Ordering::SeqCst);
    controller.tick(&mut provider, 1006).unwrap();
    controller
        .end(&common::user(), &operation.id, "user_requested", 1007)
        .unwrap();
    controller
        .revoke(&common::user(), &approval.id, 1007)
        .unwrap();
    for time in [1007, 1008] {
        now.store(time, Ordering::SeqCst);
        controller.tick(&mut provider, time).unwrap();
        let ending = controller.get(&common::user(), &operation.id).unwrap();
        assert_eq!(ending.lifecycle, Lifecycle::Ending);
        assert!(ending.locked() && !ending.all_legs_ended);
    }
    assert_eq!(retell_state.lock().unwrap().stops, 2);
    {
        let mut state = retell_state.lock().unwrap();
        let call = state.call.as_mut().unwrap();
        call["call_status"] = json!("ended");
        call["end_timestamp"] = json!(1009000);
        call["disconnection_reason"] = json!("agent_hangup");
        call["call_cost"] = json!({"combined_cost":1.2});
        call["transcript"] = json!(TRANSCRIPT_MARKER);
        call["call_analysis"] = json!({"call_successful":true});
    }
    now.store(1010, Ordering::SeqCst);
    controller.tick(&mut provider, 1010).unwrap();
    let ended = controller.get(&common::user(), &operation.id).unwrap();
    assert_eq!(ended.lifecycle, Lifecycle::Ended);
    // The worker requests stop before its terminal lookup; the earlier stop
    // receipts alone cannot establish termination. This third request is valid.
    assert_eq!(retell_state.lock().unwrap().stops, 3);
    let terminal_requests = fake_retell.requests();
    let last_stop = terminal_requests
        .iter()
        .rposition(|r| r.path.starts_with("/v2/stop-call/"))
        .unwrap();
    let terminal_lookup = terminal_requests
        .iter()
        .rposition(|r| r.path.starts_with("/v2/get-call/"))
        .unwrap();
    assert!(
        last_stop < terminal_lookup,
        "termination reads must not delay stop"
    );
    assert!(!ended.locked());
    assert!(ended.analysis_seen && ended.all_legs_ended && ended.intent.is_none());
    assert_eq!(ended.result.actual_cost_cents, Some(2));
    assert_eq!(ended.result.status, ResultStatus::NeedsReview);
    assert_ne!(ended.result.outcome, "objective_completed");
    assert_eq!(ended.result.reported_answers.len(), 1);
    assert!(!serde_json::to_string(&ended)
        .unwrap()
        .contains(TRANSCRIPT_MARKER));

    let pending_before = serde_json::to_value(controller.pending_outbox().unwrap()).unwrap();
    let expected_results = pending_before.as_array().unwrap();
    assert!(
        expected_results.len() > 1,
        "fairness requires a later correction"
    );
    let first_failed = expected_results[0].clone();
    let first_version = first_failed["result_version"].as_u64().unwrap() as u32;
    let expected_versions: BTreeSet<u32> = expected_results
        .iter()
        .map(|message| message["result_version"].as_u64().unwrap() as u32)
        .collect();
    let expected_pending = json!([first_failed]);
    let mut sink =
        HttpWorkflow::for_loopback_tests(&fake_rp.origin, Duration::from_secs(1)).unwrap();
    assert!(controller.flush_outbox(&mut sink).is_err());
    // A lost acknowledgement must not starve later corrections. Exactly the
    // first result stays pending, while all newer results are committed and acked.
    assert_eq!(
        serde_json::to_value(controller.pending_outbox().unwrap()).unwrap(),
        expected_pending
    );
    let canonical_before_replay = {
        let state = canonical_state.lock().unwrap();
        assert_eq!(state.results.len(), expected_results.len());
        for message in expected_results {
            let version = message["result_version"].as_u64().unwrap() as u32;
            assert_eq!(&state.results[&version], message);
        }
        let later_versions: BTreeSet<_> = expected_versions
            .iter()
            .copied()
            .filter(|version| *version != first_version)
            .collect();
        assert_eq!(state.acknowledged_versions, later_versions);
        let current = state.current_result.clone().unwrap();
        assert_eq!(current["result_version"], ended.result.result_version);
        assert_eq!(current["result"]["actual_cost_cents"], 2);
        current
    };
    drop(controller);
    let stages_before = canonical_state.lock().unwrap().stages.clone();
    let mut controller = open();
    assert_eq!(
        serde_json::to_value(controller.pending_outbox().unwrap()).unwrap(),
        expected_pending
    );
    let replay = controller
        .start(
            &common::user(),
            &intent,
            &approval.id,
            "integrated_flow",
            1011,
        )
        .unwrap();
    assert_eq!(replay.id, operation.id);
    assert_eq!(replay.call_id.as_deref(), Some(CALL_ID));
    controller.tick(&mut provider, 1011).unwrap();
    controller.flush_outbox(&mut sink).unwrap();
    assert!(controller.pending_outbox().unwrap().is_empty());
    assert_eq!(canonical_state.lock().unwrap().stages, stages_before);
    assert_eq!(retell_state.lock().unwrap().creates, 1);
    assert_eq!(
        retell_state.lock().unwrap().stops,
        3,
        "confirmed termination prevents further stops after restart"
    );
    let state = canonical_state.lock().unwrap();
    assert_eq!(
        state.stages,
        ["preview", "reserve", "dispatch", "continue", "continue"]
    );
    assert_eq!(
        state.results.len(),
        pending_before.as_array().unwrap().len()
    );
    assert_eq!(state.acknowledged_versions, expected_versions);
    assert_eq!(
        state.current_result.as_ref(),
        Some(&canonical_before_replay)
    );
    assert_eq!(
        state.results[&ended.result.result_version]["result"]["reported_answers"][0]
            ["verification"],
        "unverified_model_report"
    );
    drop(state);
    let requests = fake_retell.requests();
    let create = requests
        .iter()
        .find(|r| r.path == "/v2/create-phone-call")
        .unwrap();
    assert_eq!(create.body["idempotency_key"], operation.provider_key);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path == "/v2/create-phone-call")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path == "/v3/list-calls")
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path.starts_with("/v2/stop-call/"))
            .count(),
        3
    );
    let rp_requests = fake_rp.requests();
    let last_writeback = rp_requests.iter().rfind(|r| r.method == "PUT").unwrap();
    assert_eq!(last_writeback.body, first_failed);
    assert!(first_version < ended.result.result_version);
    assert_eq!(
        rp_requests.iter().filter(|r| r.method == "PUT").count(),
        pending_before.as_array().unwrap().len() + 1
    );
    assert!(rp_requests
        .iter()
        .all(|r| !String::from_utf8_lossy(&r.raw).contains(TRANSCRIPT_MARKER)));
    drop(controller);
    drop(sink);
    drop(provider);
    fake_retell.stop();
    fake_rp.stop();
}
