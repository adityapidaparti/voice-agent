use hegel::prelude::*;
use ring::hmac;
use serde_json::{json, Value};
use voice_agent::contract::{CallResult, EventKind, Intent, Lifecycle, Operation, ResultStatus};
use voice_agent::provider::{
    build_retell_request, retell_llm_template, verify_and_normalize, CreateOutcome, Provider,
    Simulation, SyntheticProvider,
};

fn operation() -> Operation {
    let intent: Intent = serde_json::from_value(json!({
        "schema_version":1,"intent_id":"intent_demo",
        "work_item":{"system":"example","reference":"work_demo","version":"v1"},
        "destination":{"e164":"+12025550100","source_ref":"directory_demo","source_version":"v1"},
        "purpose":"Ask which documents are required",
        "facts":{"reference":{"value":"EXAMPLE-123","source_ref":"record_demo","source_version":"v1"}},
        "permitted_actions":["ask_documents"],"forbidden_actions":["attest","pay","accept_terms"],
        "forbidden_disclosures":["password","otp","pin"],"ai_disclosure":true,"consent_policy_ref":"consent_demo",
        "handoff":{"recipient_ref":"owner","endpoint_ref":"owner_direct","mode":"manual","resume_ai":false,"authentication":"separate_direct_call"},
        "limits":{"attempts":1,"duration_seconds":60,"hold_seconds":30,"handoff_wait_seconds":10,"budget_cents":100,"rate_cents_per_minute":10,"rate_ref":"synthetic_rate"},
        "policy_gate_ref":"gate_demo","provider":"retell","agent_id":"agent_demo","agent_version":7,
        "not_before":1000,"not_after":2000
    })).unwrap();
    Operation {
        id: "op_demo".into(),
        owner: "owner_demo".into(),
        approval_id: "approval_demo".into(),
        digest: intent.digest().unwrap(),
        provider_key: "provider_demo".into(),
        call_id: None,
        lifecycle: Lifecycle::Submitting,
        phase: None,
        created_at: 1000,
        submitted_at: Some(1000),
        last_observed_at: 1000,
        deadline: 1060,
        phase_since: 1000,
        attempt_consumed: true,
        stop_reason: None,
        ai_stopped: false,
        all_legs_ended: false,
        uncertain_legs: false,
        analysis_seen: false,
        menu_repeats: 0,
        result: CallResult {
            schema_version: 1,
            operation_id: "op_demo".into(),
            work_item: intent.work_item.clone(),
            result_version: 0,
            status: ResultStatus::Pending,
            outcome: "unknown".into(),
            evidence_refs: vec![],
            human_result: "unobserved".into(),
            next_action: "wait".into(),
            actual_cost_cents: None,
            estimated_cost_cents: 20,
            reported_answers: vec![],
        },
        intent: Some(intent),
    }
}

fn signature(body: &[u8], millis: i64) -> String {
    let timestamp = millis.to_string();
    let mut input = body.to_vec();
    input.extend_from_slice(timestamp.as_bytes());
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, b"synthetic-webhook-key"),
        &input,
    );
    let digest: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("v={timestamp},d={digest}")
}
fn webhook(event: &str) -> Value {
    json!({"event":event,"call":{"call_id":"call_demo","metadata":{"operation_id":"op_demo"},
        "start_timestamp":1700000000000_i64,"end_timestamp":1700000003000_i64,
        "disconnection_reason":"user_hangup","call_cost":{"combined_cost":12.5}}})
}
fn normalize(value: &Value) -> voice_agent::Result<voice_agent::contract::Event> {
    let body = serde_json::to_vec(value).unwrap();
    verify_and_normalize(
        &body,
        &signature(&body, 1700000004000),
        b"synthetic-webhook-key",
        1700000004000,
    )
}

#[test]
fn independent_hmac_vector_authenticates_the_exact_raw_body() {
    // This vector was calculated independently with Python's hmac/hashlib.
    let body=br#"{"event":"call_started","call":{"call_id":"call_demo","metadata":{"operation_id":"op_demo"},"start_timestamp":1700000000000}}"#;
    let header =
        "v=1700000000000,d=4cbb3654f15d136d3eded131ca553a55ba1d34b7b59d20a93923cf96adc23db6";
    let event =
        verify_and_normalize(body, header, b"synthetic-webhook-key", 1700000000000).unwrap();
    assert_eq!(event.kind, EventKind::Started);
    assert_eq!(event.observed_at, 1700000000);
    assert_eq!(event.key, "call_started:call_demo");
    let mut changed = body.to_vec();
    changed.push(b' ');
    assert!(
        verify_and_normalize(&changed, header, b"synthetic-webhook-key", 1700000000000).is_err()
    );
    assert!(verify_and_normalize(body, header, b"different-key", 1700000000000).is_err());
}

#[test]
fn authentication_window_has_symmetric_five_minute_boundaries() {
    let body = serde_json::to_vec(&webhook("call_started")).unwrap();
    let header = signature(&body, 1700000000000);
    for delta in [-300_000_i64, 0, 300_000] {
        assert!(verify_and_normalize(
            &body,
            &header,
            b"synthetic-webhook-key",
            1700000000000 + delta
        )
        .is_ok());
    }
    for now in [i64::MIN, 0, 1699999699999, 1700000300001, i64::MAX] {
        assert!(verify_and_normalize(&body, &header, b"synthetic-webhook-key", now).is_err());
    }
}

#[test]
fn malformed_and_unsigned_events_never_reach_json_normalization() {
    for header in ["", "v=0", "v=-1,d=00", "v=1700000000000,d=xyz", "v=1700000000000,d=", "v=99999999999999999999999,d=0000000000000000000000000000000000000000000000000000000000000000"] {
        assert_eq!(verify_and_normalize(b"not json",header,b"key",1700000000000).unwrap_err().code,"invalid_webhook_signature");
    }
    let body = vec![b'a'; 1_048_577];
    assert!(verify_and_normalize(
        &body,
        &signature(&body, 1700000000000),
        b"synthetic-webhook-key",
        1700000000000
    )
    .is_err());
}

#[test]
fn transcript_and_model_success_are_not_promoted_to_evidence_or_authority() {
    let mut body = webhook("call_analyzed");
    body["call"]["transcript"] = json!("SYNTHETIC-SECRET-DO-NOT-STORE");
    body["call"]["recording_url"] =
        json!("https://example.invalid/private?token=SYNTHETIC-SECRET-DO-NOT-STORE");
    body["call"]["call_analysis"] = json!({"call_successful":true,"custom_analysis_data":{"approved":true,"new_number":"+12025550199"}});
    let event = normalize(&body).unwrap();
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(!serialized.contains("SYNTHETIC-SECRET"));
    assert!(!serialized.contains("approved"));
    assert_eq!(event.kind, EventKind::Analyzed);
    assert_eq!(event.actual_cost_cents, Some(13));
    assert!(!event.all_legs_ended);
}

#[test]
fn malformed_mapping_and_time_cannot_bind_an_operation() {
    for path in ["call_id", "metadata"] {
        let mut body = webhook("call_started");
        body["call"].as_object_mut().unwrap().remove(path);
        assert!(normalize(&body).is_err());
    }
    for name in ["", "op\nsecret", "../op"] {
        let mut body = webhook("call_started");
        body["call"]["metadata"]["operation_id"] = json!(name);
        assert!(normalize(&body).is_err());
    }
    for time in [-1_i64, 1700000304001, i64::MAX] {
        let mut body = webhook("call_ended");
        body["call"]["end_timestamp"] = json!(time);
        assert!(normalize(&body).is_err());
    }
    let mut body = webhook("call_ended");
    body["call"]["end_timestamp"] = json!(1699999999999_i64);
    assert!(normalize(&body).is_err());
}

#[test]
fn transfer_and_unknown_termination_never_release_the_call_guard() {
    for event in ["call_taken_over", "transcript_updated"] {
        assert_eq!(
            normalize(&webhook(event)).unwrap_err().code,
            "unsupported_provider_event"
        );
    }
    for reason in [
        json!("call_transfer"),
        json!("new_unknown_reason"),
        Value::Null,
    ] {
        let mut body = webhook("call_ended");
        body["call"]["disconnection_reason"] = reason;
        assert!(!normalize(&body).unwrap().all_legs_ended);
    }
    assert!(normalize(&webhook("call_ended")).unwrap().all_legs_ended);
    for event in [
        "transfer_started",
        "transfer_bridged",
        "transfer_cancelled",
        "transfer_ended",
    ] {
        let mut body = webhook(event);
        body["transfer_destination"] = json!({"number":"+12025550199"});
        let transfer = normalize(&body).unwrap();
        assert_eq!(transfer.kind, EventKind::Ended);
        assert!(!transfer.all_legs_ended);
        assert!(!transfer.key.contains("+12025550199"));
        let mut op = operation();
        op.observe(&transfer).unwrap();
        op.observe(&normalize(&webhook("call_ended")).unwrap())
            .unwrap();
        assert!(op.locked());
        assert_eq!(op.stop_reason.as_deref(), Some("uncontrolled_leg"));
    }
}

#[test]
fn invalid_cost_is_unknown_rather_than_zero_or_wrapped() {
    for cost in [json!(-1), json!(4294967296_u64), Value::Null] {
        let mut body = webhook("call_analyzed");
        body["call"]["call_cost"]["combined_cost"] = cost;
        assert_eq!(normalize(&body).unwrap().actual_cost_cents, None);
    }
    for cost in [0, 1, 1000, u32::MAX] {
        let mut body = webhook("call_analyzed");
        body["call"]["call_cost"]["combined_cost"] = json!(cost);
        assert_eq!(normalize(&body).unwrap().actual_cost_cents, Some(cost));
    }
}

#[test]
fn transfer_attempt_identity_distinguishes_time_and_destination_without_storing_them() {
    let mut body = webhook("transfer_started");
    body["call"]["call_id"] = json!("c".repeat(128));
    body["transfer_destination"] = json!({"number":"+12025550100","extension":"1234"});
    let first = normalize(&body).unwrap();
    assert!(voice_agent::contract::identifier(&first.key));
    assert_eq!(normalize(&body).unwrap().key, first.key);
    body["start_timestamp"] = json!(1700000001000_i64);
    let second = normalize(&body).unwrap();
    assert_ne!(second.key, first.key);
    body["transfer_destination"] = json!({"number":"+12025550101","extension":"1234"});
    assert_ne!(normalize(&body).unwrap().key, second.key);
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("+12025550100"));
}

#[test]
fn dropped_create_response_is_recoverable_without_another_call() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("provider.db");
    let op = operation();
    let mut first = SyntheticProvider::open(&path, Simulation::DropCreateResponse).unwrap();
    assert_eq!(first.create(&op, 1000), CreateOutcome::Unknown);
    assert_eq!(first.call_count().unwrap(), 1);
    drop(first);
    let mut restarted = SyntheticProvider::open(&path, Simulation::Success).unwrap();
    let events = restarted.lookup(&op, 1004).unwrap();
    assert_eq!(
        events.iter().map(|e| e.kind).collect::<Vec<_>>(),
        [EventKind::Started, EventKind::Ended, EventKind::Analyzed]
    );
    assert!(events[1].all_legs_ended);
    assert_eq!(restarted.call_count().unwrap(), 1);
}

#[test]
fn provider_key_deduplication_survives_restart_and_rejects_scope_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("provider.db");
    let op = operation();
    let mut provider = SyntheticProvider::open(&path, Simulation::Success).unwrap();
    let accepted = provider.create(&op, 1000);
    assert!(matches!(accepted, CreateOutcome::Accepted(_)));
    assert_eq!(provider.create(&op, 1001), accepted);
    let mut changed = op.clone();
    changed.intent.as_mut().unwrap().purpose = "Ask a different question".into();
    changed.digest = changed.intent.as_ref().unwrap().digest().unwrap();
    assert_eq!(provider.create(&changed, 1001), CreateOutcome::Unknown);
    assert!(provider.lookup(&changed, 1001).is_err());
    changed = op.clone();
    changed.id = "another_operation".into();
    assert_eq!(provider.create(&changed, 1001), CreateOutcome::Unknown);
    assert_eq!(provider.call_count().unwrap(), 1);
}

#[test]
fn provider_will_not_simulate_an_unapproved_or_real_destination() {
    let temp = tempfile::tempdir().unwrap();
    let mut provider =
        SyntheticProvider::open(temp.path().join("provider.db"), Simulation::Success).unwrap();
    for to in ["+12025550200", "+1202555010", "not-a-number"] {
        let mut op = operation();
        op.intent.as_mut().unwrap().destination.e164 = to.into();
        op.digest = op.intent.as_ref().unwrap().digest().unwrap();
        assert_eq!(provider.create(&op, 1000), CreateOutcome::Unknown);
    }
    let mut op = operation();
    op.attempt_consumed = false;
    assert_eq!(provider.create(&op, 1000), CreateOutcome::Unknown);
    op = operation();
    op.digest = "changed".into();
    assert_eq!(provider.create(&op, 1000), CreateOutcome::Unknown);
    assert_eq!(provider.call_count().unwrap(), 0);
}

#[test]
fn lost_stop_response_is_not_confirmation_but_lookup_provides_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let mut provider =
        SyntheticProvider::open(temp.path().join("provider.db"), Simulation::LostStop).unwrap();
    let mut op = operation();
    let CreateOutcome::Accepted(id) = provider.create(&op, 1000) else {
        panic!("expected accepted")
    };
    assert!(provider.stop(&op, 1001).is_err());
    op.call_id = Some(id);
    assert_eq!(
        provider.stop(&op, 1001).unwrap_err().code,
        "stop_outcome_unknown"
    );
    assert_eq!(
        provider.stop(&op, 1002).unwrap_err().code,
        "stop_outcome_unknown"
    );
    let ended = provider
        .lookup(&op, 1002)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EventKind::Ended)
        .unwrap();
    assert_eq!(ended.observed_at, 1001);
    assert!(ended.all_legs_ended);
}

#[test]
fn missing_analysis_remains_missing_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("provider.db");
    let op = operation();
    let mut provider = SyntheticProvider::open(&path, Simulation::PendingAnalysis).unwrap();
    provider.create(&op, 1000);
    drop(provider);
    let mut restarted = SyntheticProvider::open(&path, Simulation::Success).unwrap();
    assert!(restarted
        .lookup(&op, 5000)
        .unwrap()
        .iter()
        .all(|e| e.kind != EventKind::Analyzed));
}

#[test]
fn definitive_rejection_and_absent_lookup_create_no_call() {
    let temp = tempfile::tempdir().unwrap();
    let mut provider =
        SyntheticProvider::open(temp.path().join("provider.db"), Simulation::Reject).unwrap();
    let op = operation();
    assert_eq!(provider.create(&op, 1000), CreateOutcome::Rejected);
    assert!(provider.lookup(&op, 1004).unwrap().is_empty());
    assert_eq!(provider.call_count().unwrap(), 0);
}

#[test]
fn retell_payload_binds_version_limits_disclosure_and_only_approved_facts() {
    let op = operation();
    let payload = build_retell_request(&op, "+12025550199", 1000).unwrap();
    assert_eq!(payload["idempotency_key"], "provider_demo");
    assert_eq!(payload["override_agent_version"], 7);
    assert_eq!(payload["to_number"], "+12025550100");
    assert_eq!(payload["metadata"].as_object().unwrap().len(), 2);
    assert!(!payload["metadata"].to_string().contains("EXAMPLE-123"));
    let task: Value = serde_json::from_str(
        payload["retell_llm_dynamic_variables"]["approved_task"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(task["facts"], json!({"reference":"EXAMPLE-123"}));
    assert_eq!(
        payload["agent_override"]["agent"]["max_call_duration_ms"],
        60000
    );
    assert_eq!(
        payload["agent_override"]["agent"]["end_call_after_silence_ms"],
        30000
    );
    assert_eq!(
        payload["agent_override"]["agent"]["data_storage_setting"],
        "basic_attributes_only"
    );
    assert_eq!(
        payload["agent_override"]["agent"]["data_storage_retention_days"],
        30
    );
    assert_eq!(
        payload["agent_override"]["agent"]["contact_memory_config"],
        json!({"enable_read":false,"enable_update":false})
    );
    let llm = &payload["agent_override"]["retell_llm"];
    assert!(llm["begin_message"]
        .as_str()
        .unwrap()
        .contains("AI assistant"));
    assert_eq!(llm["knowledge_base_ids"], json!([]));
    assert_eq!(llm.as_object().unwrap().len(), 3);
    assert!(llm.get("general_prompt").is_none());
    assert!(llm.get("general_tools").is_none());
    let template = retell_llm_template();
    assert_eq!(template["general_tools"].as_array().unwrap().len(), 1);
    assert_eq!(template["general_tools"][0]["type"], "end_call");
    assert_eq!(template["mcps"], json!([]));
    assert_eq!(
        payload["agent_override"]["agent"]["pre_session_tools"],
        Value::Null
    );
    assert_eq!(
        payload["agent_override"]["agent"]["post_session_tools"],
        Value::Null
    );
    assert_eq!(payload["agent_override"]["agent"]["reminder_max_count"], 0);
}

#[test]
fn retell_request_builder_refuses_mutated_scope_or_unsafe_provider_keys() {
    for key in ["abc", "with.dot", "secret\nheader", ""] {
        let mut op = operation();
        op.provider_key = key.into();
        assert!(build_retell_request(&op, "+12025550199", 1000).is_err());
    }
    let mut op = operation();
    op.intent
        .as_mut()
        .unwrap()
        .facts
        .get_mut("reference")
        .unwrap()
        .value = "changed".into();
    assert!(build_retell_request(&op, "+12025550199", 1000).is_err());
    op = operation();
    op.intent = None;
    assert!(build_retell_request(&op, "+12025550199", 1000).is_err());
    assert!(build_retell_request(&operation(), "invalid", 1000).is_err());
    op = operation();
    op.intent.as_mut().unwrap().limits.duration_seconds = 30;
    op.digest = op.intent.as_ref().unwrap().digest().unwrap();
    assert_eq!(
        build_retell_request(&op, "+12025550199", 1000)
            .unwrap_err()
            .code,
        "retell_duration_below_provider_minimum"
    );
    op = operation();
    op.intent.as_mut().unwrap().limits.hold_seconds = 9;
    op.digest = op.intent.as_ref().unwrap().digest().unwrap();
    assert_eq!(
        build_retell_request(&op, "+12025550199", 1000)
            .unwrap_err()
            .code,
        "retell_silence_below_provider_minimum"
    );
}

/// A captured authentic event must not authenticate an attacker-changed payload.
#[hegel::test]
fn changing_any_body_byte_invalidates_the_captured_signature(tc: TestCase) {
    let body = serde_json::to_vec(&webhook("call_started")).unwrap();
    let header = signature(&body, 1700000000000);
    let index = tc.draw(
        gs::integers::<usize>()
            .min_value(0)
            .max_value(body.len() - 1),
    );
    let mask = tc.draw(gs::integers::<u8>().min_value(1));
    let mut changed = body;
    changed[index] ^= mask;
    assert_eq!(
        verify_and_normalize(&changed, &header, b"synthetic-webhook-key", 1700000000000)
            .unwrap_err()
            .code,
        "invalid_webhook_signature"
    );
}

/// Full-width clocks exercise arithmetic overflow as well as replay boundaries.
#[hegel::test]
fn webhook_age_is_checked_without_signed_integer_overflow(tc: TestCase) {
    let body = serde_json::to_vec(&webhook("call_started")).unwrap();
    let header = signature(&body, 1700000000000);
    let now = tc.draw(gs::integers::<i64>());
    let expected = (i128::from(now) - 1700000000000_i128).abs() <= 300_000 && now >= 0;
    assert_eq!(
        verify_and_normalize(&body, &header, b"synthetic-webhook-key", now).is_ok(),
        expected
    );
}

#[test]
fn a_late_stop_does_not_move_an_already_observed_end_time() {
    let temp = tempfile::tempdir().unwrap();
    let mut provider =
        SyntheticProvider::open(temp.path().join("provider.db"), Simulation::Success).unwrap();
    let mut op = operation();
    let CreateOutcome::Accepted(id) = provider.create(&op, 1000) else {
        panic!("expected accepted")
    };
    op.call_id = Some(id);
    provider.stop(&op, 1100).unwrap();
    let ended = provider
        .lookup(&op, 1100)
        .unwrap()
        .into_iter()
        .find(|e| e.kind == EventKind::Ended)
        .unwrap();
    assert_eq!(ended.observed_at, 1003);
}
