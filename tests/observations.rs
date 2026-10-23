use hegel::prelude::*;
use ring::hmac;
use serde_json::{json, Value};
use voice_agent::observations::{
    phase_tool, verify_phase, DtmfPlan, ObservedPhase, MAX_PHASE_BODY,
};

const KEY: &[u8] = b"synthetic-phase-signing-key";
fn payload() -> Value {
    json!({"operation_id":"op_demo","call_id":"call_demo",
        "intent_digest":format!("sha256:{}", "a".repeat(64)),"sequence":1,"phase":"hold"})
}
fn signature(body: &[u8], millis: i64) -> String {
    let timestamp = millis.to_string();
    let mut bytes = body.to_vec();
    bytes.extend_from_slice(timestamp.as_bytes());
    let signed = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, KEY), &bytes);
    let tag: String = signed.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("v={timestamp},d={tag}")
}
fn verify(value: &Value) -> voice_agent::Result<voice_agent::observations::PhaseObservation> {
    let raw = serde_json::to_vec(value).unwrap();
    verify_phase(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000)
}

#[test]
fn known_independently_signed_bytes_produce_only_the_minimal_observation() {
    // Signature fixture calculated with Python's hashlib/hmac, independently of ring.
    let raw = br#"{"operation_id":"op_demo","call_id":"call_demo","intent_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"phase":"hold"}"#;
    let signed = "v=1000000,d=541eeb9e628fe681a3cb83431c1fa57d1f343e8f37b3bc4a3eb25530b8e06962";
    let actual = verify_phase(raw, signed, KEY, 1_000_000).unwrap();
    assert_eq!(actual.phase, ObservedPhase::Hold);
    assert_eq!(actual.sequence, 1);
    assert_eq!(actual.operation_id, "op_demo");
    assert_eq!(actual.call_id, "call_demo");
    assert_eq!(actual.intent_digest, format!("sha256:{}", "a".repeat(64)));
    assert_eq!(actual.observed_at, 1000);
    assert_eq!(
        serde_json::to_value(actual)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        6
    );
}

#[test]
fn authentication_precedes_parsing_and_covers_every_body_byte() {
    let mut raw = serde_json::to_vec(&payload()).unwrap();
    let signed = signature(&raw, 1_000_000);
    raw[0] = b'[';
    assert_eq!(
        verify_phase(&raw, &signed, KEY, 1_000_000)
            .unwrap_err()
            .code,
        "invalid_webhook_signature"
    );
    assert!(verify_phase(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000).is_err());
    let valid = serde_json::to_vec(&payload()).unwrap();
    assert!(verify_phase(
        &valid,
        &signature(&valid, 1_000_000),
        b"different-synthetic-key",
        1_000_000
    )
    .is_err());
    assert!(verify_phase(&valid, &signature(&valid, 1_000_000), b"", 1_000_000).is_err());
}

#[test]
fn callback_rejects_transcript_wrappers_duplicate_fields_and_sender_clocks() {
    let wrapper =
        json!({"name":"observe_phase","args":payload(),"call":{"transcript":"SYNTHETIC"}});
    assert!(verify(&wrapper).is_err());
    for field in [
        "observed_at",
        "transcript",
        "recording_url",
        "notes",
        "name",
        "args",
    ] {
        let mut body = payload();
        body[field] = json!("SYNTHETIC");
        assert!(verify(&body).is_err(), "unexpected field {field} accepted");
    }
    let raw = serde_json::to_string(&payload()).unwrap();
    let duplicate = format!("{{\"phase\":\"talking\",{}", &raw[1..]);
    assert!(verify_phase(
        duplicate.as_bytes(),
        &signature(duplicate.as_bytes(), 1_000_000),
        KEY,
        1_000_000
    )
    .is_err());
}

#[test]
fn phase_body_size_boundary_counts_original_signed_bytes() {
    let mut raw = serde_json::to_vec(&payload()).unwrap();
    raw.resize(MAX_PHASE_BODY, b' ');
    assert!(verify_phase(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000).is_ok());
    raw.push(b' ');
    assert_eq!(
        verify_phase(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000)
            .unwrap_err()
            .code,
        "phase_body_too_large"
    );
}

#[test]
fn phase_tool_fixes_scope_and_omits_speech_and_transcript_wrapper() {
    let tool = phase_tool("https://voice.example.com/v1/functions/observe");
    assert_eq!(tool["type"], "custom");
    assert_eq!(tool["name"], "observe_phase");
    assert_eq!(tool["method"], "POST");
    assert_eq!(tool["args_at_root"], true);
    assert_eq!(tool["max_retry"], 0);
    assert_eq!(tool["timeout_ms"], 2000);
    assert_eq!(tool["speak_during_execution"], false);
    assert_eq!(tool["speak_after_execution"], false);
    assert_eq!(tool["enable_typing_sound"], false);
    let schema = &tool["parameters"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["call_id"]["const"], "{{call_id}}");
    assert_eq!(
        schema["properties"]["operation_id"]["const"],
        "{{operation_id}}"
    );
    assert_eq!(
        schema["properties"]["intent_digest"]["const"],
        "{{intent_digest}}"
    );
    assert_eq!(schema["properties"].as_object().unwrap().len(), 5);
    assert_eq!(schema["required"].as_array().unwrap().len(), 5);
    assert_eq!(schema["properties"]["sequence"]["minimum"], 1);
    assert_eq!(schema["properties"]["sequence"]["maximum"], 128);
}

/// Current operational reports have a narrow vocabulary and cannot assert human authentication.
#[hegel::test]
fn only_declared_phase_names_are_accepted(tc: TestCase) {
    let name = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                "ivr",
                "hold",
                "talking",
                "authentication_required",
                "dtmf_required",
                "declined_ai",
                "human_connected",
                "takeover",
                "success",
                "authenticated"
            ][..]
        )
        .map(str::to_owned)
    ));
    let expected = [
        "ivr",
        "hold",
        "talking",
        "authentication_required",
        "dtmf_required",
        "declined_ai",
    ]
    .contains(&name.as_str());
    let mut value = payload();
    value["phase"] = json!(name);
    tc.event(if expected {
        "accepted phase"
    } else {
        "rejected phase"
    });
    assert_eq!(verify(&value).is_ok(), expected);
}

/// Out-of-order replay is handled durably by the controller; parsing bounds resource use first.
#[hegel::test]
fn observation_sequence_accepts_exactly_the_bounded_positive_domain(tc: TestCase) {
    let sequence = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[-1_i64, 0, 1, 2, 127, 128, 129, 65535, 65536][..])
    ));
    let expected = sequence > 0 && sequence < 129;
    let mut value = payload();
    value["sequence"] = json!(sequence);
    tc.event(if expected {
        "accepted sequence"
    } else {
        "rejected sequence"
    });
    assert_eq!(verify(&value).is_ok(), expected);
}

/// A signed old report must not re-enter hold, and future skew must not extend a timer.
#[hegel::test]
fn signed_clock_bounds_hold_even_at_integer_extremes(tc: TestCase) {
    let signed_at = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[0_i64, 1, 970000, 999999, 1000000, 1030000, i64::MAX][..])
    ));
    let now = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(
            &[
                signed_at,
                signed_at.saturating_sub(30000),
                signed_at.saturating_sub(30001),
                signed_at.saturating_add(30000),
                signed_at.saturating_add(30001)
            ][..]
        )
    ));
    let raw = serde_json::to_vec(&payload()).unwrap();
    let actual = verify_phase(&raw, &signature(&raw, signed_at), KEY, now);
    let distance = (i128::from(now) - i128::from(signed_at)).abs();
    let expected = now >= 0 && signed_at >= 0 && distance <= 30000;
    tc.event(if expected {
        "fresh signed observation"
    } else {
        "rejected clock"
    });
    assert_eq!(actual.is_ok(), expected);
    if let Ok(observation) = actual {
        assert!(observation.observed_at <= now / 1000);
        assert_eq!(
            observation.observed_at,
            std::cmp::min(signed_at, now) / 1000
        );
    }
}

/// A digest is an exact binary fingerprint rendered in canonical lowercase, not a free-form ID.
#[hegel::test]
fn malformed_digests_cannot_bind_a_phase_to_an_approval(tc: TestCase) {
    let value = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                format!("sha256:{}", "a".repeat(64)),
                format!("sha256:{}", "0".repeat(64)),
                format!("sha256:{}", "a".repeat(63)),
                format!("sha256:{}", "a".repeat(65)),
                format!("sha256:{}", "A".repeat(64)),
                format!("sha256:{}", "g".repeat(64))
            ][..]
        )
    ));
    let expected = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].chars().all(|c| "0123456789abcdef".contains(c));
    let mut body = payload();
    body["intent_digest"] = json!(value);
    tc.event(if expected {
        "canonical digest"
    } else {
        "rejected digest"
    });
    assert_eq!(verify(&body).is_ok(), expected);
}

/// A future digit transport cannot broaden the menu allowlist or reset consumed attempt counts.
#[hegel::test]
fn menu_digit_plans_reject_sequences_and_exhausted_attempts(tc: TestCase) {
    let digit = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "12", "#", "*", "١"][..]
        )
        .map(str::to_owned)
    ));
    let limit = tc.draw(hegel::one_of!(
        gs::integers::<u8>(),
        gs::sampled_from(&[0_u8, 1, 2, 3, 4][..])
    ));
    let consumed = tc.draw(hegel::one_of!(
        gs::integers::<u8>(),
        gs::sampled_from(&[0_u8, 1, 2, 3][..])
    ));
    let plan = DtmfPlan {
        allowed_menu_digits: vec!["1".into(), "2".into()],
        max_presses: limit,
    };
    let expected = [1, 2, 3].contains(&limit)
        && usize::from(consumed) < usize::from(limit)
        && ["1", "2"].contains(&digit.as_str());
    tc.event(if expected {
        "allowed menu candidate"
    } else {
        "rejected menu candidate"
    });
    assert_eq!(plan.permits_menu_digit(&digit, consumed), expected);
    assert!(plan.require_retell_execution().is_err());
}

#[test]
fn even_valid_menu_plans_do_not_enable_the_unbounded_native_tool() {
    let plan = DtmfPlan {
        allowed_menu_digits: vec!["0".into()],
        max_presses: 3,
    };
    assert!(plan.validate().is_ok());
    assert!(plan.permits_menu_digit("0", 2));
    assert!(!plan.permits_menu_digit("0", 3));
    assert_eq!(
        plan.require_retell_execution().unwrap_err().code,
        "retell_bounded_dtmf_unavailable"
    );
    for allowed in [
        vec![],
        vec!["1".into(), "1".into()],
        vec!["12".into()],
        vec!["*".into()],
        vec!["".into()],
    ] {
        assert!(DtmfPlan {
            allowed_menu_digits: allowed,
            max_presses: 1
        }
        .validate()
        .is_err());
    }
}

/// The plan validator accepts only a finite set of distinct decimal menu symbols.
#[hegel::test]
fn menu_plan_validation_matches_a_set_of_single_decimal_choices(tc: TestCase) {
    let digits = tc.draw(gs::vecs(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "", "12", "*", "#"][..]
        )
        .map(str::to_owned)
    )));
    let max_presses = tc.draw(hegel::one_of!(
        gs::integers::<u8>(),
        gs::sampled_from(&[0_u8, 1, 2, 3, 4][..])
    ));
    let choices =
        std::collections::BTreeSet::from(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    let requested: std::collections::BTreeSet<_> = digits.iter().map(String::as_str).collect();
    let expected = !requested.is_empty()
        && requested.len() == digits.len()
        && requested.is_subset(&choices)
        && [1, 2, 3].contains(&max_presses);
    let plan = DtmfPlan {
        allowed_menu_digits: digits,
        max_presses,
    };
    tc.event(if expected {
        "valid menu plan"
    } else {
        "invalid menu plan"
    });
    assert_eq!(plan.validate().is_ok(), expected);
}

fn report_payload() -> Value {
    let mut value = payload();
    value.as_object_mut().unwrap().remove("phase");
    value["answer"] = json!({"status":"awaiting_documents","required_documents":["receipt","claim_form"],"next_step":"submit_documents"});
    value
}
fn report(value: &Value) -> voice_agent::Result<voice_agent::observations::ReportObservation> {
    let raw = serde_json::to_vec(value).unwrap();
    voice_agent::observations::verify_report(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000)
}

#[test]
fn categorical_answer_retains_only_unverified_nonidentifying_choices() {
    use voice_agent::observations::{
        AnswerEvidence, DocumentKind, NextStep, ReportedStatus, Verification,
    };
    let observation = report(&report_payload()).unwrap();
    assert_eq!(observation.answer.status, ReportedStatus::AwaitingDocuments);
    assert_eq!(
        observation.answer.required_documents,
        vec![DocumentKind::Receipt, DocumentKind::ClaimForm]
    );
    assert_eq!(observation.answer.next_step, NextStep::SubmitDocuments);
    let evidence = AnswerEvidence {
        evidence_ref: "report_demo".into(),
        reported_at: observation.observed_at,
        verification: Verification::UnverifiedModelReport,
        answer: observation.answer,
    };
    let serialized = serde_json::to_value(&evidence).unwrap();
    assert_eq!(serialized["verification"], "unverified_model_report");
    for unsupported in ["verified", "successful", "user_confirmed", "authenticated"] {
        let mut changed = serialized.clone();
        changed["verification"] = json!(unsupported);
        assert!(serde_json::from_value::<AnswerEvidence>(changed).is_err());
    }
    let mut unknown = report_payload();
    unknown["answer"] = json!({"status":"unknown","required_documents":[],"next_step":"unknown"});
    assert!(report(&unknown).is_ok());
}

#[test]
fn answer_report_rejects_extra_text_identifiers_and_sender_time_at_every_layer() {
    for key in [
        "notes",
        "account_id",
        "observed_at",
        "transcript",
        "recording_url",
        "verification",
        "phase",
    ] {
        let mut value = report_payload();
        value[key] = json!("SYNTHETIC");
        assert!(report(&value).is_err());
    }
    for key in ["notes", "account_id", "verified", "amount", "reference"] {
        let mut value = report_payload();
        value["answer"][key] = json!("SYNTHETIC");
        assert!(report(&value).is_err());
    }
    for key in ["status", "required_documents", "next_step"] {
        let mut value = report_payload();
        value["answer"].as_object_mut().unwrap().remove(key);
        assert!(report(&value).is_err());
    }
    let mut value = report_payload();
    value["answer"]["required_documents"] = json!([{"type":"receipt","reference":"SYNTHETIC"}]);
    assert!(report(&value).is_err());
    let wrapper =
        json!({"name":"report_answer","args":report_payload(),"call":{"transcript":"SYNTHETIC"}});
    assert!(report(&wrapper).is_err());
}

#[test]
fn phase_and_answer_payloads_cannot_be_substituted() {
    assert!(verify(&report_payload()).is_err());
    assert!(report(&payload()).is_err());
    for (field, replacement) in [
        ("operation_id", json!("")),
        ("call_id", json!("call/foreign")),
        ("intent_digest", json!("sha256:short")),
        ("sequence", json!(0)),
        ("sequence", json!(129)),
    ] {
        let mut body = report_payload();
        body[field] = replacement;
        assert!(report(&body).is_err());
    }
}

#[test]
fn report_authentication_and_size_limits_apply_before_parsing() {
    use voice_agent::observations::verify_report;
    let mut raw = serde_json::to_vec(&report_payload()).unwrap();
    let signed = signature(&raw, 1_000_000);
    raw[0] = b'[';
    assert_eq!(
        verify_report(&raw, &signed, KEY, 1_000_000)
            .unwrap_err()
            .code,
        "invalid_webhook_signature"
    );
    let mut raw = serde_json::to_vec(&report_payload()).unwrap();
    raw.resize(MAX_PHASE_BODY, b' ');
    assert!(verify_report(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000).is_ok());
    raw.push(b' ');
    assert_eq!(
        verify_report(&raw, &signature(&raw, 1_000_000), KEY, 1_000_000)
            .unwrap_err()
            .code,
        "report_body_too_large"
    );
}

#[test]
fn report_tool_keeps_the_same_narrow_scope_and_fixed_answer_schema() {
    let tool =
        voice_agent::observations::report_tool("https://voice.example.com/v1/functions/report");
    assert_eq!(tool["name"], "report_answer");
    assert_eq!(tool["url"], "https://voice.example.com/v1/functions/report");
    assert_eq!(tool["method"], "POST");
    assert_eq!(tool["args_at_root"], true);
    assert_eq!(tool["max_retry"], 0);
    assert_eq!(tool["speak_during_execution"], false);
    assert_eq!(tool["speak_after_execution"], false);
    assert_eq!(tool["timeout_ms"], 2000);
    let properties = &tool["parameters"]["properties"];
    assert_eq!(properties.as_object().unwrap().len(), 5);
    assert!(properties.get("phase").is_none());
    for (name, binding) in [
        ("call_id", "{{call_id}}"),
        ("operation_id", "{{operation_id}}"),
        ("intent_digest", "{{intent_digest}}"),
    ] {
        assert_eq!(properties[name]["const"], binding);
    }
    assert_eq!(tool["parameters"]["additionalProperties"], false);
    assert_eq!(properties["answer"]["additionalProperties"], false);
    assert_eq!(
        properties["answer"]["required"],
        json!(["status", "required_documents", "next_step"])
    );
    assert_eq!(
        properties["answer"]["properties"]["required_documents"]["maxItems"],
        4
    );
    assert_eq!(
        properties["answer"]["properties"]["required_documents"]["uniqueItems"],
        true
    );
}

/// Status and next-step reports cannot widen into model claims or arbitrary text.
#[hegel::test]
fn reported_answer_categories_match_the_small_declared_vocabularies(tc: TestCase) {
    let status = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                "unknown",
                "under_review",
                "awaiting_documents",
                "unable_to_locate",
                "approved",
                "completed",
                "authenticated"
            ][..]
        )
        .map(str::to_owned)
    ));
    let next = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                "unknown",
                "wait",
                "submit_documents",
                "contact_directly",
                "pay",
                "verify",
                "claim_complete"
            ][..]
        )
        .map(str::to_owned)
    ));
    let expected = [
        "unknown",
        "under_review",
        "awaiting_documents",
        "unable_to_locate",
    ]
    .contains(&status.as_str())
        && ["unknown", "wait", "submit_documents", "contact_directly"].contains(&next.as_str());
    let mut value = report_payload();
    value["answer"]["status"] = json!(status);
    value["answer"]["next_step"] = json!(next);
    tc.event(if expected {
        "accepted answer categories"
    } else {
        "rejected answer categories"
    });
    assert_eq!(report(&value).is_ok(), expected);
}

/// Document choices form a set, without duplicate evidence or unbounded text payloads.
#[hegel::test]
fn reported_document_choices_match_the_closed_set_without_duplicates(tc: TestCase) {
    let documents = tc.draw(gs::vecs(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                "receipt",
                "claim_form",
                "return_policy",
                "photos",
                "account_number",
                "other"
            ][..]
        )
        .map(str::to_owned)
    )));
    let allowed =
        std::collections::BTreeSet::from(["receipt", "claim_form", "return_policy", "photos"]);
    let distinct: std::collections::BTreeSet<_> = documents.iter().map(String::as_str).collect();
    let expected = distinct.len() == documents.len() && distinct.is_subset(&allowed);
    let mut value = report_payload();
    value["answer"]["required_documents"] = json!(documents);
    tc.event(if expected {
        "accepted document set"
    } else {
        "rejected document list"
    });
    assert_eq!(report(&value).is_ok(), expected);
}

/// Authentication and fresh time bind result evidence just as strictly as phases.
#[hegel::test]
fn result_reports_reject_stale_clocks_without_promoting_future_time(tc: TestCase) {
    let timestamp = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[0_i64, 1, 1000000, i64::MAX][..])
    ));
    let now = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(
            &[
                timestamp,
                timestamp.saturating_sub(30000),
                timestamp.saturating_sub(30001),
                timestamp.saturating_add(30000),
                timestamp.saturating_add(30001)
            ][..]
        )
    ));
    let raw = serde_json::to_vec(&report_payload()).unwrap();
    let actual =
        voice_agent::observations::verify_report(&raw, &signature(&raw, timestamp), KEY, now);
    let expected =
        now >= 0 && timestamp >= 0 && (i128::from(now) - i128::from(timestamp)).abs() <= 30000;
    tc.event(if expected {
        "fresh result report"
    } else {
        "rejected result clock"
    });
    assert_eq!(actual.is_ok(), expected);
    if let Ok(report) = actual {
        assert_eq!(report.observed_at, std::cmp::min(timestamp, now) / 1000);
    }
}
