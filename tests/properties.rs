//! Generated properties check the contract against small independent models.
//! The state model records evidence as sets of observations, not implementation states.
mod common;
use common::*;
use hegel::prelude::*;
use voice_agent::contract::*;

/// Approvals must expire exactly at their displayed boundary, including extreme clocks.
#[hegel::test]
fn a_call_intent_is_usable_only_inside_its_approved_time_window(tc: TestCase) {
    let now = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[999_i64, 1000, 1001, 4599, 4600, 4601][..])
    ));
    assert_eq!(intent().validate(now).is_ok(), (1000..4600).contains(&now));
}

/// Numeric limits reject out-of-domain values without overflow or implicit defaults.
#[hegel::test]
fn accepted_duration_and_budget_values_match_the_documented_limits(tc: TestCase) {
    let duration = tc.draw(hegel::one_of!(
        gs::integers::<u32>(),
        gs::sampled_from(&[0_u32, 29, 30, 59, 60, 61, 1799, 1800, 1801][..])
    ));
    let budget = tc.draw(hegel::one_of!(
        gs::integers::<u32>(),
        gs::sampled_from(&[0_u32, 19, 20, 30, 40, 100, 310, 1000, 1001][..])
    ));
    let mut i = intent();
    i.limits.duration_seconds = duration;
    i.limits.hold_seconds = 1;
    i.limits.budget_cents = budget;
    // A duration fits in this many priced minute buckets, plus one stop-delay bucket.
    let minute_buckets = (0_u64..=30).find(|m| u64::from(duration) <= 60 * m);
    let expected = (30..=1800).contains(&duration)
        && (1..=1000).contains(&budget)
        && minute_buckets.is_some_and(|m| (m + 1) * 10 <= u64::from(budget));
    tc.event(if expected {
        "valid limits"
    } else {
        "invalid limits"
    });
    assert_eq!(i.validate(1000).is_ok(), expected);
}

/// The full u32 pricing range is safe even when values will later be rejected by policy.
#[hegel::test]
fn estimates_cover_duration_rounding_and_one_stop_delay_minute(tc: TestCase) {
    let seconds = tc.draw(gs::integers::<u32>());
    let rate = tc.draw(gs::integers::<u32>());
    let mut i = intent();
    i.limits.duration_seconds = seconds;
    i.limits.rate_cents_per_minute = rate;
    let reserve = u128::from(i.estimate_cents());
    let exact_time_cost = u128::from(seconds) * u128::from(rate);
    // Remove the stop-delay minute. The remaining reserve pays for the duration,
    // and has less than one additional minute of rounding.
    let call_cost = reserve - u128::from(rate);
    assert!(call_cost * 60 >= exact_time_cost);
    assert!(call_cost * 60 <= exact_time_cost + 59 * u128::from(rate));
}

/// A fact source change is a different approval even when its wording stays the same.
#[hegel::test]
fn changing_a_fact_version_invalidates_the_old_digest(tc: TestCase) {
    let suffix = tc.draw(gs::text());
    let original = intent();
    let mut changed = original.clone();
    changed
        .facts
        .get_mut("reference")
        .unwrap()
        .source_version
        .push_str(&format!("_{suffix}"));
    assert_ne!(original.digest().unwrap(), changed.digest().unwrap());
}

/// JSON object order is representational; the frozen typed scope has one digest.
#[hegel::test]
fn reordering_json_object_members_preserves_the_approved_scope(tc: TestCase) {
    let value = tc.draw(gs::text());
    let mut i = intent();
    i.purpose = value;
    let json = serde_json::to_value(&i).unwrap();
    let reparsed: Intent = serde_json::from_value(json).unwrap();
    assert_eq!(i.digest().unwrap(), reparsed.digest().unwrap());
}

/// Secret-shaped field names must never expand the voice agent's context allowlist.
#[hegel::test]
fn unapproved_fact_keys_are_rejected_even_if_their_values_look_ordinary(tc: TestCase) {
    let key = tc.draw(gs::sampled_from(
        &[
            "password",
            "otp",
            "pin",
            "api_key",
            "token",
            "ssn",
            "card_number",
            "chat_history",
        ][..],
    ));
    let value = tc.draw(gs::text());
    let mut i = intent();
    i.facts.insert(
        key.into(),
        Fact {
            value,
            source_ref: "synthetic".into(),
            source_version: "v1".into(),
        },
    );
    assert!(i.validate(1000).is_err());
}

/// Random event order cannot turn a conversation into unsupported objective completion.
#[hegel::test]
fn results_require_both_termination_and_analysis_and_never_invent_success(tc: TestCase) {
    let commands = tc.draw(gs::vecs(gs::integers::<u8>().max_value(4)));
    let mut op = operation();
    let mut ended = false;
    let mut analyzed = false;
    let mut ai_stopped = false;
    for (n, command) in commands.into_iter().enumerate() {
        let kind = [
            EventKind::Started,
            EventKind::Ended,
            EventKind::Analyzed,
            EventKind::Takeover,
            EventKind::Phase,
        ][usize::from(command)];
        let mut e = event(&op, kind, 1000 + n as i64);
        e.phase = Some(Phase::Talking);
        op.observe(&e).unwrap();
        ended |= command == 1;
        analyzed |= command == 2;
        ai_stopped |= command == 1 || command == 3;
        assert_eq!(op.all_legs_ended, ended);
        assert_eq!(op.analysis_seen, analyzed);
        assert_eq!(op.ai_stopped, ai_stopped);
        assert_eq!(op.locked(), !ended);
        assert_eq!(
            op.result.status == ResultStatus::NeedsReview,
            ended && analyzed
        );
        if ended {
            assert_eq!(op.lifecycle, Lifecycle::Ended);
            assert_eq!(op.phase, None);
        }
        assert_ne!(op.result.outcome, "objective_completed");
        assert_eq!(op.result.human_result, "unobserved");
    }
}

/// A takeover is irreversible even if delayed talking/started observations arrive later.
#[hegel::test]
fn the_ai_never_resumes_after_a_takeover(tc: TestCase) {
    let commands = tc.draw(gs::vecs(gs::integers::<u8>().max_value(1)));
    let mut op = operation();
    op.observe(&event(&op, EventKind::Takeover, 1001)).unwrap();
    for (n, command) in commands.into_iter().enumerate() {
        let mut e = event(
            &op,
            if command == 0 {
                EventKind::Started
            } else {
                EventKind::Phase
            },
            1002 + n as i64,
        );
        e.phase = Some(Phase::Talking);
        op.observe(&e).unwrap();
        assert!(op.ai_stopped);
        assert_eq!(op.phase, Some(Phase::HumanConnected));
        assert_eq!(op.result.human_result, "unobserved");
    }
}

/// Older observations can supply evidence but cannot make observation time move backwards.
#[hegel::test]
fn last_observed_time_is_the_latest_evidence_time(tc: TestCase) {
    let times = tc.draw(gs::vecs(gs::integers::<u32>()));
    let expected = times
        .iter()
        .map(|v| i64::from(*v))
        .chain([1000])
        .max()
        .unwrap();
    let mut op = operation();
    for (n, at) in times.into_iter().enumerate() {
        let mut e = event(&op, EventKind::Started, i64::from(at));
        e.key = format!("e_{n}");
        op.observe(&e).unwrap();
    }
    assert_eq!(op.last_observed_at, expected);
}

/// Synthetic fixtures are limited to reserved numbers; Unicode never bypasses the parser.
#[hegel::test]
fn only_reserved_us_example_numbers_are_synthetic(tc: TestCase) {
    let number = tc.draw(hegel::one_of!(
        gs::text(),
        gs::integers::<u16>().map(|n| format!("+1202555{n:04}"))
    ));
    let expected = (100..=199)
        .map(|n| format!("+1202555{n:04}"))
        .any(|s| s == number);
    // The random numeric branch uses the 202 area code; arbitrary text could use any area code.
    if number.starts_with("+1202") || !us_number(&number) {
        assert_eq!(synthetic_number(&number), expected);
    }
}

#[test]
fn hashes_match_a_published_sha256_known_answer() {
    assert_eq!(
        hash(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn every_policy_field_changes_the_digest() {
    let original = serde_json::to_value(intent()).unwrap();
    fn visit(value: &serde_json::Value, path: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    path.push(key.clone());
                    visit(value, path, paths);
                    path.pop();
                }
            }
            serde_json::Value::Array(_) => paths.push(path.clone()),
            _ => paths.push(path.clone()),
        }
    }
    let mut paths = vec![];
    visit(&original, &mut vec![], &mut paths);
    for path in paths {
        let mut changed = original.clone();
        let mut at = &mut changed;
        for key in &path {
            at = &mut at[key];
        }
        match at {
            serde_json::Value::String(s) => s.push('x'),
            serde_json::Value::Bool(b) => *b = !*b,
            serde_json::Value::Number(n) => *n = (n.as_i64().unwrap() + 1).into(),
            serde_json::Value::Array(a) => a.push(serde_json::json!("another")),
            _ => panic!("unhandled policy field"),
        }
        let changed: Intent = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.digest().unwrap(),
            intent().digest().unwrap(),
            "unbound field {path:?}"
        );
    }
}

#[test]
fn unknown_contract_fields_are_rejected_instead_of_disappearing_from_the_digest() {
    let mut j = serde_json::to_value(intent()).unwrap();
    j["ignored_authority"] = serde_json::json!("attest");
    assert!(serde_json::from_value::<Intent>(j).is_err());
    let mut j = serde_json::to_value(intent()).unwrap();
    j["handoff"]["capture_disabled"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Intent>(j).is_err());
}

#[test]
fn large_reordered_event_sequences_keep_their_terminal_state() {
    let mut op = operation();
    op.observe(&event(&op, EventKind::Ended, 2000)).unwrap();
    for n in 0..10_000 {
        let mut e = event(&op, EventKind::Started, n);
        e.key = format!("large_{n}");
        op.observe(&e).unwrap();
    }
    assert_eq!(op.lifecycle, Lifecycle::Ended);
    assert_eq!(op.last_observed_at, 9999);
    assert_eq!(op.result.evidence_refs.len(), 10_001);
}

/// An independent authority model tracks only whether approval was revoked and which
/// idempotency key consumed it. Restarts and provider ambiguity cannot create new authority.
#[hegel::test]
fn arbitrary_controller_commands_never_spend_one_approval_twice(tc: TestCase) {
    use voice_agent::controller::Controller;
    let commands = tc.draw(gs::vecs(gs::integers::<u8>().max_value(5)));
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    tc.event_value("command count", commands.len() as f64);
    let mut revoked = false;
    let mut reserved: Option<(u8, String)> = None;
    let mut provider = CountingProvider {
        unknown: true,
        ..Default::default()
    };
    for command in commands {
        match command {
            0 | 1 => {
                let key = if command == 0 {
                    "first_key"
                } else {
                    "other_key"
                };
                let actual = c.start(&coordinator(), &i, &a.id, key, 1001);
                if reserved.is_some() {
                    tc.event("key reuse after reservation");
                }
                if revoked {
                    tc.event("start after revocation");
                }
                let expected = match &reserved {
                    Some((prior, _)) => *prior == command,
                    None => !revoked,
                };
                assert_eq!(actual.is_ok(), expected);
                if let Ok(op) = actual {
                    if let Some((_, prior_id)) = &reserved {
                        assert_eq!(&op.id, prior_id);
                    } else {
                        reserved = Some((command, op.id));
                    }
                }
            }
            2 => {
                c.revoke(&user(), &a.id, 1001).unwrap();
                revoked = true;
            }
            3 => {
                tc.event("worker tick");
                c.tick(&mut provider, 1001).unwrap();
            }
            4 => {
                tc.event("controller restart");
                drop(c);
                c = Controller::open(&db).unwrap();
            }
            5 => {
                if let Some((_, id)) = &reserved {
                    c.end(&user(), id, "user_requested", 1001).unwrap();
                }
            }
            _ => unreachable!(),
        }
        assert!(provider.creates <= 1);
    }
}

/// Hold is elapsed time in one continuous phase, not a lease renewed by observations.
#[hegel::test]
fn repeated_hold_observations_cannot_reset_the_hold_clock(tc: TestCase) {
    let times = tc.draw(gs::vecs(gs::integers::<u32>().min_value(1002)));
    let mut op = operation();
    let mut first = event(&op, EventKind::Phase, 1001);
    first.phase = Some(Phase::Hold);
    op.observe(&first).unwrap();
    for (n, time) in times.into_iter().enumerate() {
        let mut e = event(&op, EventKind::Phase, i64::from(time));
        e.key = format!("hold_{n}");
        e.phase = Some(Phase::Hold);
        op.observe(&e).unwrap();
        assert_eq!(op.phase_since, 1001);
    }
}

/// Explicit secret challenges remain blocked in either purpose or an allowlisted fact.
#[hegel::test]
fn seeded_secret_markers_are_blocked_before_a_packet_can_be_approved(tc: TestCase) {
    let marker = tc.draw(gs::sampled_from(
        &[
            "Password",
            "OTP",
            "PIN",
            "SSN",
            "CVV",
            "api_key",
            "security answer",
            "4111-1111-1111-1111",
        ][..],
    ));
    let in_purpose = tc.draw(gs::booleans());
    let mut i = intent();
    let seeded = format!("Synthetic {marker}: EXAMPLE");
    assert!(sensitive(&seeded));
    if in_purpose {
        i.purpose = seeded;
    } else {
        i.facts.get_mut("reference").unwrap().value = seeded;
    }
    assert!(i.validate(1000).is_err());
}

#[test]
fn identifiers_reject_empty_oversized_unicode_and_path_separators() {
    for value in ["", "a/b", "a\\b", "a b", "é", "\0"] {
        assert!(!identifier(value));
    }
    assert!(!identifier(&"a".repeat(129)));
    assert!(identifier(&"a".repeat(128)));
    assert!(identifier("example_01-v1.scope:ref"));
}

/// Validation must enforce a nonblank, bounded purpose independently of other fields.
#[hegel::test]
fn purpose_length_and_nonblank_rules_apply_to_arbitrary_text(tc: TestCase) {
    let purpose = tc.draw(hegel::one_of!(
        gs::text(),
        gs::integers::<u16>()
            .max_value(514)
            .map(|n| "a".repeat(usize::from(n))),
        gs::sampled_from(&["", " ", "\t\n", "\u{2003}"][..]).map(str::to_owned),
    ));
    let mut i = intent();
    i.purpose = purpose.clone();
    let valid = i.validate(1000).is_ok();
    if purpose.trim().is_empty() {
        tc.event("blank purpose");
        assert!(!valid);
    }
    if purpose.len() > 512 {
        tc.event("oversized purpose");
        assert!(!valid);
    }
}

/// Known ordinary prose is accepted at the byte boundary, including multibyte text.
#[hegel::test]
fn ordinary_nonempty_purposes_are_accepted_up_to_the_byte_limit(tc: TestCase) {
    let word = tc.draw(gs::sampled_from(&["a", "?", "中", "🦀", "résumé "][..]));
    let repeats = tc.draw(
        gs::integers::<usize>()
            .min_value(1)
            .max_value(512 / word.len()),
    );
    let mut i = intent();
    i.purpose = word.repeat(repeats);
    assert!(i.validate(1000).is_ok());
}

/// Destination syntax is validated locally before a trusted directory is consulted.
#[hegel::test]
fn malformed_destinations_are_rejected_with_every_other_field_valid(tc: TestCase) {
    let ten_digits = tc.draw(gs::integers::<u64>().max_value(9_999_999_999));
    let valid = format!("+1{ten_digits:010}");
    let mut i = intent();
    i.destination.e164 = valid.clone();
    assert!(i.validate(1000).is_ok());
    let malformed = tc.draw(gs::sampled_from(
        &[
            valid.replacen("+1", "+2", 1),
            valid[1..].to_string(),
            format!("{valid}0"),
            valid[..valid.len() - 1].to_string(),
            format!("+1x{:09}", ten_digits % 1_000_000_000),
        ][..],
    ));
    i.destination.e164 = malformed;
    assert!(i.validate(1000).is_err());
}

/// This model is a set of issued authorities plus one key binding: it does not
/// reproduce hashing, SQL, controller states, or provider behavior.
#[hegel::test]
fn multiple_approvals_and_clock_changes_never_bypass_single_attempt_authority(tc: TestCase) {
    use voice_agent::controller::Controller;
    struct Authority {
        issued: i64,
        id: String,
        revoked: bool,
        consumed: bool,
    }
    let commands = tc.draw(gs::vecs(gs::integers::<u8>().max_value(4)));
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let mut authorities = Vec::new();
    for issued in [1000, 1001] {
        let a = c.approve(&user(), &i, issued).unwrap();
        authorities.push(Authority {
            issued,
            id: a.id,
            revoked: false,
            consumed: false,
        });
    }
    assert_ne!(authorities[0].id, authorities[1].id);
    let mut bound: Option<(bool, String)> = None;
    tc.event_value("command count", commands.len() as f64);
    for command in commands {
        let now = tc.draw(hegel::one_of!(
            gs::integers::<i64>(),
            gs::sampled_from(&[999_i64, 1000, 1001, 1002, 4599, 4600, 4601][..])
        ));
        let selected = tc.draw(gs::integers::<usize>().max_value(authorities.len() - 1));
        if !(1000..4600).contains(&now) {
            tc.event("clock outside approved window");
        }
        match command {
            0 => {
                let actual = c.approve(&user(), &i, now);
                assert_eq!(actual.is_ok(), (1000..4600).contains(&now));
                if let Ok(a) = actual {
                    if let Some(previous) = authorities.iter().find(|a| a.issued == now) {
                        tc.event("approval timestamp collision");
                        assert_eq!(a.id, previous.id);
                        assert_eq!(a.revoked, previous.revoked);
                        assert_eq!(a.consumed, previous.consumed);
                    } else {
                        assert!(!authorities.iter().any(|prior| prior.id == a.id));
                        authorities.push(Authority {
                            issued: now,
                            id: a.id,
                            revoked: false,
                            consumed: false,
                        });
                    }
                }
            }
            1 | 2 => {
                let key = command == 1;
                let authority = &mut authorities[selected];
                if now < authority.issued {
                    tc.event("clock before selected approval");
                }
                if authority.revoked {
                    tc.event("revoked approval selected");
                }
                let expected = match &bound {
                    Some((prior, _)) => {
                        tc.event("key collision");
                        *prior == key
                    }
                    None => {
                        (authority.issued..4600).contains(&now)
                            && !authority.revoked
                            && !authority.consumed
                    }
                };
                let actual = c.start(
                    &coordinator(),
                    &i,
                    &authority.id,
                    if key { "key_a" } else { "key_b" },
                    now,
                );
                assert_eq!(actual.is_ok(), expected);
                if let Ok(op) = actual {
                    if let Some((_, prior)) = &bound {
                        assert_eq!(&op.id, prior);
                    } else {
                        authority.consumed = true;
                        bound = Some((key, op.id));
                    }
                }
            }
            3 => {
                let a = &mut authorities[selected];
                c.revoke(&user(), &a.id, now).unwrap();
                a.revoked = true;
            }
            4 => {
                drop(c);
                c = Controller::open(&db).unwrap();
            }
            _ => unreachable!(),
        }
    }
    tc.event_value("distinct approvals", authorities.len() as f64);
}

/// Unknown schema versions must fail locally instead of relying on another policy gate.
#[hegel::test]
fn only_the_supported_schema_version_can_be_approved(tc: TestCase) {
    let version = tc.draw(gs::integers::<u32>());
    let mut i = intent();
    i.schema_version = version;
    assert_eq!(i.validate(1000).is_ok(), version == 1);
}

/// Any identifier containing a path separator is invalid, regardless of its other text.
#[hegel::test]
fn malformed_identifiers_are_rejected_independently_of_the_directory(tc: TestCase) {
    const PATHS: &[&[&str]] = &[
        &["intent_id"],
        &["work_item", "system"],
        &["work_item", "reference"],
        &["work_item", "version"],
        &["destination", "source_ref"],
        &["destination", "source_version"],
        &["consent_policy_ref"],
        &["handoff", "recipient_ref"],
        &["handoff", "endpoint_ref"],
        &["policy_gate_ref"],
        &["agent_id"],
        &["limits", "rate_ref"],
        &["facts", "reference", "source_ref"],
        &["facts", "reference", "source_version"],
    ];
    let path = tc.draw(gs::sampled_from(PATHS));
    let prefix = tc.draw(gs::text());
    let mut value = serde_json::to_value(intent()).unwrap();
    let mut leaf = &mut value;
    for field in path {
        leaf = &mut leaf[*field];
    }
    *leaf = serde_json::json!(format!("{prefix}/"));
    let i: Intent = serde_json::from_value(value).unwrap();
    assert!(i.validate(1000).is_err());
}

#[test]
fn every_required_safety_rule_is_enforced_by_local_validation() {
    // These are finite policy choices, so enumerate them rather than sample them.
    let invalid: &[fn(&mut Intent)] = &[
        |i| i.ai_disclosure = false,
        |i| i.provider = "other_provider".into(),
        |i| i.handoff.resume_ai = true,
        |i| i.handoff.mode = "browser_takeover".into(),
        |i| i.handoff.authentication = "same_call".into(),
        |i| i.permitted_actions.clear(),
        |i| i.permitted_actions.push("pay".into()),
        |i| i.forbidden_actions.retain(|v| v != "attest"),
        |i| i.forbidden_actions.retain(|v| v != "pay"),
        |i| i.forbidden_actions.retain(|v| v != "accept_terms"),
        |i| i.forbidden_disclosures.retain(|v| v != "password"),
        |i| i.forbidden_disclosures.retain(|v| v != "otp"),
        |i| i.forbidden_disclosures.retain(|v| v != "pin"),
        |i| i.limits.attempts = 0,
        |i| i.limits.attempts = 2,
        |i| i.limits.hold_seconds = 0,
        |i| i.limits.hold_seconds = i.limits.duration_seconds + 1,
        |i| i.limits.handoff_wait_seconds = 0,
        |i| i.limits.handoff_wait_seconds = 61,
        |i| i.limits.rate_cents_per_minute = 0,
        |i| i.facts.get_mut("reference").unwrap().value.clear(),
        |i| i.facts.get_mut("reference").unwrap().value = "x".repeat(257),
        |i| i.not_before = 999,
    ];
    assert!(intent().validate(1000).is_ok());
    for (n, change) in invalid.iter().enumerate() {
        let mut i = intent();
        change(&mut i);
        assert!(i.validate(1000).is_err(), "rule {n} was not enforced");
    }
}

#[test]
fn permitted_actions_accept_every_nonempty_safe_subset_and_reject_extra_authority() {
    let allowed = ["ask_status", "request_next_steps", "ask_documents"];
    for mask in 0..8 {
        let mut i = intent();
        i.permitted_actions = allowed
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, action)| (*action).into())
            .collect();
        assert_eq!(i.validate(1000).is_ok(), mask != 0);
        for extra in ["pay", "attest", "accept_terms", "unknown_action"] {
            let mut expanded = i.clone();
            expanded.permitted_actions.push(extra.into());
            assert!(expanded.validate(1000).is_err(), "accepted {extra}");
        }
    }
}

#[test]
fn every_required_action_and_disclosure_prohibition_must_be_present() {
    for disclosures in [false, true] {
        let required = if disclosures {
            ["password", "otp", "pin"]
        } else {
            ["attest", "pay", "accept_terms"]
        };
        for mask in 0..8 {
            let mut i = intent();
            let values = required
                .iter()
                .enumerate()
                .filter(|(bit, _)| mask & (1 << bit) != 0)
                .map(|(_, action)| (*action).into())
                .collect();
            if disclosures {
                i.forbidden_disclosures = values;
            } else {
                i.forbidden_actions = values;
            }
            assert_eq!(i.validate(1000).is_ok(), mask == 7);
        }
    }
}

#[test]
fn all_four_fact_keys_fit_exactly_without_accepting_an_additional_key() {
    let keys = ["reference", "document", "question", "authorized_name"];
    let fact = intent().facts["reference"].clone();
    for mask in 0..16 {
        let mut i = intent();
        i.facts.clear();
        for (bit, key) in keys.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                i.facts.insert((*key).into(), fact.clone());
            }
        }
        assert!(i.validate(1000).is_ok(), "safe subset {mask}");
        i.facts.insert("extra_context".into(), fact.clone());
        assert!(i.validate(1000).is_err(), "extra context in subset {mask}");
    }
}

/// Arbitrary Unicode cannot evade the fact byte bound even when scalar counts differ.
#[hegel::test]
fn empty_and_oversized_unicode_fact_values_are_rejected(tc: TestCase) {
    let arbitrary = tc.draw(gs::text());
    let character = tc.draw(gs::sampled_from(&["", "a", "é", "中", "🦀"][..]));
    let count = tc.draw(gs::sampled_from(
        &[0_usize, 1, 63, 64, 65, 255, 256, 257][..],
    ));
    let value = tc.draw(hegel::one_of!(
        gs::just(arbitrary),
        gs::just(character.repeat(count))
    ));
    let mut i = intent();
    i.facts.get_mut("reference").unwrap().value = value.clone();
    if value.is_empty() || value.len() > 256 {
        tc.event("outside fact byte bounds");
        assert!(i.validate(1000).is_err());
    }
}

/// Ordinary non-ASCII scalars span UTF-8 widths without containing ASCII secret markers.
#[hegel::test]
fn nonempty_ordinary_unicode_facts_are_accepted_through_256_bytes(tc: TestCase) {
    let scalar = tc.draw(gs::integers::<u32>().min_value(128).max_value(0x10ffff));
    let character = char::from_u32(scalar).unwrap_or('\u{fffd}');
    let maximum = 256 / character.len_utf8();
    let count = tc.draw(hegel::one_of!(
        gs::integers::<usize>().min_value(1).max_value(maximum),
        gs::just(maximum)
    ));
    let mut i = intent();
    i.facts.get_mut("reference").unwrap().value = character.to_string().repeat(count);
    assert!(i.validate(1000).is_ok());
}

#[test]
fn each_fact_source_identifier_is_checked_without_relying_on_a_directory() {
    for source_version in [false, true] {
        for invalid in ["".into(), "a/b".into(), "é".into(), "a".repeat(129)] {
            let mut i = intent();
            let fact = i.facts.get_mut("reference").unwrap();
            if source_version {
                fact.source_version = invalid;
            } else {
                fact.source_ref = invalid;
            }
            assert!(i.validate(1000).is_err());
        }
    }
}

/// A hold budget is a positive interval contained by the entire call budget.
#[hegel::test]
fn hold_limits_span_the_full_numeric_domain_and_respect_call_duration(tc: TestCase) {
    let duration = tc.draw(gs::integers::<u32>().min_value(30).max_value(1800));
    let hold = tc.draw(hegel::one_of!(
        gs::integers::<u32>(),
        gs::sampled_from(&[0_u32, 1, duration - 1, duration, duration + 1][..])
    ));
    let mut i = intent();
    i.limits.duration_seconds = duration;
    i.limits.budget_cents = 1000;
    i.limits.hold_seconds = hold;
    assert_eq!(i.validate(1000).is_ok(), (1..=duration).contains(&hold));
}

/// Human handoff waits have their own one-minute cap, independently of call duration.
#[hegel::test]
fn handoff_wait_limits_are_positive_and_at_most_sixty_seconds(tc: TestCase) {
    let seconds = tc.draw(hegel::one_of!(
        gs::integers::<u32>(),
        gs::sampled_from(&[0_u32, 1, 59, 60, 61][..])
    ));
    let mut i = intent();
    i.limits.handoff_wait_seconds = seconds;
    assert_eq!(i.validate(1000).is_ok(), (1..=60).contains(&seconds));
}

#[test]
fn observing_foreign_or_unidentified_calls_fails_without_changing_the_operation() {
    for known_call in [false, true] {
        for violation in 0..3 {
            let mut op = operation();
            op.call_id = known_call.then(|| "call_demo".into());
            let mut e = event(&op, EventKind::Started, 1001);
            match violation {
                0 => e.operation_id = "another_operation".into(),
                1 => e.call_id.clear(),
                2 if known_call => e.call_id = "another_call".into(),
                2 => continue,
                _ => unreachable!(),
            }
            let before = serde_json::to_value(&op).unwrap();
            assert_eq!(op.observe(&e).unwrap_err().code, "event_mapping_conflict");
            assert_eq!(serde_json::to_value(&op).unwrap(), before);
        }
    }
}

#[test]
fn authenticated_start_evidence_resolves_unknown_creation_but_never_cancels_stopping() {
    for previous in [
        Lifecycle::Submitting,
        Lifecycle::StartUnknown,
        Lifecycle::Active,
    ] {
        let mut op = operation();
        op.lifecycle = previous;
        op.observe(&event(&op, EventKind::Started, 1001)).unwrap();
        assert_eq!(op.lifecycle, Lifecycle::Active);
    }
    let mut stopping = operation();
    stopping.lifecycle = Lifecycle::Ending;
    stopping.stop_reason = Some("user_requested".into());
    stopping
        .observe(&event(&stopping, EventKind::Started, 1001))
        .unwrap();
    assert_eq!(stopping.lifecycle, Lifecycle::Ending);
    assert_eq!(stopping.stop_reason.as_deref(), Some("user_requested"));
}

#[test]
fn ivr_stopping_begins_on_the_third_observation_and_its_counter_cannot_wrap() {
    let mut op = operation();
    for count in 1..=260 {
        let mut e = event(&op, EventKind::Phase, 1000 + count);
        e.phase = Some(Phase::Ivr);
        op.observe(&e).unwrap();
        assert_eq!(op.menu_repeats, count.min(255) as u8);
        assert_eq!(
            op.stop_reason.as_deref(),
            (count >= 3).then_some("blocked_ivr")
        );
    }
}

#[test]
fn a_stale_phase_cannot_replace_a_newer_hold_or_advance_its_timer() {
    let mut op = operation();
    let mut hold = event(&op, EventKind::Phase, 2000);
    hold.phase = Some(Phase::Hold);
    op.observe(&hold).unwrap();
    for phase in [
        Phase::Talking,
        Phase::Ringing,
        Phase::Ivr,
        Phase::HandoffRequested,
    ] {
        let mut stale = event(&op, EventKind::Phase, 1999);
        stale.key = format!("old_{phase:?}");
        stale.phase = Some(phase);
        op.observe(&stale).unwrap();
        assert_eq!(op.phase, Some(Phase::Hold));
        assert_eq!(op.phase_since, 2000);
        assert_eq!(op.menu_repeats, 0);
        assert!(op.stop_reason.is_none());
    }
}

/// Each accepted distinct observation advances the version once, regardless of order or kind.
#[hegel::test]
fn result_versions_count_accepted_evidence_in_arbitrary_event_sequences(tc: TestCase) {
    let commands = tc.draw(gs::vecs(gs::integers::<u8>().max_value(4)));
    let mut op = operation();
    for (index, command) in commands.into_iter().enumerate() {
        let time = tc.draw(gs::integers::<i64>());
        let kind = [
            EventKind::Started,
            EventKind::Ended,
            EventKind::Analyzed,
            EventKind::Phase,
            EventKind::Takeover,
        ][usize::from(command)];
        let mut e = event(&op, kind, time);
        e.key = format!("unique_evidence_{index}");
        e.phase = Some(Phase::Talking);
        op.observe(&e).unwrap();
        assert_eq!(op.result.result_version as usize, index + 1);
        assert_eq!(op.result.evidence_refs.len(), index + 1);
    }
}
