//! Profiles grant a menu capability only; signed reports cannot grant authority.
mod common;

use common::*;
use hegel::prelude::*;
use ring::hmac;
use serde_json::{json, Value};
use std::path::Path;
use voice_agent::contract::{Intent, Lifecycle, MenuNavigation, Operation, Phase, ResultStatus};
use voice_agent::controller::Controller;
use voice_agent::observations::{verify_phase, PhaseObservation};
use voice_agent::policy::{ControllerPolicy, DirectoryEntry};
use voice_agent::workflow::{GateDecision, GateRequest, GateStage, WorkflowAuthority};
use voice_agent::Result;

const KEY: &[u8] = b"synthetic-menu-phase-key";
const PROFILES: [MenuNavigation; 2] = [
    MenuNavigation::SpokenOnly,
    MenuNavigation::ModelGuidedPublicMenu,
];

// Frozen pre-menu v1 bytes. The expected digest was calculated independently
// with Python hashlib.sha256, not with the production digest/serialization path.
const LEGACY_INTENT: &str = r#"{"schema_version":1,"intent_id":"intent_demo","work_item":{"system":"return_protection","reference":"work_demo","version":"v1"},"destination":{"e164":"+12025550100","source_ref":"official_demo_v1","source_version":"v1"},"purpose":"Ask which documents are required","facts":{"reference":{"value":"SYNTHETIC-REF","source_ref":"work_demo","source_version":"v1"}},"permitted_actions":["ask_documents"],"forbidden_actions":["attest","pay","accept_terms"],"forbidden_disclosures":["password","otp","pin"],"ai_disclosure":true,"consent_policy_ref":"consent_demo_v1","handoff":{"recipient_ref":"owner","endpoint_ref":"owner_control","mode":"manual","resume_ai":false,"authentication":"separate_direct_call"},"limits":{"attempts":1,"duration_seconds":180,"hold_seconds":120,"handoff_wait_seconds":60,"budget_cents":100,"rate_cents_per_minute":10,"rate_ref":"rate_demo_v1"},"policy_gate_ref":"gate_demo_v1","provider":"retell","agent_id":"agent_demo","agent_version":1,"not_before":1000,"not_after":4600}"#;
const LEGACY_DIGEST: &str =
    "sha256:e4f083fd07860ab8555ffe21969ca31d4b0f459fa042fae7f0d7a4f905f2d29c";

fn with_profile(profile: MenuNavigation) -> Intent {
    let mut i = intent();
    i.menu_navigation = profile;
    i
}

fn policy(profiles: &[MenuNavigation], expires_at: i64) -> ControllerPolicy {
    ControllerPolicy {
        daily_budget_cents: 2500,
        directory: profiles
            .iter()
            .map(|&profile| {
                let i = with_profile(profile);
                DirectoryEntry {
                    work_system: i.work_item.system,
                    destination: i.destination,
                    agent_id: i.agent_id,
                    agent_version: i.agent_version,
                    menu_navigation: profile,
                    rate_ref: i.limits.rate_ref,
                    rate_cents_per_minute: i.limits.rate_cents_per_minute,
                    handoff_recipient_ref: i.handoff.recipient_ref,
                    handoff_endpoint_ref: i.handoff.endpoint_ref,
                    consent_policy_ref: i.consent_policy_ref,
                    expires_at,
                }
            })
            .collect(),
    }
}

struct SyntheticAuthority;
impl WorkflowAuthority for SyntheticAuthority {
    fn authorize(&mut self, request: &GateRequest, now: i64) -> Result<GateDecision> {
        Ok(GateDecision {
            request_digest: request.request_digest()?,
            allowed: true,
            expires_at: now + 30,
            reservation_id: (request.stage != GateStage::Preview)
                .then(|| format!("reservation_{}", request.operation_id)),
        })
    }
}

fn open(path: &Path, profiles: &[MenuNavigation], expires_at: i64) -> Controller {
    Controller::open_configured(
        path,
        policy(profiles, expires_at),
        Box::new(SyntheticAuthority),
    )
    .unwrap()
}

fn running(
    profile: MenuNavigation,
) -> (tempfile::TempDir, Controller, Operation, CountingProvider) {
    running_until(profile, 4600)
}

fn running_until(
    profile: MenuNavigation,
    not_after: i64,
) -> (tempfile::TempDir, Controller, Operation, CountingProvider) {
    let d = tempfile::tempdir().unwrap();
    let mut c = open(&d.path().join("state.db"), &[profile], 5000);
    let mut i = with_profile(profile);
    i.not_after = not_after;
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &approval.id, "menu_call", 1000)
        .unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let op = c.get(&user(), &op.id).unwrap();
    assert_eq!(p.creates, 1);
    assert_eq!(p.stops, 0);
    (d, c, op, p)
}

fn signed_phase(op: &Operation, sequence: u16, name: &str, at: i64) -> PhaseObservation {
    let raw = serde_json::to_vec(&json!({
        "operation_id": op.id,
        "call_id": op.call_id.as_deref().unwrap_or("call_unconfirmed"),
        "intent_digest": op.digest,
        "sequence": sequence,
        "phase": name
    }))
    .unwrap();
    let millis = at * 1000;
    let mut signed = raw.clone();
    signed.extend_from_slice(millis.to_string().as_bytes());
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, KEY), &signed);
    let tag: String = tag
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    verify_phase(&raw, &format!("v={millis},d={tag}"), KEY, millis).unwrap()
}

#[test]
fn omitted_and_explicit_spoken_profiles_keep_the_preexisting_signed_digest() {
    let old: Intent = serde_json::from_str(LEGACY_INTENT).unwrap();
    assert_eq!(old.menu_navigation, MenuNavigation::SpokenOnly);
    assert_eq!(serde_json::to_string(&old).unwrap(), LEGACY_INTENT);
    assert_eq!(old.digest().unwrap(), LEGACY_DIGEST);
    assert_eq!(
        with_profile(MenuNavigation::SpokenOnly).digest().unwrap(),
        LEGACY_DIGEST
    );
    let mut explicit: Value = serde_json::from_str(LEGACY_INTENT).unwrap();
    explicit["menu_navigation"] = json!("spoken_only");
    let spoken: Intent = serde_json::from_value(explicit.clone()).unwrap();
    assert_eq!(spoken.digest().unwrap(), LEGACY_DIGEST);
    assert!(serde_json::to_value(&spoken)
        .unwrap()
        .get("menu_navigation")
        .is_none());

    explicit["menu_navigation"] = json!("model_guided_public_menu");
    let native: Intent = serde_json::from_value(explicit).unwrap();
    assert_eq!(
        native.menu_navigation,
        MenuNavigation::ModelGuidedPublicMenu
    );
    assert_ne!(native.digest().unwrap(), LEGACY_DIGEST);
    assert_eq!(
        serde_json::to_value(&native).unwrap()["menu_navigation"],
        "model_guided_public_menu"
    );
    for unsupported in [
        json!(true),
        json!(false),
        json!(1),
        json!(null),
        json!({}),
        json!([]),
    ] {
        let mut raw: Value = serde_json::from_str(LEGACY_INTENT).unwrap();
        raw["menu_navigation"] = unsupported;
        assert!(serde_json::from_value::<Intent>(raw).is_err());
    }
}

#[test]
fn each_directory_profile_authorizes_exactly_the_same_intent_profile() {
    for configured in PROFILES {
        for requested in PROFILES {
            assert_eq!(
                policy(&[configured], 5000)
                    .authorize(&with_profile(requested), 1000)
                    .is_ok(),
                configured == requested,
                "configured={configured:?}, requested={requested:?}"
            );
        }
    }
    let mut old = serde_json::to_value(policy(&[MenuNavigation::SpokenOnly], 5000)).unwrap();
    old["directory"][0]
        .as_object_mut()
        .unwrap()
        .remove("menu_navigation");
    let old: ControllerPolicy = serde_json::from_value(old).unwrap();
    assert_eq!(old.directory[0].menu_navigation, MenuNavigation::SpokenOnly);
    assert!(old
        .authorize(&with_profile(MenuNavigation::SpokenOnly), 1000)
        .is_ok());
    assert!(old
        .authorize(&with_profile(MenuNavigation::ModelGuidedPublicMenu), 1000)
        .is_err());
}

#[test]
fn an_approval_cannot_be_upgraded_or_downgraded_even_when_both_profiles_are_configured() {
    for approved in PROFILES {
        let d = tempfile::tempdir().unwrap();
        let mut c = open(&d.path().join("state.db"), &PROFILES, 5000);
        let original = with_profile(approved);
        let changed = with_profile(if approved == MenuNavigation::SpokenOnly {
            MenuNavigation::ModelGuidedPublicMenu
        } else {
            MenuNavigation::SpokenOnly
        });
        let a = c.approve(&user(), &original, 1000).unwrap();
        assert_eq!(
            c.start(&user(), &changed, &a.id, "profile_change", 1000)
                .unwrap_err()
                .code,
            "approval_expired_revoked_used_or_mismatched"
        );
        // A rejected upgrade neither consumes approval nor reserves the key.
        let op = c
            .start(&user(), &original, &a.id, "profile_change", 1000)
            .unwrap();
        assert_eq!(op.intent.as_ref().unwrap().menu_navigation, approved);
        assert_eq!(
            c.start(&user(), &changed, &a.id, "profile_change", 1000)
                .unwrap_err()
                .code,
            "idempotency_conflict"
        );
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn signed_safety_boundaries_stop_both_profiles_while_public_menu_dtmf_requires_opt_in() {
    for profile in PROFILES {
        for (name, common_stop) in [
            ("ivr", None),
            ("hold", None),
            ("talking", None),
            ("dtmf_required", None),
            ("authentication_required", Some("authentication_required")),
            ("declined_ai", Some("declined_ai")),
            ("uncertain_menu", Some("uncertain_menu")),
            ("prohibited_action", Some("prohibited_action")),
        ] {
            let (_d, mut c, op, mut p) = running(profile);
            let expected_stop = if name == "dtmf_required" && profile == MenuNavigation::SpokenOnly
            {
                Some("bounded_dtmf_unavailable")
            } else {
                common_stop
            };
            c.ingest_phase(signed_phase(&op, 1, name, 1001)).unwrap();
            c.tick(&mut p, 1001).unwrap();
            let current = c.get(&user(), &op.id).unwrap();
            assert_eq!(
                current.stop_reason.as_deref(),
                expected_stop,
                "{profile:?} {name}"
            );
            assert_eq!(p.stops, usize::from(expected_stop.is_some()));
            assert_eq!(p.creates, 1);
            assert!(current.locked());
            assert_eq!(current.result.human_result, "unobserved");
            assert_eq!(current.result.evidence_refs.len(), 1);
            if let Some(reason) = expected_stop {
                assert_eq!(current.lifecycle, Lifecycle::Ending);
                assert_eq!(current.result.status, ResultStatus::NeedsReview);
                assert_eq!(current.result.outcome, reason);
            } else {
                assert_eq!(current.lifecycle, Lifecycle::Active);
                assert_eq!(current.result.status, ResultStatus::Pending);
            }
            if name == "ivr" {
                assert_eq!(current.phase, Some(Phase::Ivr));
                assert_eq!(current.menu_repeats, 1);
            } else if name == "dtmf_required" {
                assert_eq!(current.menu_repeats, 0);
                if profile == MenuNavigation::ModelGuidedPublicMenu {
                    assert_eq!(current.phase, op.phase);
                    assert_eq!(current.phase_since, op.phase_since);
                }
            }
        }
    }
}

#[test]
fn native_menu_observations_count_once_across_replay_and_stop_on_the_third_menu() {
    let profile = MenuNavigation::ModelGuidedPublicMenu;
    let (d, mut c, op, mut p) = running(profile);
    for (index, name) in ["ivr", "dtmf_required", "ivr", "dtmf_required", "ivr"]
        .into_iter()
        .enumerate()
    {
        let sequence = index as u16 + 1;
        let now = 1001 + index as i64 * 2;
        c.ingest_phase(signed_phase(&op, sequence, name, now))
            .unwrap();
        let before_replay = c.get(&user(), &op.id).unwrap();
        c.ingest_phase(signed_phase(&op, sequence, name, now + 1))
            .unwrap();
        let current = c.get(&user(), &op.id).unwrap();
        assert_eq!(current.menu_repeats, (index / 2 + 1) as u8);
        assert_eq!(
            current.result.result_version,
            before_replay.result.result_version
        );
        assert_eq!(
            current.result.evidence_refs,
            before_replay.result.evidence_refs
        );
        c.tick(&mut p, now + 1).unwrap();
        assert_eq!(p.stops, usize::from(sequence == 5));
        assert_eq!(
            current.stop_reason.as_deref(),
            (sequence == 5).then_some("blocked_ivr")
        );
        if name == "dtmf_required" {
            assert_eq!(current.phase, Some(Phase::Ivr));
            assert_eq!(current.phase_since, 1001);
        }
    }
    drop(c);
    let mut c = open(&d.path().join("state.db"), &[profile], 5000);
    c.ingest_phase(signed_phase(&op, 6, "talking", 1011))
        .unwrap();
    c.tick(&mut p, 1011).unwrap();
    let current = c.get(&user(), &op.id).unwrap();
    assert_eq!(current.stop_reason.as_deref(), Some("blocked_ivr"));
    assert_eq!(current.menu_repeats, 3);
    assert!(current.locked());
    assert_eq!(p.stops, 2);
    assert_eq!(p.creates, 1);
}

#[test]
fn ordinary_native_menu_reports_and_later_safety_reports_never_clear_the_first_stop() {
    let (_d, mut c, op, mut p) = running(MenuNavigation::ModelGuidedPublicMenu);
    c.ingest_phase(signed_phase(&op, 1, "uncertain_menu", 1001))
        .unwrap();
    for (index, name) in ["dtmf_required", "talking", "hold", "prohibited_action"]
        .into_iter()
        .enumerate()
    {
        let now = 1002 + index as i64;
        let observation = signed_phase(&op, index as u16 + 2, name, now);
        if name == "dtmf_required" {
            assert!(c.ingest_phase(observation).is_err());
        } else {
            c.ingest_phase(observation).unwrap();
        }
        c.tick(&mut p, now).unwrap();
        let current = c.get(&user(), &op.id).unwrap();
        assert_eq!(current.stop_reason.as_deref(), Some("uncertain_menu"));
        assert_eq!(current.lifecycle, Lifecycle::Ending);
        assert_eq!(current.result.status, ResultStatus::NeedsReview);
        assert!(current.locked());
        assert_eq!(p.stops, index + 1);
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn native_menu_reports_cannot_extend_hold_or_the_total_call_deadline() {
    for hold in [false, true] {
        let (_d, mut c, op, mut p) = running(MenuNavigation::ModelGuidedPublicMenu);
        c.ingest_phase(signed_phase(&op, 1, "dtmf_required", 1001))
            .unwrap();
        let phase = if hold { "hold" } else { "talking" };
        c.ingest_phase(signed_phase(&op, 2, phase, 1002)).unwrap();
        let boundary = if hold { 1122 } else { 1175 };
        c.ingest_phase(signed_phase(&op, 3, phase, boundary - 1))
            .unwrap();
        assert_eq!(c.get(&user(), &op.id).unwrap().phase_since, 1002);
        c.tick(&mut p, boundary - 1).unwrap();
        assert_eq!(p.stops, 0);
        c.tick(&mut p, boundary).unwrap();
        let reason = if hold { "hold_stop" } else { "duration_stop" };
        assert_eq!(
            c.get(&user(), &op.id).unwrap().stop_reason.as_deref(),
            Some(reason)
        );
        assert_eq!(p.stops, 1);
        assert!(c
            .ingest_phase(signed_phase(&op, 4, "dtmf_required", boundary + 1))
            .is_err());
        c.tick(&mut p, boundary + 1).unwrap();
        assert_eq!(
            c.get(&user(), &op.id).unwrap().stop_reason.as_deref(),
            Some(reason)
        );
        assert_eq!(p.stops, 2);
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn native_permission_expiry_blocks_queued_dispatch_and_stops_an_existing_call() {
    for dispatched in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let profile = MenuNavigation::ModelGuidedPublicMenu;
        let mut c = open(
            &d.path().join("state.db"),
            &[profile],
            if dispatched { 1016 } else { 5000 },
        );
        let mut i = with_profile(profile);
        if !dispatched {
            i.not_after = 1016;
        }
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &a.id, "expiring_menu", 1000).unwrap();
        let mut p = CountingProvider::default();
        if dispatched {
            c.tick(&mut p, 1000).unwrap();
            let known = c.get(&user(), &op.id).unwrap();
            c.ingest_phase(signed_phase(&known, 1, "dtmf_required", 1001))
                .unwrap();
            c.tick(&mut p, 1015).unwrap();
            assert_eq!(p.stops, 0);
        }
        c.tick(&mut p, 1016).unwrap();
        let current = c.get(&user(), &op.id).unwrap();
        assert_eq!(p.creates, usize::from(dispatched));
        assert_eq!(p.stops, usize::from(dispatched));
        if dispatched {
            assert!(current.locked());
            assert_eq!(
                current.stop_reason.as_deref(),
                Some("canonical_authority_unavailable_or_revoked")
            );
        } else {
            assert!(!current.locked());
            assert_eq!(current.lifecycle, Lifecycle::Failed);
            assert_eq!(current.result.outcome, "blocked_before_dispatch");
        }
    }
}

#[test]
fn an_in_flight_call_stops_at_approval_expiry_in_both_profiles() {
    for profile in PROFILES {
        let (_d, mut c, op, mut p) = running_until(profile, 1016);
        c.ingest_phase(signed_phase(&op, 1, "ivr", 1001)).unwrap();
        c.tick(&mut p, 1015).unwrap();
        assert_eq!(p.stops, 0);
        c.tick(&mut p, 1016).unwrap();
        let current = c.get(&user(), &op.id).unwrap();
        assert_eq!(current.stop_reason.as_deref(), Some("approval_expired"));
        assert_eq!(current.lifecycle, Lifecycle::Ending);
        assert!(current.locked());
        assert_eq!(p.stops, 1);
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn native_digit_requests_and_replays_reject_every_stop_boundary_before_the_worker_runs() {
    use voice_agent::contract::EventKind;
    for boundary in [
        "user_end",
        "revoke",
        "authentication_required",
        "prohibited_action",
        "uncertain_menu",
        "declined_ai",
        "blocked_ivr",
        "approval_expiry",
        "duration",
        "closed",
        "takeover",
        "purged_closed",
    ] {
        let not_after = if boundary == "approval_expiry" {
            1016
        } else {
            4600
        };
        let (_d, mut c, op, mut p) =
            running_until(MenuNavigation::ModelGuidedPublicMenu, not_after);
        c.ingest_phase(signed_phase(&op, 1, "dtmf_required", 1001))
            .unwrap();
        let received_at = match boundary {
            "user_end" => {
                c.end(&user(), &op.id, "user_requested", 1002).unwrap();
                1003
            }
            "revoke" => {
                c.revoke(&user(), &op.approval_id, 1002).unwrap();
                1003
            }
            "authentication_required" | "prohibited_action" | "uncertain_menu" | "declined_ai" => {
                c.ingest_phase(signed_phase(&op, 2, boundary, 1002))
                    .unwrap();
                1003
            }
            "blocked_ivr" => {
                for sequence in 2..=4 {
                    c.ingest_phase(signed_phase(
                        &op,
                        sequence,
                        "ivr",
                        1000 + i64::from(sequence),
                    ))
                    .unwrap();
                }
                1005
            }
            "approval_expiry" => 1016,
            "duration" => 1175,
            "closed" | "purged_closed" => {
                c.ingest(event(&op, EventKind::Ended, 1002)).unwrap();
                c.process_events().unwrap();
                if boundary == "purged_closed" {
                    c.ingest(event(&op, EventKind::Analyzed, 1003)).unwrap();
                    c.process_events().unwrap();
                    c.tick(&mut p, 1004).unwrap();
                    assert!(c.get(&user(), &op.id).unwrap().intent.is_none());
                }
                1005
            }
            "takeover" => {
                c.ingest(event(&op, EventKind::Takeover, 1002)).unwrap();
                c.process_events().unwrap();
                1003
            }
            _ => unreachable!(),
        };
        assert_eq!(
            p.stops, 0,
            "the rejection must precede a worker stop: {boundary}"
        );
        let before = serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap();
        let pending = serde_json::to_value(c.pending_outbox().unwrap()).unwrap();
        // Even a newly signed exact replay must be rejected after a stop. Receipt
        // time, not the old valid observation clock, determines expiry.
        for sequence in [10, 1] {
            assert!(
                c.ingest_phase_at(
                    signed_phase(&op, sequence, "dtmf_required", 1001),
                    received_at
                )
                .is_err(),
                "native digit was acknowledged after {boundary}, sequence {sequence}"
            );
            assert_eq!(
                serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap(),
                before
            );
            assert_eq!(
                serde_json::to_value(c.pending_outbox().unwrap()).unwrap(),
                pending
            );
        }
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn sqlite_lock_wait_cannot_extend_native_digit_authority_past_approval_expiry() {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    let (d, mut c, op, p) = running_until(MenuNavigation::ModelGuidedPublicMenu, 1016);
    // This exact authority is usable before contention; the rejection below
    // must come from time spent waiting, not a permanently disabled capability.
    c.ingest_phase_at(signed_phase(&op, 1, "dtmf_required", 1013), 1013)
        .unwrap();
    let before = serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap();
    let pending = serde_json::to_value(c.pending_outbox().unwrap()).unwrap();
    let observation = signed_phase(&op, 2, "dtmf_required", 1014);

    let blocker = rusqlite::Connection::open(d.path().join("state.db")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let began = Instant::now();
        ready_tx.send(()).unwrap();
        let result = c.ingest_phase_at(observation, 1014);
        let waited = began.elapsed();
        let _ = finished_tx.send(());
        (c, result, waited)
    });

    // The writer is already locked before admission begins. Waiting on its
    // completion channel both proves no early acknowledgement and controls the
    // release; there is no uncoordinated sleeping worker or subprocess.
    let ready = ready_rx.recv_timeout(Duration::from_secs(2));
    let early = ready
        .as_ref()
        .ok()
        .map(|_| finished_rx.recv_timeout(Duration::from_millis(1250)));
    // Always release the lock before asserting, including a failed coordination
    // path, so the callback thread can finish and be joined safely.
    blocker.execute_batch("COMMIT").unwrap();
    let (c, result, waited) = worker.join().unwrap();
    assert!(ready.is_ok());
    assert!(matches!(early, Some(Err(RecvTimeoutError::Timeout))));
    assert!(waited > Duration::from_secs(1));
    // 1014 plus a wait exceeding one second rounds conservatively to at least
    // 1016. The original receipt was valid, but the approval is now expired.
    assert_eq!(result.unwrap_err().code, "menu_navigation_stopped");
    assert_eq!(
        serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap(),
        before
    );
    assert_eq!(
        serde_json::to_value(c.pending_outbox().unwrap()).unwrap(),
        pending
    );
    assert_eq!(p.creates, 1);
    assert_eq!(p.stops, 0);
}

#[test]
fn unknown_native_create_is_not_retried_after_restart_and_signed_phases_cannot_invent_its_mapping()
{
    let profile = MenuNavigation::ModelGuidedPublicMenu;
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = open(&db, &[profile], 5000);
    let i = with_profile(profile);
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "unknown_menu", 1000).unwrap();
    let mut p = CountingProvider {
        unknown: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    let uncertain = c.get(&user(), &op.id).unwrap();
    assert_eq!(uncertain.lifecycle, Lifecycle::StartUnknown);
    assert!(uncertain.call_id.is_none());
    drop(c);
    let mut c = open(&db, &[profile], 5000);
    assert_eq!(
        c.start(&user(), &i, &a.id, "unknown_menu", 1001)
            .unwrap()
            .id,
        op.id
    );
    for now in [1001, 1002] {
        c.tick(&mut p, now).unwrap();
        assert_eq!(p.creates, 1);
        assert_eq!(
            c.ingest_phase(signed_phase(&uncertain, 1, "dtmf_required", now))
                .unwrap_err()
                .code,
            "phase_scope_conflict"
        );
        let current = c.get(&user(), &op.id).unwrap();
        assert!(current.call_id.is_none() && current.locked());
        assert_eq!(current.menu_repeats, 0);
    }
    p.events.push(event(
        &uncertain,
        voice_agent::contract::EventKind::Started,
        1003,
    ));
    c.tick(&mut p, 1003).unwrap();
    p.events.clear();
    let known = c.get(&user(), &op.id).unwrap();
    assert_eq!(known.call_id.as_deref(), Some("call_demo"));
    c.ingest_phase(signed_phase(&known, 1, "dtmf_required", 1004))
        .unwrap();
    c.tick(&mut p, 1004).unwrap();
    assert_eq!(p.stops, 0);
    c.end(&user(), &op.id, "user_requested", 1005).unwrap();
    c.tick(&mut p, 1005).unwrap();
    assert_eq!(p.creates, 1);
    assert_eq!(p.stops, 1);
    assert!(c.get(&user(), &op.id).unwrap().locked());
}

/// The two wire names are an independent allowlist; arbitrary strings cannot opt in.
#[hegel::test]
fn profile_names_accept_only_the_two_explicit_capabilities(tc: TestCase) {
    let name = tc.draw(hegel::one_of!(
        gs::text(),
        gs::sampled_from(
            &[
                "spoken_only",
                "model_guided_public_menu",
                "native",
                "dtmf",
                "ModelGuidedPublicMenu",
                "true",
                ""
            ][..]
        )
        .map(str::to_owned)
    ));
    let expected = ["spoken_only", "model_guided_public_menu"].contains(&name.as_str());
    let mut raw: Value = serde_json::from_str(LEGACY_INTENT).unwrap();
    raw["menu_navigation"] = json!(name);
    let actual = serde_json::from_value::<Intent>(raw);
    assert_eq!(actual.is_ok(), expected);
    tc.event(if expected {
        "accepted explicit profile"
    } else {
        "rejected profile"
    });
}

/// Equality of capability labels and a strict expiry are separate authorization conditions.
#[hegel::test]
fn directory_profile_and_expiry_match_an_independent_integer_clock_model(tc: TestCase) {
    let configured = tc.draw(gs::booleans());
    let requested = tc.draw(gs::booleans());
    let expiry = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[0_i64, 1000, 5000, i64::MAX][..])
    ));
    let now = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[expiry.saturating_sub(1), expiry, expiry.saturating_add(1)][..])
    ));
    let expected = configured == requested && i128::from(now) < i128::from(expiry);
    assert_eq!(
        policy(&[PROFILES[usize::from(configured)]], expiry)
            .authorize(&with_profile(PROFILES[usize::from(requested)]), now)
            .is_ok(),
        expected
    );
    tc.event(if expected {
        "accepted profile and clock"
    } else {
        "rejected profile or clock"
    });
}

/// The model counts reports, latches any safety boundary, and never grants a new create.
#[hegel::test]
fn generated_signed_menu_sequences_preserve_stops_and_deduplicate_replays(tc: TestCase) {
    let native = tc.draw(gs::booleans());
    let count = tc.draw(gs::integers::<u8>().max_value(8));
    let (_d, mut c, op, mut p) = running(PROFILES[usize::from(native)]);
    let mut menus = 0_u8;
    let mut stopped = false;
    let mut stop_requests = 0_usize;
    for index in 0..count {
        let command = tc.draw(gs::integers::<u8>().max_value(7));
        let name = [
            "ivr",
            "dtmf_required",
            "hold",
            "talking",
            "authentication_required",
            "declined_ai",
            "uncertain_menu",
            "prohibited_action",
        ][usize::from(command)];
        let replay = tc.draw(gs::booleans());
        let sequence = u16::from(index) + 1;
        let now = 1001 + i64::from(index) * 2;
        let rejected = native && command == 1 && stopped;
        let before = serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap();
        let observation = signed_phase(&op, sequence, name, now);
        if rejected {
            assert!(c.ingest_phase(observation).is_err());
            assert_eq!(
                serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap(),
                before
            );
            tc.event("digit refused after stop");
        } else {
            if command == 0 {
                menus += 1;
            }
            stopped |= menus >= 3 || command >= 4 || (!native && command == 1);
            c.ingest_phase(observation).unwrap();
        }
        let version = c.get(&user(), &op.id).unwrap().result.result_version;
        if replay {
            let duplicate = c.ingest_phase(signed_phase(&op, sequence, name, now + 1));
            assert_eq!(duplicate.is_err(), rejected);
            assert_eq!(
                c.get(&user(), &op.id).unwrap().result.result_version,
                version
            );
            tc.event("re-signed duplicate");
        }
        c.tick(&mut p, now + 1).unwrap();
        stop_requests += usize::from(stopped);
        let current = c.get(&user(), &op.id).unwrap();
        assert_eq!(current.menu_repeats, menus);
        assert_eq!(current.stop_reason.is_some(), stopped);
        assert_eq!(
            current.lifecycle,
            if stopped {
                Lifecycle::Ending
            } else {
                Lifecycle::Active
            }
        );
        assert_eq!(p.stops, stop_requests);
        assert_eq!(p.creates, 1);
        assert!(current.locked());
        assert_eq!(current.result.human_result, "unobserved");
    }
    tc.event(if native {
        "opted-in public menus"
    } else {
        "spoken-only menus"
    });
    tc.event(if stopped {
        "latched stop"
    } else {
        "permitted continuation"
    });
}

/// A valid signature's older timestamp cannot authorize a digit at an expired receipt clock.
#[hegel::test]
fn native_digit_acknowledgement_uses_the_fresh_receipt_clock(tc: TestCase) {
    let received = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(
            &[
                i64::MIN,
                999_i64,
                1000,
                1001,
                1014,
                1015,
                1016,
                1017,
                i64::MAX
            ][..]
        )
    ));
    let (_d, mut c, op, p) = running_until(MenuNavigation::ModelGuidedPublicMenu, 1016);
    let before = c.get(&user(), &op.id).unwrap();
    // A nonzero local processing interval rounds up to one second. Thus a
    // receipt in the final fractional second is rejected, while a backwards
    // raw receipt clock is invalid even if processing later catches up.
    let expected = (1001..1015).contains(&received);
    let actual = c.ingest_phase_at(signed_phase(&op, 1, "dtmf_required", 1001), received);
    assert_eq!(actual.is_ok(), expected);
    let after = c.get(&user(), &op.id).unwrap();
    if expected {
        assert_eq!(
            after.result.result_version,
            before.result.result_version + 1
        );
        assert_eq!(
            after.result.evidence_refs.len(),
            before.result.evidence_refs.len() + 1
        );
        assert_eq!(after.phase, before.phase);
        assert_eq!(after.phase_since, before.phase_since);
        assert_eq!(after.menu_repeats, 0);
        assert!(after.stop_reason.is_none());
    } else {
        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    }
    assert_eq!(p.creates, 1);
    assert_eq!(p.stops, 0);
    tc.event(if expected {
        "digit inside approval window"
    } else {
        "digit outside receipt window"
    });
}
