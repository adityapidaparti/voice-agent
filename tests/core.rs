mod common;
use common::*;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Barrier};
use voice_agent::contract::*;
use voice_agent::controller::{Controller, Principal, Role};

#[test]
fn only_the_authenticated_user_can_grant_an_approval() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    assert!(c.approve(&coordinator(), &intent(), 1000).is_err());
    let approved = c.approve(&user(), &intent(), 1000).unwrap();
    assert_eq!(approved.digest, intent().digest().unwrap());
    assert!(!approved.consumed);
}

#[test]
fn an_approval_binds_every_material_part_of_the_scope() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let mutations: [fn(&mut Intent); 10] = [
        |i| i.destination.e164 = "+12025550101".into(),
        |i| i.destination.source_version = "v2".into(),
        |i| i.facts.get_mut("reference").unwrap().source_version = "v2".into(),
        |i| i.facts.get_mut("reference").unwrap().value = "OTHER-REF".into(),
        |i| i.purpose = "Ask something else".into(),
        |i| i.handoff.endpoint_ref = "other_endpoint".into(),
        |i| i.limits.duration_seconds += 1,
        |i| i.agent_version += 1,
        |i| i.not_after -= 1,
        |i| i.work_item.version = "v2".into(),
    ];
    for (n, change) in mutations.iter().enumerate() {
        let mut changed = i.clone();
        change(&mut changed);
        assert_ne!(changed.digest().unwrap(), a.digest);
        assert!(c
            .start(&coordinator(), &changed, &a.id, &format!("key_{n}"), 1000)
            .is_err());
    }
    // Rejected scope changes must not consume the original authorization.
    c.start(&coordinator(), &i, &a.id, "original", 1000)
        .unwrap();
}

#[test]
fn wrong_owner_cannot_start_read_end_or_revoke_an_operation() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let other = Principal {
        owner: "other-owner".into(),
        role: Role::User,
    };
    assert!(c.start(&other, &i, &a.id, "wrong_owner", 1000).is_err());
    let op = c.start(&user(), &i, &a.id, "key_one", 1000).unwrap();
    assert!(c.get(&other, &op.id).is_err());
    assert!(c.end(&other, &op.id, "user_requested", 1001).is_err());
    assert!(c.revoke(&other, &a.id, 1001).is_err());
}

#[test]
fn expired_and_revoked_approvals_cannot_start() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    assert!(c
        .start(&user(), &i, &a.id, "expired", a.expires_at)
        .is_err());
    c.revoke(&user(), &a.id, 1001).unwrap();
    assert!(c.start(&user(), &i, &a.id, "revoked", 1001).is_err());
}

#[test]
fn repeated_key_returns_the_original_operation_and_other_keys_do_not_reuse_approval() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "same_key", 1000).unwrap();
    for now in [1000, 1001, 1002] {
        assert_eq!(
            c.start(&user(), &i, &a.id, "same_key", now).unwrap().id,
            op.id
        );
    }
    let mut changed = i.clone();
    changed.purpose.push('?');
    assert!(c.start(&user(), &changed, &a.id, "same_key", 1000).is_err());
    assert!(c.start(&user(), &i, &a.id, "another_key", 1000).is_err());
    let a2 = c.approve(&user(), &i, 1000).unwrap();
    assert!(c.start(&user(), &i, &a2.id, "new_approval", 1000).is_err());
}

#[test]
fn simultaneous_starts_reserve_only_one_operation() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let b = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let db = db.clone();
            let b = b.clone();
            let i = i.clone();
            let id = a.id.clone();
            std::thread::spawn(move || {
                let mut c = Controller::open(db).unwrap();
                b.wait();
                c.start(
                    &user(),
                    &i,
                    &id,
                    if n % 2 == 0 { "race_a" } else { "race_b" },
                    1000,
                )
            })
        })
        .collect();
    let successes: BTreeSet<_> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap().ok().map(|o| o.id))
        .collect();
    assert_eq!(successes.len(), 1);
}

#[test]
fn unknown_creation_remains_locked_across_restart_and_never_redials() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "lost_response", 1000).unwrap();
    let mut p = CountingProvider {
        unknown: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    assert_eq!(
        c.get(&user(), &op.id).unwrap().lifecycle,
        Lifecycle::StartUnknown
    );
    drop(c);
    let mut c = Controller::open(&db).unwrap();
    for n in [1001, 1060, 5000] {
        let _ = c.tick(&mut p, n);
    }
    assert_eq!(p.creates, 1);
    assert!(c.get(&user(), &op.id).unwrap().locked());
}

#[test]
fn a_crash_after_dispatch_cannot_turn_a_persisted_attempt_into_a_new_dial() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "crash_window", 1000).unwrap();
    let mut p = CountingProvider {
        panic_create: true,
        ..Default::default()
    };
    assert!(catch_unwind(AssertUnwindSafe(|| c.tick(&mut p, 1000))).is_err());
    drop(c);
    p.panic_create = false;
    let mut c = Controller::open(&db).unwrap();
    c.tick(&mut p, 1001).unwrap();
    assert_eq!(p.creates, 1);
    assert!(c.get(&user(), &op.id).unwrap().locked());
}

#[test]
fn stop_acknowledgement_alone_does_not_prove_that_the_call_has_ended() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "stop_call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    for n in 1001..1004 {
        assert_eq!(
            c.end(&coordinator(), &op.id, "user_requested", n)
                .unwrap()
                .lifecycle,
            Lifecycle::Ending
        );
        let _ = c.tick(&mut p, n);
        assert!(c.get(&user(), &op.id).unwrap().locked());
    }
    assert!(p.stops > 0);
    deliver(&mut c, event(&op, EventKind::Ended, 1005)).unwrap();
    let stopped = c.get(&user(), &op.id).unwrap();
    assert_eq!(stopped.lifecycle, Lifecycle::Ended);
    assert!(!stopped.locked());
    assert_eq!(p.creates, 1);
}

#[test]
fn revocation_during_a_call_requests_termination_of_the_same_call() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "revoke_live", 1000).unwrap();
    let mut p = CountingProvider {
        lose_stop: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    c.revoke(&user(), &a.id, 1001).unwrap();
    let _ = c.tick(&mut p, 1001);
    let observed = c.get(&user(), &op.id).unwrap();
    assert_eq!(observed.lifecycle, Lifecycle::Ending);
    assert!(observed.locked());
    assert!(p.stops > 0);
    assert_eq!(p.creates, 1);
}

#[test]
fn duplicate_and_reordered_events_keep_termination_and_do_not_duplicate_result_versions() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "events", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let end = event(&op, EventKind::Ended, 1010);
    deliver(&mut c, end.clone()).unwrap();
    let first = c.get(&user(), &op.id).unwrap();
    deliver(&mut c, end).unwrap();
    assert_eq!(
        c.get(&user(), &op.id).unwrap().result.result_version,
        first.result.result_version
    );
    deliver(&mut c, event(&op, EventKind::Started, 1001)).unwrap();
    let late = c.get(&user(), &op.id).unwrap();
    assert_eq!(late.lifecycle, Lifecycle::Ended);
    assert_eq!(late.last_observed_at, 1010);
    assert_eq!(late.result.status, ResultStatus::Pending);
    deliver(&mut c, event(&op, EventKind::Analyzed, 1011)).unwrap();
    let analyzed = c.get(&user(), &op.id).unwrap();
    assert_eq!(analyzed.result.status, ResultStatus::NeedsReview);
    assert_ne!(analyzed.result.outcome, "objective_completed");
    assert_eq!(analyzed.result.human_result, "unobserved");
}

#[test]
fn a_call_id_cannot_be_reassigned_by_an_event() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "mapping", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let mut foreign = event(&op, EventKind::Ended, 1001);
    foreign.call_id = "call_someone_else".into();
    assert!(deliver(&mut c, foreign).is_err());
    assert!(c.get(&user(), &op.id).unwrap().locked());
}

#[test]
fn three_menu_repetitions_and_hold_deadline_request_a_stop() {
    for hold in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut c = Controller::open(d.path().join("state.db")).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &a.id, "limits", 1000).unwrap();
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        for n in 1001..=1003 {
            let mut e = event(&op, EventKind::Phase, n);
            e.phase = Some(if hold { Phase::Hold } else { Phase::Ivr });
            deliver(&mut c, e).unwrap();
        }
        let _ = c.tick(&mut p, if hold { 1124 } else { 1004 });
        assert_eq!(c.get(&user(), &op.id).unwrap().lifecycle, Lifecycle::Ending);
        assert!(p.stops > 0);
    }
}

#[test]
fn fresh_upstream_gate_is_required_even_after_approval() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    c.set_gate("gate_demo_v1", "v2", 2000, true).unwrap();
    assert!(c.start(&user(), &i, &a.id, "stale_gate", 1001).is_err());
    c.set_gate("gate_demo_v1", "v1", 1001, true).unwrap();
    assert!(c.start(&user(), &i, &a.id, "expired_gate", 1001).is_err());
    c.set_gate("gate_demo_v1", "v1", 2000, false).unwrap();
    assert!(c.start(&user(), &i, &a.id, "revoked_gate", 1001).is_err());
    c.set_gate("gate_demo_v1", "v1", 2000, true).unwrap();
    c.set_starts_enabled(false).unwrap();
    assert!(c.start(&user(), &i, &a.id, "disabled", 1001).is_err());
}

#[test]
fn policy_revoked_between_reservation_and_dispatch_prevents_a_call() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    c.start(&user(), &i, &a.id, "queued", 1000).unwrap();
    c.set_gate("gate_demo_v1", "v1", 2000, false).unwrap();
    let mut p = CountingProvider::default();
    let _ = c.tick(&mut p, 1001);
    assert_eq!(p.creates, 0);
}

#[test]
fn pending_writeback_survives_restart_and_conflicts_never_trigger_redial() {
    use voice_agent::controller::{CanonicalWorkflow, Writeback, WritebackAck};
    struct Sink {
        conflict: bool,
        calls: usize,
    }
    impl CanonicalWorkflow for Sink {
        fn publish(&mut self, _: &Writeback) -> voice_agent::Result<WritebackAck> {
            self.calls += 1;
            Ok(if self.conflict {
                WritebackAck::Conflict
            } else {
                WritebackAck::AlreadyApplied
            })
        }
    }
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "outbox", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    deliver(&mut c, event(&op, EventKind::Ended, 1001)).unwrap();
    deliver(&mut c, event(&op, EventKind::Analyzed, 1002)).unwrap();
    drop(c);
    let mut c = Controller::open(&db).unwrap();
    let pending = c.pending_outbox().unwrap();
    assert!(!pending.is_empty());
    for w in &pending {
        assert_eq!(w.operation_id, op.id);
        assert_eq!(w.work_item.version, "v1");
        assert_ne!(w.result.outcome, "objective_completed");
    }
    let mut sink = Sink {
        conflict: true,
        calls: 0,
    };
    let _ = c.flush_outbox(&mut sink);
    assert_eq!(c.pending_outbox().unwrap().len(), pending.len());
    sink.conflict = false;
    c.flush_outbox(&mut sink).unwrap();
    assert!(c.pending_outbox().unwrap().is_empty());
    let count = sink.calls;
    c.flush_outbox(&mut sink).unwrap();
    assert_eq!(sink.calls, count);
    c.tick(&mut p, 1003).unwrap();
    assert_eq!(p.creates, 1);
    assert!(c.get(&user(), &op.id).unwrap().intent.is_none());
}

#[test]
fn unexpected_remaining_legs_keep_the_active_call_guard() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "legs", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let mut ended = event(&op, EventKind::Ended, 1001);
    ended.all_legs_ended = false;
    deliver(&mut c, ended).unwrap();
    deliver(&mut c, event(&op, EventKind::Analyzed, 1002)).unwrap();
    let partial = c.get(&user(), &op.id).unwrap();
    assert!(partial.locked());
    assert_eq!(partial.result.status, ResultStatus::NeedsReview);
    assert_eq!(partial.result.outcome, "uncontrolled_leg");
    let a2 = c.approve(&user(), &i, 1002).unwrap();
    assert!(c.start(&user(), &i, &a2.id, "other_leg", 1002).is_err());
}

fn deliver(c: &mut Controller, e: Event) -> voice_agent::Result<()> {
    c.ingest(e)?;
    c.process_events()
}

#[test]
fn read_only_replay_after_expiry_recovers_the_existing_operation() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let first = c
        .start(&user(), &i, &a.id, "recover_after_expiry", 1000)
        .unwrap();
    assert_eq!(
        c.start(&user(), &i, &a.id, "recover_after_expiry", 9000)
            .unwrap()
            .id,
        first.id
    );
}

#[test]
fn daily_phone_budget_is_reserved_across_finished_attempts() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let mut i = intent();
    i.limits.budget_cents = 1000;
    let mut p = CountingProvider {
        reject: true,
        ..Default::default()
    };
    for n in 0..2 {
        let a = c.approve(&user(), &i, 1000 + n).unwrap();
        c.start(&user(), &i, &a.id, &format!("attempt_{n}"), 1000 + n)
            .unwrap();
        c.tick(&mut p, 1000 + n).unwrap();
    }
    let a = c.approve(&user(), &i, 1002).unwrap();
    let e = c
        .start(&user(), &i, &a.id, "over_daily_budget", 1002)
        .unwrap_err();
    assert_eq!(e.code, "daily_reservation_limit");
    assert_eq!(p.creates, 2);
}

#[test]
fn unsubmitted_revoked_approval_and_stop_request_never_reach_the_provider() {
    for revoke in [true, false] {
        let d = tempfile::tempdir().unwrap();
        let mut c = Controller::open(d.path().join("state.db")).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &a.id, "cancel_queued", 1000).unwrap();
        if revoke {
            c.revoke(&user(), &a.id, 1001).unwrap();
        } else {
            c.end(&user(), &op.id, "user_requested", 1001).unwrap();
        }
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1001).unwrap();
        assert_eq!(p.creates, 0);
        let cancelled = c.get(&user(), &op.id).unwrap();
        assert_eq!(cancelled.lifecycle, Lifecycle::Failed);
        assert!(!cancelled.locked());
    }
}

#[test]
fn the_first_authenticated_inbox_event_claims_an_unknown_call_id_atomically() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "inbox_claim", 1000).unwrap();
    let mut p = CountingProvider {
        unknown: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    let first = event(&op, EventKind::Started, 1001);
    c.ingest(first).unwrap();
    let mut second = event(&op, EventKind::Started, 1002);
    second.call_id = "different_call".into();
    assert!(c.ingest(second).is_err());
    c.process_events().unwrap();
    assert_eq!(
        c.get(&user(), &op.id).unwrap().call_id.as_deref(),
        Some("call_demo")
    );
}

#[test]
fn reissuing_an_approval_never_resets_revoked_or_consumed_authority() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    c.start(&user(), &i, &a.id, "consume", 1000).unwrap();
    assert!(c.approve(&user(), &i, 1000).unwrap().consumed);
    c.revoke(&user(), &a.id, 1001).unwrap();
    let again = c.approve(&user(), &i, 1000).unwrap();
    assert!(again.revoked);
    assert!(again.consumed);
}

#[test]
fn another_hold_observation_does_not_extend_the_approved_hold_window() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "hold_refresh", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    for n in [1001, 1060, 1120] {
        let mut e = event(&op, EventKind::Phase, n);
        e.phase = Some(Phase::Hold);
        deliver(&mut c, e).unwrap();
    }
    c.tick(&mut p, 1121).unwrap();
    let ending = c.get(&user(), &op.id).unwrap();
    assert_eq!(ending.phase_since, 1001);
    assert_eq!(ending.lifecycle, Lifecycle::Ending);
    assert!(p.stops > 0);
}

#[test]
fn unexpected_transfer_leg_uncertainty_cannot_be_erased_by_a_plain_end_event() {
    for false_first in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let mut c = Controller::open(d.path().join("state.db")).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c
            .start(&user(), &i, &a.id, "unexpected_transfer", 1000)
            .unwrap();
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        for (n, legs_ended) in [!false_first, false_first].into_iter().enumerate() {
            let mut e = event(&op, EventKind::Ended, 1001 + n as i64);
            e.all_legs_ended = legs_ended;
            deliver(&mut c, e).unwrap();
        }
        let uncertain = c.get(&user(), &op.id).unwrap();
        assert!(uncertain.locked());
        assert_eq!(uncertain.lifecycle, Lifecycle::Ending);
        let a2 = c.approve(&user(), &i, 1003).unwrap();
        assert!(c
            .start(&user(), &i, &a2.id, "must_stay_blocked", 1003)
            .is_err());
    }
}

#[test]
fn a_started_event_after_definitive_rejection_is_an_incident_requiring_stop() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &a.id, "rejected_but_started", 1000)
        .unwrap();
    let mut p = CountingProvider {
        reject: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    assert_eq!(c.get(&user(), &op.id).unwrap().lifecycle, Lifecycle::Failed);
    deliver(&mut c, event(&op, EventKind::Started, 1001)).unwrap();
    c.tick(&mut p, 1002).unwrap();
    let incident = c.get(&user(), &op.id).unwrap();
    assert!(incident.locked());
    assert_eq!(incident.lifecycle, Lifecycle::Ending);
    assert!(p.stops > 0);
    let mut other = user();
    other.owner = "another-owner".into();
    let other_approval = c.approve(&other, &i, 1002).unwrap();
    assert!(c
        .start(&other, &i, &other_approval.id, "globally_disabled", 1002)
        .is_err());
}

#[test]
fn late_transfer_evidence_is_processed_even_when_a_newer_operation_is_active() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let old = c.start(&user(), &i, &a.id, "old_call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    deliver(&mut c, event(&old, EventKind::Ended, 1001)).unwrap();
    let a2 = c.approve(&user(), &i, 1002).unwrap();
    let newer = c.start(&user(), &i, &a2.id, "newer_call", 1002).unwrap();
    let mut late = event(&old, EventKind::Ended, 1003);
    late.all_legs_ended = false;
    deliver(&mut c, late).unwrap();
    assert!(c.get(&user(), &old.id).unwrap().locked());
    assert!(c.get(&user(), &newer.id).unwrap().locked());
    let mut other = user();
    other.owner = "other-owner".into();
    let a3 = c.approve(&other, &i, 1003).unwrap();
    assert!(c
        .start(&other, &i, &a3.id, "incident_blocks_all", 1003)
        .is_err());
}

#[cfg(unix)]
#[test]
fn database_files_are_private_and_symlink_targets_are_not_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("private.db");
    let c = Controller::open(&db).unwrap();
    assert_eq!(
        std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(c);
    let link = d.path().join("link.db");
    symlink(&db, &link).unwrap();
    assert!(Controller::open(link).is_err());
}

#[test]
fn unused_approval_facts_expire_without_needing_an_operation() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let a = c.approve(&user(), &intent(), 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000 + 86400).unwrap();
    let db = rusqlite::Connection::open(&db).unwrap();
    let json: String = db
        .query_row("SELECT data FROM approvals WHERE id=?1", [&a.id], |row| {
            row.get(0)
        })
        .unwrap();
    let saved: voice_agent::controller::Approval = serde_json::from_str(&json).unwrap();
    assert!(saved.intent.is_none());
    assert!(!json.contains("SYNTHETIC-REF"));
    assert_eq!(p.creates, 0);
}

#[test]
fn observed_cost_at_the_budget_requests_termination() {
    for observed_cost in [99, 100, 101] {
        let d = tempfile::tempdir().unwrap();
        let mut c = Controller::open(d.path().join("state.db")).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &a.id, "cost_overrun", 1000).unwrap();
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        let mut cost = event(&op, EventKind::Analyzed, 1001);
        cost.actual_cost_cents = Some(observed_cost);
        deliver(&mut c, cost).unwrap();
        c.tick(&mut p, 1001).unwrap();
        let actual = c.get(&user(), &op.id).unwrap();
        assert_eq!(
            actual.lifecycle,
            if observed_cost >= 100 {
                Lifecycle::Ending
            } else {
                Lifecycle::Active
            }
        );
        assert!(actual.locked());
        assert_eq!(p.stops > 0, observed_cost >= 100);
        assert_eq!(p.creates, 1);
    }
}

#[test]
fn cost_overruns_reduce_the_budget_available_to_later_calls() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let mut i = intent();
    i.limits.budget_cents = 1000;
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "expensive_call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let mut cost = event(&op, EventKind::Analyzed, 1001);
    cost.actual_cost_cents = Some(2000);
    deliver(&mut c, cost).unwrap();
    // A late lower observation cannot release money already conservatively reserved.
    let mut older_cost = event(&op, EventKind::Analyzed, 1000);
    older_cost.actual_cost_cents = Some(100);
    deliver(&mut c, older_cost).unwrap();
    deliver(&mut c, event(&op, EventKind::Ended, 1002)).unwrap();
    c.tick(&mut p, 1002).unwrap();
    let a2 = c.approve(&user(), &i, 1003).unwrap();
    let error = c
        .start(&user(), &i, &a2.id, "over_remaining_budget", 1003)
        .unwrap_err();
    assert_eq!(error.code, "daily_reservation_limit");
    assert_eq!(p.creates, 1);
}

#[test]
fn changed_event_payloads_quarantine_the_call_and_publish_corrective_results() {
    type EventMutation = (EventKind, fn(&mut Event));
    let cases: [EventMutation; 4] = [
        (EventKind::Ended, |e| e.all_legs_ended = false),
        (EventKind::Started, |e| e.observed_at += 1),
        (EventKind::Analyzed, |e| e.actual_cost_cents = Some(2000)),
        (EventKind::Phase, |e| e.phase = Some(Phase::Talking)),
    ];
    for (kind, mutate) in cases {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("state.db");
        let mut c = Controller::open(&db).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c
            .start(&user(), &i, &a.id, "payload_conflict", 1000)
            .unwrap();
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        let mut original = event(&op, kind, 1001);
        if kind == EventKind::Phase {
            original.phase = Some(Phase::Hold);
        }
        if kind == EventKind::Analyzed {
            original.actual_cost_cents = Some(40);
        }
        deliver(&mut c, original.clone()).unwrap();
        let before = c.get(&user(), &op.id).unwrap();
        let pending_before = c.pending_outbox().unwrap().len();
        // Exact redelivery neither changes state nor creates another result version.
        deliver(&mut c, original.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(c.get(&user(), &op.id).unwrap()).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(c.pending_outbox().unwrap().len(), pending_before);
        let mut conflict = original;
        mutate(&mut conflict);
        assert_eq!(
            c.ingest(conflict).unwrap_err().code,
            "event_payload_conflict"
        );
        drop(c);
        let mut c = Controller::open(&db).unwrap();
        let quarantined = c.get(&user(), &op.id).unwrap();
        assert!(quarantined.locked());
        assert_eq!(quarantined.lifecycle, Lifecycle::Ending);
        assert_eq!(quarantined.result.status, ResultStatus::NeedsReview);
        assert!(quarantined.result.result_version > before.result.result_version);
        let correction = c
            .pending_outbox()
            .unwrap()
            .into_iter()
            .find(|w| w.result_version == quarantined.result.result_version)
            .unwrap();
        assert_eq!(correction.result.status, ResultStatus::NeedsReview);
        assert_eq!(correction.result.outcome, "conflicting_provider_event");
        let mut other = user();
        other.owner = "other-owner".into();
        let a2 = c.approve(&other, &i, 1002).unwrap();
        assert_eq!(
            c.start(&other, &i, &a2.id, "global_quarantine", 1002)
                .unwrap_err()
                .code,
            "starts_disabled"
        );
        // Ordinary terminal evidence cannot silently clear conflicting evidence.
        deliver(&mut c, event(&op, EventKind::Ended, 1003)).unwrap();
        let still_quarantined = c.get(&user(), &op.id).unwrap();
        assert!(still_quarantined.locked());
        assert_eq!(still_quarantined.lifecycle, Lifecycle::Ending);
        assert_eq!(
            still_quarantined.result.outcome,
            "conflicting_provider_event"
        );
    }
}

#[test]
fn conflicting_cost_reports_preserve_the_largest_possible_charge() {
    for (first, conflicting) in [(40_u32, 2000_u32), (2000, 40)] {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("state.db");
        let mut c = Controller::open(&db).unwrap();
        let i = intent();
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c
            .start(&user(), &i, &a.id, "conflicting_cost", 1000)
            .unwrap();
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        let mut report = event(&op, EventKind::Analyzed, 1001);
        report.actual_cost_cents = Some(first);
        deliver(&mut c, report.clone()).unwrap();
        report.actual_cost_cents = Some(conflicting);
        assert_eq!(c.ingest(report).unwrap_err().code, "event_payload_conflict");
        drop(c);
        let db = rusqlite::Connection::open(&db).unwrap();
        let reserved: u32 = db
            .query_row(
                "SELECT reservation FROM operations WHERE id=?1",
                [&op.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 2000);
    }
}

#[test]
fn late_transfer_uncertainty_corrects_an_already_delivered_result() {
    use voice_agent::controller::{CanonicalWorkflow, Writeback, WritebackAck};
    #[derive(Default)]
    struct Applied {
        versions: Vec<u32>,
    }
    impl CanonicalWorkflow for Applied {
        fn publish(&mut self, w: &Writeback) -> voice_agent::Result<WritebackAck> {
            self.versions.push(w.result_version);
            Ok(WritebackAck::Applied)
        }
    }
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let mut c = Controller::open(&db).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &a.id, "late_correction", 1000)
        .unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    deliver(&mut c, event(&op, EventKind::Ended, 1001)).unwrap();
    deliver(&mut c, event(&op, EventKind::Analyzed, 1002)).unwrap();
    let mut sink = Applied::default();
    c.flush_outbox(&mut sink).unwrap();
    assert!(!sink.versions.is_empty());
    assert!(c.pending_outbox().unwrap().is_empty());
    let previous_version = *sink.versions.iter().max().unwrap();
    let mut late = event(&op, EventKind::Ended, 1003);
    late.all_legs_ended = false;
    let evidence = late.key.clone();
    deliver(&mut c, late).unwrap();
    drop(c);
    let c = Controller::open(&db).unwrap();
    let reopened = c.get(&user(), &op.id).unwrap();
    assert!(reopened.locked());
    assert_eq!(reopened.lifecycle, Lifecycle::Ending);
    assert_eq!(reopened.result.status, ResultStatus::NeedsReview);
    assert_eq!(reopened.result.outcome, "uncontrolled_leg");
    assert!(reopened.result.result_version > previous_version);
    let pending = c.pending_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    let correction = &pending[0];
    assert_eq!(correction.operation_id, op.id);
    assert_eq!(correction.work_item, i.work_item);
    assert_eq!(correction.result_version, reopened.result.result_version);
    assert_eq!(correction.result.status, ResultStatus::NeedsReview);
    assert_eq!(correction.result.outcome, "uncontrolled_leg");
    assert!(correction.result.evidence_refs.contains(&evidence));
    assert_eq!(correction.result.human_result, "unobserved");
    assert!(!correction.result.next_action.is_empty());
}

#[test]
fn lower_late_cost_observations_do_not_erase_a_known_higher_charge() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &a.id, "cost_observations", 1000)
        .unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    for (at, cost) in [(1002, 2000), (1001, 100)] {
        let mut e = event(&op, EventKind::Analyzed, at);
        e.actual_cost_cents = Some(cost);
        deliver(&mut c, e).unwrap();
    }
    assert_eq!(
        c.get(&user(), &op.id).unwrap().result.actual_cost_cents,
        Some(2000)
    );
}

#[test]
fn concurrent_approval_creation_cannot_restore_a_consumed_attempt() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let _initialized = Controller::open(&db).unwrap();
    let barrier = Arc::new(Barrier::new(12));
    let threads: Vec<_> = (0..12)
        .map(|n| {
            let db = db.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut c = Controller::open(db).unwrap();
                barrier.wait();
                let i = intent();
                let a = c.approve(&user(), &i, 1000).unwrap();
                let result = c.start(&user(), &i, &a.id, &format!("approval_race_{n}"), 1000);
                (a.id, result.ok().map(|op| op.id))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let approval_ids: BTreeSet<_> = results.iter().map(|(id, _)| id).collect();
    assert_eq!(approval_ids.len(), 1);
    assert_eq!(results.iter().filter(|(_, op)| op.is_some()).count(), 1);
    let mut c = Controller::open(&db).unwrap();
    assert!(c.approve(&user(), &intent(), 1000).unwrap().consumed);
}

#[test]
fn repeated_conflicting_provider_lookups_do_not_prevent_stopping_the_call() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &a.id, "conflicting_lookup", 1000)
        .unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let original = event(&op, EventKind::Started, 1001);
    deliver(&mut c, original.clone()).unwrap();
    let mut conflict = original;
    conflict.observed_at = 1002;
    p.events = vec![conflict];
    for at in [1002, 1003] {
        let previous_stops = p.stops;
        c.tick(&mut p, at).unwrap();
        assert!(p.stops > previous_stops);
        assert!(c.get(&user(), &op.id).unwrap().locked());
    }
    assert_eq!(p.creates, 1);
}

#[test]
fn revocation_and_an_ordinary_end_cannot_clear_transfer_uncertainty() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &a.id, "transfer_revoke", 1000)
        .unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let mut transfer = event(&op, EventKind::Ended, 1001);
    transfer.all_legs_ended = false;
    deliver(&mut c, transfer).unwrap();
    c.revoke(&user(), &a.id, 1002).unwrap();
    deliver(&mut c, event(&op, EventKind::Ended, 1003)).unwrap();
    c.tick(&mut p, 1004).unwrap();
    let uncertain = c.get(&user(), &op.id).unwrap();
    assert!(uncertain.locked());
    assert!(uncertain.uncertain_legs);
    assert_eq!(uncertain.lifecycle, Lifecycle::Ending);
    let mut other = user();
    other.owner = "other-owner".into();
    let a2 = c.approve(&other, &i, 1004).unwrap();
    assert_eq!(
        c.start(&other, &i, &a2.id, "still_disabled", 1004)
            .unwrap_err()
            .code,
        "starts_disabled"
    );
}

#[test]
fn ivr_stopping_reason_and_an_ordinary_end_cannot_clear_event_uncertainty() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("state.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "conflict_ivr", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let original = event(&op, EventKind::Started, 1001);
    deliver(&mut c, original.clone()).unwrap();
    let mut conflict = original;
    conflict.observed_at = 1002;
    assert_eq!(
        c.ingest(conflict).unwrap_err().code,
        "event_payload_conflict"
    );
    for at in [1003, 1004, 1005] {
        let mut e = event(&op, EventKind::Phase, at);
        e.phase = Some(Phase::Ivr);
        deliver(&mut c, e).unwrap();
    }
    deliver(&mut c, event(&op, EventKind::Ended, 1006)).unwrap();
    let uncertain = c.get(&user(), &op.id).unwrap();
    assert!(uncertain.locked());
    assert!(uncertain.uncertain_legs);
    assert_eq!(uncertain.lifecycle, Lifecycle::Ending);
    assert_eq!(uncertain.result.status, ResultStatus::NeedsReview);
}

#[test]
fn rejected_lookup_observations_cannot_starve_stops_for_any_active_owner() {
    use voice_agent::provider::{CreateOutcome, Provider};

    #[derive(Default)]
    struct ScriptedProvider {
        creates: Vec<(String, String)>,
        lookups: Vec<(String, i64)>,
        stops: Vec<(String, String, i64)>,
        rejected: Option<Event>,
    }
    impl Provider for ScriptedProvider {
        fn create(&mut self, op: &Operation, _: i64) -> CreateOutcome {
            let call_id = format!("call_{}", op.id);
            self.creates.push((op.id.clone(), call_id.clone()));
            CreateOutcome::Accepted(call_id)
        }
        fn lookup(&mut self, op: &Operation, now: i64) -> voice_agent::Result<Vec<Event>> {
            self.lookups.push((op.id.clone(), now));
            Ok(self
                .rejected
                .iter()
                .filter(|e| e.operation_id == op.id)
                .cloned()
                .collect())
        }
        fn stop(&mut self, op: &Operation, now: i64) -> voice_agent::Result<()> {
            self.stops.push((
                op.id.clone(),
                op.call_id.clone().expect("stop must use the known call"),
                now,
            ));
            Ok(())
        }
    }

    for rejection in [
        "invalid_event_envelope",
        "event_mapping_conflict",
        "event_identity_conflict",
    ] {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("state.db");
        let mut c = Controller::open(&db).unwrap();
        let revoked_owner = user();
        let expired_owner = Principal {
            owner: "other-synthetic-owner".into(),
            role: Role::User,
        };
        let mut longer = intent();
        longer.limits.duration_seconds = 600;
        longer.limits.budget_cents = 200;
        let shorter = intent();
        let revoked_approval = c.approve(&revoked_owner, &longer, 1000).unwrap();
        let expired_approval = c.approve(&expired_owner, &shorter, 1000).unwrap();
        let revoked_op = c
            .start(
                &revoked_owner,
                &longer,
                &revoked_approval.id,
                "rejected_lookup",
                1000,
            )
            .unwrap();
        let expired_op = c
            .start(
                &expired_owner,
                &shorter,
                &expired_approval.id,
                "other_call",
                1000,
            )
            .unwrap();
        let mut p = ScriptedProvider::default();
        c.tick(&mut p, 1000).unwrap();
        assert_eq!(p.creates.len(), 2);
        let revoked_op = c.get(&revoked_owner, &revoked_op.id).unwrap();
        let expired_op = c.get(&expired_owner, &expired_op.id).unwrap();
        let expected_bindings: BTreeSet<_> = [&revoked_op, &expired_op]
            .into_iter()
            .map(|op| (op.id.clone(), op.call_id.clone().unwrap()))
            .collect();
        assert_ne!(revoked_op.call_id, expired_op.call_id);
        let original = event(&revoked_op, EventKind::Started, 1001);
        deliver(&mut c, original.clone()).unwrap();
        let mut rejected = original;
        match rejection {
            "invalid_event_envelope" => rejected.key.clear(),
            "event_mapping_conflict" => rejected.call_id = "foreign_call".into(),
            "event_identity_conflict" => {
                rejected.kind = EventKind::Ended;
                rejected.all_legs_ended = true;
            }
            _ => unreachable!(),
        }
        p.rejected = Some(rejected);
        c.revoke(&revoked_owner, &revoked_approval.id, 1002)
            .unwrap();
        let before = c.get(&revoked_owner, &revoked_op.id).unwrap();
        assert!(c.pending_outbox().unwrap().is_empty());
        let mut correction_version = None;

        // One call is revoked before its duration expires; the other reaches its
        // deadline. A rejected observation must not abort either safety action.
        for at in [expired_op.deadline, expired_op.deadline + 1] {
            assert!(at < revoked_op.deadline);
            assert_eq!(c.tick(&mut p, at).unwrap_err().code, rejection);
            let stopped: BTreeSet<_> = p
                .stops
                .iter()
                .filter(|(_, _, time)| *time == at)
                .map(|(operation, call, _)| (operation.clone(), call.clone()))
                .collect();
            assert_eq!(stopped, expected_bindings, "rejection: {rejection}");
            let looked_up: BTreeSet<_> = p
                .lookups
                .iter()
                .filter(|(_, time)| *time == at)
                .map(|(operation, _)| operation.clone())
                .collect();
            assert_eq!(looked_up.len(), 2, "rejection: {rejection}");
            assert_eq!(p.creates.len(), 2);
            for (owner, original) in [(&revoked_owner, &revoked_op), (&expired_owner, &expired_op)]
            {
                let current = c.get(owner, &original.id).unwrap();
                assert_eq!(current.call_id, original.call_id);
                assert_eq!(current.lifecycle, Lifecycle::Ending);
                assert!(current.locked());
                assert!(!current.all_legs_ended);
            }

            let quarantined = c.get(&revoked_owner, &revoked_op.id).unwrap();
            assert_eq!(quarantined.result.status, ResultStatus::NeedsReview);
            assert_eq!(quarantined.result.outcome, "provider_observation_rejected");
            assert_eq!(quarantined.result.human_result, "unobserved");
            assert!(!quarantined.result.next_action.is_empty());
            let incident_refs: Vec<_> = quarantined
                .result
                .evidence_refs
                .iter()
                .filter(|reference| reference.starts_with("incident_"))
                .collect();
            assert_eq!(incident_refs.len(), 1);
            assert_eq!(
                quarantined.result.evidence_refs.len(),
                before.result.evidence_refs.len() + 1
            );
            assert!(quarantined.result.result_version > before.result.result_version);
            if let Some(version) = correction_version {
                assert_eq!(quarantined.result.result_version, version);
            } else {
                correction_version = Some(quarantined.result.result_version);
            }
            let outbox = c.pending_outbox().unwrap();
            assert_eq!(outbox.len(), 1);
            assert_eq!(outbox[0].operation_id, revoked_op.id);
            assert_eq!(outbox[0].result_version, quarantined.result.result_version);
            assert_eq!(outbox[0].result.status, ResultStatus::NeedsReview);
            assert_eq!(outbox[0].result.outcome, "provider_observation_rejected");

            // The rejection record contains a digest and safe metadata, never the
            // rejected envelope. Identical delivery after restart is one incident.
            let diagnostics = rusqlite::Connection::open(&db).unwrap();
            let mut fields = diagnostics.prepare("PRAGMA table_info(incidents)").unwrap();
            let columns: BTreeSet<String> = fields
                .query_map([], |row| row.get(1))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(
                columns,
                ["key", "operation_id", "code", "observed_at"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            );
            let count: u32 = diagnostics
                .query_row("SELECT COUNT(*) FROM incidents", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1);
            let (key, operation_id, code): (String, String, String) = diagnostics
                .query_row("SELECT key,operation_id,code FROM incidents", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .unwrap();
            assert_eq!(&key, incident_refs[0]);
            assert_eq!(operation_id, revoked_op.id);
            assert_eq!(code, rejection);
            drop(fields);
            drop(diagnostics);
            drop(c);
            c = Controller::open(&db).unwrap();
        }
        assert_eq!(
            c.set_starts_enabled(true).unwrap_err().code,
            "safety_incident_requires_resolution"
        );
    }
}
