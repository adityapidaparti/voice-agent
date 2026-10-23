mod common;
use common::*;
use hegel::prelude::*;
use std::sync::{Arc, Mutex};
use voice_agent::{
    contract::*, controller::*, observations::*, policy::*, workflow::*, Error, Result,
};

fn policy() -> ControllerPolicy {
    let i = intent();
    ControllerPolicy {
        daily_budget_cents: 2500,
        directory: vec![DirectoryEntry {
            work_system: i.work_item.system,
            destination: i.destination,
            agent_id: i.agent_id,
            agent_version: i.agent_version,
            rate_ref: i.limits.rate_ref,
            rate_cents_per_minute: i.limits.rate_cents_per_minute,
            handoff_recipient_ref: i.handoff.recipient_ref,
            handoff_endpoint_ref: i.handoff.endpoint_ref,
            consent_policy_ref: i.consent_policy_ref,
            expires_at: 5000,
        }],
    }
}
#[derive(Default)]
struct State {
    requests: Vec<GateRequest>,
    denied: Option<GateStage>,
    malformed: bool,
    unavailable: bool,
    short_lease: bool,
}
#[derive(Clone, Default)]
struct Authority(Arc<Mutex<State>>);
impl WorkflowAuthority for Authority {
    fn authorize(&mut self, r: &GateRequest, now: i64) -> Result<GateDecision> {
        let mut s = self.0.lock().unwrap();
        s.requests.push(r.clone());
        if s.unavailable {
            return Err(Error::new("synthetic_authority_unavailable", 6));
        }
        Ok(GateDecision {
            request_digest: if s.malformed {
                "wrong".into()
            } else {
                r.request_digest()?
            },
            allowed: s.denied != Some(r.stage),
            expires_at: now + if s.short_lease { 1 } else { 30 },
            reservation_id: if r.stage == GateStage::Preview {
                None
            } else {
                Some(format!("reserve_{}", r.operation_id))
            },
        })
    }
}
fn open(path: &std::path::Path, a: &Authority) -> Controller {
    Controller::open_configured(path, policy(), Box::new(a.clone())).unwrap()
}
#[test]
fn each_authority_boundary_is_bound_to_the_approved_scope_and_durable_reservation() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.db");
    let a = Authority::default();
    let mut c = open(&db, &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
    let mut provider = CountingProvider::default();
    c.tick(&mut provider, 1000).unwrap();
    drop(c);
    let mut c = open(&db, &a);
    c.tick(&mut provider, 1001).unwrap();
    assert_eq!(provider.creates, 1);
    let s = a.0.lock().unwrap();
    assert_eq!(
        s.requests.iter().map(|r| r.stage).collect::<Vec<_>>(),
        vec![
            GateStage::Preview,
            GateStage::Reserve,
            GateStage::Dispatch,
            GateStage::Continue
        ]
    );
    for r in &s.requests {
        assert_eq!(r.owner, user().owner);
        assert_eq!(r.digest, i.digest().unwrap());
        assert_eq!(r.work_item, i.work_item);
        assert_eq!(r.purpose_digest, hash(i.purpose.as_bytes()));
    }
    for r in &s.requests[2..] {
        assert_eq!(r.operation_id, op.id);
        assert_eq!(r.reservation_id, Some(format!("reserve_{}", op.id)));
    }
}
#[test]
fn denied_preview_or_reservation_creates_no_operation_and_does_not_consume_approval() {
    for stage in [GateStage::Preview, GateStage::Reserve] {
        let d = tempfile::tempdir().unwrap();
        let a = Authority::default();
        let mut c = open(&d.path().join("s.db"), &a);
        let i = intent();
        if stage == GateStage::Preview {
            a.0.lock().unwrap().denied = Some(stage);
            assert!(c.approve(&user(), &i, 1000).is_err());
            a.0.lock().unwrap().denied = None;
        }
        let approval = c.approve(&user(), &i, 1000).unwrap();
        a.0.lock().unwrap().denied = Some(GateStage::Reserve);
        assert!(c.start(&user(), &i, &approval.id, "call", 1000).is_err());
        a.0.lock().unwrap().denied = None;
        c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
    }
}
#[test]
fn unavailable_mismatched_denied_or_short_dispatch_authority_never_reaches_the_provider() {
    for failure in 0..4 {
        let d = tempfile::tempdir().unwrap();
        let a = Authority::default();
        let mut c = open(&d.path().join("s.db"), &a);
        let i = intent();
        let approval = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
        {
            let mut s = a.0.lock().unwrap();
            match failure {
                0 => s.unavailable = true,
                1 => s.malformed = true,
                2 => s.denied = Some(GateStage::Dispatch),
                _ => s.short_lease = true,
            }
        }
        let mut p = CountingProvider::default();
        c.tick(&mut p, 1000).unwrap();
        assert_eq!(p.creates, 0);
        assert_eq!(
            c.get(&user(), &op.id).unwrap().result.outcome,
            "blocked_before_dispatch"
        );
        assert_eq!(c.pending_outbox().unwrap().len(), 1);
    }
}
#[test]
fn revoked_continuation_stops_in_flight_work_and_never_releases_an_uncertain_lock() {
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let mut c = open(&d.path().join("s.db"), &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    a.0.lock().unwrap().denied = Some(GateStage::Continue);
    c.tick(&mut p, 1005).unwrap();
    let op = c.get(&user(), &op.id).unwrap();
    assert_eq!(
        op.stop_reason.as_deref(),
        Some("canonical_authority_unavailable_or_revoked")
    );
    assert!(op.locked());
    assert_eq!(p.stops, 1);
    assert_eq!(p.creates, 1);
}
#[test]
fn duplicate_start_recovers_during_authority_outage_without_a_new_reservation() {
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let mut c = open(&d.path().join("s.db"), &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
    a.0.lock().unwrap().unavailable = true;
    let recovered = c.start(&user(), &i, &approval.id, "call", 5000).unwrap();
    assert_eq!(op.id, recovered.id);
    assert_eq!(a.0.lock().unwrap().requests.len(), 2);
}
#[test]
fn simulation_and_hosted_state_cannot_cross_the_environment_boundary() {
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let sim = d.path().join("sim.db");
    let hosted = d.path().join("hosted.db");
    Controller::open(&sim).unwrap();
    assert!(Controller::open_configured(&sim, policy(), Box::new(a.clone())).is_err());
    open(&hosted, &a);
    assert!(Controller::open(&hosted).is_err());
}
#[test]
fn canonical_work_item_lock_spans_owners_purposes_and_versions() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("s.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    c.start(&user(), &i, &a.id, "one", 1000).unwrap();
    let mut other = user();
    other.owner = "other-owner".into();
    let mut changed = i.clone();
    changed.purpose = "Ask for next steps".into();
    changed.work_item.version = "v2".into();
    c.set_gate(&changed.policy_gate_ref, "v2", 5000, true)
        .unwrap();
    let a = c.approve(&other, &changed, 1000).unwrap();
    assert_eq!(
        c.start(&other, &changed, &a.id, "two", 1000)
            .unwrap_err()
            .code,
        "canonical_work_item_call_exists"
    );
    changed.work_item.reference = "independent_work".into();
    let a = c.approve(&other, &changed, 1000).unwrap();
    c.start(&other, &changed, &a.id, "three", 1000).unwrap();
}
#[test]
fn local_revocation_during_authority_request_is_seen_before_dispatch_without_holding_a_sqlite_write_lock(
) {
    struct Revoking {
        db: std::path::PathBuf,
        a: Authority,
    }
    impl WorkflowAuthority for Revoking {
        fn authorize(&mut self, r: &GateRequest, now: i64) -> Result<GateDecision> {
            if r.stage == GateStage::Dispatch {
                let db = rusqlite::Connection::open(&self.db).unwrap();
                db.busy_timeout(std::time::Duration::from_millis(100))
                    .unwrap();
                let data: String = db
                    .query_row("SELECT data FROM approvals LIMIT 1", [], |r| r.get(0))
                    .unwrap();
                let mut a: Approval = serde_json::from_str(&data).unwrap();
                a.revoked = true;
                db.execute(
                    "UPDATE approvals SET data=?1 WHERE id=?2",
                    rusqlite::params![serde_json::to_string(&a).unwrap(), a.id],
                )
                .unwrap();
            }
            self.a.authorize(r, now)
        }
    }
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("s.db");
    let a = Authority::default();
    let mut c =
        Controller::open_configured(&db, policy(), Box::new(Revoking { db: db.clone(), a }))
            .unwrap();
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    c.start(&user(), &i, &approval.id, "call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    assert_eq!(p.creates, 0);
}
fn phase(op: &Operation, sequence: u16, p: ObservedPhase, at: i64) -> PhaseObservation {
    PhaseObservation {
        operation_id: op.id.clone(),
        call_id: op.call_id.clone().unwrap(),
        intent_digest: op.digest.clone(),
        sequence,
        phase: p,
        observed_at: at,
    }
}
fn running() -> (tempfile::TempDir, Controller, Operation, CountingProvider) {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("s.db")).unwrap();
    let i = intent();
    let a = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &a.id, "call", 1000).unwrap();
    let mut p = CountingProvider::default();
    c.tick(&mut p, 1000).unwrap();
    let op = c.get(&user(), &op.id).unwrap();
    (d, c, op, p)
}
#[test]
fn phase_replays_survive_restart_without_recounting_menus_and_conflicts_stop() {
    let (d, mut c, op, mut p) = running();
    let e = phase(&op, 1, ObservedPhase::Ivr, 1001);
    c.ingest_phase(e.clone()).unwrap();
    drop(c);
    let mut c = Controller::open(d.path().join("s.db")).unwrap();
    let mut replay = e;
    replay.observed_at = 1010;
    c.ingest_phase(replay.clone()).unwrap();
    assert_eq!(c.get(&user(), &op.id).unwrap().menu_repeats, 1);
    replay.phase = ObservedPhase::Talking;
    assert_eq!(
        c.ingest_phase(replay).unwrap_err().code,
        "phase_payload_conflict"
    );
    c.tick(&mut p, 1010).unwrap();
    assert_eq!(p.stops, 1);
    assert_eq!(c.pending_outbox().unwrap().len(), 1);
}
#[test]
fn delayed_safety_phase_still_stops_but_old_ordinary_phase_cannot_reset_hold() {
    let (_d, mut c, op, mut p) = running();
    c.ingest_phase(phase(&op, 3, ObservedPhase::Hold, 1003))
        .unwrap();
    assert_eq!(
        c.ingest_phase(phase(&op, 2, ObservedPhase::Talking, 1004))
            .unwrap_err()
            .code,
        "phase_sequence_stale"
    );
    assert_eq!(c.get(&user(), &op.id).unwrap().phase_since, 1003);
    c.ingest_phase(phase(&op, 1, ObservedPhase::AuthenticationRequired, 1005))
        .unwrap();
    c.tick(&mut p, 1005).unwrap();
    assert_eq!(p.stops, 1);
    let out = c.pending_outbox().unwrap();
    assert_eq!(out[0].result.outcome, "authentication_required");
    assert_eq!(out[0].result.human_result, "unobserved");
}
#[test]
fn all_phase_stop_boundaries_and_scope_failures_are_enforced() {
    for which in [
        ObservedPhase::AuthenticationRequired,
        ObservedPhase::DtmfRequired,
        ObservedPhase::DeclinedAi,
    ] {
        let (_d, mut c, op, mut p) = running();
        let good = phase(&op, 1, which, 1001);
        for bad in 0..3 {
            let mut e = good.clone();
            match bad {
                0 => e.call_id = "foreign_call".into(),
                1 => e.intent_digest = "foreign_digest".into(),
                _ => e.sequence = 0,
            };
            assert!(c.ingest_phase(e).is_err());
        }
        assert!(c.get(&user(), &op.id).unwrap().stop_reason.is_none());
        c.ingest_phase(good).unwrap();
        c.tick(&mut p, 1001).unwrap();
        assert_eq!(p.stops, 1);
        assert!(c.get(&user(), &op.id).unwrap().locked());
    }
}
/// Configured references are authority: changing any one must fail closed.
#[hegel::test]
fn configured_directory_matches_all_frozen_identity_and_rate_fields(tc: TestCase) {
    let mutation = tc.draw(gs::integers::<u8>().max_value(11));
    let mut i = intent();
    let now = tc.draw(gs::sampled_from(&[999_i64, 1000, 4999, 5000, 5001][..]));
    match mutation {
        0 => {}
        1 => i.destination.e164 = "+12025550101".into(),
        2 => i.destination.source_ref.push('x'),
        3 => i.destination.source_version.push('x'),
        4 => i.agent_id.push('x'),
        5 => i.agent_version += 1,
        6 => i.limits.rate_ref.push('x'),
        7 => i.limits.rate_cents_per_minute += 1,
        8 => i.handoff.recipient_ref.push('x'),
        9 => i.handoff.endpoint_ref.push('x'),
        10 => i.consent_policy_ref.push('x'),
        _ => i.work_item.system.push('x'),
    }
    let expected = mutation == 0 && now < 5000;
    tc.event(if expected {
        "accepted configured scope"
    } else {
        "rejected configured scope"
    });
    assert_eq!(policy().authorize(&i, now).is_ok(), expected);
}

#[test]
fn time_spent_waiting_for_authority_cannot_extend_a_dispatch_lease_or_approval() {
    use std::sync::atomic::{AtomicI64, Ordering};
    struct Delayed {
        clock: Arc<AtomicI64>,
        delay: i64,
        authority: Authority,
    }
    impl WorkflowAuthority for Delayed {
        fn authorize(&mut self, r: &GateRequest, now: i64) -> Result<GateDecision> {
            let result = self.authority.authorize(r, now);
            if r.stage == GateStage::Dispatch {
                self.clock.fetch_add(self.delay, Ordering::SeqCst);
            }
            result
        }
    }
    for (delay, window) in [(20, 3600), (10, 5)] {
        let d = tempfile::tempdir().unwrap();
        let clock = Arc::new(AtomicI64::new(1000));
        let mut c = Controller::open_configured(
            d.path().join("s.db"),
            policy(),
            Box::new(Delayed {
                clock: clock.clone(),
                delay,
                authority: Authority::default(),
            }),
        )
        .unwrap();
        let mut i = intent();
        i.not_after = 1000 + window;
        let a = c.approve(&user(), &i, 1000).unwrap();
        let op = c.start(&user(), &i, &a.id, "delayed", 1000).unwrap();
        let mut p = CountingProvider::default();
        c.tick_with_clock(&mut p, &mut || clock.load(Ordering::SeqCst))
            .unwrap();
        assert_eq!(p.creates, 0);
        assert_eq!(c.get(&user(), &op.id).unwrap().lifecycle, Lifecycle::Failed);
    }
}
#[test]
fn callbacks_cannot_claim_an_unconfirmed_production_call_identity() {
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let mut c = open(&d.path().join("s.db"), &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c.start(&user(), &i, &approval.id, "unknown", 1000).unwrap();
    let mut p = CountingProvider {
        unknown: true,
        ..Default::default()
    };
    c.tick(&mut p, 1000).unwrap();
    assert_eq!(
        c.ingest(event(&op, EventKind::Started, 1001))
            .unwrap_err()
            .code,
        "provider_identity_awaiting_reconciliation"
    );
    let mut bound = op.clone();
    bound.call_id = Some("foreign_call".into());
    assert_eq!(
        c.ingest_phase(phase(&bound, 1, ObservedPhase::Talking, 1001))
            .unwrap_err()
            .code,
        "phase_scope_conflict"
    );
    assert!(c.get(&user(), &op.id).unwrap().call_id.is_none());
    // The authenticated lookup adapter validates full metadata/agent/numbers before
    // handing over this minimal event; only that path may reconcile an unknown ID.
    p.events = vec![event(&op, EventKind::Started, 1002)];
    c.tick(&mut p, 1002).unwrap();
    assert_eq!(
        c.get(&user(), &op.id).unwrap().call_id.as_deref(),
        Some("call_demo")
    );
    assert_eq!(p.creates, 1);
}
#[test]
fn definitive_failed_history_never_delays_an_active_stop_with_lookup_requests() {
    let d = tempfile::tempdir().unwrap();
    let mut c = Controller::open(d.path().join("s.db")).unwrap();
    let i = intent();
    let mut p = CountingProvider {
        reject: true,
        ..Default::default()
    };
    for n in 0..8 {
        let a = c.approve(&user(), &i, 1000 + n).unwrap();
        c.start(&user(), &i, &a.id, &format!("rejected_{n}"), 1000 + n)
            .unwrap();
        c.tick(&mut p, 1000 + n).unwrap();
    }
    assert_eq!(p.lookups, 0);
    p.reject = false;
    let a = c.approve(&user(), &i, 1010).unwrap();
    let op = c.start(&user(), &i, &a.id, "active", 1010).unwrap();
    c.tick(&mut p, 1010).unwrap();
    c.revoke(&user(), &a.id, 1011).unwrap();
    struct StopFirst {
        stopped: bool,
        expected: String,
    }
    impl voice_agent::provider::Provider for StopFirst {
        fn create(&mut self, _: &Operation, _: i64) -> voice_agent::provider::CreateOutcome {
            panic!("redial")
        }
        fn lookup(&mut self, op: &Operation, _: i64) -> Result<Vec<Event>> {
            assert!(self.stopped, "stop must precede optional network reads");
            assert_eq!(op.id, self.expected);
            Ok(vec![])
        }
        fn stop(&mut self, op: &Operation, _: i64) -> Result<()> {
            assert_eq!(op.id, self.expected);
            self.stopped = true;
            Ok(())
        }
    }
    let mut observer = StopFirst {
        stopped: false,
        expected: op.id,
    };
    c.tick(&mut observer, 1011).unwrap();
    assert!(observer.stopped);
}

#[test]
fn reported_categories_are_durable_unverified_canonical_evidence_even_after_termination() {
    let (d, mut c, op, mut p) = running();
    let report = ReportObservation {
        operation_id: op.id.clone(),
        call_id: op.call_id.clone().unwrap(),
        intent_digest: op.digest.clone(),
        sequence: 1,
        observed_at: 1001,
        answer: ReportedAnswer {
            status: ReportedStatus::AwaitingDocuments,
            required_documents: vec![DocumentKind::Receipt, DocumentKind::ClaimForm],
            next_step: NextStep::SubmitDocuments,
        },
    };
    let mut wrong = report.clone();
    wrong.call_id = "foreign_call".into();
    assert!(c.ingest_report(wrong).is_err());
    c.ingest_report(report.clone()).unwrap();
    drop(c);
    let mut c = Controller::open(d.path().join("s.db")).unwrap();
    let mut replay = report.clone();
    replay.observed_at = 1002;
    c.ingest_report(replay).unwrap();
    assert_eq!(c.pending_outbox().unwrap().len(), 1);
    p.events = vec![
        event(&op, EventKind::Ended, 1003),
        event(&op, EventKind::Analyzed, 1004),
    ];
    c.tick(&mut p, 1004).unwrap();
    let result = c.get(&user(), &op.id).unwrap().result;
    assert_eq!(result.reported_answers.len(), 1);
    assert_eq!(
        result.reported_answers[0].verification,
        Verification::UnverifiedModelReport
    );
    assert_eq!(result.status, ResultStatus::NeedsReview);
    assert_eq!(result.outcome, "unverified_reported_answer");
    assert_eq!(
        result.reported_answers[0].answer.required_documents,
        vec![DocumentKind::Receipt, DocumentKind::ClaimForm]
    );
    let mut changed = report;
    changed.answer.status = ReportedStatus::Unknown;
    assert_eq!(
        c.ingest_report(changed).unwrap_err().code,
        "report_payload_conflict"
    );
    assert!(c.pending_outbox().unwrap().last().unwrap().result_version > result.result_version);
}
#[test]
fn earlier_failed_writeback_does_not_suppress_a_later_corrective_result() {
    let (_d, mut c, op, _p) = running();
    c.ingest_phase(phase(&op, 1, ObservedPhase::AuthenticationRequired, 1001))
        .unwrap();
    c.ingest(event(&op, EventKind::Ended, 1002)).unwrap();
    c.ingest(event(&op, EventKind::Analyzed, 1003)).unwrap();
    c.process_events().unwrap();
    let versions = c
        .pending_outbox()
        .unwrap()
        .iter()
        .map(|w| w.result_version)
        .collect::<Vec<_>>();
    assert!(versions.len() > 1);
    struct Partial {
        calls: Vec<u32>,
    }
    impl CanonicalWorkflow for Partial {
        fn publish(&mut self, w: &Writeback) -> Result<WritebackAck> {
            self.calls.push(w.result_version);
            if self.calls.len() == 1 {
                Err(Error::new("temporary_sink_failure", 6))
            } else {
                Ok(WritebackAck::Applied)
            }
        }
    }
    let mut sink = Partial { calls: vec![] };
    assert!(c.flush_outbox(&mut sink).is_err());
    assert_eq!(sink.calls, versions);
    assert_eq!(c.pending_outbox().unwrap().len(), 1);
    let status = c.writeback_status(&user(), &op.id).unwrap();
    assert_eq!(status.pending_versions, vec![versions[0]]);
    assert_eq!(status.latest_acknowledged_version, versions.last().copied());
    let mut foreign = user();
    foreign.owner = "foreign".into();
    assert!(c.writeback_status(&foreign, &op.id).is_err());
}

#[test]
fn new_answer_evidence_cannot_cross_a_takeover_boundary_but_prior_replay_is_harmless() {
    let (_d, mut c, op, _p) = running();
    let report = ReportObservation {
        operation_id: op.id.clone(),
        call_id: op.call_id.clone().unwrap(),
        intent_digest: op.digest.clone(),
        sequence: 1,
        observed_at: 1001,
        answer: ReportedAnswer {
            status: ReportedStatus::Unknown,
            required_documents: vec![],
            next_step: NextStep::ContactDirectly,
        },
    };
    c.ingest_report(report.clone()).unwrap();
    c.ingest(event(&op, EventKind::Takeover, 1002)).unwrap();
    c.process_events().unwrap();
    let before = c.get(&user(), &op.id).unwrap().result.result_version;
    c.ingest_report(report.clone()).unwrap();
    let mut fresh = report;
    fresh.sequence = 2;
    fresh.observed_at = 1003;
    assert_eq!(
        c.ingest_report(fresh).unwrap_err().code,
        "report_call_closed"
    );
    assert_eq!(
        c.get(&user(), &op.id).unwrap().result.result_version,
        before
    );
    assert_eq!(
        c.get(&user(), &op.id)
            .unwrap()
            .result
            .reported_answers
            .len(),
        1
    );
}
#[test]
fn verified_registered_identity_can_be_stopped_without_fabricating_start_evidence() {
    use voice_agent::provider::{CreateOutcome, Provider, ProviderLookup};
    struct Registered {
        creates: usize,
        stops: usize,
    }
    impl Provider for Registered {
        fn create(&mut self, _: &Operation, _: i64) -> CreateOutcome {
            self.creates += 1;
            CreateOutcome::Unknown
        }
        fn lookup(&mut self, _: &Operation, _: i64) -> Result<Vec<Event>> {
            panic!("use typed reconciliation")
        }
        fn reconcile(&mut self, _: &Operation, _: i64) -> Result<ProviderLookup> {
            Ok(ProviderLookup {
                call_id: Some("registered_call".into()),
                events: vec![],
            })
        }
        fn stop(&mut self, op: &Operation, _: i64) -> Result<()> {
            assert_eq!(op.call_id.as_deref(), Some("registered_call"));
            self.stops += 1;
            Ok(())
        }
    }
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let mut c = open(&d.path().join("s.db"), &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    let op = c
        .start(&user(), &i, &approval.id, "registered", 1000)
        .unwrap();
    let mut p = Registered {
        creates: 0,
        stops: 0,
    };
    c.tick(&mut p, 1000).unwrap();
    let found = c.get(&user(), &op.id).unwrap();
    assert_eq!(found.call_id.as_deref(), Some("registered_call"));
    assert_eq!(found.lifecycle, Lifecycle::StartUnknown);
    assert!(found.result.evidence_refs.is_empty());
    c.revoke(&user(), &approval.id, 1001).unwrap();
    c.tick(&mut p, 1001).unwrap();
    assert_eq!(p.creates, 1);
    assert_eq!(p.stops, 1);
    assert!(c.get(&user(), &op.id).unwrap().locked());
}
#[test]
fn hosted_capacity_is_globally_reserved_before_remote_reads_for_a_second_owner() {
    let d = tempfile::tempdir().unwrap();
    let a = Authority::default();
    let mut c = open(&d.path().join("s.db"), &a);
    let i = intent();
    let approval = c.approve(&user(), &i, 1000).unwrap();
    c.start(&user(), &i, &approval.id, "one", 1000).unwrap();
    let mut other = user();
    other.owner = "second_owner".into();
    let mut other_i = i;
    other_i.work_item.reference = "independent_work".into();
    let approval = c.approve(&other, &other_i, 1000).unwrap();
    let before = a.0.lock().unwrap().requests.len();
    assert_eq!(
        c.start(&other, &other_i, &approval.id, "two", 1000)
            .unwrap_err()
            .code,
        "hosted_call_capacity_reserved"
    );
    assert_eq!(a.0.lock().unwrap().requests.len(), before);
}
