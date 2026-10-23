//! Network-call budgets are the oracle; these tests do not sleep or fabricate SQL rows.
mod common;

use hegel::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use voice_agent::contract::{Event, EventKind, Operation};
use voice_agent::controller::Controller;
use voice_agent::policy::{ControllerPolicy, DirectoryEntry};
use voice_agent::provider::{CreateOutcome, Provider};
use voice_agent::workflow::{GateDecision, GateRequest, GateStage, WorkflowAuthority};
use voice_agent::Result;

struct SyntheticAuthority;
impl WorkflowAuthority for SyntheticAuthority {
    fn authorize(&mut self, request: &GateRequest, now: i64) -> Result<GateDecision> {
        Ok(GateDecision {
            request_digest: request.request_digest()?,
            allowed: true,
            expires_at: now + 60,
            reservation_id: (request.stage != GateStage::Preview)
                .then(|| format!("reservation_{}", request.operation_id)),
        })
    }
}

fn open(path: &Path) -> Controller {
    let intent = common::intent();
    let policy = ControllerPolicy {
        daily_budget_cents: 2500,
        directory: vec![DirectoryEntry {
            work_system: intent.work_item.system,
            destination: intent.destination,
            agent_id: intent.agent_id,
            agent_version: intent.agent_version,
            menu_navigation: voice_agent::contract::MenuNavigation::SpokenOnly,
            rate_ref: intent.limits.rate_ref,
            rate_cents_per_minute: intent.limits.rate_cents_per_minute,
            handoff_recipient_ref: intent.handoff.recipient_ref,
            handoff_endpoint_ref: intent.handoff.endpoint_ref,
            consent_policy_ref: intent.consent_policy_ref,
            expires_at: 5000,
        }],
    };
    Controller::open_configured(path, policy, Box::new(SyntheticAuthority)).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
enum NetworkAction {
    Create(String),
    Lookup(String),
    Stop(String),
}

struct AdmitDuringLookup {
    database: PathBuf,
    now: i64,
}

#[derive(Default)]
struct RecordingProvider {
    actions: Vec<NetworkAction>,
    creates: usize,
    admit_during_history: Option<AdmitDuringLookup>,
    admitted: Option<Operation>,
}
impl Provider for RecordingProvider {
    fn create(&mut self, operation: &Operation, _: i64) -> CreateOutcome {
        self.creates += 1;
        self.actions
            .push(NetworkAction::Create(operation.id.clone()));
        CreateOutcome::Accepted(format!("call_{}", operation.id))
    }

    fn lookup(&mut self, operation: &Operation, _: i64) -> Result<Vec<Event>> {
        self.actions
            .push(NetworkAction::Lookup(operation.id.clone()));
        if !operation.locked() {
            if let Some(admission) = self.admit_during_history.take() {
                // A separate controller commits a real public-API admission while
                // the worker's historical network read is in flight. Taking the
                // hook before the nested tick makes this a one-shot race boundary.
                let mut other = open(&admission.database);
                let intent = common::intent();
                let approval = other.approve(&common::user(), &intent, admission.now)?;
                let arriving = other.start(
                    &common::user(),
                    &intent,
                    &approval.id,
                    "arriving_during_lookup",
                    admission.now,
                )?;
                other.tick(self, admission.now)?;
                other.revoke(&common::user(), &approval.id, admission.now)?;
                self.admitted = Some(other.get(&common::user(), &arriving.id)?);
            }
        }
        // Historical calls deliberately remain pending analysis, so every one
        // stays eligible and a biased cursor cannot hide behind removed entries.
        Ok(Vec::new())
    }

    fn stop(&mut self, operation: &Operation, _: i64) -> Result<()> {
        assert!(operation.call_id.is_some());
        self.actions.push(NetworkAction::Stop(operation.id.clone()));
        Ok(())
    }
}

fn submit(
    controller: &mut Controller,
    provider: &mut RecordingProvider,
    key: &str,
    now: i64,
) -> (String, Operation) {
    let intent = common::intent();
    let approval = controller.approve(&common::user(), &intent, now).unwrap();
    let operation = controller
        .start(&common::user(), &intent, &approval.id, key, now)
        .unwrap();
    controller.tick(provider, now).unwrap();
    let operation = controller.get(&common::user(), &operation.id).unwrap();
    assert!(operation.call_id.is_some());
    (approval.id, operation)
}

fn history(
    controller: &mut Controller,
    provider: &mut RecordingProvider,
    count: usize,
) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for index in 0..count {
        let now = 1000 + index as i64 * 3;
        let (_, operation) = submit(controller, provider, &format!("history_{index}"), now);
        controller
            .ingest(common::event(&operation, EventKind::Ended, now + 1))
            .unwrap();
        controller.process_events().unwrap();
        let ended = controller.get(&common::user(), &operation.id).unwrap();
        assert!(ended.all_legs_ended && !ended.analysis_seen && ended.intent.is_some());
        assert!(!ended.locked());
        ids.insert(ended.id);
    }
    provider.actions.clear();
    ids
}

fn historical_reads(provider: &RecordingProvider, candidates: &BTreeSet<String>) -> Vec<String> {
    provider
        .actions
        .iter()
        .filter_map(|action| match action {
            NetworkAction::Lookup(id) if candidates.contains(id) => Some(id.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_revoked_active_call_is_stopped_without_reading_pending_history() {
    let directory = tempfile::tempdir().unwrap();
    let mut controller = open(&directory.path().join("state.db"));
    let mut provider = RecordingProvider::default();
    let candidates = history(&mut controller, &mut provider, 12);
    let (approval, active) = submit(&mut controller, &mut provider, "active_call", 1100);
    controller.revoke(&common::user(), &approval, 1101).unwrap();
    let creates = provider.creates;

    for now in [1102, 1103] {
        provider.actions.clear();
        controller.tick(&mut provider, now).unwrap();
        assert!(historical_reads(&provider, &candidates).is_empty());
        assert_eq!(
            provider.actions,
            vec![
                NetworkAction::Stop(active.id.clone()),
                NetworkAction::Lookup(active.id.clone()),
            ]
        );
        assert_eq!(provider.creates, creates);
        assert!(controller
            .get(&common::user(), &active.id)
            .unwrap()
            .locked());
    }
}

#[test]
fn idle_ticks_read_exactly_one_historical_call_and_visit_every_candidate_each_round() {
    let directory = tempfile::tempdir().unwrap();
    let mut controller = open(&directory.path().join("state.db"));
    let mut provider = RecordingProvider::default();
    let candidates = history(&mut controller, &mut provider, 12);
    let creates = provider.creates;
    for round in 0..2 {
        let mut seen = BTreeSet::new();
        for turn in 0..candidates.len() {
            provider.actions.clear();
            controller
                .tick(
                    &mut provider,
                    1200 + (round * candidates.len() + turn) as i64,
                )
                .unwrap();
            let read = historical_reads(&provider, &candidates);
            assert_eq!(read.len(), 1);
            assert_eq!(
                provider.actions,
                vec![NetworkAction::Lookup(read[0].clone())]
            );
            assert!(
                seen.insert(read[0].clone()),
                "a candidate repeated before every peer was visited"
            );
        }
        assert_eq!(seen, candidates);
    }
    assert_eq!(provider.creates, creates);
}

#[test]
fn admission_during_a_historical_read_cannot_queue_more_history_ahead_of_the_next_stop() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("state.db");
    let mut controller = open(&database);
    let mut provider = RecordingProvider::default();
    let candidates = history(&mut controller, &mut provider, 12);
    provider.admit_during_history = Some(AdmitDuringLookup {
        database,
        now: 1100,
    });
    let creates = provider.creates;
    controller.tick(&mut provider, 1100).unwrap();
    assert_eq!(historical_reads(&provider, &candidates).len(), 1);
    let arriving = provider.admitted.as_ref().unwrap().clone();
    assert!(arriving.locked());
    assert!(arriving.call_id.is_some());
    assert_eq!(provider.creates, creates + 1);
    assert!(!provider
        .actions
        .iter()
        .any(|action| matches!(action, NetworkAction::Stop(_))));

    provider.actions.clear();
    controller.tick(&mut provider, 1101).unwrap();
    assert_eq!(
        provider.actions,
        vec![
            NetworkAction::Stop(arriving.id.clone()),
            NetworkAction::Lookup(arriving.id.clone()),
        ]
    );
    assert!(historical_reads(&provider, &candidates).is_empty());
    assert!(controller
        .get(&common::user(), &arriving.id)
        .unwrap()
        .locked());
}

/// The independent scheduling model allocates no background reads while a call
/// is locked, otherwise one if history exists. It does not reproduce cursor logic.
#[hegel::test]
fn generated_history_and_active_states_obey_the_network_read_budget(tc: TestCase) {
    let count = usize::from(tc.draw(gs::integers::<u8>().max_value(4)));
    let active = tc.draw(gs::booleans());
    let revoked = tc.draw(gs::booleans());
    let directory = tempfile::tempdir().unwrap();
    let mut controller = open(&directory.path().join("state.db"));
    let mut provider = RecordingProvider::default();
    let candidates = history(&mut controller, &mut provider, count);
    let active_id = if active {
        let (approval, operation) =
            submit(&mut controller, &mut provider, "generated_active", 1100);
        if revoked {
            controller.revoke(&common::user(), &approval, 1101).unwrap();
        }
        Some(operation.id)
    } else {
        None
    };
    provider.actions.clear();
    let creates = provider.creates;
    controller.tick(&mut provider, 1200).unwrap();
    let background_count = historical_reads(&provider, &candidates).len();
    let active_count = provider
        .actions
        .iter()
        .filter(|action| {
            matches!(
                action, NetworkAction::Lookup(id) if active_id.as_ref() == Some(id)
            )
        })
        .count();
    let stops = provider
        .actions
        .iter()
        .filter(|action| matches!(action, NetworkAction::Stop(_)))
        .count();
    let expected_background = usize::from(!active && count != 0);
    assert_eq!(background_count, expected_background);
    assert_eq!(active_count, usize::from(active));
    assert_eq!(stops, usize::from(active && revoked));
    assert_eq!(
        provider.actions.len(),
        background_count + active_count + stops
    );
    assert_eq!(provider.creates, creates);
    tc.event(if active {
        "active call suppresses history"
    } else {
        "idle history budget"
    });
    if count == 0 {
        tc.event("no historical candidates");
    }
    if active && revoked {
        tc.event("revoked active call");
    }
}
