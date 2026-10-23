#![allow(dead_code)]
use std::collections::BTreeMap;
use voice_agent::contract::*;
use voice_agent::controller::{Principal, Role};
use voice_agent::provider::{CreateOutcome, Provider};
use voice_agent::{Error, Result};

pub fn intent() -> Intent {
    Intent {
        schema_version: 1,
        intent_id: "intent_demo".into(),
        work_item: WorkItem {
            system: "return_protection".into(),
            reference: "work_demo".into(),
            version: "v1".into(),
        },
        destination: Destination {
            e164: "+12025550100".into(),
            source_ref: "official_demo_v1".into(),
            source_version: "v1".into(),
        },
        purpose: "Ask which documents are required".into(),
        facts: BTreeMap::from([(
            "reference".into(),
            Fact {
                value: "SYNTHETIC-REF".into(),
                source_ref: "work_demo".into(),
                source_version: "v1".into(),
            },
        )]),
        permitted_actions: vec!["ask_documents".into()],
        forbidden_actions: vec!["attest".into(), "pay".into(), "accept_terms".into()],
        forbidden_disclosures: vec!["password".into(), "otp".into(), "pin".into()],
        ai_disclosure: true,
        consent_policy_ref: "consent_demo_v1".into(),
        handoff: Handoff {
            recipient_ref: "owner".into(),
            endpoint_ref: "owner_control".into(),
            mode: "manual".into(),
            resume_ai: false,
            authentication: "separate_direct_call".into(),
        },
        limits: Limits {
            attempts: 1,
            duration_seconds: 180,
            hold_seconds: 120,
            handoff_wait_seconds: 60,
            budget_cents: 100,
            rate_cents_per_minute: 10,
            rate_ref: "rate_demo_v1".into(),
        },
        policy_gate_ref: "gate_demo_v1".into(),
        provider: "retell".into(),
        agent_id: "agent_demo".into(),
        agent_version: 1,
        menu_navigation: voice_agent::contract::MenuNavigation::SpokenOnly,
        not_before: 1000,
        not_after: 4600,
    }
}
pub fn user() -> Principal {
    Principal {
        owner: "synthetic-owner".into(),
        role: Role::User,
    }
}
pub fn coordinator() -> Principal {
    Principal {
        owner: "synthetic-owner".into(),
        role: Role::Coordinator,
    }
}
pub fn event(op: &Operation, kind: EventKind, n: i64) -> Event {
    Event {
        key: format!("event_{n}"),
        operation_id: op.id.clone(),
        call_id: op.call_id.clone().unwrap_or("call_demo".into()),
        observed_at: n,
        kind,
        phase: None,
        all_legs_ended: kind == EventKind::Ended,
        actual_cost_cents: None,
    }
}
pub fn operation() -> Operation {
    let intent = intent();
    Operation {
        id: "op_demo".into(),
        owner: user().owner,
        approval_id: "approval_demo".into(),
        digest: intent.digest().unwrap(),
        provider_key: "provider_demo".into(),
        call_id: None,
        lifecycle: Lifecycle::Submitting,
        phase: None,
        created_at: 1000,
        submitted_at: Some(1000),
        last_observed_at: 1000,
        deadline: 1180,
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
            next_action: "Wait for observations".into(),
            actual_cost_cents: None,
            estimated_cost_cents: intent.estimate_cents(),
            reported_answers: vec![],
        },
        intent: Some(intent),
    }
}
#[derive(Default)]
pub struct CountingProvider {
    pub creates: usize,
    pub stops: usize,
    pub lookups: usize,
    pub unknown: bool,
    pub reject: bool,
    pub panic_create: bool,
    pub lose_stop: bool,
    pub events: Vec<Event>,
}
impl Provider for CountingProvider {
    fn create(&mut self, _: &Operation, _: i64) -> CreateOutcome {
        self.creates += 1;
        assert!(
            !self.panic_create,
            "injected crash after provider accepted the request"
        );
        if self.unknown {
            CreateOutcome::Unknown
        } else if self.reject {
            CreateOutcome::Rejected
        } else {
            CreateOutcome::Accepted("call_demo".into())
        }
    }
    fn lookup(&mut self, _: &Operation, _: i64) -> Result<Vec<Event>> {
        self.lookups += 1;
        Ok(self.events.clone())
    }
    fn stop(&mut self, _: &Operation, _: i64) -> Result<()> {
        self.stops += 1;
        if self.lose_stop {
            Err(Error::new("stop_outcome_unknown", 6))
        } else {
            Ok(())
        }
    }
}
