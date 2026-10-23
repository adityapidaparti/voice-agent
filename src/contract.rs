use crate::{Error, Result};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    pub system: String,
    pub reference: String,
    pub version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub e164: String,
    pub source_ref: String,
    pub source_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub value: String,
    pub source_ref: String,
    pub source_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub attempts: u8,
    pub duration_seconds: u32,
    pub hold_seconds: u32,
    pub handoff_wait_seconds: u32,
    pub budget_cents: u32,
    pub rate_cents_per_minute: u32,
    pub rate_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub recipient_ref: String,
    pub endpoint_ref: String,
    pub mode: String,
    pub resume_ai: bool,
    pub authentication: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub schema_version: u32,
    pub intent_id: String,
    pub work_item: WorkItem,
    pub destination: Destination,
    pub purpose: String,
    pub facts: BTreeMap<String, Fact>,
    pub permitted_actions: Vec<String>,
    pub forbidden_actions: Vec<String>,
    pub forbidden_disclosures: Vec<String>,
    pub ai_disclosure: bool,
    pub consent_policy_ref: String,
    pub handoff: Handoff,
    pub limits: Limits,
    pub policy_gate_ref: String,
    pub provider: String,
    pub agent_id: String,
    pub agent_version: u32,
    pub not_before: i64,
    pub not_after: i64,
}
pub fn hash(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}
pub fn us_number(s: &str) -> bool {
    s.len() == 12 && s.starts_with("+1") && s[2..].bytes().all(|b| b.is_ascii_digit())
}
pub fn synthetic_number(s: &str) -> bool {
    us_number(s) && &s[5..8] == "555" && (100..=199).contains(&s[8..].parse::<u32>().unwrap_or(0))
}
/// Conservative accidental-secret detector. Human packet review remains required.
pub fn sensitive(s: &str) -> bool {
    let lower = s.to_lowercase();
    let words: Vec<_> = lower.split(|c: char| !c.is_alphanumeric()).collect();
    if words.iter().any(|w| {
        [
            "password", "passwd", "otp", "pin", "ssn", "cvv", "secret", "token",
        ]
        .contains(w)
    }) {
        return true;
    }
    if lower.contains("api_key") || lower.contains("api key") || lower.contains("security answer") {
        return true;
    }
    let mut digits = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits += 1;
            if digits >= 9 {
                return true;
            }
        } else if c != ' ' && c != '-' {
            digits = 0;
        }
    }
    false
}
impl Intent {
    pub fn validate(&self, now: i64) -> Result<()> {
        let ids = [
            &self.intent_id,
            &self.work_item.system,
            &self.work_item.reference,
            &self.work_item.version,
            &self.destination.source_ref,
            &self.destination.source_version,
            &self.consent_policy_ref,
            &self.handoff.recipient_ref,
            &self.handoff.endpoint_ref,
            &self.policy_gate_ref,
            &self.agent_id,
            &self.limits.rate_ref,
        ];
        if self.schema_version != 1
            || ids.iter().any(|s| !identifier(s))
            || !us_number(&self.destination.e164)
            || self.purpose.trim().is_empty()
            || self.purpose.len() > 512
            || self.not_before > now
            || now >= self.not_after
            || self.not_after.saturating_sub(self.not_before) > 3600
        {
            return Err(Error::new("invalid_scope_or_window", 2));
        }
        if !self.ai_disclosure
            || self.provider != "retell"
            || self.handoff.resume_ai
            || self.handoff.mode != "manual"
            || self.handoff.authentication != "separate_direct_call"
        {
            return Err(Error::new("unsupported_safety_policy", 4));
        }
        let allowed = ["ask_status", "request_next_steps", "ask_documents"];
        if self.permitted_actions.is_empty()
            || self
                .permitted_actions
                .iter()
                .any(|s| !allowed.contains(&s.as_str()))
            || ["attest", "pay", "accept_terms"]
                .iter()
                .any(|s| !self.forbidden_actions.iter().any(|v| v == s))
            || ["password", "otp", "pin"]
                .iter()
                .any(|s| !self.forbidden_disclosures.iter().any(|v| v == s))
        {
            return Err(Error::new("unsupported_actions", 4));
        }
        // An allowlist reduces accidental context sharing; it cannot detect secrets disguised as prose.
        let keys = ["reference", "document", "question", "authorized_name"];
        if sensitive(&self.purpose) || self.facts.values().any(|v| sensitive(&v.value)) {
            return Err(Error::new("sensitive_packet_rejected", 4));
        }
        if self.facts.len() > 4
            || self.facts.iter().any(|(k, v)| {
                !keys.contains(&k.as_str())
                    || v.value.is_empty()
                    || v.value.len() > 256
                    || !identifier(&v.source_ref)
                    || !identifier(&v.source_version)
            })
        {
            return Err(Error::new("fact_packet_not_allowed", 4));
        }
        let l = &self.limits;
        if l.attempts != 1
            || !(30..=1800).contains(&l.duration_seconds)
            || l.hold_seconds == 0
            || l.hold_seconds > l.duration_seconds
            || l.handoff_wait_seconds == 0
            || l.handoff_wait_seconds > 60
            || l.budget_cents == 0
            || l.budget_cents > 1000
            || l.rate_cents_per_minute == 0
            || self.estimate_cents() > u64::from(l.budget_cents)
        {
            return Err(Error::new("invalid_or_underfunded_limits", 4));
        }
        Ok(())
    }
    pub fn estimate_cents(&self) -> u64 {
        // Reserve rounded minutes plus one minute for setup/stop delay.
        (u64::from(self.limits.duration_seconds).div_ceil(60) + 1)
            * u64::from(self.limits.rate_cents_per_minute)
    }
    pub fn digest(&self) -> Result<String> {
        // v1: UTF-8 serde JSON of this typed struct in declaration order, BTreeMap fact keys,
        // integers only, ordered lists. Unknown fields rejected; no Unicode normalization.
        Ok(format!("sha256:{}", hash(&serde_json::to_vec(self)?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Submitting,
    StartUnknown,
    Active,
    Ending,
    Ended,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Ringing,
    Ivr,
    Hold,
    Talking,
    HandoffRequested,
    HumanConnected,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Pending,
    NeedsReview,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    pub schema_version: u32,
    pub operation_id: String,
    pub work_item: WorkItem,
    pub result_version: u32,
    pub status: ResultStatus,
    pub outcome: String,
    pub evidence_refs: Vec<String>,
    pub human_result: String,
    pub next_action: String,
    pub actual_cost_cents: Option<u32>,
    pub estimated_cost_cents: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reported_answers: Vec<crate::observations::AnswerEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub owner: String,
    pub approval_id: String,
    pub digest: String,
    pub provider_key: String,
    pub call_id: Option<String>,
    pub lifecycle: Lifecycle,
    pub phase: Option<Phase>,
    pub created_at: i64,
    pub submitted_at: Option<i64>,
    pub last_observed_at: i64,
    pub deadline: i64,
    pub phase_since: i64,
    pub attempt_consumed: bool,
    pub stop_reason: Option<String>,
    pub ai_stopped: bool,
    pub all_legs_ended: bool,
    #[serde(default)]
    pub uncertain_legs: bool,
    pub analysis_seen: bool,
    pub menu_repeats: u8,
    pub result: CallResult,
    pub intent: Option<Intent>,
}
impl Operation {
    pub fn locked(&self) -> bool {
        !self.all_legs_ended || self.uncertain_legs
    }
    pub fn observe(&mut self, e: &Event) -> Result<()> {
        if e.operation_id != self.id
            || e.call_id.is_empty()
            || self.call_id.as_ref().is_some_and(|c| c != &e.call_id)
        {
            return Err(Error::new("event_mapping_conflict", 4));
        }
        self.call_id = Some(e.call_id.clone());
        let previous_observation = self.last_observed_at;
        self.last_observed_at = self.last_observed_at.max(e.observed_at);
        match e.kind {
            EventKind::Started if self.lifecycle == Lifecycle::Failed => {
                self.all_legs_ended = false;
                self.lifecycle = Lifecycle::Ending;
                self.stop_reason = Some("contradictory_provider_evidence".into());
            }
            EventKind::Started if !self.all_legs_ended && self.lifecycle != Lifecycle::Ending => {
                self.lifecycle = Lifecycle::Active;
            }
            EventKind::Ended => {
                // The MVP creates no transfer legs. An unexpected leg retains the lock.
                if e.all_legs_ended && !self.uncertain_legs {
                    self.all_legs_ended = true;
                    self.lifecycle = Lifecycle::Ended;
                    self.phase = None;
                    self.ai_stopped = true;
                } else {
                    self.all_legs_ended = false;
                    self.uncertain_legs = true;
                    self.lifecycle = Lifecycle::Ending;
                    if self.stop_reason.as_deref() != Some("conflicting_provider_event") {
                        self.stop_reason = Some("uncontrolled_leg".into());
                    }
                }
            }
            EventKind::Analyzed => {
                self.analysis_seen = true;
            }
            EventKind::Takeover => {
                self.ai_stopped = true;
                if !self.all_legs_ended {
                    self.phase = Some(Phase::HumanConnected);
                }
                self.result.human_result = "unobserved".into();
                self.stop_reason.get_or_insert("unverified_takeover".into());
            }
            EventKind::Phase
                if self.locked() && !self.ai_stopped && e.observed_at >= previous_observation =>
            {
                if self.phase != e.phase {
                    self.phase_since = e.observed_at;
                }
                self.phase = e.phase;
                if e.phase == Some(Phase::Ivr) {
                    self.menu_repeats = self.menu_repeats.saturating_add(1);
                    if self.menu_repeats >= 3 {
                        self.stop_reason.get_or_insert("blocked_ivr".into());
                    }
                }
            }
            _ => {}
        }
        if e.kind == EventKind::Analyzed {
            if let Some(cost) = e.actual_cost_cents {
                self.result.actual_cost_cents =
                    Some(self.result.actual_cost_cents.unwrap_or(0).max(cost));
            }
        }
        if !self.result.evidence_refs.contains(&e.key) {
            self.result.evidence_refs.push(e.key.clone());
        }
        if self.all_legs_ended && self.analysis_seen {
            self.result.status = ResultStatus::NeedsReview;
            self.result.outcome = self.stop_reason.clone().unwrap_or_else(|| {
                if self.result.reported_answers.is_empty() {
                    "unknown".into()
                } else {
                    "unverified_reported_answer".into()
                }
            });
            self.result.next_action = "Review source evidence in the canonical workflow; use a separate direct call for verification".into();
        }
        if matches!(
            self.stop_reason.as_deref(),
            Some(
                "uncontrolled_leg"
                    | "contradictory_provider_evidence"
                    | "conflicting_provider_event"
            )
        ) {
            self.result.status = ResultStatus::NeedsReview;
            self.result.outcome = self.stop_reason.clone().unwrap_or("unknown".into());
            self.result.next_action="Resolve provider safety incident before any further call; human outcome remains unobserved".into();
        }
        // Never infer business completion from call_successful, termination, or transfer.
        self.result.result_version += 1;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Started,
    Ended,
    Analyzed,
    Phase,
    Takeover,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub key: String,
    pub operation_id: String,
    pub call_id: String,
    pub observed_at: i64,
    pub kind: EventKind,
    pub phase: Option<Phase>,
    pub all_legs_ended: bool,
    pub actual_cost_cents: Option<u32>,
}
