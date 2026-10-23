use crate::{
    contract::*,
    provider::{CreateOutcome, Provider},
    store::{self, Store},
    Error, Result,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Coordinator,
}
#[derive(Debug, Clone)]
pub struct Principal {
    pub owner: String,
    pub role: Role,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub owner: String,
    pub issuer: String,
    pub digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub consumed: bool,
    pub intent: Option<Intent>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Writeback {
    pub operation_id: String,
    pub result_version: u32,
    pub work_item: WorkItem,
    pub result: CallResult,
}
pub enum WritebackAck {
    Applied,
    AlreadyApplied,
    Conflict,
}
pub trait CanonicalWorkflow {
    fn publish(&mut self, message: &Writeback) -> Result<WritebackAck>;
}
pub struct Controller {
    store: Store,
}

fn approval(db: &Connection, id: &str) -> Result<Approval> {
    let data: Option<String> = db
        .query_row("SELECT data FROM approvals WHERE id=?1", [id], |r| r.get(0))
        .optional()?;
    serde_json::from_str(&data.ok_or(Error::new("approval_not_found", 3))?).map_err(Into::into)
}
fn save_approval(db: &Connection, a: &Approval) -> Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO approvals VALUES(?1,?2)",
        params![a.id, serde_json::to_string(a)?],
    )?;
    Ok(())
}
fn own(p: &Principal, owner: &str) -> Result<()> {
    if p.owner != owner {
        return Err(Error::new("wrong_owner", 4));
    }
    Ok(())
}
fn gate(db: &Connection, i: &Intent, now: i64) -> Result<()> {
    let value: Option<(String, i64, bool)> = db
        .query_row(
            "SELECT version,expires,allowed FROM gates WHERE reference=?1",
            [&i.policy_gate_ref],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if !value.is_some_and(|(v, e, a)| v == i.work_item.version && e > now && a) {
        return Err(Error::new("upstream_gate_stale_or_denied", 4));
    }
    Ok(())
}
fn directory(i: &Intent) -> Result<()> {
    // This is an explicitly synthetic trust directory, never an official production contact.
    if i.work_item.system != "return_protection"
        || i.destination.source_ref != "official_demo_v1"
        || i.destination.source_version != "v1"
        || i.destination.e164 != "+12025550100"
        || i.agent_id != "agent_demo"
        || i.agent_version != 1
        || i.limits.rate_ref != "rate_demo_v1"
        || i.limits.rate_cents_per_minute != 10
        || i.handoff.endpoint_ref != "owner_control"
        || i.handoff.recipient_ref != "owner"
    {
        return Err(Error::new("unverified_directory_or_configuration", 4));
    }
    Ok(())
}
fn publish_result(db: &Connection, op: &Operation) -> Result<()> {
    if !op.all_legs_ended && op.result.status != ResultStatus::NeedsReview {
        return Ok(());
    }
    let m = Writeback {
        operation_id: op.id.clone(),
        result_version: op.result.result_version,
        work_item: op.result.work_item.clone(),
        result: op.result.clone(),
    };
    db.execute(
        "INSERT OR IGNORE INTO outbox(operation_id,version,data) VALUES(?1,?2,?3)",
        params![m.operation_id, m.result_version, serde_json::to_string(&m)?],
    )?;
    Ok(())
}
impl Controller {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: Store::open(path)?,
        })
    }
    pub fn approve(&mut self, p: &Principal, i: &Intent, now: i64) -> Result<Approval> {
        if p.role != Role::User {
            return Err(Error::new("authenticated_user_required", 3));
        }
        i.validate(now)?;
        directory(i)?;
        gate(&self.store.db, i, now)?;
        if !identifier(&p.owner) {
            return Err(Error::new("invalid_owner", 4));
        }
        let digest = i.digest()?;
        let id = format!(
            "approval_{}",
            hash(format!("{}\0{}\0{}", p.owner, digest, now).as_bytes())
        );
        let a = Approval {
            id,
            owner: p.owner.clone(),
            issuer: p.owner.clone(),
            digest,
            issued_at: now,
            expires_at: i.not_after,
            revoked: false,
            consumed: false,
            intent: Some(i.clone()),
        };
        // Reissuing the same approval must not reset consumed/revoked authority.
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM approvals WHERE id=?1)",
            [&a.id],
            |r| r.get(0),
        )?;
        if exists {
            return approval(&tx, &a.id);
        }
        save_approval(&tx, &a)?;
        tx.commit()?;
        Ok(a)
    }
    pub fn start(
        &mut self,
        p: &Principal,
        i: &Intent,
        approval_id: &str,
        key: &str,
        now: i64,
    ) -> Result<Operation> {
        if !identifier(key) || !identifier(&p.owner) {
            return Err(Error::new("invalid_idempotency_key", 2));
        }
        let digest = i.digest()?;
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT id,digest FROM operations WHERE owner=?1 AND idem=?2",
                params![p.owner, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, d)) = old {
            if d != digest {
                return Err(Error::new("idempotency_conflict", 4));
            }
            return store::operation(&tx, &id);
        }
        i.validate(now)?;
        directory(i)?;
        gate(&tx, i, now)?;
        let enabled: bool = tx.query_row(
            "SELECT value FROM settings WHERE key='starts_enabled'",
            [],
            |r| r.get(0),
        )?;
        let incident: bool = tx.query_row(
            "SELECT value FROM settings WHERE key='safety_incident'",
            [],
            |r| r.get(0),
        )?;
        if !enabled || incident {
            return Err(Error::new("starts_disabled", 4));
        }
        let mut a = approval(&tx, approval_id)?;
        own(p, &a.owner)?;
        if a.revoked || a.consumed || now >= a.expires_at || now < a.issued_at || a.digest != digest
        {
            return Err(Error::new("approval_expired_revoked_used_or_mismatched", 3));
        }
        let locked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE owner=?1 AND locked=1)",
            [&p.owner],
            |r| r.get(0),
        )?;
        if locked {
            return Err(Error::new("active_or_uncertain_call_exists", 4));
        }
        let reserved: u64 = tx.query_row(
            "SELECT COALESCE(SUM(reservation),0) FROM operations WHERE owner=?1 AND day=?2",
            params![p.owner, now.div_euclid(86400)],
            |r| r.get(0),
        )?;
        if reserved + u64::from(i.limits.budget_cents) > 2500 {
            return Err(Error::new("daily_reservation_limit", 4));
        }
        let id = format!("op_{}", hash(format!("{}\0{}", p.owner, key).as_bytes()));
        let op = Operation {
            id: id.clone(),
            owner: p.owner.clone(),
            approval_id: a.id.clone(),
            digest: digest.clone(),
            provider_key: id.clone(),
            call_id: None,
            lifecycle: Lifecycle::Submitting,
            phase: Some(Phase::Ringing),
            created_at: now,
            submitted_at: None,
            last_observed_at: now,
            deadline: now.saturating_add(i64::from(i.limits.duration_seconds)),
            phase_since: now,
            attempt_consumed: true,
            stop_reason: None,
            ai_stopped: false,
            all_legs_ended: false,
            uncertain_legs: false,
            analysis_seen: false,
            menu_repeats: 0,
            result: CallResult {
                schema_version: 1,
                operation_id: id.clone(),
                work_item: i.work_item.clone(),
                result_version: 0,
                status: ResultStatus::Pending,
                outcome: "unknown".into(),
                evidence_refs: vec![],
                human_result: "unobserved".into(),
                next_action: "Wait for verified call observations".into(),
                actual_cost_cents: None,
                estimated_cost_cents: i.estimate_cents(),
            },
            intent: Some(i.clone()),
        };
        a.consumed = true;
        save_approval(&tx, &a)?;
        tx.execute(
            "INSERT INTO operations VALUES(?1,?2,?3,?4,1,?5,?6,?7)",
            params![
                id,
                p.owner,
                key,
                digest,
                now.div_euclid(86400),
                i.limits.budget_cents,
                serde_json::to_string(&op)?
            ],
        )?;
        tx.commit()?;
        Ok(op)
    }
    pub fn get(&self, p: &Principal, id: &str) -> Result<Operation> {
        let op = store::operation(&self.store.db, id)?;
        own(p, &op.owner)?;
        Ok(op)
    }
    pub fn end(&mut self, p: &Principal, id: &str, reason: &str, now: i64) -> Result<Operation> {
        if ![
            "user_requested",
            "authentication_required",
            "declined_ai",
            "consent_refused",
            "scope_change",
        ]
        .contains(&reason)
        {
            return Err(Error::new("invalid_stop_reason", 2));
        }
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut op = store::operation(&tx, id)?;
        own(p, &op.owner)?;
        if !op.all_legs_ended {
            op.stop_reason.get_or_insert(reason.into());
            op.lifecycle = Lifecycle::Ending;
            op.last_observed_at = op.last_observed_at.max(now);
            store::save_operation(&tx, &op)?;
        }
        tx.commit()?;
        Ok(op)
    }
    pub fn revoke(&mut self, p: &Principal, id: &str, _now: i64) -> Result<()> {
        if p.role != Role::User {
            return Err(Error::new("authenticated_user_required", 3));
        }
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut a = approval(&tx, id)?;
        own(p, &a.owner)?;
        a.revoked = true;
        save_approval(&tx, &a)?;
        let mut stmt = tx.prepare("SELECT data FROM operations WHERE owner=?1 AND locked=1")?;
        let rows = stmt
            .query_map([&p.owner], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for row in rows {
            let mut op: Operation = serde_json::from_str(&row)?;
            if op.approval_id == id {
                op.stop_reason.get_or_insert("approval_revoked".into());
                op.lifecycle = Lifecycle::Ending;
                store::save_operation(&tx, &op)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn set_gate(
        &mut self,
        reference: &str,
        version: &str,
        expires_at: i64,
        allowed: bool,
    ) -> Result<()> {
        self.store.db.execute(
            "INSERT OR REPLACE INTO gates VALUES(?1,?2,?3,?4)",
            params![reference, version, expires_at, allowed],
        )?;
        Ok(())
    }
    pub fn set_starts_enabled(&mut self, enabled: bool) -> Result<()> {
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let incident: bool = tx.query_row(
            "SELECT value FROM settings WHERE key='safety_incident'",
            [],
            |r| r.get(0),
        )?;
        if enabled && incident {
            return Err(Error::new("safety_incident_requires_resolution", 4));
        }
        tx.execute(
            "UPDATE settings SET value=?1 WHERE key='starts_enabled'",
            [enabled],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Trust boundary: only authenticated provider adapters may call ingest.
    /// Durable inbox acknowledgement does not imply processing or business success.
    pub fn ingest(&mut self, e: Event) -> Result<()> {
        if !identifier(&e.operation_id)
            || !identifier(&e.call_id)
            || !identifier(&e.key)
            || e.observed_at < 0
        {
            return Err(Error::new("invalid_event_envelope", 2));
        }
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut op = store::operation(&tx, &e.operation_id)?;
        if op.submitted_at.is_none() || op.call_id.as_ref().is_some_and(|id| id != &e.call_id) {
            return Err(Error::new("event_mapping_conflict", 4));
        }
        let data = serde_json::to_string(&e)?;
        let previous: Option<String> = tx
            .query_row("SELECT data FROM events WHERE key=?1", [&e.key], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(old) = previous {
            let old: Event = serde_json::from_str(&old)?;
            if old.operation_id != e.operation_id || old.call_id != e.call_id || old.kind != e.kind
            {
                return Err(Error::new("event_identity_conflict", 4));
            }
            if serde_json::to_string(&old)? != data {
                // A changed payload under a stable provider identity is an incident,
                // not a duplicate. Commit the quarantine even though the request fails.
                let conflict_key = format!("conflict_{}", hash(data.as_bytes()));
                let already: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE key=?1)",
                    [&conflict_key],
                    |r| r.get(0),
                )?;
                if !already {
                    op.call_id = Some(e.call_id.clone());
                    op.all_legs_ended = false;
                    op.lifecycle = Lifecycle::Ending;
                    op.stop_reason = Some("conflicting_provider_event".into());
                    op.uncertain_legs = true;
                    op.result.status = ResultStatus::NeedsReview;
                    op.result.outcome = "conflicting_provider_event".into();
                    op.result.next_action =
                        "Resolve contradictory provider evidence; do not start another call".into();
                    op.result.result_version += 1;
                    op.result.evidence_refs.push(conflict_key.clone());
                    if let Some(cost) = e.actual_cost_cents {
                        op.result.actual_cost_cents =
                            Some(op.result.actual_cost_cents.unwrap_or(0).max(cost));
                        tx.execute(
                            "UPDATE operations SET reservation=MAX(reservation,?2) WHERE id=?1",
                            params![op.id, cost],
                        )?;
                    }
                    store::save_operation(&tx, &op)?;
                    publish_result(&tx, &op)?;
                    tx.execute("UPDATE settings SET value=0 WHERE key='starts_enabled'", [])?;
                    tx.execute(
                        "UPDATE settings SET value=1 WHERE key='safety_incident'",
                        [],
                    )?;
                    tx.execute(
                        "INSERT INTO events(key,operation_id,data,processed) VALUES(?1,?2,?3,1)",
                        params![conflict_key, e.operation_id, data],
                    )?;
                }
                tx.commit()?;
                return Err(Error::new("event_payload_conflict", 4));
            }
            return Ok(());
        }
        op.call_id = Some(e.call_id.clone());
        store::save_operation(&tx, &op)?;
        tx.execute(
            "INSERT INTO events(key,operation_id,data) VALUES(?1,?2,?3)",
            params![e.key, e.operation_id, data],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn process_events(&mut self) -> Result<()> {
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stmt =
            tx.prepare("SELECT key,data FROM events WHERE processed=0 ORDER BY rowid")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for (key, data) in rows {
            let e: Event = serde_json::from_str(&data)?;
            let mut op = store::operation(&tx, &e.operation_id)?;
            op.observe(&e)?;
            if let Some(cost) = op.result.actual_cost_cents {
                tx.execute(
                    "UPDATE operations SET reservation=MAX(reservation,?2) WHERE id=?1",
                    params![op.id, cost],
                )?;
                if op.locked()
                    && op
                        .intent
                        .as_ref()
                        .is_some_and(|i| cost >= i.limits.budget_cents)
                {
                    op.stop_reason.get_or_insert("budget_stop".into());
                    op.lifecycle = Lifecycle::Ending;
                }
            }
            if matches!(
                op.stop_reason.as_deref(),
                Some(
                    "uncontrolled_leg"
                        | "contradictory_provider_evidence"
                        | "conflicting_provider_event"
                )
            ) {
                tx.execute("UPDATE settings SET value=0 WHERE key='starts_enabled'", [])?;
                tx.execute(
                    "UPDATE settings SET value=1 WHERE key='safety_incident'",
                    [],
                )?;
            }
            publish_result(&tx, &op)?;
            store::save_operation(&tx, &op)?;
            tx.execute("UPDATE events SET processed=1 WHERE key=?1", [key])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn record_observation_rejection(&mut self, id: &str, code: &str, now: i64) -> Result<()> {
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let key = format!("incident_{}", hash(format!("{id}\0{code}").as_bytes()));
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO incidents VALUES(?1,?2,?3,?4)",
            params![key, id, code, now],
        )?;
        if inserted != 0 {
            let mut op = store::operation(&tx, id)?;
            if op.locked() {
                op.stop_reason
                    .get_or_insert("provider_observation_rejected".into());
                op.lifecycle = Lifecycle::Ending;
            }
            op.result.status = ResultStatus::NeedsReview;
            op.result.outcome = "provider_observation_rejected".into();
            op.result.next_action = format!(
                "Resolve rejected provider observation ({code}) before another call; preserve the existing call identity"
            );
            op.result.result_version += 1;
            op.result.evidence_refs.push(key);
            store::save_operation(&tx, &op)?;
            publish_result(&tx, &op)?;
        }
        tx.execute("UPDATE settings SET value=0 WHERE key='starts_enabled'", [])?;
        tx.execute(
            "UPDATE settings SET value=1 WHERE key='safety_incident'",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn tick(&mut self, provider: &mut dyn Provider, now: i64) -> Result<()> {
        self.process_events()?;
        let mut observation_rejection = None;
        let mut stmt = self.store.db.prepare("SELECT id FROM operations")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for id in ids {
            // Persist the first-send claim BEFORE crossing the provider boundary.
            let tx = self
                .store
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut op = store::operation(&tx, &id)?;
            let a = approval(&tx, &op.approval_id)?;
            let mut dispatch = false;
            if op.locked() {
                let incident: bool = tx.query_row(
                    "SELECT value FROM settings WHERE key='safety_incident'",
                    [],
                    |r| r.get(0),
                )?;
                if incident {
                    op.stop_reason
                        .get_or_insert("provider_safety_incident".into());
                }
                if op.stop_reason.is_none() {
                    if now >= op.deadline.saturating_sub(5) {
                        op.stop_reason = Some("duration_stop".into());
                    }
                    if let Some(i) = &op.intent {
                        if op.phase == Some(Phase::Hold)
                            && now.saturating_sub(op.phase_since)
                                >= i64::from(i.limits.hold_seconds)
                        {
                            op.stop_reason = Some("hold_stop".into());
                        }
                        if op.phase == Some(Phase::HandoffRequested)
                            && now.saturating_sub(op.phase_since)
                                >= i64::from(i.limits.handoff_wait_seconds)
                        {
                            op.stop_reason = Some("handoff_timeout".into());
                        }
                    }
                }
                if a.revoked {
                    op.stop_reason.get_or_insert("approval_revoked".into());
                }
                if op.submitted_at.is_none() {
                    let usable = op.intent.as_ref().is_some_and(|i| {
                        i.validate(now).is_ok()
                            && gate(&tx, i, now).is_ok()
                            && now < a.expires_at
                            && !a.revoked
                    });
                    let enabled: bool = tx.query_row(
                        "SELECT value FROM settings WHERE key='starts_enabled'",
                        [],
                        |r| r.get(0),
                    )?;
                    if !usable || !enabled || op.stop_reason.is_some() {
                        op.lifecycle = Lifecycle::Failed;
                        op.all_legs_ended = true;
                        op.ai_stopped = true;
                        op.result.status = ResultStatus::NeedsReview;
                        op.result.outcome = "blocked_before_dispatch".into();
                        op.result.result_version += 1;
                        publish_result(&tx, &op)?;
                    } else {
                        op.submitted_at = Some(now);
                        // A crash after this commit is ambiguous even if the send had not begun.
                        op.lifecycle = Lifecycle::StartUnknown;
                        dispatch = true;
                    }
                } else if op.stop_reason.is_some() {
                    op.lifecycle = Lifecycle::Ending;
                }
            }
            store::save_operation(&tx, &op)?;
            tx.commit()?;
            if dispatch {
                let outcome = provider.create(&op, now);
                let tx = self
                    .store
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let mut current = store::operation(&tx, &id)?;
                match outcome {
                    CreateOutcome::Accepted(call_id) => {
                        if !identifier(&call_id) {
                            return Err(Error::new("invalid_provider_receipt", 6));
                        }
                        if current.call_id.as_ref().is_some_and(|c| c != &call_id) {
                            return Err(Error::new("provider_receipt_conflict", 6));
                        }
                        current.call_id = Some(call_id);
                        if !current.all_legs_ended {
                            current.lifecycle = if current.stop_reason.is_some() {
                                Lifecycle::Ending
                            } else {
                                Lifecycle::Active
                            };
                        }
                    }
                    CreateOutcome::Unknown => {} // The attempt remains consumed. Never create again.
                    CreateOutcome::Rejected => {
                        if current.call_id.is_none() {
                            current.lifecycle = Lifecycle::Failed;
                            current.all_legs_ended = true;
                            current.ai_stopped = true;
                            current.result.status = ResultStatus::NeedsReview;
                            current.result.outcome = "provider_error".into();
                            current.result.result_version += 1;
                            publish_result(&tx, &current)?;
                        }
                    }
                }
                store::save_operation(&tx, &current)?;
                tx.commit()?;
            }
            let op = store::operation(&self.store.db, &id)?;
            if op.submitted_at.is_some() && (!op.all_legs_ended || !op.analysis_seen) {
                // Safe reads only. Empty or failed lookup never releases a reservation.
                if let Ok(events) = provider.lookup(&op, now) {
                    for e in events {
                        let observation = if e.operation_id != id {
                            Err(Error::new("event_mapping_conflict", 4))
                        } else {
                            self.ingest(e)
                        };
                        if let Err(error) = observation {
                            match error.code {
                                // Already durably quarantined; replay cannot starve stops.
                                "event_payload_conflict" => {}
                                "invalid_event_envelope"
                                | "event_mapping_conflict"
                                | "event_identity_conflict" => {
                                    // Reject only the observation. Persist a minimal diagnostic
                                    // against the polled operation, then service every safety stop.
                                    self.record_observation_rejection(&id, error.code, now)?;
                                    observation_rejection.get_or_insert(error);
                                }
                                // Corrupt storage and infrastructure errors are not observations.
                                _ => return Err(error),
                            }
                        }
                    }
                    self.process_events()?;
                }
                let latest = store::operation(&self.store.db, &id)?;
                if latest.locked() && latest.stop_reason.is_some() && latest.call_id.is_some() {
                    let _ = provider.stop(&latest, now); // A stop receipt is not termination evidence.
                }
            }
            let tx = self
                .store
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut op = store::operation(&tx, &id)?;
            if (op.all_legs_ended && (op.analysis_seen || op.lifecycle == Lifecycle::Failed))
                || now.saturating_sub(op.created_at) >= 86400
            {
                op.intent = None;
                store::save_operation(&tx, &op)?;
                let mut a = approval(&tx, &op.approval_id)?;
                a.intent = None;
                save_approval(&tx, &a)?;
            }
            tx.commit()?;
        }
        // Unused/revoked approvals also contain working facts and need expiry.
        let tx = self
            .store
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stmt = tx.prepare("SELECT data FROM approvals")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for row in rows {
            let mut a: Approval = serde_json::from_str(&row)?;
            if a.revoked || now >= a.expires_at || now.saturating_sub(a.issued_at) >= 86400 {
                a.intent = None;
                save_approval(&tx, &a)?;
            }
        }
        tx.commit()?;
        match observation_rejection {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub fn pending_outbox(&self) -> Result<Vec<Writeback>> {
        let mut stmt = self
            .store
            .db
            .prepare("SELECT data FROM outbox WHERE delivered=0 ORDER BY operation_id,version")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .collect()
    }
    pub fn flush_outbox(&mut self, sink: &mut dyn CanonicalWorkflow) -> Result<()> {
        for m in self.pending_outbox()? {
            match sink.publish(&m)? {
                WritebackAck::Applied | WritebackAck::AlreadyApplied => {
                    self.store.db.execute(
                        "UPDATE outbox SET delivered=1 WHERE operation_id=?1 AND version=?2",
                        params![m.operation_id, m.result_version],
                    )?;
                }
                WritebackAck::Conflict => {} // Canonical workflow owns resolution; never overwrite.
            }
        }
        Ok(())
    }
}
