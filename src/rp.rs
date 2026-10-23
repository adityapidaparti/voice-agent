//! Adapter for an explicitly supplied existing canonical RP SQLite database.
//! No schema creation, insurer-state mutation, credential discovery or remote sync.
use crate::contract::{hash, identifier, CallResult, ResultStatus, WorkItem};
use crate::controller::{CanonicalWorkflow, Writeback, WritebackAck};
use crate::workflow::{GateDecision, GateRequest, GateStage, WorkflowAuthority};
use crate::{Error, Result};
use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::America::New_York;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

const RESERVED: &str = "voice_reserved";
const DISPATCHED: &str = "voice_dispatch_authorized";
const RESULT: &str = "voice_result_recorded";
const MAX_JSON: usize = 256 * 1024;
const TERMINAL: &[&str] = &[
    "resolved",
    "approved",
    "paid",
    "denied",
    "superseded",
    "ignored",
    "not_eligible",
    "discarded",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpSnapshot {
    pub work_item: WorkItem,
    pub policy_gate_ref: String,
    pub case_key: String,
    pub subject_type: String,
    pub subject_id: String,
}

pub struct RpWorkflow {
    db: Connection,
}

#[derive(Debug, Clone)]
struct Case {
    subject_type: String,
    subject_id: String,
    case_key: String,
    item_id: Option<String>,
    claim_id: Option<String>,
    inactive: bool,
    records: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    schema_version: u32,
    reservation_id: String,
    owner: String,
    operation_id: String,
    digest: String,
    purpose_digest: String,
    work_item: WorkItem,
    policy_gate_ref: String,
    case_key: String,
    subject_type: String,
    subject_id: String,
    item_id: Option<String>,
    claim_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggedResult {
    schema_version: u32,
    input_digest: String,
    call_ended: bool,
    result: CallResult,
}

fn failure(code: &'static str) -> Error {
    Error::new(code, 4)
}
fn parse_json(bytes: &str) -> Result<Value> {
    if bytes.len() > MAX_JSON {
        return Err(failure("rp_record_too_large"));
    }
    let value: Value = serde_json::from_str(bytes).map_err(|_| failure("rp_record_invalid"))?;
    if !value.is_object() {
        return Err(failure("rp_record_invalid"));
    }
    Ok(value)
}
fn existing(path: &Path, read_only: bool) -> Result<Connection> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| failure("rp_database_unavailable"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(failure("rp_database_must_exist"));
    }
    let mode = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let db = Connection::open_with_flags(path, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    db.pragma_update(None, "trusted_schema", "OFF")?;
    // Prepared reads validate the supported contract; never create or migrate tables.
    for sql in [
        "SELECT id,status,automation_status,next_action,next_action_reason,updated_at,notion_sync_status FROM rp_items LIMIT 0",
        "SELECT id,item_id,resolved,status,automation_status,next_action,next_action_reason,updated_at,notion_sync_status FROM rp_claims LIMIT 0",
        "SELECT case_key,subject_type,subject_id,details_json FROM rp_work_state LIMIT 0",
        "SELECT work_date,timezone FROM rp_work_days LIMIT 0",
        "SELECT work_date,case_key,ordinal,subject_type,subject_id FROM rp_daily_selections LIMIT 0",
        "SELECT id,claim_id,item_id,operation_id,action,summary,details_json FROM rp_activity_log LIMIT 0",
        "SELECT state,subject_type,subject_id,item_id,claim_id FROM rp_operations LIMIT 0",
    ] { db.prepare(sql).map_err(|_| failure("rp_schema_unsupported"))?; }
    Ok(db)
}

/// America/New_York boundaries, including DST, rather than the host timezone or UTC date.
pub fn work_day(now: i64) -> Result<String> {
    let utc = DateTime::<Utc>::from_timestamp(now, 0).ok_or(failure("rp_clock_invalid"))?;
    Ok(utc.with_timezone(&New_York).format("%Y-%m-%d").to_string())
}
fn lease_end(now: i64) -> Result<i64> {
    let date = DateTime::<Utc>::from_timestamp(now, 0)
        .ok_or(failure("rp_clock_invalid"))?
        .with_timezone(&New_York)
        .date_naive()
        .succ_opt()
        .ok_or(failure("rp_clock_invalid"))?;
    let midnight = New_York
        .from_local_datetime(
            &date
                .and_hms_opt(0, 0, 0)
                .ok_or(failure("rp_clock_invalid"))?,
        )
        .single()
        .ok_or(failure("rp_clock_invalid"))?
        .timestamp();
    Ok(now.saturating_add(60).min(midnight))
}
fn reference(value: &str) -> Result<(&str, &str)> {
    let (kind, id) = value
        .split_once(':')
        .ok_or(failure("rp_exact_reference_required"))?;
    if !matches!(kind, "item" | "claim") || !identifier(id) {
        return Err(failure("rp_exact_reference_required"));
    }
    Ok((kind, id))
}
fn item_record(db: &Connection, id: &str) -> Result<Value> {
    let value = db.query_row(
        "SELECT id,status,automation_status,next_action,next_action_reason,updated_at FROM rp_items WHERE id=?1", [id], |r| {
            Ok(json!({"id":r.get::<_,String>(0)?,"status":r.get::<_,String>(1)?,"automation_status":r.get::<_,String>(2)?,
                "next_action":r.get::<_,Option<String>>(3)?,"next_action_reason":r.get::<_,Option<String>>(4)?,
                "updated_at":r.get::<_,String>(5)?}))
        }).optional()?.ok_or(failure("rp_identity_missing"))?;
    Ok(value)
}
fn claim_record(db: &Connection, id: &str) -> Result<Value> {
    let value = db.query_row(
        "SELECT id,item_id,resolved,status,automation_status,next_action,next_action_reason,updated_at FROM rp_claims WHERE id=?1", [id], |r| {
            Ok(json!({"id":r.get::<_,String>(0)?,"item_id":r.get::<_,Option<String>>(1)?,
                "resolved":r.get::<_,bool>(2)?,"status":r.get::<_,String>(3)?,"automation_status":r.get::<_,String>(4)?,
                "next_action":r.get::<_,Option<String>>(5)?,"next_action_reason":r.get::<_,Option<String>>(6)?,
                "updated_at":r.get::<_,String>(7)?}))
        }).optional()?.ok_or(failure("rp_identity_missing"))?;
    Ok(value)
}
fn inactive(record: &Value) -> bool {
    record["resolved"] == true
        || record["status"]
            .as_str()
            .is_some_and(|s| TERMINAL.contains(&s))
}
fn resolve(db: &Connection, input: &str) -> Result<Case> {
    let (kind, id) = reference(input)?;
    let mut claim = if kind == "claim" {
        Some(claim_record(db, id)?)
    } else {
        None
    };
    let item_id = if kind == "item" {
        Some(id.to_string())
    } else {
        claim
            .as_ref()
            .and_then(|c| c["item_id"].as_str().map(str::to_owned))
    };
    let item = item_id
        .as_ref()
        .map(|item_id| item_record(db, item_id))
        .transpose()?;
    if let Some(item_id) = &item_id {
        let mut query = db.prepare("SELECT id FROM rp_claims WHERE item_id=?1 AND resolved=0 AND status NOT IN ('superseded','ignored','discarded') ORDER BY id")?;
        let claims = query
            .query_map([item_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if claims.len() > 1 {
            return Err(failure("rp_ambiguous_identity"));
        }
        if kind == "item" {
            if let Some(id) = claims.first() {
                claim = Some(claim_record(db, id)?);
            }
        }
    }
    let subject_type = if claim.is_some() { "claim" } else { "item" }.to_string();
    let subject_id = claim
        .as_ref()
        .and_then(|c| c["id"].as_str())
        .unwrap_or(id)
        .to_string();
    let case_key = item_id
        .as_ref()
        .map(|id| format!("item:{id}"))
        .unwrap_or_else(|| format!("claim:{subject_id}"));
    let claim_id = claim.as_ref().map(|_| subject_id.clone());
    Ok(Case {
        subject_type,
        subject_id,
        case_key,
        item_id,
        claim_id,
        inactive: item.as_ref().is_some_and(inactive) || claim.as_ref().is_some_and(inactive),
        records: json!({"item":item,"claim":claim}),
    })
}
fn work_state(db: &Connection, case: &Case) -> Result<Value> {
    let row = db
        .query_row(
            "SELECT subject_type,subject_id,details_json FROM rp_work_state WHERE case_key=?1",
            [&case.case_key],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(failure("rp_work_state_required"))?;
    let stored = resolve(db, &format!("{}:{}", row.0, row.1))?;
    if stored.case_key != case.case_key
        || stored.subject_type != case.subject_type
        || stored.subject_id != case.subject_id
    {
        return Err(failure("rp_work_identity_mismatch"));
    }
    parse_json(&row.2)
}
fn core_work(work: &Value) -> Value {
    let mut core = work.clone();
    if let Some(map) = core.as_object_mut() {
        map.remove("voice_results");
        map.remove("voice_state_change");
    }
    core
}
fn version(case: &Case, work: &Value) -> Result<String> {
    Ok(format!(
        "rp_state_{}",
        hash(&serde_json::to_vec(&json!({
            "case_key":case.case_key,"subject_type":case.subject_type,"subject_id":case.subject_id,
            "records":case.records,"work":core_work(work)
        }))?)
    ))
}
fn selected(db: &Connection, case: &Case, day: &str) -> Result<()> {
    let timezone: Option<String> = db
        .query_row(
            "SELECT timezone FROM rp_work_days WHERE work_date=?1",
            [day],
            |r| r.get(0),
        )
        .optional()?;
    if timezone.as_deref() != Some("America/New_York") {
        return Err(failure("rp_daily_allocation_missing_or_wrong_timezone"));
    }
    let mut query=db.prepare("SELECT case_key,ordinal,subject_type,subject_id FROM rp_daily_selections WHERE work_date=?1 ORDER BY ordinal")?;
    let rows = query
        .query_map([day], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.is_empty() || rows.len() > 2 {
        return Err(failure("rp_daily_allocation_invalid"));
    }
    let mut keys = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    for (key, ordinal, kind, id) in &rows {
        let target = resolve(db, &format!("{kind}:{id}"))?;
        if target.case_key != *key
            || !(1..=2).contains(ordinal)
            || !keys.insert(key.clone())
            || !ordinals.insert(*ordinal)
        {
            return Err(failure("rp_daily_allocation_invalid"));
        }
    }
    if !keys.contains(&case.case_key) {
        return Err(failure("rp_case_not_selected_today"));
    }
    Ok(())
}
fn no_uncertain_portal_operation(db: &Connection, case: &Case) -> Result<()> {
    let blocked:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM rp_operations o LEFT JOIN rp_claims c ON c.id=o.claim_id LEFT JOIN rp_claims s ON o.subject_type='claim' AND s.id=o.subject_id WHERE o.state IN ('reserved','external_started','external_confirmed','needs_recovery') AND ((?1 IS NOT NULL AND (o.item_id=?1 OR c.item_id=?1 OR s.item_id=?1 OR (o.subject_type='item' AND o.subject_id=?1))) OR (?2 IS NOT NULL AND (o.claim_id=?2 OR (o.subject_type='claim' AND o.subject_id=?2)))))",
        params![case.item_id,case.claim_id],|r|r.get(0))?;
    if blocked {
        return Err(failure("rp_uncertain_portal_operation"));
    }
    Ok(())
}
fn guarded_snapshot(db: &Connection, input: &str, now: i64) -> Result<(RpSnapshot, Case, Value)> {
    let case = resolve(db, input)?;
    if case.inactive {
        return Err(failure("rp_case_inactive"));
    }
    let work = work_state(db, &case)?;
    if !matches!(work["state"].as_str(), Some("ready" | "working")) {
        return Err(failure("rp_parent_work_blocked"));
    }
    let day = work_day(now)?;
    selected(db, &case, &day)?;
    no_uncertain_portal_operation(db, &case)?;
    let snapshot = RpSnapshot {
        work_item: WorkItem {
            system: "rp".into(),
            reference: format!("{}:{}", case.subject_type, case.subject_id),
            version: version(&case, &work)?,
        },
        policy_gate_ref: format!("rp_{day}_{}", hash(case.case_key.as_bytes())),
        case_key: case.case_key.clone(),
        subject_type: case.subject_type.clone(),
        subject_id: case.subject_id.clone(),
    };
    Ok((snapshot, case, work))
}
/// Read one eligible canonical case without reserving a slot or writing any data.
pub fn snapshot(path: impl AsRef<Path>, input: &str, now: i64) -> Result<RpSnapshot> {
    let mut db = existing(path.as_ref(), true)?;
    let tx = db.transaction()?;
    let (snapshot, _, _) = guarded_snapshot(&tx, input, now)?;
    tx.commit()?;
    Ok(snapshot)
}
impl RpWorkflow {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            db: existing(path.as_ref(), false)?,
        })
    }
}
fn reservation_id(owner: &str, operation: &str) -> String {
    format!(
        "voice_reservation_{}",
        hash(format!("{owner}\0{operation}").as_bytes())
    )
}
fn reservation(db: &Connection, id: &str) -> Result<Option<Reservation>> {
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT action,details_json FROM rp_activity_log WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((action, data)) => {
            if action != RESERVED || data.len() > MAX_JSON {
                return Err(failure("rp_reservation_conflict"));
            }
            serde_json::from_str(&data)
                .map(Some)
                .map_err(|_| failure("rp_reservation_conflict"))
        }
    }
}
fn results(db: &Connection, operation: &str) -> Result<Vec<LoggedResult>> {
    let mut query =
        db.prepare("SELECT details_json FROM rp_activity_log WHERE operation_id=?1 AND action=?2")?;
    let rows = query
        .query_map(params![operation, RESULT], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|data| {
            if data.len() > MAX_JSON {
                return Err(failure("rp_result_record_invalid"));
            }
            serde_json::from_str(&data).map_err(|_| failure("rp_result_record_invalid"))
        })
        .collect()
}
fn active_reservation(db: &Connection, operation: &str) -> Result<bool> {
    let latest = results(db, operation)?
        .into_iter()
        .max_by_key(|r| r.result.result_version);
    Ok(latest.is_none_or(|r| !r.call_ended))
}
fn no_other_reservation(db: &Connection, case: &Case, own: &str) -> Result<()> {
    let mut query=db.prepare("SELECT details_json FROM rp_activity_log WHERE action=?1 AND ((?2 IS NOT NULL AND item_id=?2) OR (?3 IS NOT NULL AND claim_id=?3))")?;
    let rows = query
        .query_map(params![RESERVED, case.item_id, case.claim_id], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for data in rows {
        if data.len() > MAX_JSON {
            return Err(failure("rp_reservation_conflict"));
        }
        let reservation: Reservation =
            serde_json::from_str(&data).map_err(|_| failure("rp_reservation_conflict"))?;
        if reservation.reservation_id != own && active_reservation(db, &reservation.operation_id)? {
            return Err(failure("rp_case_already_reserved"));
        }
    }
    Ok(())
}
fn log(
    db: &Connection,
    id: &str,
    binding: &Reservation,
    action: &str,
    summary: &str,
    data: &str,
) -> Result<()> {
    db.execute("INSERT INTO rp_activity_log(id,claim_id,item_id,operation_id,action,summary,details_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![id,binding.claim_id,binding.item_id,binding.operation_id,action,summary,data])?;
    Ok(())
}
impl WorkflowAuthority for RpWorkflow {
    fn authorize(&mut self, request: &GateRequest, now: i64) -> Result<GateDecision> {
        let hex = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        if request.work_item.system != "rp"
            || !identifier(&request.owner)
            || !identifier(&request.operation_id)
            || !request.digest.strip_prefix("sha256:").is_some_and(hex)
            || !hex(&request.purpose_digest)
        {
            return Err(failure("rp_gate_scope_invalid"));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (snapshot, case, _) = guarded_snapshot(&tx, &request.work_item.reference, now)?;
        if serde_json::to_value(&snapshot.work_item)? != serde_json::to_value(&request.work_item)?
            || snapshot.policy_gate_ref != request.policy_gate_ref
        {
            return Err(failure("rp_snapshot_changed"));
        }
        let id = reservation_id(&request.owner, &request.operation_id);
        if request
            .reservation_id
            .as_ref()
            .is_some_and(|old| old != &id)
        {
            return Err(failure("rp_reservation_conflict"));
        }
        no_other_reservation(&tx, &case, &id)?;
        let binding = Reservation {
            schema_version: 1,
            reservation_id: id.clone(),
            owner: request.owner.clone(),
            operation_id: request.operation_id.clone(),
            digest: request.digest.clone(),
            purpose_digest: request.purpose_digest.clone(),
            work_item: request.work_item.clone(),
            policy_gate_ref: request.policy_gate_ref.clone(),
            case_key: case.case_key.clone(),
            subject_type: case.subject_type,
            subject_id: case.subject_id,
            item_id: case.item_id,
            claim_id: case.claim_id,
        };
        let collision:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM rp_activity_log WHERE operation_id=?1 AND action=?2 AND id<>?3)",params![request.operation_id,RESERVED,id],|r|r.get(0))?;
        if collision {
            return Err(failure("rp_reservation_conflict"));
        }
        let old = reservation(&tx, &id)?;
        if old.as_ref().is_some_and(|old| {
            serde_json::to_value(old).ok() != serde_json::to_value(&binding).ok()
        }) {
            return Err(failure("rp_reservation_conflict"));
        }
        match request.stage {
            GateStage::Preview => {
                if request.reservation_id.is_some() {
                    return Err(failure("rp_gate_scope_invalid"));
                }
            }
            GateStage::Reserve => {
                if old.is_none() {
                    log(
                        &tx,
                        &id,
                        &binding,
                        RESERVED,
                        "Voice operation reserved; no call outcome implied",
                        &serde_json::to_string(&binding)?,
                    )?;
                }
            }
            GateStage::Dispatch | GateStage::Continue => {
                if old.is_none() || request.reservation_id.as_deref() != Some(id.as_str()) {
                    return Err(failure("rp_reservation_required"));
                }
                if !active_reservation(&tx, &request.operation_id)? {
                    return Err(failure("rp_reservation_terminal"));
                }
                let dispatch_id = format!("voice_dispatch_{}", hash(id.as_bytes()));
                let old: Option<(String, String)> = tx
                    .query_row(
                        "SELECT action,details_json FROM rp_activity_log WHERE id=?1",
                        [&dispatch_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let data = serde_json::to_string(&binding)?;
                match old {
                    Some((action, prior)) if action != DISPATCHED || prior != data => {
                        return Err(failure("rp_dispatch_conflict"))
                    }
                    None if request.stage == GateStage::Dispatch => log(
                        &tx,
                        &dispatch_id,
                        &binding,
                        DISPATCHED,
                        "Dispatch authority granted; execution is not yet confirmed",
                        &data,
                    )?,
                    None => return Err(failure("rp_dispatch_required")),
                    _ => {}
                }
            }
        }
        let decision = GateDecision {
            request_digest: request.request_digest()?,
            allowed: true,
            expires_at: lease_end(now)?,
            reservation_id: if request.stage == GateStage::Preview {
                None
            } else {
                Some(id)
            },
        };
        tx.commit()?;
        Ok(decision)
    }
}
fn sanitized(message: &Writeback) -> Result<CallResult> {
    let r = &message.result;
    if r.schema_version != 1
        || r.result_version == 0
        || r.result_version != message.result_version
        || r.operation_id != message.operation_id
        || serde_json::to_value(&r.work_item)? != serde_json::to_value(&message.work_item)?
        || (r.status == ResultStatus::Pending && !message.call_ended)
        || !identifier(&r.outcome)
        || r.evidence_refs.len() > 512
        || r.evidence_refs.iter().any(|r| !identifier(r))
        || r.reported_answers.len() > 16
    {
        return Err(failure("rp_result_scope_invalid"));
    }
    for evidence in &r.reported_answers {
        if !identifier(&evidence.evidence_ref)
            || evidence.reported_at < 0
            || !r.evidence_refs.contains(&evidence.evidence_ref)
        {
            return Err(failure("rp_result_scope_invalid"));
        }
        evidence.answer.validate()?;
    }
    let mut clean = r.clone();
    // End evidence can precede analysis; it is publishable without inventing a business outcome.
    clean.status = ResultStatus::NeedsReview;
    if r.status == ResultStatus::Pending {
        clean.outcome = "unknown".into();
    }
    clean.human_result = "unobserved".into();
    clean.next_action=if message.call_ended {
        "Review the bounded voice evidence in this canonical case; use a separate direct call for authentication. Business completion is not established."
    }else{
        "Resolve this operation's provider state before any new call; do not redial. Use a separate direct call for authentication."
    }.into();
    Ok(clean)
}
impl CanonicalWorkflow for RpWorkflow {
    fn publish(&mut self, message: &Writeback) -> Result<WritebackAck> {
        if !identifier(&message.operation_id) || message.work_item.system != "rp" {
            return Err(failure("rp_result_scope_invalid"));
        }
        let clean = sanitized(message)?;
        let input_digest = hash(&serde_json::to_vec(message)?);
        let event_id = format!(
            "voice_result_{}",
            hash(format!("{}\0{}", message.operation_id, message.result_version).as_bytes())
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT action,details_json FROM rp_activity_log WHERE id=?1",
                [&event_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((action, data)) = old {
            let old: LoggedResult =
                serde_json::from_str(&data).map_err(|_| failure("rp_result_record_invalid"))?;
            return Ok(if action == RESULT && old.input_digest == input_digest {
                WritebackAck::AlreadyApplied
            } else {
                WritebackAck::Conflict
            });
        }
        let mut query =
            tx.prepare("SELECT id FROM rp_activity_log WHERE operation_id=?1 AND action=?2")?;
        let ids = query
            .query_map(params![message.operation_id, RESERVED], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(query);
        if ids.len() != 1 {
            return Err(failure("rp_reservation_required"));
        }
        let binding = reservation(&tx, &ids[0])?.ok_or(failure("rp_reservation_required"))?;
        if serde_json::to_value(&binding.work_item)? != serde_json::to_value(&message.work_item)? {
            return Err(failure("rp_result_scope_invalid"));
        }
        let latest = results(&tx, &message.operation_id)?
            .into_iter()
            .map(|r| r.result.result_version)
            .max()
            .unwrap_or(0);
        // Promotion/relinking changes allocation keys, never the original reservation lineage.
        let current_target = resolve(&tx, &binding.work_item.reference).ok();
        let target_key = current_target
            .as_ref()
            .map(|c| c.case_key.as_str())
            .unwrap_or(&binding.case_key);
        let logged = LoggedResult {
            schema_version: 1,
            input_digest,
            call_ended: message.call_ended,
            result: clean.clone(),
        };
        log(
            &tx,
            &event_id,
            &binding,
            RESULT,
            "Voice evidence recorded; business outcome unverified; Notion sync pending",
            &serde_json::to_string(&logged)?,
        )?;
        if message.result_version > latest {
            // Late evidence remains attachable to a blocked/retired/promoted case. It may
            // never clear a parent blocker or replace a newer parent's sourced update.
            let row:Option<(String,String,String)>=tx.query_row("SELECT subject_type,subject_id,details_json FROM rp_work_state WHERE case_key=?1",[target_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((kind, id, data)) = row {
                let mut work = parse_json(&data)?;
                let current = current_target.as_ref();
                let current_version = current.map(|c| version(c, &work)).transpose()?;
                let original =
                    current_version.as_deref() == Some(binding.work_item.version.as_str());
                let own_change = current_version.is_some()
                    && work["voice_state_change"]["operation_id"] == message.operation_id
                    && current_version.as_deref() == work["voice_state_change"]["version"].as_str();
                let can_change = original || own_change;
                if work.get("voice_results").is_some_and(|v| !v.is_object()) {
                    return Err(failure("rp_voice_reference_conflict"));
                }
                if work.get("voice_results").is_none() {
                    work["voice_results"] = json!({});
                }
                work["voice_results"][&message.operation_id] = json!({"event_id":event_id,"result_version":message.result_version,
                    "call_ended":message.call_ended,"notion_sync_status":"pending","reservation_case_key":binding.case_key});
                if can_change
                    && matches!(
                        work["state"].as_str(),
                        Some("ready" | "working" | "needs_recovery")
                    )
                {
                    work["state"] = json!("needs_recovery");
                    work["next_step"] = json!(clean.next_action);
                    work["source"] = json!(
                        "voice-agent verified operational evidence; business outcome unverified"
                    );
                    work["event_id"] = json!(event_id);
                    if let Some(case) = current {
                        work["voice_state_change"] = json!({"operation_id":message.operation_id,"version":version(case,&work)?});
                    }
                }
                tx.execute("UPDATE rp_work_state SET details_json=?2,updated_at=CURRENT_TIMESTAMP WHERE case_key=?1 AND subject_type=?3 AND subject_id=?4",
                    params![target_key,serde_json::to_string(&work)?,kind,id])?;
            }
        }
        // Local evidence is durable; the parent must sync and verify the exact Notion row.
        if let Some(item) = &binding.item_id {
            tx.execute(
                "UPDATE rp_items SET notion_sync_status='pending' WHERE id=?1",
                [item],
            )?;
        }
        if let Some(claim) = &binding.claim_id {
            tx.execute(
                "UPDATE rp_claims SET notion_sync_status='pending' WHERE id=?1",
                [claim],
            )?;
        }
        if let Some(current) = current_target {
            if let Some(item) = current.item_id {
                tx.execute(
                    "UPDATE rp_items SET notion_sync_status='pending' WHERE id=?1",
                    [item],
                )?;
            }
            if let Some(claim) = current.claim_id {
                tx.execute(
                    "UPDATE rp_claims SET notion_sync_status='pending' WHERE id=?1",
                    [claim],
                )?;
            }
        }
        tx.commit()?;
        Ok(WritebackAck::Applied)
    }
}
