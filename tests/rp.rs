//! Original minimal synthetic schema fixtures; no real RP database or private records are opened.
mod common;
use hegel::prelude::*;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use voice_agent::contract::{hash, CallResult, ResultStatus};
use voice_agent::controller::{CanonicalWorkflow, Writeback, WritebackAck};
use voice_agent::rp::{snapshot, work_day, RpWorkflow};
use voice_agent::workflow::{GateRequest, GateStage, WorkflowAuthority};

const SCHEMA: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE rp_items(id TEXT PRIMARY KEY,status TEXT NOT NULL,automation_status TEXT NOT NULL,next_action TEXT,next_action_reason TEXT,updated_at TEXT NOT NULL,notion_sync_status TEXT NOT NULL);
CREATE TABLE rp_claims(id TEXT PRIMARY KEY,item_id TEXT REFERENCES rp_items(id),resolved INTEGER NOT NULL,status TEXT NOT NULL,automation_status TEXT NOT NULL,next_action TEXT,next_action_reason TEXT,updated_at TEXT NOT NULL,notion_sync_status TEXT NOT NULL);
CREATE TABLE rp_work_state(case_key TEXT PRIMARY KEY,subject_type TEXT NOT NULL,subject_id TEXT NOT NULL,details_json TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE rp_work_days(work_date TEXT PRIMARY KEY,timezone TEXT NOT NULL);
CREATE TABLE rp_daily_selections(work_date TEXT NOT NULL,case_key TEXT NOT NULL,ordinal INTEGER NOT NULL,subject_type TEXT NOT NULL,subject_id TEXT NOT NULL,PRIMARY KEY(work_date,case_key));
CREATE TABLE rp_activity_log(id TEXT PRIMARY KEY,claim_id TEXT REFERENCES rp_claims(id),item_id TEXT REFERENCES rp_items(id),operation_id TEXT,action TEXT NOT NULL,summary TEXT,details_json TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE rp_operations(id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('file_claim','respond_docs')),state TEXT NOT NULL,subject_type TEXT NOT NULL,subject_id TEXT NOT NULL,item_id TEXT,claim_id TEXT);
"#;
fn timestamp(value: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap()
        .timestamp()
}
fn clock() -> i64 {
    timestamp("2026-10-23T12:00:00Z")
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    db: Connection,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute_batch("INSERT INTO rp_items VALUES('item-a','ready','ready','ask_documents',NULL,'version-one','synced'),('item-b','ready','ready','prepare',NULL,'version-one','synced');
            INSERT INTO rp_claims VALUES('claim-a','item-a',0,'docs_requested','ready','ask_documents',NULL,'version-one','synced');
            INSERT INTO rp_work_days VALUES('2026-10-23','America/New_York');
            INSERT INTO rp_daily_selections VALUES('2026-10-23','item:item-a',1,'item','item-a'),('2026-10-23','item:item-b',2,'item','item-b');").unwrap();
        for id in ["item-a", "item-b"] {
            db.execute("INSERT INTO rp_work_state(case_key,subject_type,subject_id,details_json) VALUES(?1,'item',?2,?3)",params![format!("item:{id}"),id,json!({"state":"ready","source":"synthetic-parent","event_id":"initial"}).to_string()]).unwrap();
        }
        Self {
            _directory: directory,
            path,
            db,
        }
    }
    fn request(&self, operation: &str) -> GateRequest {
        self.request_for(operation, "item:item-a")
    }
    fn request_for(&self, operation: &str, reference: &str) -> GateRequest {
        let snap = snapshot(&self.path, reference, clock()).unwrap();
        GateRequest {
            owner: "synthetic-owner".into(),
            operation_id: operation.into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            work_item: snap.work_item,
            policy_gate_ref: snap.policy_gate_ref,
            purpose_digest: hash(b"ask required documents"),
            stage: GateStage::Reserve,
            reservation_id: None,
        }
    }
    fn state(&self) -> Value {
        serde_json::from_str(
            &self
                .db
                .query_row(
                    "SELECT details_json FROM rp_work_state WHERE case_key='item:item-a'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap()
    }
    fn parent_state(&self, state: Value) {
        self.db
            .execute(
                "UPDATE rp_work_state SET details_json=?1 WHERE case_key='item:item-a'",
                [state.to_string()],
            )
            .unwrap();
    }
    fn events(&self, action: &str) -> i64 {
        self.db
            .query_row(
                "SELECT COUNT(*) FROM rp_activity_log WHERE action=?1",
                [action],
                |r| r.get(0),
            )
            .unwrap()
    }
}
fn reserved(f: &Fixture, operation: &str) -> (RpWorkflow, GateRequest) {
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    let mut request = f.request(operation);
    let decision = adapter.authorize(&request, clock()).unwrap();
    request.reservation_id = decision.reservation_id;
    request.stage = GateStage::Dispatch;
    adapter.authorize(&request, clock() + 1).unwrap();
    (adapter, request)
}
fn result(request: &GateRequest, version: u32, ended: bool) -> Writeback {
    Writeback {
        operation_id: request.operation_id.clone(),
        result_version: version,
        work_item: request.work_item.clone(),
        call_ended: ended,
        result: CallResult {
            schema_version: 1,
            operation_id: request.operation_id.clone(),
            work_item: request.work_item.clone(),
            result_version: version,
            status: ResultStatus::NeedsReview,
            outcome: "unknown".into(),
            evidence_refs: vec!["verified-provider-event".into()],
            human_result: "MODEL-FREE-TEXT-MUST-NOT-PERSIST".into(),
            next_action: "MODEL-FREE-TEXT-MUST-NOT-PERSIST".into(),
            actual_cost_cents: Some(20),
            estimated_cost_cents: 30,
            reported_answers: vec![],
        },
    }
}

#[test]
fn opens_only_existing_compatible_databases_and_snapshot_is_read_only() {
    let f = Fixture::new();
    let missing = f.path.with_file_name("missing.sqlite");
    assert!(RpWorkflow::open(&missing).is_err());
    assert!(snapshot(&missing, "item:item-a", clock()).is_err());
    assert!(!missing.exists());
    let empty = f.path.with_file_name("empty.sqlite");
    std::fs::write(&empty, []).unwrap();
    assert!(RpWorkflow::open(&empty).is_err());
    assert_eq!(std::fs::metadata(empty).unwrap().len(), 0);
    let before = std::fs::read(&f.path).unwrap();
    let snap = snapshot(&f.path, "item:item-a", clock()).unwrap();
    assert_eq!(snap.work_item.system, "rp");
    assert_eq!(snap.work_item.reference, "claim:claim-a");
    assert_eq!(snap.case_key, "item:item-a");
    assert_eq!(before, std::fs::read(&f.path).unwrap());
    assert_eq!(f.events("voice_reserved"), 0);
    for bad in [
        "claim-a",
        "claim:",
        "claim:missing",
        "item:missing",
        "number:12345",
    ] {
        assert!(snapshot(&f.path, bad, clock()).is_err());
    }
}

#[test]
fn new_york_days_and_leases_observe_midnight_and_both_dst_transitions() {
    for (utc, day) in [
        ("2026-01-15T04:59:59Z", "2026-01-14"),
        ("2026-01-15T05:00:00Z", "2026-01-15"),
        ("2026-07-15T03:59:59Z", "2026-07-14"),
        ("2026-07-15T04:00:00Z", "2026-07-15"),
        ("2026-03-08T06:59:59Z", "2026-03-08"),
        ("2026-03-08T07:00:00Z", "2026-03-08"),
        ("2026-11-01T05:59:59Z", "2026-11-01"),
        ("2026-11-01T06:00:00Z", "2026-11-01"),
    ] {
        assert_eq!(work_day(timestamp(utc)).unwrap(), day);
    }
    assert!(work_day(i64::MIN).is_err());
    assert!(work_day(i64::MAX).is_err());
    let f = Fixture::new();
    let mut request = f.request("op-midnight");
    request.stage = GateStage::Preview;
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    let before = timestamp("2026-10-24T03:59:40Z");
    let decision = adapter.authorize(&request, before).unwrap();
    assert_eq!(decision.expires_at, timestamp("2026-10-24T04:00:00Z"));
    assert!(
        adapter.authorize(&request, decision.expires_at).is_err(),
        "prior day's slots never carry across NY midnight"
    );
}

/// Known winter/summer offsets give an independent day-boundary oracle over every second of a UTC day.
#[hegel::test]
fn day_boundaries_use_new_york_offset_instead_of_utc_or_host_timezone(tc: TestCase) {
    let winter = tc.draw(gs::booleans());
    let seconds = tc.draw(hegel::one_of!(
        gs::integers::<u32>(),
        gs::sampled_from(&[0_u32, 14399, 14400, 17999, 18000, 86399][..])
    )) % 86400;
    let (base, offset, prior, current) = if winter {
        ("2026-01-15T00:00:00Z", 18000, "2026-01-14", "2026-01-15")
    } else {
        ("2026-07-15T00:00:00Z", 14400, "2026-07-14", "2026-07-15")
    };
    tc.event(if seconds < offset {
        "before local midnight"
    } else {
        "after local midnight"
    });
    assert_eq!(
        work_day(timestamp(base) + i64::from(seconds)).unwrap(),
        if seconds < offset { prior } else { current }
    );
}

#[test]
fn selection_timezone_two_case_cap_and_blocked_slots_are_not_substituted() {
    let f = Fixture::new();
    f.db.execute("UPDATE rp_work_days SET timezone='UTC'", [])
        .unwrap();
    assert!(snapshot(&f.path, "item:item-a", clock()).is_err());
    f.db.execute("UPDATE rp_work_days SET timezone='America/New_York'", [])
        .unwrap();
    f.db.execute("UPDATE rp_items SET status='paid' WHERE id='item-b'", [])
        .unwrap();
    assert!(
        snapshot(&f.path, "item:item-a", clock()).is_ok(),
        "completed other case retains its slot"
    );
    f.db.execute(
        "INSERT INTO rp_items VALUES('item-c','ready','ready',NULL,NULL,'v1','synced')",
        [],
    )
    .unwrap();
    f.db.execute("INSERT INTO rp_work_state(case_key,subject_type,subject_id,details_json) VALUES('item:item-c','item','item-c','{\"state\":\"ready\"}')",[]).unwrap();
    assert_eq!(
        snapshot(&f.path, "item:item-c", clock()).unwrap_err().code,
        "rp_case_not_selected_today"
    );
    f.db.execute(
        "INSERT INTO rp_daily_selections VALUES('2026-10-23','item:item-c',3,'item','item-c')",
        [],
    )
    .unwrap();
    assert_eq!(
        snapshot(&f.path, "item:item-a", clock()).unwrap_err().code,
        "rp_daily_allocation_invalid"
    );
}

#[test]
fn inactive_ambiguous_and_parent_blocked_cases_fail_closed() {
    for state in [
        "waiting_user",
        "waiting_external",
        "blocked_tool",
        "needs_recovery",
        "done",
        "unknown",
    ] {
        let f = Fixture::new();
        f.parent_state(json!({"state":state,"next_step":"preserve this parent instruction"}));
        assert_eq!(
            snapshot(&f.path, "item:item-a", clock()).unwrap_err().code,
            "rp_parent_work_blocked"
        );
    }
    let f = Fixture::new();
    f.db.execute("UPDATE rp_claims SET resolved=1 WHERE id='claim-a'", [])
        .unwrap();
    assert_eq!(
        snapshot(&f.path, "claim:claim-a", clock())
            .unwrap_err()
            .code,
        "rp_case_inactive"
    );
    let f = Fixture::new();
    f.db.execute("INSERT INTO rp_claims VALUES('claim-a2','item-a',0,'draft','ready',NULL,NULL,'v1','synced')",[]).unwrap();
    assert_eq!(
        snapshot(&f.path, "item:item-a", clock()).unwrap_err().code,
        "rp_ambiguous_identity"
    );
    assert_eq!(
        snapshot(&f.path, "claim:claim-a", clock())
            .unwrap_err()
            .code,
        "rp_ambiguous_identity"
    );
}

#[test]
fn every_inflight_portal_state_blocks_voice_and_committed_released_or_expired_does_not() {
    let f = Fixture::new();
    let request = f.request("op-gate");
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    f.db.execute("INSERT INTO rp_operations VALUES('portal-op','respond_docs','reserved','claim','claim-a',NULL,'claim-a')",[]).unwrap();
    for state in [
        "reserved",
        "external_started",
        "external_confirmed",
        "needs_recovery",
    ] {
        f.db.execute("UPDATE rp_operations SET state=?1", [state])
            .unwrap();
        assert_eq!(
            adapter.authorize(&request, clock()).unwrap_err().code,
            "rp_uncertain_portal_operation"
        );
    }
    for state in ["committed", "released", "expired"] {
        f.db.execute("UPDATE rp_operations SET state=?1", [state])
            .unwrap();
        let mut preview = request.clone();
        preview.stage = GateStage::Preview;
        assert!(adapter.authorize(&preview, clock()).is_ok());
    }
    assert_eq!(f.events("voice_reserved"), 0);
    let count: i64 =
        f.db.query_row("SELECT COUNT(*) FROM rp_operations", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn durable_reservation_and_dispatch_replays_bind_scope_and_parent_changes_revoke() {
    let f = Fixture::new();
    let request = f.request("op-one");
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    let first = adapter.authorize(&request, clock()).unwrap();
    let replay = adapter.authorize(&request, clock() + 1).unwrap();
    assert_eq!(first.reservation_id, replay.reservation_id);
    assert_eq!(f.events("voice_reserved"), 1);
    let mut conflict = request.clone();
    conflict.digest = format!("sha256:{}", "b".repeat(64));
    assert!(adapter.authorize(&conflict, clock()).is_err());
    let mut dispatch = request.clone();
    dispatch.stage = GateStage::Dispatch;
    dispatch.reservation_id = first.reservation_id;
    adapter.authorize(&dispatch, clock()).unwrap();
    drop(adapter);
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    adapter.authorize(&dispatch, clock() + 1).unwrap();
    assert_eq!(f.events("voice_dispatch_authorized"), 1);
    let mut continuation = dispatch;
    continuation.stage = GateStage::Continue;
    let mut state = f.state();
    state["voice_results"] = json!({"older-operation":{"result_version":1}});
    f.parent_state(state);
    assert!(
        adapter.authorize(&continuation, clock() + 2).is_ok(),
        "adapter-owned additive references do not invalidate scope"
    );
    let mut state = f.state();
    state["source"] = json!("new parent evidence");
    f.parent_state(state);
    assert_eq!(
        adapter
            .authorize(&continuation, clock() + 3)
            .unwrap_err()
            .code,
        "rp_snapshot_changed"
    );
}

#[test]
fn two_connections_cannot_reserve_the_same_case_concurrently() {
    let f = Fixture::new();
    let one = f.request("op-race-one");
    let mut two = one.clone();
    two.operation_id = "op-race-two".into();
    two.owner = "other-owner".into();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = vec![];
    for request in [one, two] {
        let path = f.path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut a = RpWorkflow::open(path).unwrap();
            barrier.wait();
            a.authorize(&request, clock()).is_ok()
        }));
    }
    let accepted = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 1);
    assert_eq!(f.events("voice_reserved"), 1);
}

#[test]
fn uncertain_result_stays_locked_and_newer_correction_relocks_after_terminal_evidence() {
    let f = Fixture::new();
    let (mut adapter, request) = reserved(&f, "op-one");
    assert!(matches!(
        adapter.publish(&result(&request, 1, false)).unwrap(),
        WritebackAck::Applied
    ));
    f.parent_state(
        json!({"state":"ready","source":"parent reconciled work","event_id":"reset-one"}),
    );
    let mut next = f.request("op-two");
    next.stage = GateStage::Preview;
    assert_eq!(
        adapter.authorize(&next, clock()).unwrap_err().code,
        "rp_case_already_reserved"
    );
    adapter.publish(&result(&request, 5, true)).unwrap();
    assert!(
        adapter.authorize(&next, clock()).is_ok(),
        "verified terminal operational evidence releases the reservation"
    );
    adapter.publish(&result(&request, 6, false)).unwrap();
    assert_eq!(
        adapter.authorize(&next, clock()).unwrap_err().code,
        "rp_case_already_reserved"
    );
    adapter.publish(&result(&request, 4, true)).unwrap();
    assert_eq!(
        adapter.authorize(&next, clock()).unwrap_err().code,
        "rp_case_already_reserved",
        "an older terminal result cannot unlock newer uncertainty"
    );
    assert_eq!(f.state()["voice_results"]["op-one"]["result_version"], 6);
}

#[test]
fn result_versions_are_immutable_and_parent_blockers_survive_late_writeback() {
    let f = Fixture::new();
    let (mut adapter, request) = reserved(&f, "op-one");
    f.parent_state(json!({"state":"waiting_user","next_step":"Parent requires a specific missing fact","source":"parent-message","event_id":"parent-new","already_asked":true}));
    let result = result(&request, 2, true);
    assert!(matches!(
        adapter.publish(&result).unwrap(),
        WritebackAck::Applied
    ));
    let state = f.state();
    assert_eq!(state["state"], "waiting_user");
    assert_eq!(
        state["next_step"],
        "Parent requires a specific missing fact"
    );
    assert_eq!(state["event_id"], "parent-new");
    assert_eq!(state["already_asked"], true);
    assert_eq!(state["voice_results"]["op-one"]["result_version"], 2);
    assert!(matches!(
        adapter.publish(&result).unwrap(),
        WritebackAck::AlreadyApplied
    ));
    let mut conflict = result.clone();
    conflict.result.actual_cost_cents = Some(99);
    assert!(matches!(
        adapter.publish(&conflict).unwrap(),
        WritebackAck::Conflict
    ));
    assert_eq!(f.events("voice_result_recorded"), 1);
    let (status, sync): (String, String) =
        f.db.query_row(
            "SELECT status,notion_sync_status FROM rp_claims WHERE id='claim-a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "docs_requested");
    assert_eq!(sync, "pending");
    let logged: String =
        f.db.query_row(
            "SELECT details_json FROM rp_activity_log WHERE action='voice_result_recorded'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!logged.contains("MODEL-FREE-TEXT"));
    let data: Value = serde_json::from_str(&logged).unwrap();
    assert_eq!(data["result"]["human_result"], "unobserved");
}

#[test]
fn safe_initial_writeback_sets_recovery_and_later_own_correction_updates_only_its_step() {
    let f = Fixture::new();
    let (mut adapter, request) = reserved(&f, "op-one");
    adapter.publish(&result(&request, 1, true)).unwrap();
    let before = f.state();
    assert_eq!(before["state"], "needs_recovery");
    assert!(before["next_step"]
        .as_str()
        .unwrap()
        .contains("Business completion is not established"));
    adapter.publish(&result(&request, 2, false)).unwrap();
    let after = f.state();
    assert_eq!(after["state"], "needs_recovery");
    assert!(after["next_step"]
        .as_str()
        .unwrap()
        .contains("do not redial"));
    assert_eq!(after["voice_results"]["op-one"]["result_version"], 2);
}

#[test]
fn canonical_sync_failure_rolls_back_result_and_state_then_retries_without_redial() {
    let f = Fixture::new();
    let (mut adapter, request) = reserved(&f, "op-one");
    let original = f.state();
    f.db.execute_batch("CREATE TRIGGER synthetic_sync_failure BEFORE UPDATE OF notion_sync_status ON rp_items BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    assert!(adapter.publish(&result(&request, 1, true)).is_err());
    assert_eq!(f.events("voice_result_recorded"), 0);
    assert_eq!(f.state(), original);
    f.db.execute_batch("DROP TRIGGER synthetic_sync_failure")
        .unwrap();
    assert!(matches!(
        adapter.publish(&result(&request, 1, true)).unwrap(),
        WritebackAck::Applied
    ));
    assert_eq!(f.events("voice_result_recorded"), 1);
    assert_eq!(f.events("voice_dispatch_authorized"), 1);
}

#[test]
fn result_without_reservation_or_with_foreign_scope_is_rejected() {
    let f = Fixture::new();
    let request = f.request("op-unreserved");
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    assert!(adapter.publish(&result(&request, 1, true)).is_err());
    let (mut adapter, request) = reserved(&f, "op-reserved");
    let mut foreign = result(&request, 1, true);
    foreign.work_item.reference = "item:item-b".into();
    foreign.result.work_item = foreign.work_item.clone();
    assert!(adapter.publish(&foreign).is_err());
    let mut bad = result(&request, 1, true);
    bad.result
        .evidence_refs
        .push("raw content cannot be an evidence reference".into());
    assert!(adapter.publish(&bad).is_err());
    assert_eq!(f.events("voice_result_recorded"), 0);
}

#[test]
fn item_promotion_preserves_parent_state_and_marks_new_claim_sync_pending() {
    let f = Fixture::new();
    f.db.execute("DELETE FROM rp_claims WHERE id='claim-a'", [])
        .unwrap();
    let request = f.request("op-before-promotion");
    assert_eq!(request.work_item.reference, "item:item-a");
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    adapter.authorize(&request, clock()).unwrap();
    f.db.execute("INSERT INTO rp_claims VALUES('claim-promoted','item-a',0,'submitted','ready',NULL,NULL,'v2','synced')",[]).unwrap();
    f.db.execute("UPDATE rp_work_state SET subject_type='claim',subject_id='claim-promoted',details_json=?1 WHERE case_key='item:item-a'",[json!({"state":"working","source":"parent promotion","next_step":"parent next step"}).to_string()]).unwrap();
    adapter.publish(&result(&request, 1, true)).unwrap();
    let state = f.state();
    assert_eq!(state["state"], "working");
    assert_eq!(state["source"], "parent promotion");
    assert_eq!(state["next_step"], "parent next step");
    assert_eq!(
        state["voice_results"]["op-before-promotion"]["result_version"],
        1
    );
    let sync: String =
        f.db.query_row(
            "SELECT notion_sync_status FROM rp_claims WHERE id='claim-promoted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sync, "pending");
    let status: String =
        f.db.query_row(
            "SELECT status FROM rp_claims WHERE id='claim-promoted'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "submitted");
}

#[test]
fn linking_an_orphan_claim_does_not_escape_its_reservation_or_lose_late_results() {
    let f = Fixture::new();
    f.db.execute("UPDATE rp_claims SET item_id=NULL WHERE id='claim-a'", [])
        .unwrap();
    f.db.execute("UPDATE rp_work_state SET case_key='claim:claim-a',subject_type='claim',subject_id='claim-a' WHERE case_key='item:item-a'",[]).unwrap();
    f.db.execute("UPDATE rp_daily_selections SET case_key='claim:claim-a',subject_type='claim',subject_id='claim-a' WHERE case_key='item:item-a'",[]).unwrap();
    let original = f.request_for("op-orphan", "claim:claim-a");
    let mut adapter = RpWorkflow::open(&f.path).unwrap();
    adapter.authorize(&original, clock()).unwrap();
    f.db.execute(
        "UPDATE rp_claims SET item_id='item-a',updated_at='parent-linked' WHERE id='claim-a'",
        [],
    )
    .unwrap();
    f.db.execute("UPDATE rp_work_state SET case_key='item:item-a',details_json=?1 WHERE case_key='claim:claim-a'",[json!({"state":"ready","source":"parent linked item"}).to_string()]).unwrap();
    f.db.execute(
        "UPDATE rp_daily_selections SET case_key='item:item-a' WHERE case_key='claim:claim-a'",
        [],
    )
    .unwrap();
    let next = f.request("op-after-link");
    assert_eq!(
        adapter.authorize(&next, clock()).unwrap_err().code,
        "rp_case_already_reserved"
    );
    adapter.publish(&result(&original, 1, false)).unwrap();
    let state = f.state();
    assert_eq!(state["source"], "parent linked item");
    assert_eq!(state["state"], "ready");
    assert_eq!(
        state["voice_results"]["op-orphan"]["reservation_case_key"],
        "claim:claim-a"
    );
    assert_eq!(state["voice_results"]["op-orphan"]["result_version"], 1);
    assert_eq!(
        adapter.authorize(&next, clock()).unwrap_err().code,
        "rp_case_already_reserved"
    );
    let item_sync: String =
        f.db.query_row(
            "SELECT notion_sync_status FROM rp_items WHERE id='item-a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(item_sync, "pending");
}

#[test]
fn controller_end_before_analysis_flushes_each_version_without_poisoning_the_outbox() {
    use voice_agent::contract::EventKind;
    use voice_agent::controller::Controller;
    use voice_agent::policy::{ControllerPolicy, DirectoryEntry};
    let f = Fixture::new();
    let now = clock();
    let snap = snapshot(&f.path, "item:item-a", now).unwrap();
    let mut intent = common::intent();
    intent.work_item = snap.work_item;
    intent.policy_gate_ref = snap.policy_gate_ref;
    intent.not_before = now;
    intent.not_after = now + 3600;
    let policy = ControllerPolicy {
        daily_budget_cents: 2500,
        directory: vec![DirectoryEntry {
            work_system: "rp".into(),
            destination: intent.destination.clone(),
            agent_id: intent.agent_id.clone(),
            agent_version: intent.agent_version,
            menu_navigation: intent.menu_navigation,
            rate_ref: intent.limits.rate_ref.clone(),
            rate_cents_per_minute: intent.limits.rate_cents_per_minute,
            handoff_recipient_ref: intent.handoff.recipient_ref.clone(),
            handoff_endpoint_ref: intent.handoff.endpoint_ref.clone(),
            consent_policy_ref: intent.consent_policy_ref.clone(),
            expires_at: now + 3600,
        }],
    };
    let state = f.path.with_file_name("voice-controller.sqlite");
    let mut controller =
        Controller::open_configured(&state, policy, Box::new(RpWorkflow::open(&f.path).unwrap()))
            .unwrap();
    let user = common::user();
    let approval = controller.approve(&user, &intent, now).unwrap();
    let operation = controller
        .start(&user, &intent, &approval.id, "rp-integration", now)
        .unwrap();
    let mut provider = common::CountingProvider::default();
    controller.tick(&mut provider, now).unwrap();
    let operation = controller.get(&user, &operation.id).unwrap();
    controller
        .ingest(common::event(&operation, EventKind::Started, now + 1))
        .unwrap();
    controller.process_events().unwrap();
    controller
        .ingest(common::event(&operation, EventKind::Ended, now + 2))
        .unwrap();
    controller.process_events().unwrap();
    let pending = controller.pending_outbox().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].result.status, ResultStatus::Pending);
    assert!(pending[0].call_ended);
    let mut sink = RpWorkflow::open(&f.path).unwrap();
    controller.flush_outbox(&mut sink).unwrap();
    assert!(controller.pending_outbox().unwrap().is_empty());
    let mut analyzed = common::event(&operation, EventKind::Analyzed, now + 3);
    analyzed.actual_cost_cents = Some(20);
    controller.ingest(analyzed).unwrap();
    controller.process_events().unwrap();
    controller.flush_outbox(&mut sink).unwrap();
    assert!(controller.pending_outbox().unwrap().is_empty());
    assert_eq!(f.events("voice_result_recorded"), 2);
    assert_eq!(provider.creates, 1);
}
