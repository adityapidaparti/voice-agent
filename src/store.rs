use crate::{contract::Operation, Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::{path::Path, time::Duration};

pub struct Store {
    pub(crate) db: Connection,
}
impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Refuse symlinks; deployment must additionally use a private dedicated data directory.
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Error::new("unsafe_database_path", 4));
        }
        if !path.exists() {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
          CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, idem TEXT NOT NULL,
            digest TEXT NOT NULL, locked INTEGER NOT NULL, day INTEGER NOT NULL,
            reservation INTEGER NOT NULL, data TEXT NOT NULL, UNIQUE(owner,idem));
          DROP INDEX IF EXISTS one_active_owner;
          CREATE TABLE IF NOT EXISTS events(key TEXT PRIMARY KEY, operation_id TEXT NOT NULL, data TEXT NOT NULL, processed INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS incidents(key TEXT PRIMARY KEY, operation_id TEXT NOT NULL, code TEXT NOT NULL, observed_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS outbox(operation_id TEXT NOT NULL, version INTEGER NOT NULL, data TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(operation_id,version));
          CREATE TABLE IF NOT EXISTS environment(name TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS operation_scopes(operation_id TEXT PRIMARY KEY, scope TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS report_observations(operation_id TEXT NOT NULL, sequence INTEGER NOT NULL, fingerprint TEXT NOT NULL, PRIMARY KEY(operation_id,sequence));
          CREATE TABLE IF NOT EXISTS phase_observations(operation_id TEXT NOT NULL, sequence INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(operation_id,sequence));
          CREATE TABLE IF NOT EXISTS authority_reservations(operation_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS gates(reference TEXT PRIMARY KEY, version TEXT NOT NULL, expires INTEGER NOT NULL, allowed INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
          INSERT OR IGNORE INTO gates VALUES('gate_demo_v1','v1',9223372036854775807,1);
          INSERT OR IGNORE INTO settings VALUES('starts_enabled',1);
          INSERT OR IGNORE INTO settings VALUES('safety_incident',0);
        ")?;
        Ok(Self { db })
    }
    pub fn open_bound(path: impl AsRef<Path>, environment: &str) -> Result<Self> {
        let mut store = Self::open(path)?;
        let tx = store
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .query_row("SELECT name FROM environment LIMIT 1", [], |r| r.get(0))
            .optional()?;
        if let Some(current) = current {
            if current != environment {
                return Err(Error::new("database_environment_mismatch", 4));
            }
        } else {
            let used: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM approvals) OR EXISTS(SELECT 1 FROM operations)",
                [],
                |r| r.get(0),
            )?;
            if used && environment != "simulation" {
                return Err(Error::new("database_environment_mismatch", 4));
            }
            tx.execute("INSERT INTO environment VALUES(?1)", [environment])?;
        }
        // Backfill scope for recoverable legacy synthetic operations.
        let mut stmt=tx.prepare("SELECT id,data FROM operations WHERE id NOT IN (SELECT operation_id FROM operation_scopes)")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        for (id, data) in rows {
            let op: Operation = serde_json::from_str(&data)?;
            let work = &op.result.work_item;
            let scope =
                crate::contract::hash(&serde_json::to_vec(&(&work.system, &work.reference))?);
            tx.execute(
                "INSERT INTO operation_scopes VALUES(?1,?2)",
                params![id, scope],
            )?;
        }
        tx.commit()?;
        Ok(store)
    }
}
pub(crate) fn operation(db: &Connection, id: &str) -> Result<Operation> {
    let data: Option<String> = db
        .query_row("SELECT data FROM operations WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    serde_json::from_str(&data.ok_or(Error::new("operation_not_found", 2))?).map_err(Into::into)
}
pub(crate) fn save_operation(db: &Connection, op: &Operation) -> Result<()> {
    db.execute(
        "UPDATE operations SET data=?2,locked=?3 WHERE id=?1",
        params![op.id, serde_json::to_string(op)?, op.locked()],
    )?;
    Ok(())
}
