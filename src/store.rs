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
          CREATE TABLE IF NOT EXISTS gates(reference TEXT PRIMARY KEY, version TEXT NOT NULL, expires INTEGER NOT NULL, allowed INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
          INSERT OR IGNORE INTO gates VALUES('gate_demo_v1','v1',9223372036854775807,1);
          INSERT OR IGNORE INTO settings VALUES('starts_enabled',1);
          INSERT OR IGNORE INTO settings VALUES('safety_incident',0);
        ")?;
        Ok(Self { db })
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
