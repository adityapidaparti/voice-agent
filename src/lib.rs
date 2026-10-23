pub mod contract;
pub mod controller;
pub mod provider;
pub mod server;
pub mod store;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: &'static str,
    pub exit: i32,
}
impl Error {
    pub fn new(code: &'static str, exit: i32) -> Self {
        Self { code, exit }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::new("storage_unavailable", 6)
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new("invalid_json", 2)
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::new("io_unavailable", 6)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
