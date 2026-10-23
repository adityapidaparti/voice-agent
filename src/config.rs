//! Explicit hosted configuration. Parsing and checking never read provider secrets or use network.
use crate::contract::{hash, identifier};
use crate::controller::{Principal, Role};
use crate::policy::ControllerPolicy;
use crate::retell::RetellConfig;
use crate::{Error, Result};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

const MAX_CONFIG: u64 = 256 * 1024;
const MAX_CREDENTIAL_LIFETIME: i64 = 30 * 86400;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedConfig {
    pub schema_version: u32,
    /// Operator enablement is separate from each call's authenticated approval.
    pub starts_enabled: bool,
    pub public_origin: String,
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub credentials_file: PathBuf,
    pub retell_key_env: String,
    pub workflow_token_env: String,
    pub workflow_base_url: String,
    pub policy: ControllerPolicy,
    pub retell: RetellConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRole {
    User,
    Coordinator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: String,
    pub owner: String,
    pub role: CredentialRole,
    /// SHA-256 of the complete bearer, never the bearer itself.
    pub token_sha256: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFile {
    pub schema_version: u32,
    pub credentials: Vec<Credential>,
}

fn credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

/// Token generation is an operator setup action; this validates a supplied 256-bit format.
pub fn token_digest(token: &str) -> Result<String> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3
        || parts[0] != "v1"
        || !credential_id(parts[1])
        || !hex_digest(parts[2])
        || parts[2].bytes().all(|b| b == parts[2].as_bytes()[0])
    {
        return Err(Error::new("invalid_controller_credential_format", 3));
    }
    Ok(hash(token.as_bytes()))
}

fn constant_eq(candidate: &str, expected: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"voice-credential-hash-comparison-v1");
    hmac::verify(
        &key,
        candidate.as_bytes(),
        hmac::sign(&key, expected.as_bytes()).as_ref(),
    )
    .is_ok()
}

impl CredentialFile {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.credentials.is_empty() || self.credentials.len() > 128 {
            return Err(Error::new("invalid_credential_configuration", 4));
        }
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for record in &self.credentials {
            if !credential_id(&record.id)
                || !identifier(&record.owner)
                || !hex_digest(&record.token_sha256)
                || record.not_before < 0
                || record.expires_at <= record.not_before
                || record.expires_at.saturating_sub(record.not_before) > MAX_CREDENTIAL_LIFETIME
                || !ids.insert(&record.id)
                || !hashes.insert(&record.token_sha256)
            {
                return Err(Error::new("invalid_credential_configuration", 4));
            }
        }
        Ok(())
    }

    pub fn authenticate(&self, token: &str, clock: i64) -> Result<Principal> {
        self.validate()?;
        let candidate =
            token_digest(token).map_err(|_| Error::new("authentication_required", 3))?;
        let id = token.split('.').nth(1).unwrap_or("");
        let record = self
            .credentials
            .iter()
            .find(|r| r.id == id)
            .ok_or(Error::new("authentication_required", 3))?;
        if !constant_eq(&candidate, &record.token_sha256)
            || record.revoked
            || clock < record.not_before
            || clock >= record.expires_at
        {
            return Err(Error::new("authentication_required", 3));
        }
        Ok(Principal {
            owner: record.owner.clone(),
            role: match record.role {
                CredentialRole::User => Role::User,
                CredentialRole::Coordinator => Role::Coordinator,
            },
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&read_private_file(path)?)?;
        value.validate()?;
        Ok(value)
    }
}

/// The service never silently widens an insecure path's permissions.
pub fn ensure_private_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(Error::new("unsafe_hosted_path", 4));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::new("hosted_path_must_be_private", 4));
        }
    }
    #[cfg(not(unix))]
    return Err(Error::new("hosted_private_permissions_unsupported", 4));
    Ok(())
}

fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(Error::new("hosted_path_must_be_absolute", 4));
    }
    ensure_private_path(
        path.parent().ok_or(Error::new("unsafe_hosted_path", 4))?,
        true,
    )?;
    ensure_private_path(path, false)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err(Error::new("configuration_too_large", 2));
    }
    Ok(bytes)
}

pub fn https_origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::new("invalid_https_origin", 4))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::new("invalid_https_origin", 4));
    }
    Ok(url)
}

/// HTTP is allowed only for the explicit local simulation route. Remote control uses TLS.
pub fn controller_origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::new("invalid_controller_url", 2))?;
    if url.scheme() == "https" {
        return https_origin(value);
    }
    let literal = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .parse::<IpAddr>();
    if url.scheme() != "http"
        || !literal.is_ok_and(|ip| ip.is_loopback())
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::new(
            "plaintext_controller_requires_literal_loopback",
            4,
        ));
    }
    Ok(url)
}

fn environment_name(value: &str) -> bool {
    value.starts_with("VOICE_")
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl HostedConfig {
    pub fn load(path: &Path, clock: i64) -> Result<Self> {
        let value: Self = serde_json::from_slice(&read_private_file(path)?)?;
        value.validate(clock)?;
        Ok(value)
    }

    pub fn validate(&self, clock: i64) -> Result<()> {
        if self.schema_version != 1
            || !self.listen.ip().is_loopback()
            || self.listen.port() == 0
            || !self.database.is_absolute()
            || self.database == self.credentials_file
            || !environment_name(&self.retell_key_env)
            || !environment_name(&self.workflow_token_env)
            || self.retell_key_env == self.workflow_token_env
        {
            return Err(Error::new("invalid_hosted_configuration", 4));
        }
        let origin = https_origin(&self.public_origin)?;
        https_origin(&self.workflow_base_url)?;
        self.policy.validate(clock)?;
        self.retell.validate()?;
        if self.policy.directory.iter().any(|entry| {
            entry.agent_id != self.retell.agent_id
                || entry.agent_version != self.retell.agent_version
        }) {
            return Err(Error::new("policy_agent_pin_mismatch", 4));
        }
        if let Some(webhook) = &self.retell.webhook_url {
            let expected = origin
                .join("v1/webhooks/retell")
                .map_err(|_| Error::new("invalid_hosted_configuration", 4))?;
            if webhook != expected.as_str() {
                return Err(Error::new("webhook_origin_mismatch", 4));
            }
        }
        let parent = self
            .database
            .parent()
            .ok_or(Error::new("unsafe_hosted_path", 4))?;
        ensure_private_path(parent, true)?;
        if self.database.exists() || self.database.symlink_metadata().is_ok() {
            ensure_private_path(&self.database, false)?;
        }
        for suffix in ["-wal", "-shm"] {
            let mut name = self.database.as_os_str().to_os_string();
            name.push(suffix);
            let path = PathBuf::from(name);
            if path.exists() || path.symlink_metadata().is_ok() {
                ensure_private_path(&path, false)?;
            }
        }
        // Hashes are not provider secrets. Re-read this file for every authenticated request.
        CredentialFile::load(&self.credentials_file)?;
        Ok(())
    }

    /// Call only after the explicit live-runtime flag. Never called by config-check.
    pub fn runtime_secrets(&self) -> Result<(String, String)> {
        let read = |name: &str| {
            let secret =
                std::env::var(name).map_err(|_| Error::new("runtime_secret_required", 3))?;
            if secret.len() < 16
                || secret.len() > 4096
                || secret.contains(char::is_whitespace)
                || secret.starts_with("synthetic-")
                || secret.starts_with("REPLACE_")
            {
                return Err(Error::new("invalid_runtime_secret", 3));
            }
            Ok(secret)
        };
        Ok((read(&self.retell_key_env)?, read(&self.workflow_token_env)?))
    }
}
