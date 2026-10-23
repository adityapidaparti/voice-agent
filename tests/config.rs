//! Configuration and identity checks use synthetic bearer material only.
use hegel::prelude::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use voice_agent::config::{
    controller_origin, token_digest, Credential, CredentialFile, CredentialRole, HostedConfig,
};
use voice_agent::contract::{hash, Destination};
use voice_agent::controller::Role;
use voice_agent::policy::{ControllerPolicy, DirectoryEntry};
use voice_agent::retell::RetellConfig;

const USER_TOKEN: &str =
    "v1.operator.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const COORDINATOR_TOKEN: &str =
    "v1.assistant.fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn credentials(clock: i64) -> CredentialFile {
    CredentialFile {
        schema_version: 1,
        credentials: vec![
            Credential {
                id: "operator".into(),
                owner: "owner-example".into(),
                role: CredentialRole::User,
                token_sha256: hash(USER_TOKEN.as_bytes()),
                not_before: clock,
                expires_at: clock + 600,
                revoked: false,
            },
            Credential {
                id: "assistant".into(),
                owner: "owner-example".into(),
                role: CredentialRole::Coordinator,
                token_sha256: hash(COORDINATOR_TOKEN.as_bytes()),
                not_before: clock,
                expires_at: clock + 600,
                revoked: false,
            },
        ],
    }
}

#[cfg(unix)]
fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    // tempfile inherits the process umask unless permissions are explicit.
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[cfg(unix)]
fn private_write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[cfg(unix)]
fn configuration(directory: &Path, clock: i64) -> HostedConfig {
    let credentials_file = directory.join("credentials.json");
    private_write(
        &credentials_file,
        &serde_json::to_vec(&credentials(clock)).unwrap(),
    );
    HostedConfig {
        schema_version: 1,
        starts_enabled: false,
        public_origin: "https://voice.example.invalid".into(),
        listen: "127.0.0.1:8787".parse().unwrap(),
        database: directory.join("controller.db"),
        credentials_file,
        retell_key_env: "VOICE_TEST_RETELL_KEY".into(),
        workflow_token_env: "VOICE_TEST_WORKFLOW_TOKEN".into(),
        workflow_base_url: "https://workflow.example.invalid".into(),
        policy: ControllerPolicy {
            daily_budget_cents: 1000,
            directory: vec![DirectoryEntry {
                work_system: "return_protection".into(),
                destination: Destination {
                    e164: "+12025550100".into(),
                    source_ref: "official_demo_v1".into(),
                    source_version: "v1".into(),
                },
                agent_id: "agent_demo".into(),
                agent_version: 1,
                rate_ref: "rate_demo_v1".into(),
                rate_cents_per_minute: 10,
                handoff_recipient_ref: "owner".into(),
                handoff_endpoint_ref: "owner_control".into(),
                consent_policy_ref: "synthetic_consent_v1".into(),
                expires_at: clock + 3600,
            }],
        },
        retell: RetellConfig {
            from_number: "+12025550101".into(),
            agent_id: "agent_demo".into(),
            agent_version: 1,
            llm_id: "llm_demo".into(),
            llm_version: 1,
            agent_snapshot_sha256: "a".repeat(64),
            llm_snapshot_sha256: "b".repeat(64),
            webhook_url: Some("https://voice.example.invalid/v1/webhooks/retell".into()),
        },
    }
}

#[test]
fn identity_is_derived_from_distinct_scoped_records_and_known_simulation_tokens_fail() {
    let file = credentials(1000);
    let user = file.authenticate(USER_TOKEN, 1001).unwrap();
    assert_eq!(user.owner, "owner-example");
    assert_eq!(user.role, Role::User);
    let coordinator = file.authenticate(COORDINATOR_TOKEN, 1001).unwrap();
    assert_eq!(coordinator.role, Role::Coordinator);
    for token in [
        "synthetic-owner-token",
        "synthetic-coordinator-token",
        "v1.operator.0000",
        "v1.operator.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        assert!(file.authenticate(token, 1001).is_err());
    }
    for token in [
        "v1.operator.fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "v1.assistant.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            token_digest(token).is_ok(),
            "wrong secret must reach authentication"
        );
        assert!(
            file.authenticate(token, 1001).is_err(),
            "public ID is not a credential"
        );
    }
    let mut bad = file.clone();
    bad.credentials[1].token_sha256 = bad.credentials[0].token_sha256.clone();
    assert!(
        bad.validate().is_err(),
        "one bearer cannot acquire two identities"
    );
    let mut bad = file;
    bad.credentials[1].id = bad.credentials[0].id.clone();
    assert!(
        bad.validate().is_err(),
        "ambiguous identity must fail closed"
    );
}

/// The credential window is modeled as a half-open interval, independently of hash parsing.
#[hegel::test]
fn a_bearer_grants_only_its_recorded_role_inside_its_unrevoked_window(tc: TestCase) {
    let clock = tc.draw(hegel::one_of!(
        gs::integers::<i64>(),
        gs::sampled_from(&[999_i64, 1000, 1001, 1599, 1600, 1601][..])
    ));
    let revoked = tc.draw(gs::booleans());
    let coordinator = tc.draw(gs::booleans());
    let mismatch = tc.draw(gs::integers::<u8>().max_value(2));
    let mut file = credentials(1000);
    let index = usize::from(coordinator);
    file.credentials[index].revoked = revoked;
    let token = if coordinator {
        COORDINATOR_TOKEN
    } else {
        USER_TOKEN
    };
    let modified = match mismatch {
        0 => token.to_owned(),
        1 => token.replacen("v1.", "v1.other-", 1),
        _ => {
            let mut bytes = token.as_bytes().to_vec();
            let position =
                bytes.len() - 64 + usize::from(tc.draw(gs::integers::<u8>().max_value(63)));
            bytes[position] = if bytes[position] == b'0' { b'1' } else { b'0' };
            String::from_utf8(bytes).unwrap()
        }
    };
    assert!(token_digest(&modified).is_ok());
    tc.event(match mismatch {
        0 => "matching secret",
        1 => "unknown ID",
        _ => "wrong secret, known ID",
    });
    let result = file.authenticate(&modified, clock);
    let expected = (1000..1600).contains(&clock) && !revoked && mismatch == 0;
    tc.event(if expected {
        "accepted credential"
    } else {
        "rejected credential"
    });
    assert_eq!(result.is_ok(), expected);
    if let Ok(principal) = result {
        assert_eq!(principal.owner, "owner-example");
        assert_eq!(
            principal.role,
            if coordinator {
                Role::Coordinator
            } else {
                Role::User
            }
        );
    }
}

/// Replacing either identity or payload changes the complete bearer digest.
#[hegel::test]
fn arbitrary_bearers_never_match_a_distinct_existing_credential(tc: TestCase) {
    let id = if tc.draw(gs::booleans()) {
        "operator"
    } else {
        "assistant"
    };
    let left = tc.draw(gs::integers::<u128>());
    let right = tc.draw(gs::integers::<u128>());
    let generated = format!("v1.{id}.{left:032x}{right:032x}");
    let examples = [
        generated,
        USER_TOKEN.to_owned(),
        COORDINATOR_TOKEN.to_owned(),
        "synthetic-owner-token".to_owned(),
    ];
    let candidate = tc.draw(hegel::one_of!(gs::text(), gs::sampled_from(&examples[..])));
    let file = credentials(1000);
    let result = file.authenticate(&candidate, 1200);
    let expected = candidate == USER_TOKEN || candidate == COORDINATOR_TOKEN;
    assert_eq!(result.is_ok(), expected);
    if candidate == USER_TOKEN {
        assert_eq!(
            token_digest(&candidate).unwrap(),
            hash(USER_TOKEN.as_bytes())
        );
    }
}

#[test]
fn transport_origins_separate_tls_from_literal_loopback_plaintext() {
    for allowed in [
        "https://voice.example.invalid",
        "https://127.0.0.1:8787",
        "http://127.0.0.1:8787",
        "http://[::1]:8787",
    ] {
        assert!(controller_origin(allowed).is_ok(), "{allowed}");
    }
    for denied in [
        "http://voice.example.invalid",
        "http://localhost:8787",
        "http://192.0.2.1",
        "https://name:private@voice.example.invalid",
        "https://voice.example.invalid?key=private",
        "https://voice.example.invalid/path",
        "https://voice.example.invalid/#private",
        "file:///private",
    ] {
        assert!(controller_origin(denied).is_err(), "{denied}");
    }
}

#[cfg(unix)]
#[test]
fn private_configuration_is_checked_without_provider_secrets_or_database_creation() {
    let dir = private_directory();
    let clock = voice_agent::now();
    let config = configuration(dir.path(), clock);
    let path = dir.path().join("config.json");
    private_write(&path, &serde_json::to_vec(&config).unwrap());
    let result = Command::new(env!("CARGO_BIN_EXE_voice"))
        .args(["config-check", "--config"])
        .arg(&path)
        .env(&config.retell_key_env, "invalid whitespace sentinel")
        .env(&config.workflow_token_env, "invalid whitespace sentinel")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["configuration_valid"], true);
    assert_eq!(value["runtime_secrets_read"], false);
    assert_eq!(value["network_requests"], 0);
    assert!(!config.database.exists());
    assert!(!String::from_utf8_lossy(&result.stdout).contains(USER_TOKEN));
    let result = Command::new(env!("CARGO_BIN_EXE_voice"))
        .args(["serve", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(4));
    assert!(
        !config.database.exists(),
        "missing explicit enablement must have no runtime side effects"
    );
}

#[cfg(unix)]
#[test]
fn unsafe_files_pins_and_public_listeners_are_rejected_before_startup() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = private_directory();
    let config = configuration(dir.path(), 1000);
    assert!(config.validate(1000).is_ok());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        config.validate(1000).unwrap_err().code,
        "hosted_path_must_be_private"
    );
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut bad = config.clone();
    bad.listen = "0.0.0.0:8787".parse().unwrap();
    assert!(bad.validate(1000).is_err());
    let mut bad = config.clone();
    bad.retell.agent_version += 1;
    assert!(bad.validate(1000).is_err());
    let mut bad = config.clone();
    bad.policy.directory[0].expires_at = 1000;
    assert!(bad.validate(1000).is_err());
    let mut bad = config.clone();
    bad.public_origin = "http://voice.example.invalid".into();
    assert!(bad.validate(1000).is_err());
    let mut bad = config.clone();
    bad.retell.webhook_url = Some("https://other.example.invalid/v1/webhooks/retell".into());
    assert!(bad.validate(1000).is_err());
    let mut bad = config.clone();
    bad.retell_key_env = bad.workflow_token_env.clone();
    assert!(bad.validate(1000).is_err());
    std::fs::set_permissions(
        &config.credentials_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(config.validate(1000).is_err());
    std::fs::set_permissions(
        &config.credentials_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let linked = dir.path().join("linked.json");
    symlink(&config.credentials_file, &linked).unwrap();
    let mut bad = config.clone();
    bad.credentials_file = linked;
    assert!(bad.validate(1000).is_err());
    let wal = dir.path().join("controller.db-wal");
    std::fs::write(&wal, b"synthetic").unwrap();
    std::fs::set_permissions(wal, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(config.validate(1000).is_err());
}

#[cfg(unix)]
struct HostedChild(Child);
#[cfg(unix)]
impl Drop for HostedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[test]
fn hosted_http_rereads_revocation_and_rejects_coordinator_approval_without_vendor_calls() {
    let dir = private_directory();
    let clock = voice_agent::now();
    let mut config = configuration(dir.path(), clock);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.listen = listener.local_addr().unwrap();
    drop(listener);
    let path = dir.path().join("config.json");
    private_write(&path, &serde_json::to_vec(&config).unwrap());
    // Empty controller: no call operations exist, so the provider is never invoked.
    let mut child = HostedChild(
        Command::new(env!("CARGO_BIN_EXE_voice"))
            .args(["serve", "--config"])
            .arg(&path)
            .arg("--enable-live-calling")
            .env(
                &config.retell_key_env,
                "seeded-not-a-real-retell-credential",
            )
            .env(
                &config.workflow_token_env,
                "seeded-not-a-real-workflow-credential",
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send((result, line));
    });
    let (_, line) = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("hosted startup timeout");
    assert!(
        !line.is_empty(),
        "hosted runtime must start with an empty DB and synthetic secrets"
    );
    let ready: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["simulation"], false);
    let base = format!("http://{}", config.listen);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    for token in [USER_TOKEN, COORDINATOR_TOKEN] {
        assert_eq!(
            client
                .get(format!("{base}/health"))
                .bearer_auth(token)
                .send()
                .unwrap()
                .status(),
            200
        );
    }
    assert_eq!(
        client
            .get(format!("{base}/health"))
            .bearer_auth("synthetic-owner-token")
            .send()
            .unwrap()
            .status(),
        401
    );
    let example = Command::new(env!("CARGO_BIN_EXE_voice"))
        .arg("example")
        .output()
        .unwrap();
    let intent: Value = serde_json::from_slice(&example.stdout).unwrap();
    let response = client
        .post(format!("{base}/v1/approvals"))
        .bearer_auth(COORDINATOR_TOKEN)
        .json(&json!({"intent":intent,"via":"user"}))
        .send()
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "role rejection occurs before authoritative RP access"
    );
    for route in ["observe", "report"] {
        let response = client
            .post(format!("{base}/v1/functions/{route}"))
            .header("X-Retell-Signature", "invalid-signature")
            .body("synthetic-sensitive-body-must-not-be-retained")
            .send()
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "signed function route must reject before parsing or bearer auth"
        );
        assert!(!response
            .text()
            .unwrap()
            .contains("synthetic-sensitive-body"));
        let response = client
            .post(format!("{base}/v1/functions/{route}"))
            .header("X-Retell-Signature", "invalid-signature")
            .body("x".repeat(65537))
            .send()
            .unwrap();
        assert_eq!(
            response.status(),
            400,
            "function request body must be bounded"
        );
    }
    let mut records = credentials(clock);
    records.credentials[1].revoked = true;
    let replacement = dir.path().join("credentials-next.json");
    private_write(&replacement, &serde_json::to_vec(&records).unwrap());
    std::fs::rename(replacement, &config.credentials_file).unwrap();
    assert_eq!(
        client
            .get(format!("{base}/health"))
            .bearer_auth(COORDINATOR_TOKEN)
            .send()
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{base}/health"))
            .bearer_auth(USER_TOKEN)
            .send()
            .unwrap()
            .status(),
        200
    );
    private_write(&config.credentials_file, b"malformed configuration");
    assert!(!client
        .get(format!("{base}/health"))
        .bearer_auth(USER_TOKEN)
        .send()
        .unwrap()
        .status()
        .is_success());
    let db = rusqlite::Connection::open(&config.database).unwrap();
    let operations: i64 = db
        .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(operations, 0);
    for name in ["controller.db", "controller.db-wal"] {
        if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
            assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-sensitive-body"));
        }
    }
}
