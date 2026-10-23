use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn voice(args: &[&str], token: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_voice"));
    command.args(args).env_remove("VOICE_TOKEN");
    if let Some(token) = token {
        command.env("VOICE_TOKEN", token);
    }
    command.output().unwrap()
}
fn json_output(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("intent.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json_output(voice(&["example"], None))).unwrap(),
    )
    .unwrap();
    path
}
struct Server {
    child: Child,
    url: String,
}
impl Server {
    fn start(directory: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_voice"))
            .args(["serve", "--simulation", "--listen", "127.0.0.1:0", "--db"])
            .arg(directory.join("controller.db"))
            .arg("--provider-db")
            .arg(directory.join("provider.db"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line);
            let _ = sender.send((result, line));
        });
        let (_, line) = receiver
            .recv_timeout(Duration::from_secs(15))
            .expect("controller startup timed out");
        if line.is_empty() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "controller startup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let ready: Value = serde_json::from_str(&line).unwrap();
        Self {
            child,
            url: format!("http://{}", ready["listen"].as_str().unwrap()),
        }
    }
    fn cli(&self, args: &[&str], token: &str) -> Output {
        let mut all = vec!["--controller", &self.url];
        all.extend_from_slice(args);
        voice(&all, Some(token))
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn dryrun_needs_no_credentials_or_server_and_creates_no_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    let one = json_output(voice(
        &[
            "--controller",
            "invalid-but-unused",
            "dryrun",
            "--intent",
            path.to_str().unwrap(),
        ],
        None,
    ));
    let two = json_output(voice(&["dryrun", "--intent", path.to_str().unwrap()], None));
    assert_eq!(one, two);
    assert_eq!(one["estimate_cents"], 30);
    assert_eq!(one["live_calling"], false);
    assert_eq!(one["intent"]["destination"]["e164"], "+12025550100");
    assert_eq!(one["intent"]["facts"]["reference"]["value"], "EXAMPLE-001");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
}

#[test]
fn simulation_and_loopback_are_required_before_opening_databases() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [vec![], vec!["--simulation", "--listen", "0.0.0.0:0"]] {
        let db = dir.path().join("should-not-exist.db");
        let provider = dir.path().join("provider.db");
        let mut args = vec![
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--provider-db",
            provider.to_str().unwrap(),
        ];
        args.extend(extra);
        let output = voice(&args, None);
        assert_eq!(output.status.code(), Some(4));
        assert!(!db.exists());
        assert!(!provider.exists());
    }
}

#[test]
fn plaintext_remote_urls_credentials_in_urls_and_redirect_targets_are_not_allowed() {
    for base in [
        "http://example.com",
        "http://127.0.0.1@192.0.2.1",
        "http://name:seeded-secret@127.0.0.1:1",
        "http://127.0.0.1:1?token=seeded-secret",
        "http://localhost:1",
    ] {
        let output = voice(
            &["--controller", base, "status", "op_example"],
            Some("synthetic-owner-token"),
        );
        assert_eq!(output.status.code(), Some(4), "{base}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("seeded-secret"));
    }
}

#[test]
fn doctor_reports_unpassed_launch_gates_without_reading_credentials() {
    let output = json_output(voice(&["doctor"], None));
    assert_eq!(output["live_calling"], false);
    assert_eq!(output["simulation_available"], true);
    assert!(output["setup_gates"].as_array().unwrap().len() >= 5);
}

#[test]
fn unknown_intent_fields_are_rejected_without_echoing_their_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["credential"] = json!("seeded-private-string");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = voice(&["dryrun", "--intent", path.to_str().unwrap()], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("seeded-private-string"));
    assert!(output.stdout.is_empty());
}

#[test]
fn authenticated_approval_durable_start_and_result_work_across_client_exit_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let intent = fixture(dir.path());
    let mut input: Value = serde_json::from_slice(&std::fs::read(&intent).unwrap()).unwrap();
    let expires = voice_agent::now() + 5;
    input["not_after"] = json!(expires);
    std::fs::write(&intent, serde_json::to_vec(&input).unwrap()).unwrap();
    let path = intent.to_str().unwrap();
    let server = Server::start(dir.path());
    let denied = server.cli(
        &["approve", "--intent", path, "--via", "user"],
        "synthetic-coordinator-token",
    );
    assert_eq!(denied.status.code(), Some(3));
    let approved = json_output(server.cli(
        &["approve", "--intent", path, "--via", "user"],
        "synthetic-owner-token",
    ));
    let approval = approved["id"].as_str().unwrap();
    let started = json_output(server.cli(
        &[
            "start",
            "--intent",
            path,
            "--approval",
            approval,
            "--idempotency-key",
            "cli-demo-attempt",
        ],
        "synthetic-coordinator-token",
    ));
    let id = started["id"].as_str().unwrap();
    assert_eq!(started["attempt_consumed"], true);
    assert!(
        started["intent"].is_null(),
        "status must not copy the fact packet"
    );
    let duplicate = json_output(server.cli(
        &[
            "start",
            "--intent",
            path,
            "--approval",
            approval,
            "--idempotency-key",
            "cli-demo-attempt",
        ],
        "synthetic-coordinator-token",
    ));
    assert_eq!(duplicate["id"], id);

    // Every preceding CLI has exited. The server worker must still finish on its own.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let result = json_output(server.cli(&["result", id], "synthetic-coordinator-token"));
        if result["status"] == "needs_review" {
            assert_ne!(result["outcome"], "objective_completed");
            assert_eq!(result["human_result"], "unobserved");
            assert!(!result["evidence_refs"].as_array().unwrap().is_empty());
            break;
        }
        assert!(Instant::now() < deadline, "worker did not finish: {result}");
        std::thread::sleep(Duration::from_millis(100));
    }
    while voice_agent::now() < expires {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        voice(&["dryrun", "--intent", path], None).status.code(),
        Some(2)
    );
    drop(server);
    let restarted = Server::start(dir.path());
    let restored = json_output(restarted.cli(&["status", id], "synthetic-owner-token"));
    assert_eq!(restored["lifecycle"], "ended");
    let repeated = json_output(restarted.cli(
        &[
            "start",
            "--intent",
            path,
            "--approval",
            approval,
            "--idempotency-key",
            "cli-demo-attempt",
        ],
        "synthetic-coordinator-token",
    ));
    assert_eq!(repeated["id"], id);
    let db = rusqlite::Connection::open(dir.path().join("provider.db")).unwrap();
    let accepted_calls: u64 = db
        .query_row("SELECT COUNT(*) FROM synthetic_calls", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        accepted_calls, 1,
        "duplicate starts and restart must not create another phone call"
    );
}

#[test]
fn http_auth_body_limits_and_webhook_failures_are_private() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(dir.path());
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = client
        .get(format!("{}/health", server.url))
        .bearer_auth("seeded-invalid-token")
        .send()
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(!response.text().unwrap().contains("seeded-invalid-token"));
    let response = client
        .post(format!("{}/v1/approvals", server.url))
        .bearer_auth("synthetic-owner-token")
        .body("x".repeat(65537))
        .send()
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.json::<Value>().unwrap()["error"]["code"],
        "request_too_large"
    );
    let response = client
        .post(format!("{}/v1/webhooks/retell", server.url))
        .header("X-Retell-Signature", "invalid-signature")
        .body("seeded-sensitive-transcript")
        .send()
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(!response
        .text()
        .unwrap()
        .contains("seeded-sensitive-transcript"));
    let response = client
        .post(format!("{}/v1/approvals", server.url))
        .bearer_auth("synthetic-owner-token")
        .header("Origin", "https://untrusted.example")
        .body("{}")
        .send()
        .unwrap();
    assert_eq!(response.status(), 403);
    for name in [
        "controller.db",
        "controller.db-wal",
        "provider.db",
        "provider.db-wal",
    ] {
        if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
            assert!(!String::from_utf8_lossy(&bytes).contains("seeded-sensitive-transcript"));
        }
    }
}

#[test]
fn https_control_is_accepted_but_requires_a_scoped_credential_before_network() {
    let output = voice(
        &[
            "--controller",
            "https://voice.example.invalid",
            "status",
            "op_example",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("controller_credential_required"));
    let output = voice(
        &[
            "--controller",
            "https://voice.example.invalid",
            "status",
            "op_example",
        ],
        Some("synthetic-owner-token"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid_controller_credential_format")
    );
}
