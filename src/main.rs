use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use voice_agent::contract::{Destination, Fact, Handoff, Intent, Limits, WorkItem};
use voice_agent::{now, Error, Result};

#[derive(Parser)]
#[command(
    version,
    about = "Approval-bound calling CLI with synthetic and explicitly configured Retell runtimes."
)]
struct Cli {
    #[arg(long, global = true, default_value = "http://127.0.0.1:8787")]
    controller: String,
    /// JSON is the default; this flag also supports explicit agent invocations.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a synthetic intent with a fresh approval window.
    Example,
    /// Validate and show the complete frozen scope without network or writes.
    Dryrun {
        #[arg(long)]
        intent: PathBuf,
    },
    /// Record approval using an authenticated user credential, not this flag alone.
    Approve {
        #[arg(long)]
        intent: PathBuf,
        #[arg(long)]
        via: String,
    },
    /// Submit once and return the durable operation identifier.
    Start {
        #[arg(long)]
        intent: PathBuf,
        #[arg(long)]
        approval: String,
        #[arg(long)]
        idempotency_key: String,
    },
    Status {
        id: String,
    },
    Result {
        id: String,
    },
    End {
        id: String,
        #[arg(long, default_value = "user_requested")]
        reason: String,
    },
    Revoke {
        approval_id: String,
    },
    /// Run a local simulation or an explicitly configured hosted controller.
    Serve {
        #[arg(long, conflicts_with = "config")]
        db: Option<PathBuf>,
        #[arg(long, conflicts_with = "config")]
        provider_db: Option<PathBuf>,
        #[arg(long, conflicts_with = "config")]
        listen: Option<SocketAddr>,
        #[arg(long, conflicts_with = "config")]
        simulation: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Enables configured provider execution; every call still needs user approval.
        #[arg(long, requires = "config", conflicts_with = "simulation")]
        enable_live_calling: bool,
    },
    /// Check nonsecret configuration and permissions; never reads runtime secrets or uses network.
    ConfigCheck {
        #[arg(long)]
        config: PathBuf,
    },
    /// Hash an already provisioned VOICE_TOKEN without printing or storing the bearer.
    CredentialDigest,
    /// Explain remaining launch gates without reading credentials or contacting services.
    Doctor,
}

fn example() -> Intent {
    let clock = now();
    Intent {
        schema_version: 1,
        intent_id: "synthetic-intent-001".into(),
        work_item: WorkItem {
            system: "return_protection".into(),
            reference: "demo-case-001".into(),
            version: "v1".into(),
        },
        destination: Destination {
            e164: "+12025550100".into(),
            source_ref: "official_demo_v1".into(),
            source_version: "v1".into(),
        },
        purpose: "Ask which documents are needed for a fictional example".into(),
        facts: [(
            "reference".into(),
            Fact {
                value: "EXAMPLE-001".into(),
                source_ref: "synthetic_record".into(),
                source_version: "v1".into(),
            },
        )]
        .into(),
        permitted_actions: vec!["ask_documents".into(), "request_next_steps".into()],
        forbidden_actions: vec!["attest".into(), "pay".into(), "accept_terms".into()],
        forbidden_disclosures: vec!["password".into(), "otp".into(), "pin".into()],
        ai_disclosure: true,
        consent_policy_ref: "synthetic_consent_v1".into(),
        handoff: Handoff {
            recipient_ref: "owner".into(),
            endpoint_ref: "owner_control".into(),
            mode: "manual".into(),
            resume_ai: false,
            authentication: "separate_direct_call".into(),
        },
        limits: Limits {
            attempts: 1,
            duration_seconds: 120,
            hold_seconds: 60,
            handoff_wait_seconds: 30,
            budget_cents: 100,
            rate_cents_per_minute: 10,
            rate_ref: "rate_demo_v1".into(),
        },
        policy_gate_ref: "gate_demo_v1".into(),
        provider: "retell".into(),
        agent_id: "agent_demo".into(),
        agent_version: 1,
        not_before: clock,
        not_after: clock + 1800,
    }
}

fn load_intent(path: &Path) -> Result<Intent> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(Error::new("intent_too_large", 2));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_intent(path: &Path) -> Result<Intent> {
    let intent = load_intent(path)?;
    intent.validate(now())?;
    Ok(intent)
}

fn identifier(id: &str) -> Result<&str> {
    if !voice_agent::contract::identifier(id) {
        return Err(Error::new("invalid_identifier", 2));
    }
    Ok(id)
}

fn request(base: &str, path: &str, data: Option<Value>) -> Result<Value> {
    let mut url = voice_agent::config::controller_origin(base)?;
    let token = std::env::var("VOICE_TOKEN")
        .map_err(|_| Error::new("controller_credential_required", 3))?;
    if url.scheme() == "https" {
        voice_agent::config::token_digest(&token)?;
    }
    url.set_path(path);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .map_err(|_| Error::new("controller_client_unavailable", 6))?;
    let request = if let Some(data) = data {
        client.post(url).json(&data)
    } else {
        client.get(url)
    };
    let response = request
        .bearer_auth(token)
        .send()
        .map_err(|_| Error::new("controller_response_unknown_inspect_same_operation", 6))?;
    let success = response.status().is_success();
    let mut bytes = Vec::new();
    response
        .take(262145)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new("controller_response_unknown_inspect_same_operation", 6))?;
    if bytes.len() > 262144 {
        return Err(Error::new("controller_response_too_large", 6));
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::new("controller_response_invalid", 6))?;
    if !success {
        // The server has a fixed vocabulary. Do not echo arbitrary upstream body text.
        let exit = value
            .pointer("/error/exit")
            .and_then(Value::as_i64)
            .filter(|n| (2..=6).contains(n))
            .unwrap_or(6) as i32;
        let code = match exit {
            2 => "controller_rejected_input",
            3 => "approval_or_authentication_rejected",
            4 => "controller_policy_block",
            5 => "provider_rejected",
            _ => "controller_outcome_unknown",
        };
        return Err(Error::new(code, exit));
    }
    Ok(value)
}

fn run(cli: Cli) -> Result<Value> {
    let _ = cli.json;
    match cli.command {
        Command::Example => Ok(serde_json::to_value(example())?),
        Command::Dryrun { intent } => {
            let intent = read_intent(&intent)?;
            Ok(
                json!({"intent_digest":intent.digest()?,"estimate_cents":intent.estimate_cents(),
                "live_calling":false,"intent":intent}),
            )
        }
        Command::Approve { intent, via } => {
            if via != "user" {
                return Err(Error::new("user_approval_required", 3));
            }
            request(
                &cli.controller,
                "/v1/approvals",
                Some(json!({"intent":read_intent(&intent)?,"via":via})),
            )
        }
        Command::Start {
            intent,
            approval,
            idempotency_key,
        } => request(
            &cli.controller,
            "/v1/start",
            Some(
                json!({"intent":load_intent(&intent)?,"approval":identifier(&approval)?,"idempotency_key":identifier(&idempotency_key)?}),
            ),
        ),
        Command::Status { id } => request(
            &cli.controller,
            &format!("/v1/operations/{}", identifier(&id)?),
            None,
        ),
        Command::Result { id } => request(
            &cli.controller,
            &format!("/v1/operations/{}/result", identifier(&id)?),
            None,
        ),
        Command::End { id, reason } => request(
            &cli.controller,
            &format!("/v1/operations/{}/end", identifier(&id)?),
            Some(json!({"reason":reason})),
        ),
        Command::Revoke { approval_id } => request(
            &cli.controller,
            &format!("/v1/approvals/{}/revoke", identifier(&approval_id)?),
            Some(json!({})),
        ),
        Command::Serve {
            db,
            provider_db,
            listen,
            simulation,
            config,
            enable_live_calling,
        } => {
            if let Some(path) = config {
                if !enable_live_calling {
                    return Err(Error::new("explicit_live_runtime_enablement_required", 4));
                }
                let config = voice_agent::config::HostedConfig::load(&path, now())?;
                voice_agent::server::run_hosted(config, enable_live_calling)?;
            } else {
                if !simulation {
                    return Err(Error::new("explicit_runtime_mode_required", 4));
                }
                voice_agent::server::run(
                    db.ok_or(Error::new("simulation_database_required", 2))?,
                    provider_db.ok_or(Error::new("simulation_provider_database_required", 2))?,
                    listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8787))),
                    simulation,
                )?;
            }
            Ok(Value::Null)
        }
        Command::ConfigCheck { config } => {
            let config = voice_agent::config::HostedConfig::load(&config, now())?;
            Ok(json!({"configuration_valid":true,"live_calling":false,
                "operator_starts_enabled":config.starts_enabled,
                "runtime_secrets_read":false,"network_requests":0,
                "live_acceptance_verified":false}))
        }
        Command::CredentialDigest => {
            let token = std::env::var("VOICE_TOKEN")
                .map_err(|_| Error::new("controller_credential_required", 3))?;
            Ok(json!({"token_sha256":voice_agent::config::token_digest(&token)?}))
        }
        Command::Doctor => Ok(
            json!({"live_calling":false,"simulation_available":true,"configured_runtime_available":true,"live_acceptance_verified":false,"setup_gates":[
                "Explicit approval for funded provider account, outbound number and controlled calls",
                "Provision expiring owner/coordinator credentials, HTTPS, hosted worker and private durable storage",
                "Verified official destinations, pinned published agent and narrowly scoped tools",
                "Canonical upstream policy gates and evidence-backed versioned writeback",
                "Approved geography, consent, retention, rates and residual cost exposure",
                "Measured IVR, hold, latency, offline operation, termination and billing acceptance tests",
                "Verified human takeover and capture isolation; use a separate direct call until proven"
            ]}),
        ),
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return;
        }
        Err(_) => {
            eprintln!("{{\"error\":{{\"code\":\"invalid_command\",\"exit\":2}}}}");
            std::process::exit(2);
        }
    };
    match run(cli) {
        Ok(value) => {
            let mut stdout = std::io::stdout().lock();
            if serde_json::to_writer_pretty(&mut stdout, &value).is_err()
                || writeln!(stdout).is_err()
            {
                std::process::exit(6);
            }
        }
        Err(error) => {
            eprintln!("{}", json!({"error":error}));
            std::process::exit(error.exit);
        }
    }
}
