# Hosted control and setup

Retell hosts the voice agent and telephony. The Rust service owns approval,
reservation, reconciliation, deadlines and canonical result writeback. Run it on
an always-on host so closing the CLI or sleeping a laptop does not stop its worker.
The source build does not provision a host, install credentials or make a call.

`voice serve --simulation --db controller.db --provider-db provider.db` remains a
fully synthetic loopback service. Production integration requires both a private
configuration file and the affirmative `--enable-live-calling` flag. `starts_enabled`
in configuration also controls admission; each operation still requires an
unexpired, matching user approval. The worker resumes durable operations after a
restart. A latched safety incident continues to block new starts.

## Private files and operator credentials

Use a dedicated unprivileged service identity, a mode-0700 configuration directory,
a mode-0700 persistent data directory and mode-0600 files. Paths must be absolute.
The service refuses symlink files and nonprivate configuration, credential, SQLite,
WAL and shared-memory files. Do not put these runtime files in Git or backups that
lack equivalent protection. Configure retention and encrypted host storage as part
of deployment review; SQLite logical cleanup is not evidence of erased backups.

Controller credentials have the form `v1.<credential-id>.<64 lowercase hex digits>`.
The final component must be generated from 32 bytes of operating-system randomness
by the authorized operator. It must never be a password or a real account number.
Generation, installation and persistent access are setup actions, not part of a
source-build run. Provision distinct credentials for the human user and assistant
coordinator. `voice credential-digest` reads an already supplied `VOICE_TOKEN` and
prints only its SHA-256 digest; it does not generate or install access.

The credentials file has this schema (the placeholders are intentionally invalid):

```json
{
  "schema_version": 1,
  "credentials": [
    {
      "id": "operator",
      "owner": "owner-example",
      "role": "user",
      "token_sha256": "REPLACE_WITH_FULL_BEARER_SHA256",
      "not_before": 0,
      "expires_at": 0,
      "revoked": false
    },
    {
      "id": "assistant",
      "owner": "owner-example",
      "role": "coordinator",
      "token_sha256": "REPLACE_WITH_DIFFERENT_BEARER_SHA256",
      "not_before": 0,
      "expires_at": 0,
      "revoked": false
    }
  ]
}
```

Credential lifetimes may not exceed 30 days. Use much shorter lifetimes where
practical. Roles and ownership come from the private record, never from request
parameters. Coordinators cannot approve or revoke approvals. Atomic replacement
of the private credentials file revokes or rotates access on the next request;
malformed or unreadable replacements fail closed. Replace the file without making
its parent or contents group/world accessible. Keep a separate host-admin recovery
route for expired credentials. Simulation tokens are not accepted in hosted mode.

## Configuration and launch

`deploy/config.example.json` shows the full nonsecret shape. It intentionally fails
validation: its pins are placeholders and its synthetic directory is expired. The
example numbers, rates and budgets are not approved production configuration.

The main JSON config uses `schema_version: 1`, `starts_enabled`, `public_origin`
(an HTTPS origin), `listen` (literal loopback with a fixed port), `database` and
`credentials_file` (absolute private paths), `retell_key_env` and
`workflow_token_env` (distinct `VOICE_` environment names), `workflow_base_url`
(an HTTPS origin), `policy` (the approved directory and rate pins), and `retell`
(the pinned provider configuration). Unknown fields are errors. An optional Retell
webhook URL must equal `public_origin` plus `/v1/webhooks/retell`.

Run `voice config-check --config /absolute/private/config.json` before launch.
This checks schema, pins, policy expiry and file permissions without reading the
provider/RP environment secrets or making network requests. A successful check
is not a live-provider or deployment acceptance result. Configure secrets through
the host's secret mechanism. The service reads only its two explicitly named
secret variables, and only in the live runtime; secrets never belong in command
arguments or source files.

The reviewed launch command is:

```sh
voice serve --config /etc/voice-agent/config.json --enable-live-calling
```

`deploy/voice-agent.service` and `deploy/Caddyfile` are operator-review templates,
not deployed resources. The service listens only on loopback. A TLS reverse proxy
must bound request/body/header time and size, restrict ingress and avoid request
body or authorization logging. Caddy's example hostname is reserved and cannot be
used as a real deployment. Verify the selected host, operating-system hardening,
DNS, certificate issuance, egress policy, restarts and backup behavior before use.

Provider polling and stop checks run independently of canonical writeback. An RP
writeback timeout leaves the outbox pending and does not occupy the stop worker.
Ended calls awaiting evidence receive at most one background lookup per tick in
round-robin order, and none while another operation is active. Admission during
that one read cannot start a whole historical polling batch. Authenticated `/health`
reports worker and writeback freshness separately. A stale
call worker prevents admission. Errors and HTTP responses use fixed codes instead
of echoing provider bodies, credentials or fact packets.

## Parent control route

Use `VOICE_TOKEN` from the authorized secret mechanism and
`voice --controller https://<approved-controller-host> --json ...` for approval,
start, status, result, end and revoke. HTTPS validates the server certificate;
redirects, proxies and automatic retries are disabled. Plain HTTP is accepted only
for a literal loopback simulation address. A response timeout means inspect the
same operation/idempotency key; it is never permission to submit a fresh attempt.
The user credential is used only for approval/revocation; the assistant uses its
coordinator credential for approved operations. Do not share the user credential
with the assistant.

Retell event callbacks use `/v1/webhooks/retell`; the narrow signed phase tool uses
`/v1/functions/observe`; the bounded answer-report tool uses `/v1/functions/report`.
Their HMAC signature is verified before parsing, and the
body is bounded. Polling works without callbacks, but fine IVR/hold observations
require a reachable authenticated tool endpoint. Disabling retained transcript
and recording does not remove transient provider processing or callback delivery.
Never place a card/account number, security code, password, PIN, OTP or other
financial authentication data in an intent, tool payload or captured call.

## Required acceptance before an Amex workflow

The parent must arrange approved Retell signup/terms/KYC, an outbound number and
funding; approved hosting and secrets; an actual canonical RP adapter matching the
published protocol; verified official recipient and purpose; and explicit call and
cost bounds. First conduct a separately approved own-number test with synthetic
facts, then verify expiry/revocation, AI disclosure, interruption/stop, restart,
IVR/hold behavior, cost accounting and canonical result capture. A successful
synthetic HTTP test cannot substitute for this test call.

An Amex call must clearly identify the assistant as AI and honor refusal or scope
changes. Same-call sensitive authentication and capture isolation are not verified.
Stop the AI call and let the user authenticate through a separate direct call;
do not claim transfer has isolated audio or resumed the AI safely. Basic Attributes
Only means later Get Call cannot supply retained transcript evidence. Results must
use minimal signed observations and verified lifecycle/cost evidence; unknown
business outcomes remain marked for review in the canonical workflow.

Template references: [Caddy server timeouts](https://caddyserver.com/docs/caddyfile/options#timeouts),
[Caddy body limits](https://caddyserver.com/docs/caddyfile/directives/request_body),
and [systemd service execution sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
The templates have not been installed or validated against a chosen host.
