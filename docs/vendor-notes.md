# Retell boundary, checked 23 October 2026

These are implementation constraints, not a claim that an account is configured.

The [create-call API](https://docs.retellai.com/api-references/create-phone-call)
uses `POST /v2/create-phone-call`, an owned source number, destination, agent/version,
optional per-call overrides and a provider idempotency key. That key deduplicates the
same request for up to one hour. Our controller still never retries a create.
Metadata is for correlation; approved task context is placed in dynamic variables.
Per-call LLM overrides do not replace arbitrary tools or prompts: the pinned base
configuration must be fetched and verified before a future live adapter can run.

[Webhook verification](https://docs.retellai.com/features/secure-webhook) uses
`v=timestamp_ms,d=hex` and HMAC-SHA256 over the exact body concatenated with that
timestamp. Verify freshness and signature before parsing or storing an allowlisted
envelope. Use the key marked for webhook verification. Re-serialized JSON is not the
signed byte sequence.

[Lifecycle webhooks](https://docs.retellai.com/features/register-webhook) may arrive
separately for start, end and analysis. Only minimal typed facts are persisted.
A provider success label has no canonical business authority.

[Live monitoring](https://docs.retellai.com/features/live-monitoring) documents that
browser takeover permanently stops the AI and pauses the live transcript. That
does not prove recording or other capture isolation. Browser takeover remains disabled;
sensitive verification uses a separate human-direct call.

[Stop call](https://docs.retellai.com/api-references/stop-call) targets the known call
at `POST /v2/stop-call/{call_id}`. A lost response requires reconciliation.

[Agent settings](https://docs.retellai.com/api-references/create-agent) define maximum
duration and silence limits. The wire builder checks supported ranges rather than
silently widening approved limits. Retell's Basic Attributes Only mode minimizes
retained data; it is not a promise of zero processing or zero temporary storage.
