# Activation and acceptance gates

Public source and a configurable transport do not authorize calls or expenditure.
This build used only synthetic facts, fake HTTP peers and reserved example numbers.
No account, real credential, number, hosted service or real call was used.

| Gate | Implemented and tested offline | External acceptance still required |
|---|---|---|
| Approval/control | Scope digest, owner/role checks, hashed expiring credentials, revocation, HTTPS CLI | Provision separate human/coordinator access; privately review the actual recipient, purpose, facts, window and budget |
| Durable runtime | SQLite environment separation, reservations, restart recovery, stop-first worker and independent outbox worker | Authorized always-on host, TLS, private persistent storage, backups, recovery, monitoring and laptop-sleep test |
| Retell | HTTPS create/get/list/stop, exact published agent/LLM pins, bounded transport, no create retries | Authorized account, terms, outbound KYC, number, scoped key, approved published agent, funding and actual provider acceptance |
| Canonical RP | Existing SQLite allocation/ownership adapter, immutable activity evidence and conditional work-state updates; synthetic fixtures | Authorize colocated access to the existing RP database, validate its schema and perform parent-owned exact Notion row sync/read-back; no new HTTP service required |
| Limits | Complete configured rate reference, daily/call reservations, absolute deadline and dispatch lease | Current all-in pricing, explicit spend approval, measured ringing/stop delay and all-leg billing; no claim of an exact hard dollar cap |
| IVR/hold | Signed bounded phase observations; menu/hold timers; spoken menu instructions | Own-number test, silent hold/audio behavior and latency; model phase classification is not guaranteed |
| DTMF | Explicit approved/pinned native public-menu profile; default remains spoken-only | Native digits are model-guided, without deterministic digit/count enforcement. Verify own-number menu navigation and signed observations before use; sensitive input always requires a separate direct call |
| Human boundary | AI disclosure; no impersonation; stop on authentication/refusal; no transfer tool | Test user stop control and refusal handling. Sensitive verification remains in a separate direct call |
| Result capture | Lifecycle/cost evidence plus signed categorical answers marked unverified; versioned canonical outbox | Compare own-number test observations with reality; canonical RP decides business meaning. Basic Attributes Only does not retain a later-fetchable transcript |
| Privacy/legal | Args-only callbacks, no raw transcript/media retention, private runtime files | Applicable calling/consent review, provider terms, encrypted host/storage/backup retention and verified deletion |

Activation order: (1) approve account/number/budget/host/access setup;
(2) connect the actual canonical RP authority and result sink;
(3) review the complete nonsecret configuration and published-agent pins;
(4) authorize a synthetic test call to the user's own verified number with explicit
cost/time bounds; (5) verify stop, response-loss reconciliation, result capture and
laptop independence; (6) separately approve the specific Amex recipient/purpose/facts
and cost envelope. The source build does not perform these actions.

`voice config-check` validates configuration without secrets or network. Only
`voice serve --config ... --enable-live-calling` loads explicitly named runtime
credentials; `starts_enabled` and a fresh user approval are still required.
Do not use demonstration tokens, contacts, rates or gates in a live deployment.

Retell processes audio even with Basic Attributes Only. The absence of retained
recordings is not proof that sensitive authentication is isolated. Do not transmit
payment-card data, financial account identifiers, SSNs, OTPs, PINs or passwords.
Transfer and same-call authentication cannot be enabled by an intent.
