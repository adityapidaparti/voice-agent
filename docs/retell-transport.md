# Retell transport

The runtime adapter uses the published Retell REST API through HTTPS. Construction
is offline. The hosted service selects the live adapter only through its explicit
configuration and calling switch; individual calls still require a frozen user
approval and an authoritative workflow lease.

Each dispatch reads the numeric agent and LLM versions, requires both to be
published, compares the complete canonical JSON snapshots with reviewed SHA-256
pins, and independently checks the safety profile. A matching hash cannot enable
arbitrary tools, knowledge bases, transfer, captured DTMF input, contact memory,
open retention, or a different prompt. Native menu navigation has its own explicit
profile and exact prompt/tool snapshot; a pin cannot promote the default profile
to that capability. This intentionally fails closed when even
an unrecognized snapshot field changes. Review and update the pins after a vendor
configuration change; do not replace them automatically.

The approved profile uses `basic_attributes_only`, at most 30 days of basic
attribute retention, no session hooks or post-call analysis fields, and an exact
`end_call` tool. `spoken_only` remains the default menu-navigation profile, with
its existing restrictive template unchanged. When a webhook endpoint is configured, it also requires the exact
minimal `observe_phase` and `report_answer` custom tools for that controller
origin. The per-call
payload carries only the approved facts, purpose and rules plus operation/digest
correlation. Financial account identifiers, card details and authentication data
must never enter this AI call. Authentication remains a separate direct call.

Transport requests have two-second timeouts, no proxies, no redirects and no
automatic retries. Two configuration reads and one create have a ten-second
preparation budget. The authoritative dispatch lease and intent expiry are checked
again using elapsed monotonic time after configuration reads and immediately before
submission. Before create, the remaining approved deadline reserves 30
seconds for ringing, two seconds for submission and five seconds for stop margin.
Retell requires at least 60 seconds of connected-call duration, so fewer than 97
seconds remaining after configuration checks is rejected. Short approvals are
never silently extended. These bounds are conservative client controls, not a
vendor guarantee about all billing or network delays.

A 201 response must contain the expected call identity, destination, agent version
and operation/digest metadata. Documented 400/401/402/422/429 responses reject the
one consumed attempt. Timeouts, server errors, redirects, malformed success bodies
and mismatched success metadata retain an unknown outcome. There is no automatic
create retry, including within Retell's documented one-hour idempotency window.

Known calls reconcile with `GET /v2/get-call/{call_id}`. Unknown create outcomes use
`POST /v3/list-calls`, filtered by agent and operation metadata, with local digest
and identity validation. Pagination is bounded to three pages of 100 records;
incomplete listings, repeated cursors or multiple call identities stay unresolved.
A unique registered call is bound even before it has start/end timestamps, so a
revoked ringing call can be stopped without fabricating connection evidence.
An empty list never authorizes a new call. `POST /v2/stop-call/{call_id}` requests
termination; a successful response is not evidence that every leg ended.

Polling normalizes only timestamps, identity, termination evidence and cumulative
cost. Different cumulative costs become distinct evidence; the controller retains
the maximum observed cost independent of delivery order. It discards transcripts,
recording links and model-generated success fields. Under Basic Attributes Only,
later transcript retrieval cannot be used as a result-capture mechanism. Minimal
phase and answer callbacks provide result capture without later transcript
retrieval. Answers use only bounded status, document-type and next-step categories,
with no free text or financial identifiers. Authentication proves the source of a
report, not the correctness of the model's interpretation: these reports remain
unverified evidence and require canonical review. Neither reports nor polling
establish business completion.

Native `press_digit` is excluded from `spoken_only`: a DTMF-required boundary ends
that profile's call. The separately approved `model_guided_public_menu` profile
adds the exact `press_public_menu_digit` native tool with `delay_ms: 5000`. Both the
frozen intent and runtime Retell configuration must select that profile. The
controller's verified directory must authorize it too. Changing the profile
changes the intent digest and requires a new approval; selecting a different
published tool snapshot cannot substitute for that approval.

The opt-in prompt permits only a clearly announced single public department-routing
digit relevant to the approved purpose, after the full menu and a successful signed
`dtmf_required` observation. In this profile that phase means public-menu
navigation; in `spoken_only` it remains a stop boundary. The `uncertain_menu` and
`prohibited_action` phases always request a stop. The prompt also stops for
sensitive input, authentication, payment, account/reference codes, extensions,
attestation, legal
acceptance, refused consent or any action outside public routing. Operators must exclude financial identifiers from the approved fact packet.
The accidental-secret heuristic cannot prove their absence; human packet review
remains required. Transfers remain disabled and
unexpected transfer evidence blocks further work for review.

These are model instructions, not exact digit or press-count enforcement. Retell's
native tool can technically choose digits and sequences at runtime; its published
schema exposes a name, description and delay, not a digit allowlist or authorization
callback. Controller deadlines, observed safety boundaries, approval revocation and
stop requests still apply, but they cannot prove which digits the model sent. The
bounded neutral `DtmfPlan` remains unavailable as an exact Retell execution contract.

The native profile requires a configured public HTTPS callback origin and the exact
signed observation/result tools. Literal-IP and syntactically local-only callback hosts are rejected, including
trailing-dot variants. This is a syntax check, not proof of public reachability. Actual vendor-to-host reachability and own-number IVR behavior still need
an explicitly authorized deployed acceptance test; offline configuration checks do
not establish either. No native-menu call is enabled implicitly by a missing field:
omitted `menu_navigation` deserializes as `spoken_only`.

All integration tests use a literal-loopback fake HTTP service and a fixed synthetic
credential. They are protocol and failure tests, not live-provider acceptance.

Primary API references checked 2026-10-23:

- [Create Phone Call](https://docs.retellai.com/api-references/create-phone-call)
- [Get Voice Agent](https://docs.retellai.com/api-references/get-agent)
- [Get Retell LLM](https://docs.retellai.com/api-references/get-retell-llm)
- [Get Call](https://docs.retellai.com/api-references/get-call)
- [List Calls](https://docs.retellai.com/api-references/list-calls)
- [Stop Call](https://docs.retellai.com/api-references/stop-call)
- [Press Digit](https://docs.retellai.com/build/single-multi-prompt/press-digit)
- [Official SDK tool schema](https://github.com/RetellAI/retell-typescript-sdk/blob/main/src/resources/llm.ts)
- [Data storage settings](https://docs.retellai.com/accounts/privacy-disable)
