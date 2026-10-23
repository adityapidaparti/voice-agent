# Retell transport

The runtime adapter uses the published Retell REST API through HTTPS. Construction
is offline. The hosted service selects the live adapter only through its explicit
configuration and calling switch; individual calls still require a frozen user
approval and an authoritative workflow lease.

Each dispatch reads the numeric agent and LLM versions, requires both to be
published, compares the complete canonical JSON snapshots with reviewed SHA-256
pins, and independently checks the safety profile. A matching hash cannot enable
arbitrary tools, knowledge bases, transfer, captured DTMF input, contact memory,
open retention, or a different prompt. This intentionally fails closed when even
an unrecognized snapshot field changes. Review and update the pins after a vendor
configuration change; do not replace them automatically.

The approved profile uses `basic_attributes_only`, at most 30 days of basic
attribute retention, no session hooks or post-call analysis fields, and an exact
`end_call` tool. When a webhook endpoint is configured, it also requires the exact
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

Native `press_digit` is excluded: its documented configuration has prompting and a
pause delay, not an enforceable per-call digit allowlist or authorization callback.
A DTMF-required boundary ends this profile's call. The bounded neutral menu contract
must not be represented as live Retell digit execution. Transfer is also disabled;
unexpected transfer evidence leaves the operation blocked for review.

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
- [Data storage settings](https://docs.retellai.com/accounts/privacy-disable)
