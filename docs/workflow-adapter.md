# Generic canonical-workflow adapter

This is a proposed versioned HTTP contract for a canonical return-protection (RP)
service. It is not an implementation of a known RP vendor API. The adapter has no default
production endpoint, account or credential discovery; hosted configuration supplies
an explicitly approved endpoint.
All executable examples and peers in `tests/workflow.rs` are synthetic. Passing
these tests does not establish live-provider or live-RP acceptance.

The canonical workflow owns business eligibility, revocation, quotas, reservations
and claims. Voice-agent stores operational state and a durable result outbox. It
does not create a second claims ledger or treat a completed call as a completed
business objective.

## Rust boundary

`WorkflowAuthority: Send` provides
`authorize(&mut self, &GateRequest, now: i64) -> Result<GateDecision>`.
`GateDecision::validate` also supports independent contract checks. `HttpWorkflow`
implements this authority and the controller's existing `CanonicalWorkflow`
writeback interface.

`HttpWorkflow::new(base_url: &str, bearer_token: String)` accepts an HTTPS origin
with no URL user information, path prefix, query or fragment. Construction does not
send a request. The caller must provide an explicitly authorized endpoint and
credential through its approved secret-management mechanism. The adapter never
reads environment variables or local credential files.

`HttpWorkflow::for_loopback_tests(base_url: &str, timeout: Duration)` accepts only
literal loopback HTTP, such as `http://127.0.0.1:12345`, and always uses the fixed
synthetic token `synthetic-workflow-token`. It cannot accept a real token. This
explicit test constructor does not enable production HTTP transport.

Both constructors disable environment proxies, redirects and automatic retries.
Production uses verified TLS, a five-second total timeout and a three-second
connection timeout. Test timeouts must be positive and at most five seconds.
Request and response bodies are limited to 65,536 bytes. Errors expose a fixed
diagnostic code; they never echo response bodies, bearer tokens or full URLs.

## Authority request

Send `POST /v1/voice/authorize` with bearer authentication and JSON content type.
The body has exactly these fields, in the typed Rust declaration order:

```json
{
  "owner": "synthetic-owner",
  "operation_id": "op_example",
  "digest": "sha256:<approved-intent-digest>",
  "work_item": {
    "system": "return_protection",
    "reference": "work_demo",
    "version": "v1"
  },
  "policy_gate_ref": "gate_demo_v1",
  "purpose_digest": "<hex-sha256-of-purpose>",
  "stage": "reserve",
  "reservation_id": null
}
```

The server returns HTTP 200 with:

```json
{
  "request_digest": "<hex-sha256-of-exact-request-body-bytes>",
  "allowed": true,
  "expires_at": 1060,
  "reservation_id": "reservation_example"
}
```

The request contains opaque references and digests, not the fact packet or purpose
text. `request_digest` has no `sha256:` prefix. The client computes it over its
compact UTF-8 typed JSON, including explicit null fields. A server can hash the
received body bytes directly, avoiding another language's JSON reserialization.
Unknown decision fields are rejected.

The `Idempotency-Key` is `voice_` followed by hex SHA-256 over compact JSON of the
three-element array `[operation_id, digest, stage]`. This key is stable across an
ambiguous request outcome and differs between stages. The canonical service must
bind a key to one scope and one reservation; it must reject a conflicting request.
Repeated evaluations must still check current revocation and issue fresh expiry
times. Idempotency must not cache an old allowed decision indefinitely.

The stage names are `preview`, `reserve`, `dispatch` and `continue`:

| Stage | Canonical service responsibility |
| --- | --- |
| Preview | Check eligibility without allocating or consuming call authority. |
| Reserve | Atomically reserve canonical capacity once for this operation and scope. |
| Dispatch | Recheck the same reservation immediately before possible submission. |
| Continue | Recheck the reservation and revocation while the call remains active. |

The adapter accepts only `allowed: true`, the matching request digest and a
decision whose expiry is strictly after `now` and no more than 60 seconds ahead.
All stages except preview require a nonempty opaque reservation identifier. An
identifier is at most 128 ASCII bytes containing letters, digits, `_`, `-`, `.`,
or `:`. If the request already includes a reservation, the response must return
that exact reservation. An optional preview reservation must also be valid.

Denial, stale authority, changed reservations, mismatched request digests, malformed
responses and transport uncertainty all fail closed. The adapter makes one HTTP
attempt and never silently repeats an authority request. The controller owns the
decision to block dispatch or request a stop; these adapter tests do not replace
tests of those controller boundaries. If a reserve response is lost, the canonical
service must retain the same reservation for reconciliation under the same key.

## Result writeback

Send `PUT /v1/voice/results/{operation_id}/{result_version}` with the complete
typed `Writeback` JSON and bearer authentication. `If-Match` carries the canonical
work-item version as a quoted strong ETag, for example `"v1"`. The canonical
service must atomically compare that version and deduplicate operation/version.
The adapter rejects inconsistent outer and embedded operation, result-version or
work-item fields before making a request.

HTTP 200 or 201 must include exactly:

```json
{
  "operation_id": "op_example",
  "result_version": 7,
  "status": "applied"
}
```

`status` is `applied` or `already_applied`; operation ID and numeric result version
must equal the request. Unknown fields, unknown statuses and mismatched identities
are errors. HTTP 409 returns `Conflict` without interpreting its untrusted body.
Every other status, malformed acknowledgement, timeout or dropped body is an
error. None of these outcomes acknowledges outbox delivery.

After uncertainty, retrying the same outbox entry repeats the same PUT path and
body. The canonical service returns `already_applied` if it committed the prior
attempt. This retries result delivery only: it must not create another call,
refresh user approval, mark business completion or overwrite conflicting
canonical state. A newer corrective result uses a larger result version and
remains subject to optimistic concurrency.

## Validation and activation gates

The test suite supplies independent loopback peers for wire identity, allow/deny,
expiry, reservation mismatch, malformed JSON, excessive bodies, redirects, dropped
responses, timeouts, HTTP 500 and writeback conflict. Hegel properties exercise
full-width clocks with a wider-arithmetic lifetime oracle and valid/invalid opaque
reservations. An outbox integration test checks persistence across a lost
acknowledgement and restart without another provider create. These are offline
synthetic checks; report execution results separately from the presence of tests.

Before activation, the actual RP owner must approve and implement this protocol,
including atomic reservations, freshness/revocation, scope-bound idempotency,
reconciliation, optimistic concurrency and corrective result semantics. The
operator must separately authorize endpoint access and credentials, verify TLS and
service authentication, define clock-skew policy, and run authorized staging
contract tests. Hosted deployment, paid services and real calls require their own
explicit authorization. This source build authorizes none of those actions.
