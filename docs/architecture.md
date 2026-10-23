# Architecture and contracts

One Rust package contains a typed neutral contract, SQLite controller, provider
boundary, HTTP control surface and CLI. The controller worker is separate from
each CLI request. A deployed controller must run on an always-on host; the local
demo does not prove laptop-sleep independence.

## State and authority

The control boundary assigns a principal from authentication, never from request
JSON. The demo has separate synthetic user/coordinator credentials and binds only
to literal loopback. These known demo tokens provide role tests, not production
identity assurance. No provider credentials are loaded.

Only the user principal can issue or revoke an approval. A snapshot binds the
destination and provenance, purpose, facts and versions, allowed/forbidden actions,
disclosure, handoff, limits, provider, pinned agent and start window.

Digest v1 is SHA-256 over UTF-8 serde JSON of the typed Intent: fields in declaration
order, fact maps sorted by key, integer money/time, ordered lists, no Unicode
normalization. Unknown fields are rejected. This is an application canonical format,
not RFC 8785. Reordering JSON object keys cannot change the typed digest; reordering
semantic lists does change it. Struct/schema changes require a new contract version.

SQLite uses WAL and FULL synchronous commits. An immediate transaction checks the
fresh upstream gate, reserves budget and active-owner exclusivity, consumes approval
and creates the operation. A second transaction marks the send as possibly performed
before calling the provider. A crash in that gap deliberately sacrifices availability:
the attempt stays unknown, even if no send occurred. Reconciliation uses only reads.
No create retry is implemented, including Retell's limited one-hour idempotency window.

Same owner/key/digest retrieves the original operation; changed digest conflicts.
Concurrency and budget reservations survive unknown responses. The synthetic daily
cap is USD 25 in UTC; its independent phone budget does not implement any upstream
business quota. A conservative versioned synthetic rate reserves rounded minutes
plus stop allowance. These amounts authorize no real spend.

The event inbox stores authenticated minimal observations before acknowledgement.
Operation binding and inbox insertion are atomic. Processing and versioned outbox
insertion share a transaction. Duplicate provider event identities do not mint result
versions. Reordered starts cannot reverse normal terminal state. Contradictory provider
evidence and unknown transfer legs disable starts and retain uncertainty.

Stops are repeat-safe requests against a known call ID. A receipt is not proof of
termination. Duration, hold and handoff deadlines run in the controller worker.
Repeated hold observations cannot reset the hold clock. Three IVR menu observations
request termination. Actual voice/DTMF detection and silent hold behavior need
controlled provider tests.

## Human boundaries

Only manual fallback is accepted in this release. Authentication, payment,
attestations and scope changes require the human. Browser takeover and warm transfer
cannot be enabled by an intent. An observed takeover permanently stops AI participation;
the human segment stays unobserved. Capture isolation is unproven, so credentials must
use a separate direct call. Unknown transfer legs retain their lock even after a
primary call ends.

## Canonical workflow

The service stores operational calls, never a claims ledger. The synthetic gate checks
an opaque workflow reference/version/expiry before reservation and dispatch. A real
upstream adapter must perform authoritative reservation and revocation checks.

A durable outbox carries operation ID, result version, canonical work reference/version,
observed evidence references, cost uncertainty and next action. The consumer must
deduplicate operation/version and use optimistic concurrency. Conflict or lost
acknowledgement leaves the item pending; retrying that write never triggers a call.
No model success label or transfer can mark a claim submitted, paid or complete.

## Privacy and limitations

Unknown input fields, non-allowlisted fact keys and obvious secret patterns are rejected.
Text filters are defense in depth; they cannot establish that arbitrary prose contains
no secret. Authenticated human packet review remains necessary.

No raw transcript, recording, signed URL or freeform provider analysis enters durable
events or routine logs. Working intent snapshots are logically removed on final
analysis, definitive failure or within 24 hours; unused approvals expire too.
SQLite WAL, filesystem snapshots and backups may retain prior bytes: this is not
cryptographic erasure. Production needs encrypted storage, retention/checkpoint and
backup policies, scoped deletion and tested recovery. Minimal operational tombstone
retention is unresolved; old keys must not become new dial authority.

The demo gate, trust directory, rates, fixed credentials and simulated provider are
explicit test substitutes. Production startup, worker-health admission, secret-manager
integration, a real RP adapter and browser controls are deliberately unavailable.
