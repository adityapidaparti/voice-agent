# Architecture and contracts

One Rust package contains a typed neutral contract, SQLite controller, provider
boundary, HTTP control surface and CLI. The controller worker is separate from
each CLI request. A deployed controller must run on an always-on host; the local
demo does not prove laptop-sleep independence.

## State and authority

The control boundary assigns a principal from authentication, never from request
JSON. The demo has separate synthetic user/coordinator credentials and binds only
to literal loopback. These known demo tokens provide role tests, not production
identity assurance. Hosted mode instead reads private scoped credential hashes,
checks expiry/revocation on every request, and loads only explicitly configured
provider/RP secrets after an affirmative runtime flag. It cannot reopen a simulation
database as hosted state.

Only the user principal can issue or revoke an approval. A snapshot binds the
destination and provenance, purpose, facts and versions, allowed/forbidden actions,
disclosure, handoff, limits, provider, pinned agent and start window.

Digest v1 is SHA-256 over UTF-8 serde JSON of the typed Intent: fields in declaration
order, fact maps sorted by key, integer money/time, ordered lists, no Unicode
normalization. Unknown fields are rejected. This is an application canonical format,
not RFC 8785. Reordering JSON object keys cannot change the typed digest; reordering
semantic lists does change it. Struct/schema changes require a new contract version.

SQLite uses WAL and FULL synchronous commits. Hosted authority checks happen outside
write transactions. The canonical RP service atomically reserves its own capacity;
the local immediate transaction rechecks approval, reserves phone budget and active
owner/work-item exclusivity, consumes approval and creates the operation. A second transaction marks the send as possibly performed
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
evidence and unknown transfer legs disable starts and retain uncertainty. Rejected
lookup observations retain the known call mapping, record only a fixed diagnostic
code and time, and cannot prevent current or later operations from requesting a stop.
The worker reports that diagnostic after its safety pass; storage failures remain
fail-fast.

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

The service stores operational calls, never a claims ledger. The synthetic gate is
isolated from hosted mode. Hosted mode checks the generic RP authority at preview,
reservation and dispatch. A continuation recheck becomes due after five seconds
or when its lease expires; bounded network work still contributes to actual latency. Authority uncertainty requests a stop. The
canonical service must implement the protocol in workflow-adapter.md.

Dispatch is a bounded lease, not an atomic transaction spanning two providers.
After a grant and local send fence, a concurrent revocation is an in-flight stop
request. The worker refreshes its monotonic clock after blocking operations and
Retell rechecks the lease and approval immediately before POST. No claim is made
that a revocation racing an already admitted network send can retract that send.
Authoritative lookup/create receipts establish hosted call identity; signed phase
reports cannot seize an unknown call ID.

A durable outbox carries operation ID, result version, canonical work reference/version,
observed evidence references, cost uncertainty and next action. The consumer must
deduplicate operation/version and use optimistic concurrency. Conflict or lost
acknowledgement leaves the item pending; retrying that write never triggers a call.
No model success label or transfer can mark a claim submitted, paid or complete.
Categorical answer callbacks carry only a closed vocabulary of status, document
categories and next step. They are marked unverified_model_report and remain
needs_review. Signatures establish source, not truth. The outbox carries these
observations to the existing canonical record; it does not create claim authority.
Later corrective versions are attempted even if an older writeback failed.

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
explicit test substitutes. The hosted transport/auth/configuration code is available,
but real provider setup, the actual RP-side protocol implementation and deployment
acceptance remain external gates. Native DTMF and transfer stay disabled.

Hosted admission allows one active or uncertain call globally. This bounds provider
and authority servicing without a worker pool; a different owner cannot queue a
second call. Late contradictory evidence can still reveal an older uncontrolled
leg, which latches a global incident and requests stops. New report callbacks are
rejected after AI stop/takeover/termination; only exact previous reports can replay.
A registered call found by authoritative lookup binds its ID even without a vendor
start timestamp, so revocation can stop ringing without fabricating start evidence.

Ended calls awaiting evidence are background work. At most one receives a lookup
per tick, selected by a rotating cursor. A fresh database check suppresses that
lookup while any operation is active. A new call admitted during the check/send
race can encounter one bounded historical lookup, never a full batch of them.
