# Concrete canonical RP adapter

The `RpWorkflow` adapter uses an explicitly selected, existing RP SQLite database.
It never creates a database, migrates its schema, allocates daily work, contacts an
insurer or changes a claim's business status. Source-build tests use original
minimal synthetic schemas and reserved identifiers. They do not open real RP data.

The controller can use this adapter on the same always-on host as the canonical RP
database, with separately approved access to its private directory. A copied cache
or a second independent claim database does not satisfy the authority requirement.
If canonical storage remains on a sleeping laptop, the call controller cannot rely
on this direct adapter: arrange approved colocated storage or implement the HTTPS
workflow protocol against the actual canonical owner. Do not solve that problem by
silently syncing an independent competing ledger.

## Read and write contract

| Canonical table | Adapter use |
| --- | --- |
| `rp_items` | Exact local ID, status, automation status, next action/reason and `updated_at`; marks `notion_sync_status` pending after evidence |
| `rp_claims` | Exact local ID and item link, resolved/status/automation status, next action/reason and `updated_at`; marks sync pending |
| `rp_work_days` | Requires today's sealed allocation in `America/New_York` |
| `rp_daily_selections` | Requires the exact canonical case among at most two persisted slots; never replaces blocked/completed slots |
| `rp_work_state` | Reads the parent's sourced work state; adds bounded voice-result references and conditional recovery steps |
| `rp_operations` | Read-only rejection of reserved, started, confirmed-but-uncommitted, or recovery portal work for the case |
| `rp_activity_log` | Immutable `voice_reserved`, `voice_dispatch_authorized` and `voice_result_recorded` events |

The adapter deliberately does not read payment-card data, claim numbers, metadata
blobs, documents, uploads, credentials or the RP automation configuration. Relevant
canonical writes must update `updated_at`; the snapshot also includes the listed
typed state columns and all parent-owned `rp_work_state.details_json` content. It
hashes the work details locally and never exports them in a snapshot or logs them.
The only excluded work fields are its own additive `voice_results` and
`voice_state_change` namespaces. Unknown or malformed canonical records fail closed.

`rp-snapshot` obtains an eligible work item and policy-gate reference without a
reservation or mutation. References are exact `item:<local-id>` or
`claim:<local-id>`, never fuzzy titles or insurer claim numbers. An item with one
active claim resolves to that claim's exact ID while keeping one daily case slot.
Ambiguous claims, retired/resolved cases, missing work state, parent blockers,
wrong-day/wrong-timezone selection, overfull allocation and uncertain portal work
prevent authorization. The adapter does not interpret a daily slot as call consent.
Authenticated intent approval, directory/rate pins and provider execution gates
remain independently required.

## Durable reservation and publication

Reserve runs in an immediate SQLite transaction. It binds owner, operation ID,
intent digest, canonical work version, purpose digest and policy gate. Replays of
the same binding are harmless; conflicting input is rejected. A second unresolved
reservation for the same item or claim is rejected across separate connections and
across item promotion or claim relinking. The adapter stores this evidence in the
existing activity log; it never inserts a voice action into `rp_operations`, whose
kinds describe portal filing and document response.

Every dispatch and continued-call check re-evaluates canonical eligibility and the
frozen snapshot. Dispatch authorization records evidence of permission, not proof
that a vendor call happened. Leases are at most 60 seconds and never extend past
New York midnight. A parent change invalidates the snapshot. Adding this adapter's
result references alone does not silently revoke an unchanged parent state.

A result version is immutable and identified by operation plus version. The stored
record contains a digest of the original message and a sanitized `CallResult`:
bounded source references and model-reported categories are retained; free-form
human-result/next-action strings are replaced with fixed, conservative language.
Model reports are not verified insurer outcomes. All results require review and
cannot mark a claim complete, submitted, paid, approved or resolved.

Only the newest result version controls reservation release. `call_ended: true`
comes from controller evidence that all legs ended without uncertainty. Missing
legacy values default false and retain the reservation. A newer corrective result
with `call_ended: false` re-locks the case; an older terminal result cannot unlock
it. Idempotent writeback does not create or retry a call.

Publication atomically appends the event, merges the latest operation reference
into the current canonical case's work state, and marks local Notion sync pending.
Promotion/relinking keeps the old reservation lineage while attaching late evidence
to the current case. The adapter changes work state to `needs_recovery` with a fixed
next step only if the original snapshot still matches, or the exact prior state
change belongs to this adapter and remains unchanged. Parent blockers, later source
updates and existing completion evidence are preserved. Older result versions remain
in history without replacing a newer work-state reference. A failed transaction
leaves the result retryable without partial state or a new call.

## Remaining operational gates

This increment does not open the live RP database or provision persistent access.
The parent must select the actual canonical path and approve its use on the hosted
runtime. Canonical RP storage and its existing ownership workflow must remain the
same source of truth. The parent still owns exact Notion-row synchronization and
read-back verification. `notion_sync_status: pending` is an explicit outstanding
step, not a claim of remote publication. No reminders, schedules or parent workflow
settings are modified by this adapter.
