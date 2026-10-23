# Testing evidence

Run `cargo test --locked` for examples, process integration and Hegel properties.
The checked-in Hegel development profile uses 2,000 cases per property; CI uses 5,000.
A reported passing count applies to generated cases, not every possible schedule or input.

## Research applied

- [Claessen and Hughes, QuickCheck (2000)](https://www.cs.tufts.edu/~nr/cs257/archive/john-hughes/quick.pdf):
  generation distribution is part of the test design. We combine hostile full-range
  values with constructed valid intents, collisions and exact boundary examples.
  Digest checks pin a known SHA-256 answer and compare independently reordered JSON.
- [Hughes, Experiences with QuickCheck](https://publications.lib.chalmers.se/records/fulltext/232550/local_232550.pdf):
  generated command sequences are checked against a smaller state model; rejected
  transitions and crash boundaries matter as much as accepted examples. Disk and
  concurrency tests supplement the sequential model.
- [Petrović et al., Practical Mutation Testing at Scale (2021)](https://arxiv.org/pdf/2102.11378):
  mutations are concrete test goals. We focus mutations on safety policy and lifecycle
  code, inspect survivors, and distinguish caught faults from unbuildable/equivalent
  mutants instead of presenting a blanket percentage as proof.

The prior CLI projects informed generic practices: sentence-named properties with a
user-facing reason, independent oracles, full-domain rejection tests, synthetic
fixtures, small native CLIs, narrow credentials, and minimal user documentation.
No private transcripts, prior implementation code or personal records are included.

## Coverage boundaries

Examples cover approval role/owner/expiry/revocation/digest changes; same-key replay;
single-attempt consumption; global active guard; concurrent starts; lost create/stop
responses; restart; state/event ordering; deadlines; stale policy gates; outbox
deduplication/conflicts; logical snapshot expiry. Process tests exercise real loopback
HTTP, actual CLI parsing, separate identities and clients that exit before results.

Properties cover digest identity and changes, full numeric limits, unknown fields,
secret rejection, event-state nonregression and model-generated transitions.
Provider tests pin the webhook signature algorithm, raw-byte dependence, time window,
payload minimization and schema-shaped requests.

Live audio, real billing, physical erasure, hosted outages and true account authentication
are untested. See the release matrix. A build or synthetic test is not evidence that
Retell is configured or a business will accept an AI caller.

## Verification ledger

Initial automated mutation run: 122 mutants in validation, budget estimation and
operation lifecycle; 90 caught, 32 survived, zero unbuildable mutants and zero timeouts.
This intentionally exposed insufficient direct assertions for individual validation
rules, early menu termination, normal start transitions and exact result versions.
Tests were strengthened before the final rerun. The interrupted parallel rerun
produced no completed mutant results and is not counted as passing evidence.

Review fixes include atomic approval issuance, durable pending call identity, conflicting
webhook quarantine, corrective outbox versions after late incidents, monotonic cost
observations, unused approval expiry and expired-window CLI recovery. A separate
uncertain-leg flag now survives revocation, repeated conflicts cannot starve stops,
and safety incidents stop other active operations. Independent reviewers read source
without inheriting the test suite.

Logical deletion does not certify physical deletion from SQLite WAL or backups.

## Offline reference baseline verification

The final automatic contract run tested 123 mutations: all 123 were caught, with
zero survivors, zero unbuildable mutants and zero timeouts. The earlier 32 survivors
were inspected and covered with independent validation, boundary and transition
assertions; no mutation was excluded to improve the count. This run targeted the baseline
contract source before hosted integration. The subsequent lookup-rejection controller fix has its
own seeded fault and full-suite regression validation.

The baseline suite passed from the requested project folder: 103 checks, including
26 Hegel properties at 5,000 cases each (130,000 generated cases), 39 controller
regressions, 14 ordinary contract checks, 17 ordinary provider checks and seven CLI
process integrations. Formatting and Clippy with warnings denied also passed.

All seven separately seeded safety mutations were caught by regression assertions:
approval digest bypass, duplicate dispatch after ambiguity, conflicting-event
suppression, premature reservation release, stale cost overwrite, missing incident
correction, and rejected observations starving safety stops. None survived, failed
to compile or timed out. These seeded faults supplement the automatically generated
contract mutations.

Run heavy verification jobs sequentially on a development machine:

```sh
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1
HEGEL_TEST_CASES=5000 cargo test --locked --offline
HEGEL_TEST_CASES=200 cargo mutants --file src/contract.rs \
  --re 'Operation::|Intent::validate|Intent::estimate_cents' \
  --jobs 1 --jobserver-tasks 1 --timeout 60 --build-timeout 240 \
  -- --test core --test properties --test provider
python3 scripts/seeded_mutations.py
```

The mutation harness always uses scratch copies and checks an unmodified baseline.
The lower property case count makes mutation feedback practical; the unmodified
release suite uses 5,000 cases. Assertions and supported input ranges are unchanged.
No mutation score establishes correctness beyond the tested faults and distributions.

Publication checks used Gitleaks 8.30.1 and the project privacy tripwire against
candidate files and Git history. Cargo metadata reported license expressions for
all 173 resolved packages; the review found permissive licensing options throughout.
The repository contains synthetic fixtures and authored source, not private input
specifications, transcripts, recovery archives or personal workflow records.

## Hosted integration verification

Hosted adapter examples use independent loopback peers for exact requests, pin
mismatch, malformed or excessive responses, redirects, ambiguous create outcomes,
pagination conflicts, delayed configuration reads and stopped-call reconciliation.
Authority tests cover all stages, durable reservations, database environment binding,
revocation during an unlocked network request, delayed lease/approval expiry,
cross-owner canonical work-item locking, unbound callback rejection and stop
priority over rejected history. Args-only phase/answer reports have closed schemas,
independent signature vectors and full-range clock/scope properties.

The final integrated suite passed 188 tests, including 43 Hegel properties
configured for 5,000 cases each. The composition test runs independent fake Retell
and RP servers through approval, reservation, a lost create receipt, delayed call
visibility, restart, signed categorical observations, revocation, stop receipts,
terminal evidence and lost writeback acknowledgements. It verifies that newer
canonical corrections survive replay of an older result. It uses a synthetic HTTP
500 for the uncertain create response, not a real provider or physical network cut.

Three scheduling examples and a generated history/active-state property bound
background lookups and verify fair rotation, active-call priority and admission
during a background request. The oracle counts network operations, without sleeps
or fabricated database rows. Source review identified this delay class before
release; the worker now limits historical reconciliation to one call per tick and
defers it while any operation is active.

The first hosted mutation run caught 14 of 15 faults. The survivor omitted the
credential secret comparison: previous wrong-secret examples failed format or ID
checks first. Tests now include valid-format secret substitutions for known IDs,
arbitrary payloads and generated single-position changes. The survivor was caught
on a focused rerun with a passing unmodified baseline. No assertion or supported
generator domain was weakened. The baseline contract score above is not a score
for newly added hosted code. None of these tests is live-provider evidence.

Two further faults removed the historical-read cap and active-call deferral. Both
were caught by the scheduling regressions on the final controller, after a passing
unmodified baseline. Across the original run and focused reruns, all 17 hosted
faults have been caught; none remains a known survivor, and none produced a compile
or infrastructure failure or a timeout. This is a targeted fault set, not an
exhaustive automatic mutation score for the entire runtime.

Run the hosted faults serially with `python3 scripts/hosted_mutations.py`.
Use `--fault NAME` for a focused triage rerun; selected results are kept separately
from the original run. The harness distinguishes caught, survived, compile or
infrastructure failure, and timeout, and fails if any fault is not caught.

Final local formatting, Clippy across all targets with warnings denied, and the
synthetic CLI demo passed. The demo verifies duplicate-start recovery and completion
after submitting clients exit. Publication scans covered all 48 staged candidate
files and every reachable Git blob; Gitleaks found no leaks. The unchanged resolved
dependency set contains 173 packages with permissive licensing options. Deployment
templates were reviewed as source, not installed or accepted on a real host.


## Native menus and concrete RP adapter

The opt-in menu profile has digest/directory/published-agent pin checks, while
omitted or explicit spoken-only fields retain the prior digest and template.
A separate signed phase schema makes uncertainty and prohibited actions stop
boundaries. Examples and a generated command model cover accepted and rejected
profiles, changed approvals, two-level menus, replay, revocation, expiry, uncertain
creates and stop preservation. A coordinated SQLite lock-contention test proves
that waiting for a transaction cannot extend authority to acknowledge a digit.

The concrete RP tests use a minimal original synthetic schema in a temporary
SQLite file. They exercise the existing two-case allocation, New York midnight
and DST boundaries, blocked/retired/ambiguous cases, uncertain portal operations,
concurrent reservations, immutable versions, parent-state preservation, rollback,
item promotion and orphan-claim relinking. A controller composition test publishes
termination before analysis and verifies that every legitimate outbox version can
be acknowledged without treating termination as business success. No live RP
rows or provider accounts participate in these tests.

The initial targeted run caught 19 of 20 new faults. The survivor removed both
provider profile checks: its test previously used an unavailable port, so a
transport failure masqueraded as policy rejection. The strengthened test supplies
valid independent snapshot/create responses and asserts that neither mismatch
direction reaches the network. The first focused rerun also exposed a harness
cache issue: preserved copied timestamps allowed Cargo to reuse a previous mutant
binary for an unmodified baseline. That failed baseline is not mutation evidence.
All three scratch-copy harnesses now use fresh source timestamps; the initial logs
were preserved and the complete new campaign was rerun.

The corrected run passed its unmodified baseline and caught all 20 new faults,
with zero surviving, unbuildable/infrastructure-failed or timed-out mutants. These
faults cover profile/stop/clock/menu boundaries, daily allocation, portal and call
reservations, conflicting and out-of-order evidence, parent updates, identity
changes, early termination publication, sync markers and timezone boundaries.
The targeted score applies to this fault set, not every possible implementation
change. Run it serially with `python3 scripts/menu_rp_mutations.py`; `--fault NAME`
supports focused triage without overwriting the full-run results.

The timezone dependency addition resolves seven new packages, all with MIT or
Apache-2.0 licensing options; the complete resolved graph contains 180 packages.

The final integrated local suite passed 233 tests, including 49 Hegel properties
configured for 5,000 cases each. Formatting, Clippy across all targets with warnings
denied, and the synthetic CLI demo passed. The demo confirmed duplicate-start
recovery and completion after submitting clients exited. These checks do not
establish live Retell, hosted deployment or production RP acceptance.

Publication review covered all 53 staged candidate files and all reachable Git
history. The privacy tripwire and Gitleaks found no leaks; staged source and
dependency-license changes were reviewed before publication. Private source data,
local recovery archives and test output are excluded from the repository.
