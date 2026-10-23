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

## Final verification

The complete suite passed from the requested project folder: 102 checks, including
26 Hegel properties at 5,000 cases each (130,000 generated cases), 38 controller
regressions, 14 ordinary contract checks, 17 ordinary provider checks and seven CLI
process integrations. Formatting and Clippy with warnings denied also passed.

All six separately seeded safety mutations were caught by regression assertions:
approval digest bypass, duplicate dispatch after ambiguity, conflicting-event
suppression, premature reservation release, stale cost overwrite and missing
incident correction. None survived, failed to compile or timed out. These seeded
faults supplement the automatically generated contract mutations.

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
