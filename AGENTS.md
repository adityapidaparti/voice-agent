# Working on voice-agent

Keep the architecture small: typed neutral contracts, SQLite controller, provider
boundary and thin CLI. No real credentials, calls, deployment or paid service is
authorized by the source-build workflow.

Use synthetic fixtures and reserved example numbers. Do not import private source
documents, transcripts, prior archives, personal facts or raw provider logs.
Never weaken an assertion or generator to make a failure disappear.

Validate changed behavior with examples and Hegel properties. Include both accepted
and rejected values and an independent oracle. Check crash boundaries and meaningful
races. Run focused mutation tests after a meaningful safety change; triage survivors.

Run cargo fmt --check, cargo test --locked, cargo clippy --locked --all-targets --
-D warnings and scripts/privacy_scan.py. Use CARGO_NET_OFFLINE=true after fetching
dependencies when network is unavailable: Hegel invokes nested Cargo. Loopback
process tests require an environment that permits listening on localhost.

Before public pushes, inspect staged diff and reachable Git history for private data,
review dependency licenses, and report actual checks. Never describe a synthetic test
as a live-provider acceptance result.

Run only one heavy test or mutation job at a time on the development machine. Set
CARGO_BUILD_JOBS=1 and RUST_TEST_THREADS=1; use cargo-mutants --jobs 1 and
--jobserver-tasks 1. Do not use computer or browser UI control for project work.
