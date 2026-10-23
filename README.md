# voice-agent

A small Rust calling controller with a thin `voice` CLI. Prepare a bounded
task, approve its exact scope, submit once, and inspect the result later.

**This release is an offline reference implementation.** It runs synthetic calls
on a loopback controller. It cannot contact Retell or place a phone call.
The Retell request and webhook boundary are implemented; production authentication,
hosting, canonical workflow integration and controlled phone tests remain release gates.

## Try it

Rust 1.89 or newer and Python 3 for the smoke test:

```sh
cargo build --locked
python3 scripts/demo.py
```

The demo starts a temporary controller, creates a fictional intent and user
approval, submits it twice, closes the submitting clients, then retrieves one
durable operation and a result. It uses a reserved example number and fake tokens.

For individual commands:

```sh
mkdir -p .run
cargo run -- serve --simulation --db .run/controller.db --provider-db .run/provider.db
# In another terminal:
target/debug/voice example > .run/intent.json
target/debug/voice dryrun --intent .run/intent.json
VOICE_TOKEN=synthetic-owner-token target/debug/voice approve --intent .run/intent.json --via user
VOICE_TOKEN=synthetic-coordinator-token target/debug/voice start --intent .run/intent.json --approval APPROVAL_ID --idempotency-key demo-attempt-1
VOICE_TOKEN=synthetic-coordinator-token target/debug/voice status OPERATION_ID
VOICE_TOKEN=synthetic-coordinator-token target/debug/voice result OPERATION_ID
```

Every response is JSON. `voice end OPERATION_ID` requests termination;
`voice revoke APPROVAL_ID` requires the simulated user credential.
`voice doctor` lists setup gates. The `--via user` flag grants no authority.

A completed phone call is not proof that a business task succeeded. Results
remain `needs_review` until the canonical workflow assesses the evidence.
Unknown starts retain their attempt and lock. Repeating a start with the same key
retrieves its existing operation; a different key never repairs uncertainty.

See [architecture](docs/architecture.md), [release gates](docs/release-gates.md),
[verification](docs/testing.md) and the [assistant guide](skills/voice/SKILL.md).

Tested with [Hegel](https://hegel.dev) property-based tests.

## Development

```sh
export CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1
cargo fmt --check
CARGO_NET_OFFLINE=true cargo test --locked --offline
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/privacy_scan.py
```

On a fresh machine, run `cargo test --locked` online once. Hegel builds a native
engine with a nested Cargo invocation; `cargo fetch --locked` alone may not fill
that engine cache. Use `CARGO_NET_OFFLINE=true` after both dependency sets are cached.
CI builds online on a fresh runner.
