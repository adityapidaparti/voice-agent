#!/usr/bin/env python3
"""Focused integration faults in disposable copies; one Cargo job, no working-tree mutation."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target/hosted-mutations"
# Each fault represents an omitted safety boundary; tuples can remove redundant
# defenses together where the intended fault is total omission of that boundary.
FAULTS = [
    ("skip_remote_dispatch", "src/controller.rs", [("if needs_check {", "if needs_check && !dispatching {")]),
    ("reuse_stale_dispatch_clock", "src/controller.rs", [("let received = clock();", "let received = now;")]),
    ("skip_canonical_work_lock", "src/controller.rs", [("if scope_locked {", "if false {")]),
    ("allow_unbound_callbacks", "src/controller.rs", [("&& !authoritative_lookup", "&& false")]),
    ("lose_registered_identity", "src/controller.rs", [("if let Some(call_id) = observation.call_id {", "if let Some(call_id) = None::<String> {")]),
    ("report_after_takeover", "src/controller.rs", [("if op.ai_stopped || !op.locked() {", "if false {")]),
    ("suppress_report_conflict", "src/controller.rs", [("if old == fingerprint {", "if true {")]),
    ("stop_writeback_after_first_error", "src/controller.rs", [("failure.get_or_insert(error);\n                    continue;", "return Err(error);")]),
    ("skip_vendor_pin_checks", "src/retell.rs", [("|| self.check_configuration().is_err()", "|| false")]),
    ("ignore_lease_during_pin_reads", "src/retell.rs", [
        ("now.saturating_add(elapsed) >= authorization_expires_at.min(intent.not_after)", "false"),
        ("now.saturating_add(send_elapsed) >= authorization_expires_at.min(intent.not_after)", "false")]),
    ("trust_foreign_call_scope", "src/retell.rs", [("|| call.metadata.intent_digest != op.digest", "|| false")]),
    ("ignore_credential_revocation", "src/config.rs", [("|| record.revoked", "|| false")]),
    ("unbounded_background_reads", "src/controller.rs", [("background_reads == 0 && !active_exists", "!active_exists")]),
    ("poll_history_during_active_call", "src/controller.rs", [("background_reads == 0 && !active_exists", "background_reads == 0")]),
    ("ignore_credential_secret", "src/config.rs", [("!constant_eq(&candidate, &record.token_sha256)", "false")]),
    ("accept_denied_authority", "src/workflow.rs", [("if !self.allowed {", "if false {")]),
    ("ignore_authority_binding", "src/workflow.rs", [("if self.request_digest != request.request_digest()? {", "if false {")]),
]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fault", action="append", choices=[fault[0] for fault in FAULTS],
                    help="Rerun a named fault after triage (repeatable); default runs all faults.")
args = parser.parse_args()
if args.fault:
    selected = set(args.fault)
    FAULTS = [fault for fault in FAULTS if fault[0] in selected]
    OUTPUT = OUTPUT / ("selected-" + "-".join(sorted(selected)))
OUTPUT.mkdir(parents=True, exist_ok=True)
results = []
with tempfile.TemporaryDirectory(prefix="voice-hosted-mutations-") as temp:
    scratch = Path(temp)
    for name in ["Cargo.toml", "Cargo.lock", "hegel.toml", "src", "tests"]:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, scratch / name)
        else:
            shutil.copy2(source, scratch / name)
    env = {**os.environ, "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "1",
           "RUST_TEST_THREADS": "1", "HEGEL_TEST_CASES": "200",
           "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(OUTPUT / "build"))}
    command = ["cargo", "test", "--locked", "--offline", "--no-fail-fast"]
    for suite in ["authority", "retell", "config", "observations", "workflow", "scheduling"]:
        command += ["--test", suite]
    def run(name):
        log = OUTPUT / (name + ".log")
        try:
            with log.open("w") as stream:
                result = subprocess.run(command, cwd=scratch, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=240)
            output = log.read_text()
            if result.returncode == 0:
                return "passed"
            if "test result: FAILED" in output:
                return "caught"
            return "compile_or_infrastructure_failure"
        except subprocess.TimeoutExpired:
            return "timeout"
    baseline = run("baseline")
    if baseline != "passed":
        raise SystemExit("Unmodified baseline: " + baseline)
    print("baseline: passed", flush=True)
    for name, filename, replacements in FAULTS:
        path = scratch / filename
        original = path.read_text()
        changed = original
        for needle, replacement in replacements:
            if changed.count(needle) != 1:
                raise SystemExit("Ambiguous or missing mutation target: " + name)
            changed = changed.replace(needle, replacement, 1)
        try:
            path.write_text(changed)
            outcome = run(name)
            outcome = "survived" if outcome == "passed" else outcome
            results.append({"name": name, "outcome": outcome})
            print(f"{len(results)}/{len(FAULTS)} {name}: {outcome}", flush=True)
            (OUTPUT / "results.json").write_text(json.dumps({"baseline":baseline,"mutants":results},indent=2)+"\n")
        finally:
            path.write_text(original)
if any(result["outcome"] != "caught" for result in results):
    raise SystemExit(1)
