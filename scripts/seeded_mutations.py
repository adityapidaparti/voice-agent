#!/usr/bin/env python3
"""Plant specific safety faults in a scratch copy; never mutate the working source."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
output = root/"target/seeded-mutations"
output.mkdir(parents=True, exist_ok=True)
mutations = [
    ("approval_digest_bypass", "src/controller.rs",
     "|| a.digest != digest", "|| false"),
    ("duplicate_dispatch_after_ambiguity", "src/controller.rs",
     "if op.submitted_at.is_none() {",
     "if op.submitted_at.is_none() || op.lifecycle == Lifecycle::StartUnknown {"),
    ("conflicting_event_suppression", "src/controller.rs",
     "if serde_json::to_string(&old)? != data {", "if false {"),
    ("premature_reservation_release", "src/contract.rs",
     "!self.all_legs_ended || self.uncertain_legs\n", "self.lifecycle == Lifecycle::Active\n"),
    ("stale_cost_overwrite", "src/contract.rs",
     "Some(self.result.actual_cost_cents.unwrap_or(0).max(cost))", "Some(cost)"),
    ("missing_incident_correction", "src/controller.rs",
     "if !op.all_legs_ended && op.result.status != ResultStatus::NeedsReview {",
     "if !op.all_legs_ended {"),
]
results = []
with tempfile.TemporaryDirectory(prefix="voice-seeded-mutations-") as temporary:
    scratch = Path(temporary)
    for item in ["Cargo.toml", "Cargo.lock", "hegel.toml", "src", "tests"]:
        src, dest = root/item, scratch/item
        if src.is_dir():
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)
    env = {**os.environ, "CARGO_NET_OFFLINE":"true", "CARGO_BUILD_JOBS":"1", "RUST_TEST_THREADS":"1", "HEGEL_TEST_CASES":"200", "CARGO_TARGET_DIR":os.environ.get("CARGO_TARGET_DIR", str(output/"build"))}
    def run(name):
        log = output/(name+".log")
        try:
            with log.open("w") as stream:
                process = subprocess.run(["cargo", "test", "--locked", "--offline", "--test", "core"],
                    cwd=scratch, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=240)
            text = log.read_text()
            if process.returncode == 0:
                return "passed"
            if "test result: FAILED" in text:
                return "caught"
            return "compile_or_infrastructure_failure"
        except subprocess.TimeoutExpired:
            return "timeout"
    baseline = run("baseline")
    if baseline != "passed":
        raise SystemExit("Baseline failed: "+baseline+"; see target/seeded-mutations/baseline.log")
    for name, file, needle, replacement in mutations:
        path = scratch/file
        original = path.read_text()
        if needle not in original:
            raise SystemExit("Mutation target changed: "+name)
        try:
            path.write_text(original.replace(needle,replacement,1))
            outcome = run(name)
            if outcome == "passed":
                outcome = "survived"
            results.append({"name":name,"outcome":outcome})
            print(name+": "+outcome,flush=True)
        finally:
            path.write_text(original)
(output/"results.json").write_text(json.dumps({"baseline":baseline,"mutants":results},indent=2)+"\n")
if any(r["outcome"]!="caught" for r in results):
    raise SystemExit(1)
