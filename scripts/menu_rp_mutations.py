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
OUTPUT = ROOT / "target/menu-rp-mutations"
# Each fault represents an omitted safety boundary; tuples can remove redundant
# defenses together where the intended fault is total omission of that boundary.
FAULTS = [
    ("menu_policy_bypass", "src/policy.rs", [("&& d.menu_navigation == i.menu_navigation", "&& true")]),
    ("menu_profile_dispatch_bypass", "src/retell.rs", [
        ("|| intent.menu_navigation != self.config.menu_navigation", "|| false"),
        ("if intent.menu_navigation != self.config.menu_navigation {", "if false {")]),
    ("menu_ack_after_stop", "src/controller.rs", [("if observation.phase == ObservedPhase::DtmfRequired\n            &&", "if false\n            &&")]),
    ("menu_stale_lock_clock", "src/controller.rs", [("received_at.saturating_add(i64::try_from(elapsed_seconds).unwrap_or(i64::MAX))", "received_at")]),
    ("menu_double_count", "src/controller.rs", [("op.last_observed_at = op.last_observed_at.max(e.observed_at);", "op.menu_repeats = op.menu_repeats.saturating_add(1); op.last_observed_at = op.last_observed_at.max(e.observed_at);")]),
    ("menu_ignore_uncertainty", "src/controller.rs", [("ObservedPhase::UncertainMenu => Some(\"uncertain_menu\"),", "ObservedPhase::UncertainMenu => None,")]),
    ("menu_ignore_prohibited_action", "src/controller.rs", [("ObservedPhase::ProhibitedAction => Some(\"prohibited_action\"),", "ObservedPhase::ProhibitedAction => None,")]),
    ("active_approval_expiry_omitted", "src/controller.rs", [("op.stop_reason.get_or_insert(\"approval_expired\".into());", "let _ = &op.stop_reason;")]),
    ("rp_selection_bypass", "src/rp.rs", [("if !keys.contains(&case.case_key) {", "if false {")]),
    ("rp_uncertain_portal_bypass", "src/rp.rs", [("if blocked {", "if false {")]),
    ("rp_concurrent_reservation_bypass", "src/rp.rs", [("no_other_reservation(&tx, &case, &id)?;", "// omitted canonical reservation exclusion")]),
    ("rp_uncertain_release", "src/rp.rs", [("Ok(latest.is_none_or(|r| !r.call_ended))", "Ok(false)")]),
    ("rp_conflicting_result_replay", "src/rp.rs", [("action == RESULT && old.input_digest == input_digest", "action == RESULT")]),
    ("rp_old_result_overwrites_new", "src/rp.rs", [("if message.result_version > latest {", "if true {")]),
    ("rp_parent_state_overwrite", "src/rp.rs", [("let can_change = original || own_change;", "let can_change = true;")]),
    ("rp_alias_reservation_bypass", "src/rp.rs", [("if reservation.reservation_id != own", "if reservation.case_key == case.case_key && reservation.reservation_id != own")]),
    ("rp_pending_terminal_rejected", "src/rp.rs", [("(r.status == ResultStatus::Pending && !message.call_ended)", "r.status == ResultStatus::Pending")]),
    ("rp_promoted_sync_omitted", "src/rp.rs", [("if let Some(current) = current_target {", "if let Some(current) = None::<Case> {")]),
    ("rp_stale_snapshot_allowed", "src/rp.rs", [("serde_json::to_value(&snapshot.work_item)? != serde_json::to_value(&request.work_item)?", "false")]),
    ("rp_utc_day_substitution", "src/rp.rs", [("utc.with_timezone(&New_York)", "utc.with_timezone(&Utc)")]),
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
with tempfile.TemporaryDirectory(prefix="voice-menu-rp-mutations-") as temp:
    scratch = Path(temp)
    # Fresh mtimes are essential with a shared Cargo target: an old copied mtime
    # can otherwise reuse the previous run's last mutant binary as its baseline.
    for name in ["Cargo.toml", "Cargo.lock", "hegel.toml", "src", "tests"]:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, scratch / name, copy_function=shutil.copy)
        else:
            shutil.copy(source, scratch / name)
    env = {**os.environ, "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "1",
           "RUST_TEST_THREADS": "1", "HEGEL_TEST_CASES": "200",
           "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(OUTPUT / "build"))}
    def run(name):
        # Baseline validates every selected suite; each fault then runs the suite
        # that exercises its boundary, avoiding unrelated repeated HTTP delays.
        suites = (["menu_policy", "rp", "retell"] if name == "baseline" else
                  ["rp"] if name.startswith("rp_") else
                  ["retell"] if name == "menu_profile_dispatch_bypass" else ["menu_policy"])
        command = ["cargo", "test", "--locked", "--offline", "--no-fail-fast"]
        for suite in suites:
            command += ["--test", suite]
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
