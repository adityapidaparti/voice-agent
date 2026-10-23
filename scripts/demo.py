#!/usr/bin/env python3
"""Exercise the synthetic controller with short-lived CLI processes; no external service."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[1]
target = Path(os.environ.get("CARGO_TARGET_DIR", str(root/"target")))
if not target.is_absolute():
    target = root/target
binary = target / "debug/voice"
if not binary.is_file():
    subprocess.run(["cargo", "build", "--locked"], cwd=root, check=True)
with tempfile.TemporaryDirectory(prefix="voice-demo-") as directory:
    d = Path(directory)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    server = subprocess.Popen([str(binary), "serve", "--simulation",
        "--db", str(d/"controller.db"), "--provider-db", str(d/"provider.db"),
        "--listen", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        def command(*args, owner=False):
            env = {**os.environ, "VOICE_TOKEN":
                "synthetic-owner-token" if owner else "synthetic-coordinator-token"}
            out = subprocess.run([str(binary), "--controller", base, *args],
                env=env, check=True, capture_output=True, text=True)
            return json.loads(out.stdout)
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError("Synthetic controller exited before startup")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Synthetic controller did not become ready")
        intent = command("example")
        path = d/"intent.json"
        path.write_text(json.dumps(intent))
        dry = command("dryrun", "--intent", str(path))
        approval = command("approve", "--intent", str(path), "--via", "user", owner=True)
        args = ("start", "--intent", str(path), "--approval", approval["id"],
                "--idempotency-key", "synthetic-demo-attempt")
        first = command(*args)
        second = command(*args)
        assert first["id"] == second["id"]
        # Each command process already exited. Only the controller remains.
        for _ in range(100):
            status = command("status", first["id"])
            result = command("result", first["id"])
            if result["status"] == "needs_review":
                break
            time.sleep(.1)
        else:
            raise RuntimeError("Synthetic call did not finish")
        assert status["lifecycle"] == "ended"
        assert result["outcome"] != "objective_completed"
        print(json.dumps({"synthetic_only": True, "digest": dry["intent_digest"],
            "duplicate_start_same_operation": True, "clients_exited_before_completion": True,
            "lifecycle": status["lifecycle"], "result_status": result["status"]}, indent=2))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
