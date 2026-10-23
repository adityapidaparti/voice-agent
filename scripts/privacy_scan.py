#!/usr/bin/env python3
"""Fail closed on obvious private artifacts in candidate files and every historical Git blob.

This is a reproducible tripwire, not a claim to detect all secrets. Human staged-diff
review and credential scanning are still required before public publication.
"""
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
def git(*args):
    return subprocess.run(["git", *args], cwd=root, check=True,
                          capture_output=True).stdout
files = set(git("ls-files", "-z").decode().split("\0"))
files.update(git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0"))
patterns = [
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    rb"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}",
    rb"sk-[A-Za-z0-9]{24,}",
    rb"AKIA[A-Z0-9]{16}",
    rb"/Users/[A-Za-z0-9._-]+/",
    rb"libfile_[a-f0-9]{20,}",
    rb"[A-Za-z0-9._%+-]+@(?:gmail|outlook|icloud)\.com",
]
bad_names = re.compile(r"(?:^|/)(?:\.env(?:\..*)?|recovery|source|verified-restore|\.claude|\.local)(?:/|$)|\.(?:db|docx|tar|jsonl)$")
failed = []
def inspect(label, data):
    if any(re.search(p, data) for p in patterns):
        failed.append(label)
for name in sorted(files - {""}):
    if bad_names.search(name):
        failed.append(name)
    path = root/name
    if path.is_file():
        inspect(name, path.read_bytes())
# Scan all reachable historical blobs, not only HEAD. Do not print matching secrets.
if subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
    for row in git("rev-list", "--objects", "--all").decode().splitlines():
        oid, _, name = row.partition(" ")
        if git("cat-file", "-t", oid).strip() == b"blob":
            if bad_names.search(name):
                failed.append("history:"+name)
            inspect("history:"+name, git("cat-file", "blob", oid))
if failed:
    print("Privacy scan failed (paths only):", ", ".join(sorted(set(failed))), file=sys.stderr)
    sys.exit(1)
print(f"Privacy tripwire passed: {len(files-{''})} candidate files and reachable Git history.")
