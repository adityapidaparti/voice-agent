---
name: voice
description: Operate the approval-bound voice CLI for bounded calling tasks.
---

# Voice CLI

Read README and run `voice doctor` first. This release is synthetic only.
Do not load real provider credentials or use this demo to call a real recipient.

1. Produce a minimal intent with a verified recipient reference, precise purpose,
   source-versioned approved facts, allowed actions and cost/time bounds.
2. Run `voice dryrun --intent FILE`. Present the full scope and digest for review.
3. Approval requires the authenticated user role. `--via user` alone is not authority.
   The coordinator must never create or claim a user's approval.
4. Submit with the approval ID and one stable idempotency key. Preserve the operation ID.
5. Inspect `status` and `result`. Pending is not final; ended is not objective completed.
   Unknown means reconcile the existing operation. Never change a key to force a retry.
6. Use `end` for an authorized stop. Keep reporting ending until termination is observed.
7. Feed operation/version and evidence into the canonical workflow. It owns all business
   eligibility, policy and completion rules. Failed writeback never justifies redial.

AI identity must be disclosed. Never impersonate the user or infer facts.
Authentication, attestations, payments and scope changes go to the human.
Takeover cannot resume AI; sensitive verification requires a separate direct call.
No phone transfer or browser takeover is enabled until its acceptance gates pass.

Exit codes: 0 accepted/read; 2 invalid input; 3 approval/authentication failure;
4 policy block; 5 definite provider rejection; 6 unknown outcome/storage/transport failure.
Use JSON stdout. Diagnostics on stderr are intentionally sanitized.
