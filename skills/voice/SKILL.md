---
name: voice
description: Operate the approval-bound voice CLI for bounded calling tasks.
---

# Voice CLI

Read README and run `voice doctor` first. The demo is synthetic. The configured
Retell runtime requires the external setup and acceptance gates in
`docs/release-gates.md`; the source-build workflow does not authorize credentials,
deployment, expenditure or calls. Use the hosted route only after those specific
authorizations and a synthetic own-number acceptance call. Never substitute demo
contacts, tokens, rates or canonical workflow gates for approved configuration.

1. For an authorized existing RP database, use `voice rp-snapshot --database FILE
   --reference claim:LOCAL_ID` (or `item:LOCAL_ID`) to read the selected canonical
   case/version and daily gate. It writes nothing and grants no contact approval.
   Produce a minimal intent with a verified recipient reference, precise purpose,
   source-versioned approved facts, allowed actions and cost/time bounds. Keep
   `spoken_only` unless the user explicitly approves `model_guided_public_menu`
   with matching operator directory and published agent pins. Explain that native
   routing cannot enforce an exact digit allowlist or press count.
2. Run `voice dryrun --intent FILE`. Present the full scope and digest for review.
3. Approval requires the authenticated user role. `--via user` alone is not authority.
   The coordinator must never create or claim a user's approval.
4. Submit with the approval ID and one stable idempotency key. Preserve the operation ID.
5. Inspect `status` and `result`. Pending is not final; ended is not objective completed.
   Unknown means reconcile the existing operation. Never change a key to force a retry.
6. Use `end` for an authorized stop. Keep reporting ending until termination is observed.
7. Inspect `status.canonical_writeback` for pending and acknowledged result versions.
   The configured outbox writes to canonical RP; do not create a second claims ledger.
   RP owns eligibility, policy and completion rules. Failed writeback never justifies
   redial. A local RP acknowledgement does not mean its Notion record was synced;
   perform the parent-owned exact-row sync/read-back and retain pending status on
   failure. Categorical reports are unverified model evidence, not confirmed facts.

AI identity must be disclosed. Never impersonate the user or infer facts.
Authentication, attestations, payments and scope changes go to the human.
Takeover cannot resume AI; sensitive verification requires a separate direct call.
No phone transfer or browser takeover is enabled until its acceptance gates pass.

Exit codes: 0 accepted/read; 2 invalid input; 3 approval/authentication failure;
4 policy block; 5 definite provider rejection; 6 unknown outcome/storage/transport failure.
Use JSON stdout. Diagnostics on stderr are intentionally sanitized.
