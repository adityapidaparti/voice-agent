# Operational observations and IVR limits

The optional `observe_phase` custom function sends a small signed POST to
`/v1/functions/observe`. Its pinned schema fixes the operation ID, call ID and
intent digest from dynamic variables. The model chooses only a phase and a
sequence number from 1 through 128. The controller binds those fields to a
submitted operation and durably deduplicates observations before acknowledgement.
Changed evidence under a reused sequence is a conflict, not a harmless replay.

The default published schema accepts IVR, hold, talking, authentication required,
DTMF required and AI declined; the last three request a stop. The opt-in native
public-menu schema additionally accepts uncertain menu and prohibited action,
both mandatory stop boundaries. In that profile only, DTMF required records a
public-routing prerequisite without counting another IVR menu or extending its
timer. A stopped, revoked, expired or closed native call cannot acknowledge even
an exact replay of that prerequisite. The controller conservatively stops after
three reported IVR menus; this is not a verified count of actual digit presses. A signed classification
is still a model observation: it does not prove consent, successful authentication,
business completion, or a human takeover. Total duration and approval revocation
remain controller responsibilities even if the model never reports a phase.

The parser verifies the original body bytes before deserializing, permits at most
30 seconds of clock skew, bounds the body to 16 KiB, rejects additional fields,
and clamps future observation times to receipt time. Operator hosts need clock
synchronization. Retell's `args_at_root` mode omits the usual call wrapper and its
transcript. The tool disables automatic retries and speech during/after execution.
A lost callback cannot establish a new permission.

No current native Retell LLM tool can enforce the requested exact outbound digit
allowlist. Its Press Digit tool chooses digits from model instructions, and the
live-call update endpoint does not document a send-DTMF operation. The default profile therefore excludes Press Digit. The explicitly approved
`model_guided_public_menu` profile enables native public department routing with
its own prompt, exact pinned tools and signed callback endpoint. It has no hard
digit/count guarantee; the model must stop rather than guess, enter identifiers,
authenticate or accept terms. See [Retell profile details](retell-transport.md). `DtmfPlan` only
validates a possible provider-neutral menu plan: distinct single decimal digits,
at most three presses, with consumed reservations counted. It does not authorize
or execute digits and is not part of the current approved intent. Any future
execution path must add digest binding and durable reservation before sending;
an uncertain send must consume its attempt without automatic replay. Authentication
codes and account identifiers must never be sent through such a menu interface.

Vendor references checked for this implementation:

- [Custom function request/signature and args-only behavior](https://docs.retellai.com/build/single-multi-prompt/custom-function)
- [System and caller-supplied dynamic variables](https://docs.retellai.com/build/dynamic-variables)
- [Official SDK custom-tool field definitions](https://github.com/RetellAI/retell-typescript-sdk/blob/main/src/resources/llm.ts)
- [Native Press Digit behavior](https://docs.retellai.com/build/single-multi-prompt/press-digit)
- [Supported live-call updates](https://docs.retellai.com/api-references/update-live-call)

These are protocol and synthetic-test guarantees. Hosted callback reachability,
clock synchronization, actual model reporting, vendor signature delivery and
privacy settings require separately approved live acceptance testing.

## Categorical answers without retained transcripts

`report_answer` uses the same signed, args-only scope and bounded sequence on
`/v1/functions/report`. Its answer has exactly three fields:

- `status`: unknown, under review, awaiting documents, or unable to locate.
- `required_documents`: a set of at most four choices: receipt, claim form,
  return policy, and photos. Empty means no supported document request was reported.
- `next_step`: unknown, wait, submit documents, or contact directly.

There are no amounts, account identifiers, confirmation numbers, links, quotations,
or free-text notes. Missing answers remain unknown; the model must not invent them.
The callback rejects unknown fields and duplicate document choices. Every stored
answer carries `unverified_model_report` verification status and a source evidence
reference. A verified signature establishes callback provenance, not truth of the
reported answer. The canonical workflow remains responsible for reconciliation;
these categories cannot declare approval, payment, authentication, or completion.

This path captures a limited useful answer while Basic Attributes Only prevents
later transcript retrieval. It deliberately cannot reconstruct the conversation
or support facts outside the small vocabulary. Unsupported questions require a
direct human follow-up. Live acceptance must verify that the pinned model calls
the tool correctly and that missing or interrupted callbacks stay unknown.
