# Release gates

Public source availability is not a deployment or calling approval. No real credential,
account, number, paid service, hosted deployment or phone call was used in this build.

| Gate | Current evidence | Still required before live calling |
|---|---|---|
| Scope and approval | Typed snapshot/digest, user/coordinator tests | Real authenticated user session, secure approval presentation and scopes |
| Durable start | Transactional reservation; crash/restart and concurrency tests | Hosted durable database, backups, monitored worker-health admission |
| Retell | Request builder and signature normalization against primary schema | Authorized account/funding/KYC, number, live transport and pinned published agent verification |
| Unknown outcome | Read-only reconciliation; no automatic create retries | Controlled response-loss test and provider history correlation |
| Limits | Synthetic rate reservation and durable stop/deadline logic | Current full rate model, approved exposure, all-leg billing/stop measurements |
| IVR / hold / audio | State-machine menu and hold timers | DTMF tool verification, ten-minute silent hold, loop detection and measured latency/interruption |
| Human boundary | Manual fallback; no AI resume; human result unknown | Tested private user end control, takeover identity/microphone/closure behavior |
| Authentication | Separate direct call required | Independent proof of no AI processing, transcription or capture in sensitive segment |
| Transfer | Unsupported legs quarantine calling | Control and cost enforcement for every carrier leg before allowing transfer |
| Privacy / consent | Synthetic tests; no raw media persistence | Geography, consent, lawful calling/processing decisions, storage and deletion acceptance |
| Canonical workflow | Versioned outbox plus consumer contract | Inspect actual canonical RP contract; fresh policy reservation; real consumer concurrency tests |
| Offline operation | Controller subprocess outlives CLI clients | Approved hosted deployment and actual laptop-sleep test |

No runtime flag enables production calling. A future reviewed live adapter must pass
these gates before making its first explicitly authorized call. Do not use the demo
tokens, directory, rates or synthetic policy gate in a public deployment.
