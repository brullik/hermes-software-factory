# Hermes Autonomous Factory 2.5

Hermes 2.5 inserts a functional-readiness authority between Q6 and Q7. A new
Candidate may enter Q7 only in this order:

```text
Q0-Q6 PASS
-> Q6.5 real operation handshakes PASS
-> PRE-Q8 10/10 first-run PASS
-> Golden Product COMPLETED
-> Stable health/intake and internal verifier PASS
-> independently signed FUNCTIONALLY_READY result
-> Q7
```

The functional state, receipts, owner actions, and notification outbox are
durable. Persistent systemd timers resume the sequence after reboot. A missing
external credential creates one typed owner action; an unchanged missing
credential never consumes another attempt. Q7 units are not enabled by the
initial qualification service.

## Credential boundaries

Candidate GitHub operations use a separate credential installed at
`/etc/hermes-factory/candidate-credentials.d/github-token`. Only the broker
receives it through systemd `LoadCredential`. Candidate workers can reach the
broker Unix socket but cannot read the credential source or the copied runtime
credential. Requests are limited by operation, owner, repository namespace,
and workspace root, and immutable receipts bind the entire request digest.
The protected installer accepts a classic personal access token; Q6.5 requires
both the `repo` and `workflow` scopes and proves a real private workflow-file
push before the credential is admitted. The ephemeral Q6.5 canary is archived,
not deleted, so the credential does not require the broad `delete_repo` scope.

Golden Product intake uses a separate bot credential at
`/etc/hermes-factory/candidate-credentials.d/candidate-telegram-token`. This
prevents a second `getUpdates` consumer from racing the Stable Telegram gateway.
The Stable notification token is used only by the owner notifier and is never
made visible to Candidate or model processes.

The permanent Stable product lane has its own `LoadCredential` broker and
repository namespace. A real pre-PRE-Q8 probe creates a private canary
repository, clones it, pushes a workflow and branch, opens a PR, reads checks,
closes the PR safely, and archives the repository. A missing broker credential
is the only owner-action outcome. Once a credential epoch exists, a broker,
GitHub, CI, or receipt defect is recorded as `BROKEN_INTERNAL` and fails the
qualification; it is never delegated to the owner.

Every model-writing worker enables only Hermes' terminal tool and forces that
tool through rootless Podman with an empty environment-forwarding allowlist.
The Stable provider gate invokes all three model routes and additionally makes
a real terminal tool call. That call must run inside Podman, see the mounted
workspace, see neither credential directory nor any known credential variable,
and create a mode-0600 nonce marker. Final readiness requires a fresh copy of
this four-operation proof after production observation.

## Recursive improvement

The improvement governor operates only in
`/var/lib/hermes-factory-improvement-lab`. It permits one objective and one
active experiment branch, at most three cycles, and at most two implementation
attempts per cycle. Independent baseline/candidate scorecards must show a
configured measurable delta with no safety regression. Gate, credential,
trust-root, Stable, audit-history, and production-risk changes are rejected
before model execution. An accepted experiment creates an immutable Candidate
release epoch with `FULL_QUALIFICATION_REQUIRED`; it never edits Stable or
bypasses the normal release pipeline. The persistent detector now binds every
LTS decision to an immutable production-observation digest and records either a
typed opportunity or `NO_MEASURABLE_OPPORTUNITY`; merely having an enabled
timer is not readiness evidence. The LTS proof also executes one isolated,
single-attempt Candidate lane for the latest observation, independently
compares it, deterministically rejects a no-improvement result, and proves the
Stable release identity did not change.

## Autonomous runtime

The capability reconciler, functional qualification, Golden Product,
notification, support-bundle, and recursive-improvement units contain no Codex
runtime dependency. Stable product workers use a separate operation-scoped
broker and cannot fall back to ambient `gh` authentication. Its real private
repository, workflow push, PR, checks, and safe-close journey is a pre-PRE-Q8
gate. Stable remains authoritative until exact promotion. Production authority
begins only after Q7, authoritative Q8, exact signed promotion, 24-hour
observation, and the final signed `FACTORY_LTS_READY` result.

Confirmed terminal Controller or Candidate-qualification incidents are scanned
by a persistent reconciler. It creates exactly one redacted, immutable support
bundle per incident without sending a technical task to the owner. Telegram
owner delivery is reserved for one genuinely external action and completed
results. Golden commissioning waits silently for a real owner-originated intake;
it does not ask the bot to impersonate the owner and it does not fabricate a
database row. Qualification delivery probes are silent and deleted immediately
after their typed Telegram receipts are observed. Intermediate progress and
repair messages are rejected or retired without delivery.

The signed `FACTORY_LTS_READY` notification uses a durable write-ahead outbox.
Internal `AUTONOMOUS_FACTORY_READY` is committed only after the notifier has a
matching immutable Telegram receipt for the exact signed manifest digest. A
restart in the irreducible send/receipt window records `DELIVERY_UNCERTAIN` and
never risks a duplicate send; readiness remains fail-closed.
