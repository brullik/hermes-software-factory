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
push before the credential is admitted.

Golden Product intake uses a separate bot credential at
`/etc/hermes-factory/candidate-credentials.d/candidate-telegram-token`. This
prevents a second `getUpdates` consumer from racing the Stable Telegram gateway.
The Stable notification token is used only by the owner notifier and is never
made visible to Candidate or model processes.

## Recursive improvement

The improvement governor operates only in
`/var/lib/hermes-factory-improvement-lab`. It permits one objective and one
active experiment branch, at most three cycles, and at most two implementation
attempts per cycle. Independent baseline/candidate scorecards must show a
configured measurable delta with no safety regression. Gate, credential,
trust-root, Stable, audit-history, and production-risk changes are rejected
before model execution. An accepted experiment creates an immutable Candidate
release epoch with `FULL_QUALIFICATION_REQUIRED`; it never edits Stable or
bypasses the normal release pipeline.

## Autonomous runtime

The capability reconciler, functional qualification, Golden Product,
notification, support-bundle, and recursive-improvement units contain no Codex
runtime dependency. Stable remains authoritative until exact promotion. Low-risk
pilot use begins only after the owner receives `FACTORY_FUNCTIONALLY_READY`;
production authority begins only after Q7, authoritative Q8, and exact signed
promotion complete.
