# Autonomous recovery

## Invariant

Every non-terminal, non-paused product must have a runnable or waiting durable
task. `PipelineReconciler` checks this invariant continuously. An empty queue is
an incident, not a normal idle state.

## Failure routing

1. A transient infrastructure or quota failure requeues the same task with a
   bounded delay.
2. An internal semantic, implementation, test, CI, release, or acceptance
   failure creates a repair task with the previous reason and evidence.
3. A failed release candidate is closed and the target worktree is restored to
   the configured base branch before repair.
4. The repair pipeline runs Builder, Test Engineer, Security Reviewer,
   Independent Reviewer, Staging Release, and Product Tester again.
5. Repair cycle 1 uses at least Terra; cycle 2 uses Sol.
6. Exceeding `max_repair_cycles` closes the current problem hypothesis,
   preserves evidence, and sends the exact reason to the owner in Russian.
7. Director then compares provider findings with controller-owned evidence. A
   controller-scope contradiction is resolved by orchestration; every distinct,
   proven defect receives its own actionable repair brief and bounded budget.
8. One blocker signature may run at most three full repair cycles. If the same
   signature still fails, Director opens a separate bounded
   `DIAGNOSIS-REASSESSMENT` hypothesis. Its brief forbids repeating the previous
   fix and first checks whether the task statement, allowed scope, controller
   gate or environment, or the original implementation diagnosis is wrong.
9. A transient provider interruption does not replace the active semantic
   hypothesis. Hermes carries its blocker IDs, required fixes, definition of
   done, and safe evidence references into the transient retry brief.
10. Only after the bounded diagnosis-reassessment policy is exhausted does the
    product remain `FAILED_SAFE` with the exact Russian reason notification.

Default Builder scope includes the repository's Python project contract
(`pyproject.toml`) because mandatory dependency and license gates require that
file. A repository-supplied PM task still replaces the default scope completely;
Hermes never widens frozen PM `allowed_paths`.

The reconciler never restarts product planning when recovery can continue from
the failed stage.

## OWNER_ACTION boundary

`OWNER_ACTION` is allowed only for a machine-classified external blocker such
as an absent credential, 2FA/CAPTCHA, purchase, legal decision, or an explicitly
irreversible production action. An unknown or internal error remains a factory
incident and consumes the bounded repair policy; it is not delegated to the
owner.

## Durable notification delivery

Notifications are committed to SQLite before Telegram delivery. The gateway
claims each outbox row with a lease, delivers it to every configured owner, and
marks it complete only after successful sends. A transport error records a
sanitized failure and leaves the item available for retry.
