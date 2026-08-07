# Codex VPS progress

## Checkpoint 0 - package and live inventory

- Package ZIP SHA-256:
  `dd06ee498e9bfa621e655adae3b0d0fa48db1e7a4da50a635707b35b4ab90767`.
- Local and VPS `SHA256SUMS`: PASS.
- Mandatory contracts and `GOAL-1-DESKTOP-CODEX-BOOTSTRAP.md`: read fully.
- VPS: Ubuntu 24.04; official Codex, `jq` and `tmux` initially absent.
- Live `main` and Candidate: `1514525a076190983f6dc13ffb6ec1c9c260c2ca`.
- Existing GitHub broker was healthy but intentionally excluded the core repo.
- Existing Telegram gateway is active and already uses systemd credential
  delivery; no second shell bot will be introduced.
- PRE-Q8 ended fail-closed at 18:36:37 UTC; no qualification service was stopped
  or restarted by this bootstrap.
- Production pilot container remained healthy; public listeners unchanged.

## Checkpoint 1 - isolated identity, CLI, worktree and broker boundary

- Immediately before persistent bootstrap, Q7/Q8/PRE-Q8 processes were absent;
  failed qualification units remained fail-closed and were not restarted.
- Installed only `jq 1.7` and `tmux 3.4`; the pending kernel update was recorded
  and no reboot was performed.
- Created `hermescodex` as uid/gid `1001`, with only supplementary group
  `hermescodexops`; it has no sudo, Docker or production-runtime group access.
  Home, auth, state, evidence and worktree roots are private.
- Official standalone installer SHA-256:
  `ba92dd27e5c06f0d3bbc58bfa4b9cfb6599cd2742fbb1f92a2765e6c07dedb5a`.
- Installed `codex-cli 0.147.0` binary SHA-256:
  `cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40`.
- `/home/hermescodex/.codex/auth.json` is absent; no Desktop credential was
  copied. Device authentication remains the single external owner action.
- Public clone and worktree were created from exact main
  `1514525a076190983f6dc13ffb6ec1c9c260c2ca` on branch
  `codex/vps-bootstrap-20260807-goal1`.
- Added strict core broker policy: exact repository and operation allowlists,
  task-branch-only push, main-only PR base, exact-head checks, review threads,
  policy/evidence digests, SHA-bound squash merge, single-parent verification,
  postcondition branch cleanup and conflict-safe replay.
- Focused gate: 24 strict broker tests PASS. `ruff` PASS and strict `mypy` PASS
  for all changed broker modules.
- Authoritative full regression in a one-shot private mount namespace, copied
  venv and `umask 0022`: PASS, exit 0, 100% of collected tests.
- PR #165 was created only through the typed broker. Its first CI run exposed a
  stale source manifest; the manifest was rebuilt, committed and pushed, after
  which all exact-head required checks and independent review passed.

## Checkpoint 2 - Telegram typed approvals, permission profile and supervisor

- Extended the existing `hermes-factory-gateway`; no second bot or shell/RCE
  input path was added. `/approve` and `/deny` accept only exact action IDs and
  fixed confirmation-code grammar.
- Added a group-private SQLite approval/outbox store with private-chat/exact-owner
  enforcement inherited from the gateway, immutable action/state digests,
  nonce/TTL, one-time receipts, durable duplicate-update suppression and
  transport retry without re-executing an action.
- Added a non-root durable Codex supervisor with `flock`, JSONL/state mode `0600`,
  immediate persistence of `thread.started.thread_id`, exact `exec resume`,
  bounded exponential backoff and states RUNNING, WAITING_QUOTA,
  WAITING_OWNER_ACTION, RETRYABLE_FAILURE, TERMINAL_BLOCKED and COMPLETED.
- The supervisor accepts only the exact public core-repository origin, a
  `codex/*` task branch and an ancestor trusted-base SHA. A failure before a
  durable thread ID fails closed instead of creating a duplicate task.
- Official OpenAI permission profiles are used for workspace-write semantics
  with explicit deny rules for Codex auth and all production paths, no arbitrary
  egress and only the exact core-broker Unix socket. No `--yolo`,
  danger-full-access or raw GitHub token is present.
- Ubuntu 24.04 AppArmor initially denied the bundled bubblewrap helper an
  unprivileged user namespace. A version-pinned, path-specific AppArmor profile
  now grants only `userns` to that helper; the Codex sandbox starts successfully.
- Focused `ruff`, strict `mypy` and 25 Telegram/supervisor/gateway tests: PASS.
- Full isolated regression: 590 tests collected, 590 PASS, exit 0, 360.6 seconds.
- Exact local CI gates: version consistency, manifest (459 files), SBOM,
  package validation, secret scan, pilot tests, compileall, full ruff and mypy
  (129 source files), wheel build and wheel version consistency: PASS.
- The new supervisor unit is still disabled and the production gateway has not
  been restarted. Live Telegram approval and controlled Codex crash/resume await
  governed merge, immutable deployment and separate VPS device authentication.

Next checkpoint: commit/push checkpoint 2, refresh PR #165, prepare immutable
GitHub governance rollback, enforce squash-only, merge through the strict broker,
then run canary and commissioning probes.
