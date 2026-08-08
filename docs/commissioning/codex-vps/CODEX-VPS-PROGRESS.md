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

## Checkpoint 3 - exact-head CI and squash-only GitHub governance

- Checkpoint 2 was committed as
  `e0709c9f34944aff0b77fb9297f65ffb6bf9ce3e` and pushed only through the
  typed broker. PR #165 remained open against `main` with the exact task branch.
- The exact-head broker read reported SUCCESS for independent review and all
  five required checks: package integrity, quality, release readiness, scope
  guard and security.
- Captured immutable before-state for repository settings, the active main
  ruleset and effective main rules. The active ruleset has no bypass actors,
  `current_user_can_bypass=never`, strict required checks and required review
  thread resolution.
- Immediately before mutation, the launcher verified that no Q7/Q8/PRE-Q8 unit
  or systemd job was running and that Candidate remained clean at
  `1514525a076190983f6dc13ffb6ec1c9c260c2ca`.
- Enforced squash-only both at repository settings and ruleset ID `19798586`:
  merge commits and rebase merges are disabled, squash is enabled, and branch
  deletion after merge remains enabled. The exact five required checks were
  preserved.
- The one-time transition stored precondition projections, API responses,
  rollback payloads and SHA-256 checksums. Automatic rollback was armed before
  each mutation. A separate `--validate-only` run verified every stored digest
  and exact live after-state without executing the rollback.
- Sanitized before/after repository, ruleset and effective-main evidence is
  included in this directory. No credential or secret value is present.
- After evidence capture, package/version/manifest/SBOM/secret/wheel gates
  passed. The full regression ran in a private mount namespace that hid all
  production paths, used a deterministic unauthenticated `gh` probe and allowed
  only IPv4/IPv6 loopback: 590 collected, 590 PASS in 299.92 seconds. Pilot,
  compileall, full ruff and strict mypy (129 source files) also passed.
- The first commissioning merge attempt stopped before any GitHub mutation
  because the broker identity could not read an owner-mode `0600` evidence
  manifest. That unhandled `PermissionError` terminated and restarted the
  broker, while PR #165 correctly remained open. The broker now catches any
  manifest-read `OSError` and returns a typed fail-closed error without a merge
  call. A dedicated negative regression test asserts both the error and absence
  of a `PUT`; 17 focused tests, ruff and strict mypy pass.

Next checkpoint: commit/push the governance evidence, merge PR #165 through the
strict exact-head broker, deploy the merged immutable runtime and run disposable
canary commissioning.

## Checkpoint 4 - post-auth shared notification-store boundary

- The owner completed a separate VPS `codex login --device-auth`; no Desktop
  credential was copied. `codex login status` reports ChatGPT login, while the
  Codex home and credential file retain modes `0700` and `0600`.
- The owner-action directory now has the designed setgid
  `root:hermescodexops` mode `2770`; SQLite, WAL and SHM files are
  `hermesfactory:hermescodexops` mode `0660`.
- A live write probe under the exact supervisor User/Group/SupplementaryGroups
  exposed an unconditional `chmod(0660)` in `CodexOwnerActionStore`. Linux
  correctly rejected that operation because `hermescodex` is a permitted group
  writer but not the file owner.
- The minimal fail-closed correction skips `chmod` only when the current mode is
  already exactly `0660`; any other mode still requires a successful correction
  or raises and closes the connection. A regression mocks non-owner `chmod` and
  proves an existing correctly shared database opens without calling it.
- Focused owner-action/supervisor regression: 18/18 PASS. Ruff and strict mypy:
  PASS. Full regression in a private mount namespace with loopback only and
  production paths hidden: 594/594 PASS. Version, 469-file manifest, SBOM,
  package, secret, ruff and mypy gates: PASS.

Next checkpoint: commit and publish this minimal fix through a fresh governed
PR, wait for all exact-head checks, squash-merge through the broker, deploy the
immutable merge, then continue live model/crash/resume commissioning.

## Checkpoint 5 - exact Codex CLI contract and live model boundary

- The installed Codex CLI `0.147.0` does not expose a
  `--permission-profile` flag. Official OpenAI permission-profile guidance
  selects the named profile through top-level `default_permissions`; passing
  legacy `--sandbox` settings would override that profile. The supervisor now
  launches `codex --strict-config exec` and relies on the validated
  `approval_policy = "on-request"`, `approvals_reviewer = "auto_review"` and
  `default_permissions = "codex-vps-workspace"` configuration.
- The optional shell snapshot optimization is disabled because the pinned CLI
  emitted a Bash snapshot syntax error on this host. This does not change the
  permission boundary or production semantics.
- The owner-required model contract is pinned as `model = "gpt-5.6-sol"` with
  `model_reasoning_effort = "xhigh"` (the CLI value for Very High). Live
  `turn_context` evidence confirms the exact model, effort, managed permission
  profile, `on-request` approval policy and `auto_review` reviewer.
- A live structured model smoke completed with status PASS. A non-disclosing
  one-byte read probe was redirected to `/dev/null` and returned
  `AUTH_READ_DENIED`; the launcher independently proved the worktree clean
  before and after. Event and result SHA-256 values are
  `e62b129557b86eca4b53543ed2421a0129597ba5d7ec6582129b967c9bb1ade2`
  and `585a90c168e7dd1bd72e14b8e929154c9e902b611a542c217e36e26b81ec03cf`.
  A bounded secret-pattern scan found zero matches.
- Focused supervisor/config tests are 9/9 PASS with Ruff and strict mypy PASS.
  The isolated full regression passed 594 of 595 tests in one run; the sole
  environment-sensitive capability test then passed separately after its
  harness received a private HOME/XDG/GH config and production broker sockets
  were hidden. This provides aggregate 595/595 regression coverage while
  retaining private network, hidden production paths and non-root execution.

Next checkpoint: rebuild the source manifest, run package/SBOM/secret gates,
publish and merge the exact-head PR through the typed broker, deploy the
immutable merge, then execute controlled supervisor crash/resume commissioning.

## Checkpoint 6 - durable resume and code-mode systemd compatibility

- The first controlled crash intentionally killed the supervisor immediately
  after thread.started; the rollout was still zero bytes, so a resume correctly
  failed closed as session_lookup. The commissioning watchdog was tightened to
  require a non-empty, parseable and synced rollout before killing the process.
- With a durable rollout, systemd proved KILL, result=signal, restart counter
  1 and a second start of the same unit. The supervisor preserved the exact
  session ID and recorded resume_count=1, but the resumed model returned
  TERMINAL_BLOCKED: its code-mode host repeatedly exited on signal 5
  (SIGTRAP) and closed stdout.
- The unit had MemoryDenyWriteExecute=true. A new isolated A/B instance changed
  only that property to false while retaining the named permission profile,
  NoNewPrivileges, read-only system paths, explicit production-path denies,
  private state and exact network boundary. It was killed after the first
  successful durable tool output and resumed the same session ID.
- The A/B result is COMPLETED: resume_count=1, zero supervisor failures,
  exact GPT-5.6-sol with xhigh, four structured evidence items, a clean
  worktree, all state files mode 0600, and no SIGTRAP. Secret scans of state,
  journal and the 70,148-byte rollout reported zero findings.
- The template now documents the V8 requirement and sets
  MemoryDenyWriteExecute=false; a regression test locks that compatibility
  decision while asserting that the independent privilege, filesystem and
  production isolation controls remain enabled.
- Source verification after the fix: 10/10 supervisor tests plus the blocked
  routing regression, Ruff and strict mypy PASS; isolated full regression
  595/595 PASS; version, 469-file manifest, SBOM, package, secret, policy,
  pilot, compileall, full Ruff and strict mypy gates PASS. The new 2.5.0 wheel
  SHA-256 is f45acbc7da4cb2afdc73fd301d7511cb66815979013be0f2515a8e4cc9ca00d7.

Next checkpoint: publish and squash-merge the exact head through the typed
broker, deploy the immutable merge, then repeat the controlled crash/resume
without an instance override.
