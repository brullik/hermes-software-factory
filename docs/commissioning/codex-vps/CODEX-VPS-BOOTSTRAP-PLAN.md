# Codex VPS bootstrap plan

Generated from live evidence on 2026-08-07 UTC. This is a commissioning plan,
not proof of completion.

## Immutable baseline

- Repository: `brullik/hermes-software-factory`.
- Live `main` and Candidate release: `1514525a076190983f6dc13ffb6ec1c9c260c2ca`.
- Candidate release is detached and clean under
  `/opt/hermes-factory-candidate/releases/1514525a076190983f6dc13ffb6ec1c9c260c2ca`.
- PRE-Q8 orchestration ended fail-closed at 2026-08-07 18:36:37 UTC.
- Production controller, workers, gateway, GitHub broker and pilot container are
  not bootstrap targets.
- No reboot is planned.

The following paths are read-only for this bootstrap unless an exact later
checkpoint explicitly says otherwise:

- `/opt/hermes-factory/current`
- `/opt/hermes-factory-candidate/current`
- `/var/lib/hermes-factory`
- `/var/lib/hermes-factory-candidate`
- `/var/lib/hermes-factory-functional`
- `/var/lib/hermes-factory-pre-q8`
- `/var/lib/hermes-factory-verifier`
- all current qualification evidence and journals

## New isolated scope

- Unix identity: `hermescodex` (no sudo/docker/production groups).
- Home/auth: `/home/hermescodex/.codex`, mode `0700`.
- Repository clone: `/var/lib/hermes-codex/repository`.
- Worktrees/state: `/var/lib/hermes-codex/worktrees` and
  `/var/lib/hermes-codex/state`, mode `0700`.
- Task branch: `codex/vps-bootstrap-20260807-*` from exact live `origin/main`.
- Non-secret config: `/etc/hermes-codex`.
- Root-owned wrappers: `/usr/local/libexec/hermes-codex-*`.
- Supervisor unit: `hermes-codex-vps.service`, installed disabled until A00-A38.
- Core GitHub autonomy uses a separate exact-repository broker/socket/receipt
  scope; the Candidate broker allowlist/state is not widened in place.

## Dependency order

1. Preserve read-only live inventory and package hashes.
2. Install only missing bootstrap packages and the official standalone Codex
   CLI as `hermescodex`; record version and installer/binary SHA-256.
3. Create the isolated public clone/worktree and commit this plan/progress.
4. Perform all code changes and tests in the isolated branch.
5. Export live GitHub repository/ruleset state and its rollback material.
6. Submit broker/governance/supervisor changes through PR and existing gates.
7. Perform the single unavoidable owner action in a protected terminal:
   separate Codex device login. Reuse the existing root-owned GitHub credential
   only through the exact-repository broker and only if live probes prove its
   scope; never expose or copy its value.
8. Run canary branch/PR/checks/squash lifecycle through the service identity.
9. Verify Telegram typed owner action using the existing gateway.
10. Run controlled supervisor crash/resume and representative Hermes goal.
11. Close A00-A38 and enable the supervisor only after commissioning PASS.

## Rollback

- Keep production/Candidate services untouched.
- Stop/disable only `hermes-codex-vps.service` and the dedicated core broker.
- Revoke only the VPS credential epoch; preserve Candidate credential/state.
- Restore GitHub ruleset from the immutable `GITHUB-RULESET-BEFORE.json` and
  recorded digest/command.
- Preserve Codex evidence and task worktree for audit; remove them only under a
  separate reviewed uninstall action.
- Revert the bootstrap PR by normal governed PR; never direct-push `main`.

## Stop/fail-closed conditions

- Any active Q7/Q8/deploy/rollback state makes production/governance mutations
  unavailable until a new safe-window probe passes.
- Any credential exposure, repository mismatch, stale SHA, non-squash method,
  missing check, unresolved thread, fork head or replay conflict stops the
  affected operation.
- Two identical failed attempts trigger diagnosis escalation, not repetition.
- Final PASS requires authoritative evidence for all A00-A38.
