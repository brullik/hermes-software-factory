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
- Created `hermescodex` as uid/gid `1001`, with no supplementary groups, sudo or
  Docker access. Home, auth, state, evidence and worktree roots are private.
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
- Focused gate: 21 broker tests PASS. `ruff` PASS and strict `mypy` PASS for all
  changed broker modules.
- First full regression correctly exposed three VPS environment collisions:
  permissive inherited umask, real production fallback paths and a symlinked
  Python venv. No product-code assertion caused those seven failures.
- Authoritative full regression in a one-shot private mount namespace, copied
  venv and `umask 0022`: PASS, exit 0, 100% of collected tests.
- Post-regression proof: no namespace mounts remained; controller/gateway stayed
  active; PRE-Q8 remained fail-closed; Candidate stayed clean at
  `1514525a076190983f6dc13ffb6ec1c9c260c2ca`.

Next checkpoint: checkpoint commit and bootstrap PR transport.
