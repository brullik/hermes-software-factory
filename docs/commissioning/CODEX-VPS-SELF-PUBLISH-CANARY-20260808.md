# Codex VPS self-publication canary

This commissioning canary proves one exactly-once GitHub publication from the
supervised VPS through the typed Unix-socket broker. It is neutral evidence,
not a product change, deployment, Stable-runtime change, or factory-readiness
claim.

## Frozen lineage

- Replay guard: `CODEX-VPS-CANARY-20260808-ONE`
- Branch: `codex/vps-self-publish-canary-20260808`
- Trusted base: `59e98d03f8a0d13848283e89e454e899ab3f48d3`
- Original goal digest:
  `031b0f3414532cb26781bb6637ae0f456c94a5270aeaca7c852e13b29bce6497`
- Approval evidence digest:
  `1058b3f2b4870342396df0e2214f50c52332c6f2a467ac75b663aa7ea8434771`
- Frozen contract digest:
  `57ce0b5fb728a1239cc4a641896c55b473c9f3c7e216c5692deb82217d627a4c`
- Contract-only first commit:
  `d1d6f2b3ae76cf13077d48cd579e751fe0326e33`

## Required proof

The exact two-commit head must pass the merge-base scope guard, package and
manifest validation, focused tests, secret scanning, Ruff, mypy, and the full
controller CI-parity run. The typed broker must then push that exact head,
create a non-draft pull request against `main`, and confirm exact-head metadata,
all required checks, independent review, and zero unresolved review threads.

The canary must never be merged. After verification, the typed broker closes
the pull request and removes the remote task branch. Immutable broker receipts
and a replay completion record prevent a second publication after retries,
process crashes, or service restarts. The preserved original branch and stash
are then restored and compared with the pre-canary status and content digests.
