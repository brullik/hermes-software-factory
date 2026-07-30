# Semantic lifecycle recovery

This runbook migrates durable product graphs without deleting tasks, failures,
events, evidence, or accepted results. The generated recovery plan is bound to
the exact audited state fingerprint and is safe to replay after interruption.

## Preconditions

- The exact release commit and package digest are known.
- Controller is running; gateway and workers are stopped or drained.
- A local backup, `restic check`, and restore drill have passed.
- `factory maintenance enter` has closed intake and new task claims.

Do not edit the production SQLite database manually.

For an existing installation, provision the controller-owned rootless builder
and install the updated service units once from the exact promoted source:

```bash
sudo /opt/hermes-factory/current/scripts/bootstrap/upgrade-autonomy-runtime.sh
```

The script performs a no-network `FROM scratch` build as `hermesfactory`; an
installed executable alone is not accepted as builder capability evidence.

## Commands

```bash
sudo -u hermesfactory factory maintenance enter \
  --reason semantic-lifecycle-migration
sudo install -d -o hermesfactory -g hermesfactory -m 0750 \
  /var/lib/hermes-factory/recovery
sudo -u hermesfactory factory state-audit \
  --output /var/lib/hermes-factory/recovery/state-audit.json
sudo -u hermesfactory factory recovery-plan --all-active \
  --output /var/lib/hermes-factory/recovery/plan.json
sudo -u hermesfactory factory recovery-plan --all-active --dry-run \
  --plan /var/lib/hermes-factory/recovery/plan.json
sudo -u hermesfactory factory recovery-apply \
  --plan /var/lib/hermes-factory/recovery/plan.json
sudo -u hermesfactory factory graph-verify --all-active
```

The apply step supersedes poisoned active work, resolves its open historical
failures and incidents, preserves accepted immutable records, and creates
exactly one deterministic semantic recovery root per active legacy product.
Replaying the same plan returns `REPLAYED` and creates no duplicate work.

Leave maintenance only after graph verification, service health, capability
preflight, and the selected canary recovery root are all ready:

```bash
sudo -u hermesfactory factory maintenance leave
```

`/readyz` returns HTTP 503 while maintenance is active. `/healthz` remains
available for liveness, and `/metrics` exposes maintenance and SQLite busy
counters.

## Product policy

- Historical accepted records are retained for audit. A compiled plan may use
  them only through validated, typed dependency evidence.
- Repeated same-role repair chains are superseded; the recovery root must
  propose a changed semantic hypothesis.
- Paused products stay paused unless a recovery action explicitly carries a
  resume status.
- The production canary is resumed only after rootless container builder,
  scanners, GitHub, staging, backup, production, and rollback capabilities
  pass controller-owned probes.
