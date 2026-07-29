#!/usr/bin/env bash
set -euo pipefail

PROOF_PATH="${BACKUP_PROOF_PATH:-/var/lib/hermes-factory/evidence/backup-latest.json}"
MAX_AGE_SECONDS="${OFFSITE_BACKUP_MAX_AGE_SECONDS:-93600}"
PYTHON_BIN="/opt/hermes-factory/venv/bin/python"
DUE_CHECK="/opt/hermes-factory/current/scripts/backup/offsite-backup-due.py"
BACKUP_RUNNER="/opt/hermes-factory/current/scripts/backup/run-backup.sh"

if "$PYTHON_BIN" "$DUE_CHECK" \
  --proof "$PROOF_PATH" \
  --max-age-seconds "$MAX_AGE_SECONDS"; then
  export BACKUP_PROOF_PATH="$PROOF_PATH"
  exec /usr/bin/env bash "$BACKUP_RUNNER"
else
  status=$?
  if [ "$status" -eq 10 ]; then
    exit 0
  fi
  exit "$status"
fi
