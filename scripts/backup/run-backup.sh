#!/usr/bin/env bash
set -euo pipefail

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY must be supplied by systemd credential or secure environment}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE must point to a root-readable file}"

STATE_DIR="/var/lib/hermes-factory"
ETC_DIR="/etc/hermes-factory"
PRODUCTS_DIR="/opt/hermes-factory-products"
PILOT_DATA_DIR="${PILOT_DATA_DIR:-/var/lib/docker/volumes/pilot_pilot-data/_data}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if command -v sqlite3 >/dev/null && [ -f "$STATE_DIR/controller.db" ]; then
  sqlite3 "$STATE_DIR/controller.db" ".backup '$TMP_DIR/controller.db'"
fi

BACKUP_PATHS=(
  "$TMP_DIR"
  "$STATE_DIR/evidence"
  "$STATE_DIR/kanban"
  "$ETC_DIR"
)
if [ -d "$PILOT_DATA_DIR" ]; then
  BACKUP_PATHS+=("$PILOT_DATA_DIR")
fi
if [ -d "$PRODUCTS_DIR" ]; then
  BACKUP_PATHS+=("$PRODUCTS_DIR")
fi

restic backup "${BACKUP_PATHS[@]}" \
  --exclude "$ETC_DIR/credentials.d" \
  --tag hermes-factory

restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
restic check
restic snapshots --latest 1 --tag hermes-factory --json \
  > "$TMP_DIR/latest-snapshot.json"
/opt/hermes-factory/venv/bin/python \
  /opt/hermes-factory/current/scripts/backup/write-backup-proof.py \
  --snapshots-json "$TMP_DIR/latest-snapshot.json" \
  --proof "$STATE_DIR/evidence/backup-latest.json"
