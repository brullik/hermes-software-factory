#!/usr/bin/env bash
set -euo pipefail

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY must be supplied by systemd credential or secure environment}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE must point to a root-readable file}"

STATE_DIR="/var/lib/hermes-factory"
ETC_DIR="/etc/hermes-factory"
PRODUCTS_DIR="/opt/hermes-factory-products"
PILOT_DATA_DIR="${PILOT_DATA_DIR:-/var/lib/docker/volumes/pilot_pilot-data/_data}"
INPUT_DIR="${BACKUP_INPUT_DIR:-/var/cache/hermes-factory/backup-input}"
LOCK_FILE="${BACKUP_LOCK_FILE:-/run/lock/hermes-factory-backup.lock}"
PROOF_PATH="${BACKUP_PROOF_PATH:-$STATE_DIR/evidence/backup-latest.json}"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf -- "$TMP_DIR"
  rm -f -- "$INPUT_DIR/controller.db" "$INPUT_DIR/controller.db.next"
}
trap cleanup EXIT

if [ -L "$INPUT_DIR" ]; then
  printf 'backup input directory must not be a symlink\n' >&2
  exit 78
fi
install -d -o root -g root -m 0700 "$INPUT_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  printf 'another Hermes backup is already running\n' >&2
  exit 75
fi

# The host lock proves no Hermes backup process is active locally. Let restic
# remove only stale backend locks left by interrupted previous runs.
restic unlock

rm -f -- "$INPUT_DIR/controller.db" "$INPUT_DIR/controller.db.next"

if command -v sqlite3 >/dev/null && [ -f "$STATE_DIR/controller.db" ]; then
  sqlite3 "$STATE_DIR/controller.db" ".backup '$INPUT_DIR/controller.db.next'"
  chmod 0600 "$INPUT_DIR/controller.db.next"
  mv -- "$INPUT_DIR/controller.db.next" "$INPUT_DIR/controller.db"
fi

BACKUP_PATHS=(
  "$INPUT_DIR"
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
  --proof "$PROOF_PATH"
