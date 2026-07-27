#!/usr/bin/env bash
set -euo pipefail

: "${HEALTH_URL:?HEALTH_URL is required}"
: "${ROLLBACK_COMMAND:?ROLLBACK_COMMAND must reference an allowlisted wrapper}"

read -r -a rollback_argv <<< "${ROLLBACK_COMMAND}"
if [ "${#rollback_argv[@]}" -ne 3 ] \
  || [ "${rollback_argv[0]}" != "/opt/hermes-factory/bin/factory-rollback" ] \
  || [ "${rollback_argv[1]}" != "--release-id" ] \
  || [[ ! "${rollback_argv[2]}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf 'rollback command rejected: only factory-rollback --release-id <safe-id> is allowed\n' >&2
  exit 78
fi

attempts=12
for ((i=1; i<=attempts; i++)); do
  if curl --fail --silent --show-error --max-time 5 "$HEALTH_URL" >/dev/null; then
    printf 'health=PASS attempt=%s\n' "$i"
    exit 0
  fi
  sleep 5
done

printf 'health=FAIL action=rollback\n' >&2
exec "${rollback_argv[@]}"
