#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 || "$1" != "--release-id" || ! "$2" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf 'usage: factory-rollback --release-id <safe-release-id>\n' >&2
  exit 2
fi

RELEASE_ID="$2"
RELEASE_ROOT="/var/lib/hermes-factory/releases"
RELEASE_DIR="${RELEASE_ROOT}/${RELEASE_ID}"
COMPOSE_FILE="${RELEASE_DIR}/compose.yaml"
if [[ ! -f "${COMPOSE_FILE}" || -L "${COMPOSE_FILE}" ]]; then
  printf 'release manifest is missing\n' >&2
  exit 1
fi
if [[ "${RELEASE_DIR}" != "${RELEASE_ROOT}"/* ]]; then
  printf 'release path escaped allowlisted root\n' >&2
  exit 78
fi

docker compose --project-directory "${RELEASE_DIR}" --file "${COMPOSE_FILE}" up -d --no-build
