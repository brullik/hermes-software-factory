#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-lts-ready.sh must run as root\n' >&2
  exit 1
fi

PYTHON=/opt/hermes-factory-verifier/venv/bin/python
SOURCE_COMMIT="$(${PYTHON} -c \
  'import yaml; value=yaml.safe_load(open("/etc/hermes-factory/qualification-control.yaml",encoding="utf-8")); print(value["source_commit"])')"
ROOT="/var/lib/hermes-factory-functional/ready/${SOURCE_COMMIT}"
REQUEST="${ROOT}/unsigned-lts.json"
SIGNED="${ROOT}/signed-lts.json"

install -d -o hermesverifier -g hermesfunctional -m 2750 "${ROOT}"
runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result \
  lts-request "${REQUEST}"
runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result \
  sign "${REQUEST}" "${SIGNED}"
RESULT="$(runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result \
  lts-dispatch "${SIGNED}")"
STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"
if [[ "${STATUS}" == FINAL_NOTIFICATION_PENDING ]]; then
  systemctl start --wait hermes-factory-owner-notifier.service
  RESULT="$(runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result \
    lts-dispatch "${SIGNED}")"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["status"])')"
fi
if [[ "${STATUS}" != AUTONOMOUS_FACTORY_READY ]]; then
  printf 'Final ready result did not reach its Telegram receipt: %s\n' "${STATUS}" >&2
  exit 1
fi
printf '%s\n' "${RESULT}"
