#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-functional-ready.sh must run as root\n' >&2
  exit 1
fi

PYTHON=/opt/hermes-factory-verifier/venv/bin/python
SOURCE_COMMIT="$(${PYTHON} -c \
  'import yaml; v=yaml.safe_load(open("/etc/hermes-factory/qualification-control.yaml",encoding="utf-8")); print(v["source_commit"])')"
ROOT="/var/lib/hermes-factory-verifier/functional-ready/${SOURCE_COMMIT}"
REQUEST="${ROOT}/unsigned.json"
SIGNED="${ROOT}/signed.json"

install -d -o hermesverifier -g hermesfunctional -m 0750 "${ROOT}"
runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result request "${REQUEST}"
runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result sign "${REQUEST}" "${SIGNED}"
runuser -u hermesverifier -- "${PYTHON}" -m scripts.ready_result dispatch "${SIGNED}"
systemctl enable --now hermes-factory-shadow-verify.timer hermes-factory-shadow-finalize.timer
systemctl start --wait hermes-factory-shadow-verify.service
systemctl start --wait hermes-factory-shadow-finalize.service
